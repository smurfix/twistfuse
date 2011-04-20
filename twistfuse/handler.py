# -*- coding: utf-8 -*-
from __future__ import division,print_function

##
##  Copyright © 2011, Matthias Urlichs <matthias@urlichs.de>
##
## This code descends from an implementation at
## http://codespeak.net/svn/user/arigo/hack/pyfuse.
## which does not have a license statement, but (according to
## personal communication with its author) has been released
## under the 3-clause MIT license.

from kernel import *
import os, errno, sys, stat, socket
from traceback import print_exc

from zope.interface import implements
from twisted.internet import abstract,fdesc,protocol,reactor
from twisted.internet.defer import maybeDeferred,inlineCallbacks,returnValue,Deferred
from twisted.internet.interfaces import IReadDescriptor
from twisted.internet.main import CONNECTION_DONE,CONNECTION_LOST
from twisted.internet.process import Process

from passfd import recvfd
try:
	errno.ENOATTR
except AttributeError:
	errno.ENOATTR=61 # TODO: this is Linux


__all__ = ("Handler","NoReply")


def debugproc(p):
	return p
	def doit(*a,**k):
		print(">",p,a,k)
		try:
			res = p(*a,**k)
		except Exception:
			e1,e2,e3 = sys.exc_info()
			raise e1,e2,e3
		else:
			if isinstance(res,Deferred):
				def pr(r):
					print("<",p,r)
					return r
				res.addBoth(pr)
			else:
				print("<",p,res)
		return res
	return doit

class NoReply(Exception):
	"""Raise this exception to not send a FUSE reply back"""
	pass
class ExitLoop(StopIteration):
	"""Special loop break-out exception for readdir, if the buffer gets full"""
	pass

class FDReader(object):
	implements(IReadDescriptor)

	def logPrefix(self): return ">FDR"

	def __init__(self,fd,proc):
		self.fd = fd
		self.proc = proc
		fdesc.setNonBlocking(fd)
		reactor.addReader(self)

	def fileno(self):
		if self.fd is None: return -1
		return self.fd.fileno()

	def doRead(self):
		reactor.removeReader(self)
		try:
			fd = recvfd(self.fd)[0]
		except Exception as e:
			self._close()
			self.proc.got_no_fd(e)
		else:
			self._close()
			self.proc.got_fd(fd)

	def _close(self):
		if self.fd is not None:
			fd = self.fd
			self.fd = None
			reactor.removeReader(self)
			fd.close()
			fd = None

	def connectionLost(self,reason):
		if self.fd is not None:
			self._close()
			self.proc.got_no_fd(reason)
	
	def __del__(self):
		if self.fd is not None:
			self._close()


class FMHandler(object):
	def __init__(self):
		pass
	def makeConnection(self,proc):
		pass
	def childDataReceived(self, childFD, data):
		sys.stderr.write(data)
	def childConnectionLost(self, childFD):
		pass
	def processExited(self, reason):
		pass
	def processEnded(self, reason):
		pass


class FuseMounter(Process):
	def __init__(self, handler, mountpoint, opts):
		self.handler = handler
		(s0, s1) = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0)
		args = ["fusermount",mountpoint]
		if opts:
			args.extend(["-o",opts])

		s0f = s0.fileno()
		super(FuseMounter,self).__init__(reactor, "/bin/fusermount", args, {"_FUSE_COMMFD":str(s0f)}, None, FMHandler(), childFDs={0:"w",1:"r",2:"r",s0f:s0f})
		s0.close()
		self.fd = FDReader(s1,self)

	def got_fd(self,fd):
		self.handler.mount_done(fd)
	def got_no_fd(self,reason):
		self.handler.mount_error(reason)
		

class FuseFD(abstract.FileDescriptor):
	def __init__(self,handler,fd):
		super(FuseFD,self).__init__()
		self.fd = fd
		self.handler = handler
		reactor.addReader(self)
		self.connected = True
	def fileno(self):
		return self.fd
	def writeSomeData(self, data):
		return fdesc.writeToFD(self.fd, data)

	def doRead(self):
		# use max_length, as the kernel doesn't like split read requests
		try:
			data = os.read(self.fd, self.handler.MAX_LENGTH)
		except (OSError, IOError), ioe:
			if ioe.args[0] in (errno.EAGAIN, errno.EINTR):
				return
			else:
				return CONNECTION_LOST
		if not data:
			return CONNECTION_DONE
		self.handler.dataReceived(data)

	def dataReceived(self, data):
		self.handler.dataReceived(data)


class Handler(object, protocol.Protocol):
	__system = os.system
	mountpoint = fd = None
	__in_header_size  = fuse_in_header.calcsize()
	__out_header_size = fuse_out_header.calcsize()
	MAX_LENGTH = FUSE_MAX_IN

	def __init__(self, logfile='STDERR'):
		if logfile == 'STDERR':
			logfile = sys.stderr
		self.logfile = logfile
		self.filehandles = {}
		self.dirhandles = {}
		self.notices = {}
		self.nexth = 1
		self.data = ""
		super(Handler,self).__init__()

	def mount_done(self,fd):
		self.transport = FuseFD(self,fd)
		self.log('* mounted at %s', self.mountpoint)
	def mount_error(self,reason):
		print(reason, file=sys.stderr)
		reactor.stop()

	def mount(self,filesystem,mountpoint, **opts1):
		opts = getattr(filesystem, 'MOUNT_OPTIONS', {}).copy()
		opts.update(opts1)
		if opts:
			opts = opts.items()
			opts.sort()
			optlist = []
			for item in opts:
				if item[1] is None:
					optlist.append(item[0])
				else:
					optlist.append('%s=%s' % item)
			opts = ','.join(optlist)
		else:
			opts = None
		self.mountpoint = mountpoint
		self.filesystem = filesystem
		FuseMounter(self,mountpoint,opts)

	def umount(self):
		fs = self.filesystem
		if fs is not None:
			fs.stop(False)
		fd = self.fd
		if fd is not None:
			self.fd = None
			fd.close()
		if self.mountpoint:
			cmd = "fusermount -u '%s'" % self.mountpoint.replace("'", r"'\''")
			self.mountpoint = None
			self.log('* %s', cmd)
			self.__system(cmd)
	__del__ = umount

	def log(self,s,*a):
		if not self.logfile:
			return
		print(s%a, file=self.logfile)


	## Twisted stuff

	def dataReceived(self, data):
		self.data += data
		headersize = self.__in_header_size
		if len(self.data) < headersize:
			return
		req = fuse_in_header(self.data[:headersize])
		if len(self.data) < req.len:
			return
		msg = self.data[headersize:req.len]
		self.data = self.data[req.len:]

		try:
			name,s_in,s_out = fuse_opcode2name[req.opcode]
		except KeyError:
			self.log('%d: not implemented', req.opcode)
			self.send_reply(req, err=errno.ENOSYS)
			return
			
		def doit(msg):
			try:
				meth = getattr(self, "fuse_"+name)
			except (IndexError, AttributeError):
				raise NotImplementedError
			if s_in is not None:
				msg = s_in(msg)
			self.log('%s(%d) << %s', name, req.nodeid, msg)
			return meth(req, msg)

		reply = maybeDeferred(doit,msg)
#		def logReply(r):
#			self.log('   >> %s', repr(r))
#			return r
#		reply.addBoth(logReply)

		def dataHandler(reply):
			if s_out is not None and hasattr(reply,"items"):
				reply = s_out(**reply)
			self.send_reply(req, reply)
		def errHandler(e):
			if e.check(NotImplementedError):
				self.log('%s: not implemented', name)
				self.send_reply(req, err=errno.ENOSYS)
			elif e.check(EnvironmentError): # superclass of IOError, OSError
				if e.value.errno is None:
					errn = e.value.args[0]
					errs = " ".join(e.value.args[1:])
				else:
					errn = e.value.errno
					errs = e.value.strerror
				self.log('%s: %d: %s', name, -(errn or 0), errs)
				self.send_reply(req, err = errn or errno.ESTALE)
			elif e.check(NoReply):
				pass
			else:
				e.printTraceback(file=sys.stderr)
				self.send_reply(req, err = errno.ESTALE)
		reply.addCallback(dataHandler)
		reply.addErrback(errHandler)

	def send_reply(self, req, reply=None, err=0):
		assert 0 <= err < 1000
		if reply is None:
			reply = ''
		elif isinstance(reply, unicode):
			reply = reply.encode("utf-8")
		elif not isinstance(reply, str):
			reply = reply.pack()
		f = fuse_out_header(unique = req.unique,
							error  = -err,
							len    = self.__out_header_size + len(reply))
		data = f.pack() + reply
		try:
			#self.transport.write(data)
			l = os.write(self.transport.fileno(),data)
			if l != len(data):
				raise RuntimeError("could not write to FUSE socket")
		except Exception as e:
			print_exc(file=sys.stderr)
			self.connectionLost(e)
			

	def connectionLost (self, reason=protocol.connectionDone):
		self.umount()
		reactor.stop()
		
	# ____________________________________________________________

	def fuse_init(self, req, msg):
		self.log('INIT: %d.%d', msg.major, msg.minor)
		d = self.filesystem.mount(self, msg.flags)
		rd = dict(major = FUSE_KERNEL_VERSION,
			minor = FUSE_KERNEL_MINOR_VERSION, max_readahead = 1024*1024,
			max_background=20, max_write=4096, flags = 0)
		if d:
			rd.update(d)
		self.MAX_LENGTH = rd['max_write']+fuse_in_header.calcsize()+fuse_write_in.calcsize()
		return rd


	@debugproc
	@inlineCallbacks
	def fuse_getattr(self, req, msg):
		node = yield self.filesystem.getnode(req.nodeid)
		res = yield self._getattr(node, ctx=req)
		returnValue( res )

	@debugproc
	@inlineCallbacks
	def _getattr(self,node,ctx):
		attr = yield node.getattr()
		if 'attr' not in attr:
			attr = {'attr':attr}
			attr['attr_valid'] = (1,0)
			attr['entry_valid'] = (1,0)
		returnValue( attr )

	@debugproc
	@inlineCallbacks
	def fuse_setattr(self, req, msg):
		node = yield self.filesystem.getnode(req.nodeid)
		values = {}
		if msg.valid & FATTR_MODE:
			values['mode'] = msg.mode & 0777
		if msg.valid & FATTR_UID:
			values['uid'] = msg.uid
		if msg.valid & FATTR_GID:
			values['gid '] = msg.gid
		if msg.valid & FATTR_SIZE:
			values['size'] = msg.size
		if msg.valid & FATTR_ATIME:
			values['atime'] = msg.atime
		if msg.valid & FATTR_MTIME:
			values['mtime'] = msg.mtime
		node.setattr(ctx=req, **values)
		res = yield self._getattr(node, ctx=req)
		returnValue( res )

	@debugproc
	def fuse_release(self, req, msg):
		try:
			f = self.filehandles.pop(msg.fh)
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		else:
			return f.release(ctx=req)

	@debugproc
	def fuse_releasedir(self, req, msg):
		try:
			f = self.dirhandles.pop(msg.fh)
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		else:
			return f.release(ctx=req)

	@debugproc
	@inlineCallbacks
	def fuse_opendir(self, req, msg):
		node = yield self.filesystem.getnode(req.nodeid)
		attr = yield node.getattr()
		if 'attr' in attr:
			attr = attr['attr']
		if mode2type(attr['mode']) != TYPE_DIR:
			raise IOError(errno.ENOTDIR, node)
		f = yield node.opendir(ctx=req)
		fh = self.nexth
		self.nexth += 1
		self.dirhandles[fh] = f
		returnValue( dict(fh = fh) )

	@debugproc
	def fuse_fsyncdir(self, req, msg):
		try:
			f = self.dirhandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		return f.sync(msg.fsync_flags, ctx=req)

	@debugproc
	@inlineCallbacks
	def fuse_readdir(self, req, msg):
		try:
			f = self.dirhandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		# start or rewind
		d_entries = []
		length = [0]

		def _read_cb(name, type, inode, off):
			if isinstance(name,unicode):
				name = name.encode("utf-8")
			d_entry = fuse_dirent(ino  = inode,
			                      off  = off,
			                      type = type,
			                      name = name)
			d_len = fuse_dirent.calcsize(len(name))
			if length[0]+d_len > msg.size:
				raise ExitLoop
			d_entries.append(d_entry)
			length[0] += fuse_dirent.calcsize(len(name))

		try:
			yield f.read(_read_cb, offset=msg.offset, ctx=req)
		except ExitLoop:
			pass
		data = ''.join([d.pack() for d in d_entries])
		returnValue( data )

	@inlineCallbacks
	def replyentry(self, res):
		if isinstance(res,tuple):
			node,entry_valid = res
		else:
			node = res
			entry_valid = node.entry_valid()
		attr = yield node.getattr()
		if 'attr' not in attr:
			attr = {'attr': attr}
		if 'attr_valid' not in attr:
			attr['attr_valid'] = node.attr_valid()
		if 'entry_valid' not in attr:
			attr['entry_valid'] = entry_valid
		yield self.filesystem.remember(node)
		returnValue( attr )

	@debugproc
	@inlineCallbacks
	def fuse_lookup(self, req, msg):
		node = yield self.filesystem.getnode(req.nodeid)
		res = yield node.lookup(msg)
		res = yield self.replyentry(res)
		returnValue( res )

	@debugproc
	@inlineCallbacks
	def fuse_open(self, req, msg):
		node = yield self.filesystem.getnode(req.nodeid)
		attr = yield node.getattr()
		if 'attr' in attr:
			attr = attr['attr']
		if mode2type(attr["mode"]) != TYPE_REG:
			raise IOError(errno.EPERM, node)
		f = yield node.open(msg.flags, ctx=req)
		if isinstance(f, tuple):
			f, open_flags = f
		else:
			open_flags = 0
		fh = self.nexth
		self.nexth += 1
		self.filehandles[fh] = f
		returnValue( dict(fh = fh, open_flags = open_flags) )

	@debugproc
	@inlineCallbacks
	def fuse_create(self, req, msg):
		msg, filename = msg
		node = yield self.filesystem.getnode(req.nodeid)
		attr = yield node.getattr()
		if 'attr' in attr:
			attr = attr['attr']
		if mode2type(attr["mode"]) != TYPE_DIR:
			raise IOError(errno.EPERM, node)
		f = yield node.create(filename, msg.flags, msg.mode, msg.umask, ctx=req)
		inode = f[0]
		if len(f) > 2:
			open_flags = f[2]
		else:
			open_flags = 0
		f = f[1]

		fh = self.nexth
		self.nexth += 1
		self.filehandles[fh] = f
		res = yield self.replyentry(inode)
		res['open'] = {'fh':fh, 'open_flags':open_flags }
		returnValue( res )


	@debugproc
	def fuse_read(self, req, msg):
		try:
			f = self.filehandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		return f.read(msg.offset, msg.size, ctx=req)

	@debugproc
	def fuse_flush(self, req, msg):
		try:
			f = self.filehandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		return f.flush(msg.flush_flags, ctx=req)

	@debugproc
	def fuse_fsync(self, req, msg):
		try:
			f = self.filehandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		return f.sync(msg.fsync_flags, ctx=req)

	@debugproc
	@inlineCallbacks
	def fuse_getlk(self, req, msg):
		try:
			f = self.filehandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		yield f.getlock(msg.start,msg.end,msg.type, ctx=req)
		returnValue( dict(start = msg.start, end = msg.end,
		             type = msg.type, pid = msg.pid) )
		
	@debugproc
	@inlineCallbacks
	def fuse_setlk(self, req, msg):
		try:
			f = self.filehandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		yield f.setlock(msg.start,msg.end,msg.type, wait=0, ctx=req)
		returnValue( dict(start = msg.start, end = msg.end,
		             type = msg.type, pid = msg.pid) )
		
	@debugproc
	@inlineCallbacks
	def fuse_setlkw(self, req, msg):
		try:
			f = self.filehandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		yield f.setlock(msg.start,msg.end,msg.type, wait=1, ctx=req)
		returnValue( dict(start = msg.start, end = msg.end,
		             type = msg.type, pid = msg.pid) )
		
	@debugproc
	@inlineCallbacks
	def fuse_write(self, req, msg):
		msg, data = msg
		try:
			f = self.filehandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		size = yield f.write(msg.offset, data, ctx=req)
		if size is None: size = len(data)
		returnValue( dict(size = size) )

	@debugproc
	@inlineCallbacks
	def fuse_mknod(self, req, msg):
		msg, filename = msg
		node = yield self.filesystem.getnode(req.nodeid)
		res = yield node.mknod(filename, msg.mode,msg.rdev,msg.umask, ctx=req)
		res = yield self.replyentry(res)
		returnValue( res )

	@debugproc
	@inlineCallbacks
	def fuse_mkdir(self, req, msg):
		msg, filename = msg
		node = yield self.filesystem.getnode(req.nodeid)
		res = yield node.mkdir(filename, msg.mode,msg.umask, ctx=req)
		res = yield self.replyentry(res)
		returnValue( res )

	@debugproc
	@inlineCallbacks
	def fuse_symlink(self, req, msg):
		linkname, target = msg
		node = yield self.filesystem.getnode(req.nodeid)
		res = yield node.symlink(linkname, target, ctx=req)
		res = yield self.replyentry(res)
		returnValue( res )

	@debugproc
	@inlineCallbacks
	def fuse_link(self, req, msg):
		msg, target = msg
		oldnode = yield self.filesystem.getnode(msg.oldnodeid)
		newnode = yield self.filesystem.getnode(req.nodeid)
		res = yield newnode.link(oldnode, target, ctx=req)
		res = yield self.replyentry(res)
		returnValue( res )

	@debugproc
	@inlineCallbacks
	def fuse_unlink(self, req, msg):
		filename = msg

		node = yield self.filesystem.getnode(req.nodeid)
		yield node.unlink(filename, ctx=req)
		returnValue( None )

	@debugproc
	@inlineCallbacks
	def fuse_rmdir(self, req, msg):
		dirname = msg

		node = yield self.filesystem.getnode(req.nodeid)
		yield node.rmdir(dirname, ctx=req)
		returnValue( None )

	@debugproc
	@inlineCallbacks
	def fuse_access(self, req, msg):
		node = yield self.filesystem.getnode(req.nodeid)
		yield node.access(msg.mask, ctx=req)
		returnValue( None )

	@debugproc
	def fuse_interrupt(self, req, msg):
		# Pass req.unique into every upcall?
		raise IOError(errno.ENOSYS, "interrupt not supported")

	@debugproc
	@inlineCallbacks
	def fuse_forget(self, req, msg):
		self.log("FORGET %s %s",repr(req),repr(msg))

		try:
			node = yield self.filesystem.getnode(req.nodeid)
			yield self.filesystem.forget(node)
		except Exception:
			pass
		raise NoReply

	@debugproc
	@inlineCallbacks
	def fuse_batch_forget(self, req, msg):
		self.log("BFORGET",repr(req),repr(msg))
		if hasattr(self.filesystem, 'forget'):
			msg, data = msg
			size = fuse_forget_one.calcsize()
			offset = 0
			for i in range(msg.count):
				msg1 = fuse_forget_one(data[offset:offset+size])
				try:
					node = yield self.filesystem.getnode(msg1.nodeid)
					yield self.filesystem.forget(node)
				except Exception:
					pass
				offset += size
		raise NoReply

	@debugproc
	@inlineCallbacks
	def fuse_readlink(self, req, msg):
		node = yield self.filesystem.getnode(req.nodeid)
		target = yield node.readlink(ctx=req)
		returnValue( target )

	@debugproc
	@inlineCallbacks
	def fuse_rename(self, req, msg):
		msg, oldname, newname = msg
		oldnode = yield self.filesystem.getnode(req.nodeid)
		newnode = yield self.filesystem.getnode(msg.newdir)
		yield self.filesystem.rename(oldnode, oldname, newnode, newname, ctx=req)
		returnValue( None )

	@debugproc
	def getxattrs(self, node):
		return node.getxattrs()

	@debugproc
	@inlineCallbacks
	def fuse_listxattr(self, req, msg):
		node = yield self.filesystem.getnode(req.nodeid)
		if hasattr(node,'listxattrs'):
			names = yield node.listxattrs(ctx=req)
		else:
			names = yield node.getxattrs(ctx=req)
			names = names.keys()

		totalsize = 0
		for name in names:
			totalsize += len(name)+1
		if msg.size > 0:
			if msg.size < totalsize:
				raise IOError(errno.ERANGE, "buffer too small")
			names.append('')
			returnValue( '\x00'.join(names) )
		else:
			returnValue( fuse_getxattr_out(size=totalsize) )

	@debugproc
	@inlineCallbacks
	def fuse_getxattr(self, req, msg):
		node = yield self.filesystem.getnode(req.nodeid)
		msg, name = msg
		if hasattr(node,'getxattr'):
			value = yield node.getxattr(name, ctx=req)
		else:
			xattrs = yield node.getxattrs(ctx=req)
			try:
				value = xattrs[name]
			except KeyError:
				raise IOError(errno.ENOATTR, "no such xattr")

		value = str(value)
		if msg.size > 0:
			if msg.size < len(value):
				raise IOError(errno.ERANGE, "buffer too small")
			returnValue( value )
		else:
			returnValue( fuse_getxattr_out(size=len(value)) )

	@debugproc
	@inlineCallbacks
	def fuse_setxattr(self, req, msg):
		node = yield self.filesystem.getnode(req.nodeid)
		msg, name, value = msg
		assert len(value) == msg.size
		if hasattr(node,'setxattr'):
			res = yield node.setxattr(name,value, msg.flags,ctx=req)
			returnValue( res )

		xattrs = yield node.getxattrs(ctx=req)
		# XXX msg.flags ignored
		if msg.flags & XATTR_CREATE and name in xattrs:
			raise IOError(errno.ENOATTR, "attribute exists")
		if msg.flags & XATTR_REPLACE and name not in xattrs:
			raise IOError(errno.ENOATTR, "attribute does not exist")
		try:
			xattrs[name] = value
		except KeyError:
			raise IOError(errno.ENOATTR, "cannot set xattr")

	@debugproc
	@inlineCallbacks
	def fuse_removexattr(self, req, msg):
		node = yield self.filesystem.getnode(req.nodeid)
		if hasattr(node,'removexattr'):
			res = yield node.removexattr(msg, ctx=req)
			returnValue( res )

		xattrs = yield node.getxattrs(ctx=req)
		try:
			del xattrs[msg]
		except KeyError:
			raise IOError(errno.ENOATTR, "cannot delete xattr")
		returnValue( None )

	@debugproc
	def fuse_statfs(self, req, msg):
		return self.filesystem.statfs()

	def send_notice(self, code, msg):
		if msg is None:
			msg = ''
		elif not isinstance(msg, str):
			msg = msg.pack()
		f = fuse_out_header(unique = 0,
							error  = code,
							len    = self.__out_header_size + len(msg))
		data = f.pack() + msg
		try:
			#self.transport.write(data)
			l = os.write(self.transport.fileno(),data)
			if l != len(data):
				raise RuntimeError("could not write notification to FUSE socket")
		except Exception as e:
			print_exc(file=sys.stderr)
			self.connectionLost(e)
	
	def fuse_notify_reply(self, req, msg):
		req = self.notices.pop(req.unique)
		req.done(msg)
		raise NoReply
		
