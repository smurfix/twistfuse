# -*- coding: utf-8 -*-
from __future__ import division

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

from zope.interface import implements
from twisted.internet import abstract,fdesc,protocol,reactor
from twisted.internet.defer import maybeDeferred
from twisted.internet.interfaces import IReadDescriptor
from twisted.internet.process import Process

from passfd import recvfd

__all__ = ("Handler","NoReply")

class NoReply(Exception):
	"""Raise this exception to not send a FUSE reply back"""
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
			print >>sys.stderr,"FD NOREAD",e
			self.proc.got_no_fd(e)
		else:
			self._close()
			print >>sys.stderr,"FD GOT",fd
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
			print >>sys.stderr,"FD READ",reason
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
		print >>sys.stderr,"EXD",repr(reason)
	def processEnded(self, reason):
		print >>sys.stderr,"END",repr(reason)

		

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
		return fdesc.readFromFD(self.fd, self.dataReceived)
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
		print >>sys.stderr,reason
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
			opts = ' '.join(optlist)
		else:
			opts = None
		self.mountpoint = mountpoint
		self.filesystem = filesystem
		FuseMounter(self,mountpoint,opts)

	def umount(self):
		fs = self.filesystem
		if fs is not None:
			self.filesystem = None
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

	def __del__(self):
		fs = getattr(self,"filesystem",None)
		if fs is not None:
			self.filesystem = None
			fs.stop(True)
		fd = getattr(self,"fd",None)
		if fd is not None:
			self.fd = None
			fd.close()
		mountpoint = getattr(self,"mountpoint",None)
		if mountpoint is not None:
			self.mountpoint = None
			cmd = "fusermount -u '%s'" % mountpoint.replace("'", r"'\''")
			self.log('* %s', cmd)
			self.__system(cmd)

	def log(self,s,*a):
		if not self.logfile:
			return
		print >>sys.stderr,s % a


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

		name,s_in,s_out = fuse_opcode2name[req.opcode]
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
		def logReply(r):
			self.log('   >> %s', repr(r))
			return r
		reply.addBoth(logReply)

		def dataHandler(reply):
			if s_out is not None and hasattr(reply,"items"):
				reply = s_out(**reply)
			self.send_reply(req, reply)
		def errHandler(e):
			if e.check(NotImplementedError):
				self.log('%s: not implemented', name)
				self.send_reply(req, err=errno.ENOSYS)
			elif e.check(EnvironmentError): # superclass of IOError, OSError
				if e.value.strerror is not None:
					self.log('%s: %s', name, e.value.strerror)
				self.send_reply(req, err = e.value.errno or errno.ESTALE)
			elif e.check(NoReply):
				pass
			else:
				e.raiseException()
		reply.addCallbacks(dataHandler,errHandler)

	def send_reply(self, req, reply=None, err=0):
		assert 0 <= err < 1000
		if reply is None:
			reply = ''
		elif not isinstance(reply, str):
			print "R",repr(reply)
			reply = reply.pack()
		f = fuse_out_header(unique = req.unique,
							error  = -err,
							len    = self.__out_header_size + len(reply))
		data = f.pack() + reply
		self.transport.write(data)

	def connectionLost (self, reason=protocol.connectionDone):
		self.umount()
		reactor.stop()
		
	# ____________________________________________________________

	def fuse_init(self, req, msg):
		self.log('INIT: %d.%d', msg.major, msg.minor)
		d = self.filesystem.mount(self, msg.flags)
		rd = dict(major = FUSE_KERNEL_VERSION,
			minor = FUSE_KERNEL_MINOR_VERSION, max_readahead = 1024*1024,
			max_background=20, max_write=65536, flags = 0)
		if d:
			rd.update(d)
		return rd


	def fuse_getattr(self, req, msg):
		node = self.filesystem.getnode(req.nodeid)
		return self._getattr(node)

	def _getattr(self,node):
		attr = node.getattr()
		if isinstance(attr,tuple):
			attr, attr_valid = attr
		else:
			attr_valid = node.attr_valid()
		return dict(attr_valid = attr_valid, attr = attr)

	def fuse_setattr(self, req, msg):
		node = self.filesystem.getnode(req.nodeid)
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
		node.setattr(**values)
		return self._getattr(node)

	def fuse_release(self, req, msg):
		try:
			f = self.filehandles.pop(msg.fh)
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		else:
			f.release()

	def fuse_releasedir(self, req, msg):
		try:
			f = self.dirhandles.pop(msg.fh)
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		else:
			f.release()

	def fuse_opendir(self, req, msg):
		node = self.filesystem.getnode(req.nodeid)
		attr = node.getattr()
		if isinstance(attr,tuple):
			attr = attr[0]
		if mode2type(attr['mode']) != TYPE_DIR:
			raise IOError(errno.ENOTDIR, node)
		f = node.opendir()
		fh = self.nexth
		self.nexth += 1
		self.dirhandles[fh] = f
		return dict(fh = fh)

	def fuse_fsyncdir(self, req, msg):
		try:
			f = self.dirhandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		f.sync(msg.fsync_flags)

	def fuse_readdir(self, req, msg):
		try:
			f = self.dirhandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		# start or rewind
		d_entries = []
		length = 0
		print "RD",msg.offset,msg.size
		for name, type, inode, off in f.read(offset=msg.offset):
			print "E",name, type, inode, off
			d_entry = fuse_dirent(ino  = inode,
			                      off  = off,
			                      type = type,
			                      name = name)
			d_len = fuse_dirent.calcsize(len(name))
			if length+d_len > msg.size:
				break
			d_entries.append(d_entry)
			length += fuse_dirent.calcsize(len(name))

		data = ''.join([d.pack() for d in d_entries])
		return data

	def replyentry(self, res):
		if isinstance(res,tuple):
			node,entry_valid = res
		else:
			node = res
			entry_valid = node.entry_valid()
		attr = node.getattr()
		if isinstance(attr,tuple):
			attr, attr_valid = attr
		else:
			attr_valid = node.attr_valid()
		self.filesystem.remember(node)
		return dict(nodeid = node.nodeid, entry_valid = entry_valid,
					attr_valid = attr_valid, attr = attr)

	def fuse_lookup(self, req, msg):
		node = self.filesystem.getnode(req.nodeid)
		res = node.lookup(msg)
		return self.replyentry(res)

	def fuse_open(self, req, msg):
		node = self.filesystem.getnode(req.nodeid)
		attr = node.getattr()
		if isinstance(attr,tuple):
			attr = attr[0]
		if mode2type(attr["mode"]) != TYPE_REG:
			raise IOError(errno.EPERM, node)
		f = node.open(msg.flags)
		if isinstance(f, tuple):
			f, open_flags = f
		else:
			open_flags = 0
		fh = self.nexth
		self.nexth += 1
		self.filehandles[fh] = f
		return dict(fh = fh, open_flags = open_flags)

	def fuse_create(self, req, msg):
		msg, filename = msg
		node = self.filesystem.getnode(req.nodeid)
		attr = node.getattr()
		if isinstance(attr,tuple):
			attr = attr[0]
		if mode2type(attr["mode"]) != TYPE_REG:
			raise IOError(errno.EPERM, node)
		f = node.create(filename, msg.flags & mask, msg.umask)
		if isinstance(f, tuple):
			f, open_flags = f
		else:
			open_flags = 0
		fh = self.nexth
		self.nexth += 1
		self.filehandles[fh] = f
		return dict(fh = fh, open_flags = open_flags)

	def fuse_read(self, req, msg):
		try:
			f = self.filehandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		return f.read(msg.offset, msg.size)

	def fuse_flush(self, req, msg):
		try:
			f = self.filehandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		f.flush(msg.flush_flags)

	def fuse_fsync(self, req, msg):
		try:
			f = self.filehandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		f.sync(msg.fsync_flags)

	def fuse_getlk(self, req, msg):
		try:
			f = self.filehandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		f.getlock(msg.start,msg.end,msg.type)
		return dict(start = msg.start, end = msg.end,
		            type = msg.type, pid = msg.pid)
		
	def fuse_setlk(self, req, msg):
		try:
			f = self.filehandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		f.setlock(msg.start,msg.end,msg.type, wait=0)
		return dict(start = msg.start, end = msg.end,
		            type = msg.type, pid = msg.pid)
		
	def fuse_setlkw(self, req, msg):
		try:
			f = self.filehandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		f.setlock(msg.start,msg.end,msg.type, wait=1)
		return dict(start = msg.start, end = msg.end,
		            type = msg.type, pid = msg.pid)
		
	def fuse_write(self, req, msg):
		msg, data = msg
		try:
			f = self.filehandles[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		size = f.write(msg.offset, data)
		if size is None: size = len(data)
		return dict(size = size)

	def fuse_mknod(self, req, msg):
		msg, filename = msg
		node = self.filesystem.getnode(req.nodeid)
		res = node.mknod(filename, msg.mode,msg.dev,msg.umask)
		return self.replyentry(res)

	def fuse_mkdir(self, req, msg):
		msg, filename = msg
		node = self.filesystem.getnode(req.nodeid)
		res = node.mkdir(filename, msg.mode,msg.umask)
		return self.replyentry(res)

	def fuse_symlink(self, req, msg):
		linkname, target = msg
		node = self.filesystem.getnode(req.nodeid)
		res = node.symlink(linkname, target)
		return self.replyentry(res)

	def fuse_link(self, req, msg):
		filename = c2pystr(msg)
		oldnode = self.filesystem.getnode(req.nodeid)
		newnode = self.filesystem.getnode(req.nodeid)
		res = newnode.link(oldnode, target)
		return self.replyentry(res)

	def fuse_unlink(self, req, msg):
		filename = msg

		node = self.filesystem.getnode(req.nodeid)
		node.unlink(filename)

	def fuse_rmdir(self, req, msg):
		dirname = msg

		node = self.filesystem.getnode(req.nodeid)
		node.rmdir(dirname)

	def fuse_access(self, req, msg):
		node = self.filesystem.getnode(req.nodeid)
		node.access(msg.mask)

	def fuse_interrupt(self, req, msg):
		# Pass req.unique into every upcall?
		raise IOError(errno.ENOSYS, "interrupt not supported")

	def fuse_forget(self, req, msg):
		if hasattr(self.filesystem, 'forget'):
			node = self.filesystem.getnode(req.nodeid)
			self.filesystem.forget(req.nodeid)
		raise NoReply

	def fuse_batch_forget(self, req, msg):
		if hasattr(self.filesystem, 'forget'):
			msg, data = msg
			size = fuse_forget_one.calcsize()
			offset = 0
			for i in range(msg.count):
				msg1 = fuse_forget_one(data[offset:offset+size])
				self.filesystem.forget(msg1.nodeid)
				offset += size
		raise NoReply

	def fuse_readlink(self, req, msg):
		if not hasattr(self.filesystem, 'readlink'):
			raise IOError(errno.ENOSYS, "readlink not supported")
		node = self.filesystem.getnode(req.nodeid)
		target = node.readlink()
		return target

	def fuse_rename(self, req, msg):
		msg, oldname, newname = msg
		oldnode = self.filesystem.getnode(req.nodeid)
		newnode = self.filesystem.getnode(msg.newdir)
		self.filesystem.rename(oldnode, oldname, newnode, newname)

	def getxattrs(self, node):
		if not hasattr(node, 'getxattrs'):
			raise IOError(errno.ENOSYS, "xattrs not supported")
		return node.getxattrs()

	def fuse_listxattr(self, req, msg):
		node = self.filesystem.getnode(req.nodeid)
		if hasattr(node,'listxattr'):
			names = node.listxattr()
		else:
			names = self.getxattrs(node).keys()

		totalsize = 0
		for name in names:
			totalsize += len(name)+1
		if msg.size > 0:
			if msg.size < totalsize:
				raise IOError(errno.ERANGE, "buffer too small")
			names.append('')
			return '\x00'.join(names)
		else:
			return fuse_getxattr_out(size=totalsize)

	def fuse_getxattr(self, req, msg):
		node = self.filesystem.getnode(req.nodeid)
		msg, name = msg
		if hasattr(node,'getxattr'):
			value = node.getxattr(msg,name)
		else:
			xattrs = self.getxattrs(node)
			try:
				value = xattrs[name]
			except KeyError:
				raise IOError(errno.ENODATA, "no such xattr")    # == ENOATTR

		value = str(value)
		if msg.size > 0:
			if msg.size < len(value):
				raise IOError(errno.ERANGE, "buffer too small")
			return value
		else:
			return fuse_getxattr_out(size=len(value))

	def fuse_setxattr(self, req, msg):
		node = self.filesystem.getnode(req.nodeid)
		msg, name, value = msg
		assert len(value) == msg.size
		if hasattr(node,'setxattr'):
			return node.setxattr(msg,name,value)

		xattrs = self.getxattrs(node)
		# XXX msg.flags ignored
		try:
			xattrs[name] = value
		except KeyError:
			raise IOError(errno.ENODATA, "cannot set xattr")    # == ENOATTR

	def fuse_removexattr(self, req, msg):
		node = self.filesystem.getnode(node)
		if hasattr(node,'removexattr'):
			return node.removexattr(msg)

		xattrs = self.getxattrs(node)
		try:
			del xattrs[msg]
		except KeyError:
			raise IOError(errno.ENODATA, "cannot delete xattr")   # == ENOATTR

	def send_notice(self, code, msg):
		if msg is None:
			msg = ''
		elif not isinstance(msg, str):
			msg = msg.pack()
		f = fuse_out_header(unique = 0,
							error  = code,
							len    = self.__out_header_size + len(msg))
		data = f.pack() + msg
		self.transport.write(data)
	
	def fuse_notify_reply(self, req, msg):
		req = self.notices.pop(req.unique)
		req.done(msg)
		raise NoReply
		
