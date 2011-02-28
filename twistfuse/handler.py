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
import os, errno, sys, stat

__all__ = ("Handler","NoReply")

class NoReply(Exception):
	"""Raise this exception to not send a FUSE reply back"""
	pass

def fuse_mount(mountpoint, opts=None):
	"""Options is a comma-separated list of FUSE options"""
	# TODO: call fusermount directly
	if not isinstance(mountpoint, str):
		raise TypeError
	if opts is not None and not isinstance(opts, str):
		raise TypeError
	try:
		import dl
		fuse = dl.open('libfuse.so.2')
		if fuse.sym('fuse_mount_compat22'):
			fnname = 'fuse_mount_compat22'
		else:
			fnname = 'fuse_mount'     # older versions of libfuse.so
		return fuse.call(fnname, mountpoint, opts)
	except ImportError:
		import ctypes
		fuse = ctypes.CDLL('libfuse.so.2')
		try:
			fn = fuse.fuse_mount_compat22
		except AttributeError:
			fn = fuse.fuse_mount      # older versions of libfuse.so
		fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
		fn.restype = ctypes.c_int
		return fn(mountpoint, opts)

class Handler(object):
	__system = os.system
	mountpoint = fd = None
	__in_header_size  = fuse_in_header.calcsize()
	__out_header_size = fuse_out_header.calcsize()
	MAX_READ = FUSE_MAX_IN

	def __init__(self, logfile='STDERR'):
		if logfile == 'STDERR':
			logfile = sys.stderr
		self.logfile = logfile
		self.filehandles = {}
		self.dirhandles = {}
		self.notices = {}
		self.nexth = 1

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
		fd = fuse_mount(mountpoint, opts)
		if fd < 0:
			raise IOError("mount failed")
		self.fd = fd
		self.log('* mounted at %s', mountpoint)

	def umount(self):
		if self.filesystem is not None:
			fs = self.filesystem
			self.filesystem = None
			fs.stop(False)
		if self.fd is not None:
			os.close(self.fd)
			self.fd = None
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
		if self.fd is not None:
			os.close(fd)
			self.fd = None
		mountpoint = getattr(self,"mountpoint",None)
		if mountpoint is not None:
			cmd = "fusermount -u '%s'" % mountpoint.replace("'", r"'\''")
			self.mountpoint = None
			self.log('* %s', cmd)
			self.__system(cmd)

	def log(self,s,*a):
		if not self.logfile:
			return
		print >>sys.stderr,s % a

	def loop_forever(self):
		try:
			while True:
				msg = os.read(self.fd, FUSE_MAX_IN)
				if not msg:
					raise EOFError("out-kernel connection closed")
				self.handle_message(msg)
		except KeyboardInterrupt:
			return

	def handle_message(self, msg):
		headersize = self.__in_header_size
		req = fuse_in_header(msg[:headersize])
		assert req.len == len(msg)
		name = req.opcode
		try:
			try:
				name,s_in,s_out = fuse_opcode2name[req.opcode]
				meth = getattr(self, "fuse_"+name)
			except (IndexError, AttributeError):
				raise NotImplementedError
			msg = msg[headersize:]
			if s_in is not None:
				msg = s_in(msg)
			self.log('%s(%d) << %s', name, req.nodeid, msg)
			reply = meth(req, msg)
			self.log('   >> %s', repr(reply))
		except NotImplementedError:
			self.log('%s: not implemented', name)
			self.send_reply(req, err=errno.ENOSYS)
		except EnvironmentError, e:
			if e.strerror is not None:
				self.log('%s: %s', name, e)
			self.send_reply(req, err = e.errno or errno.ESTALE)
		except NoReply:
			pass
		else:
			if s_out is not None and hasattr(reply,"items"):
				reply = s_out(**reply)
			self.send_reply(req, reply)

	def send_reply(self, req, reply=None, err=0):
		assert 0 <= err < 1000
		if reply is None:
			reply = ''
		elif not isinstance(reply, str):
			reply = reply.pack()
		f = fuse_out_header(unique = req.unique,
							error  = -err,
							len    = self.__out_header_size + len(reply))
		data = f.pack() + reply
		try:
			while data:
				count = os.write(self.fd, data)
				if not count:
					raise EOFError("in-kernel connection closed")
				data = data[count:]
		except OSError, e:
			if e.errno == errno.ENOENT:  # op interrupted by kernel
				self.log('operation interrupted')
			else:
				raise

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
		self._send_kernel(data)

	def _send_kernel(self, data):
		try:
			while data:
				count = os.write(self.fd, data)
				if not count:
					raise EOFError("in-kernel connection closed")
				data = data[count:]
		except OSError, e:
			if e.errno == errno.ENOENT:  # op interrupted by kernel
				self.log('operation interrupted')
			else:
				raise

	def send_notice(self, code, msg):
		if msg is None:
			msg = ''
		elif not isinstance(msg, str):
			msg = msg.pack()
		f = fuse_out_header(unique = 0,
							error  = code,
							len    = self.__out_header_size + len(msg))
		data = f.pack() + msg
		self._send_kernel(data)
	
	def fuse_notify_reply(self, req, msg):
		req = self.notices.pop(req.unique)
		req.done(msg)
		raise NoReply
		
