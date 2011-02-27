# -*- coding: utf-8 -*-
from __future__ import division

##
##  Copyright © 2011, Matthias Urlichs <matthias@urlichs.de>
##
##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation, either version 3 of the License, or
##  (at your option) any later version.
##
##  This program is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License (included; see the file LICENSE)
##  for more details.
##
## Large portions of this code have been copied from 
## http://codespeak.net/svn/user/arigo/hack/pyfuse, but that code
## does not have any copyright or license notices.

from kernel import *
import os, errno, sys, stat

def fuse_mount(mountpoint, opts=None):
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

	def __init__(self, mountpoint, filesystem, logfile='STDERR', **opts1):
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
		fd = fuse_mount(mountpoint, opts)
		if fd < 0:
			raise IOError("mount failed")
		self.fd = fd
		if logfile == 'STDERR':
			logfile = sys.stderr
		self.logfile = logfile
		self.log('* mounted at %s', mountpoint)
		self.mountpoint = mountpoint
		self.filesystem = filesystem
		self.filehandles = {}
		self.dirhandles = {}
		self.notices = {}
		self.nexth = 1
		self.filesystem.start(self)

	def __del__(self):
		if self.filesystem is not None:
			fs = self.filesystem
			self.filesystem = None
			fs.stop()
		if self.fd is not None:
			os.close(self.fd)
			self.fd = None
		if self.mountpoint:
			cmd = "fusermount -u '%s'" % self.mountpoint.replace("'", r"'\''")
			self.mountpoint = None
			self.log('* %s', cmd)
			self.__system(cmd)

	# TODO: support deferred close
	close = __del__

	def log(self,s,*a):
		if not self.logfile:
			return
		print >>sys.stderr,s % a

	def loop_forever(self):
		while True:
			msg = os.read(self.fd, FUSE_MAX_IN)
			if not msg:
				raise EOFError("out-kernel connection closed")
			self.handle_message(msg)

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
			if s_in is None:
				s_in = lambda x:x
			self.log('%s(%d)', name, req.nodeid)
			reply = meth(req, s_in(msg[headersize:]))
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

	def notsupp_or_ro(self):
		if hasattr(self.filesystem, "modified"):
			raise IOError(errno.ENOSYS, "not supported")
		else:
			raise IOError(errno.EROFS, "read-only file system")

	# ____________________________________________________________

	def fuse_init(self, req, msg):
		self.log('INIT: %d.%d', msg.major, msg.minor)
		if hasattr(self.filesystem,'init'):
			flags = self.filesystem.init(msg.flags)
		else:
			flags = 0
		return dict(major = FUSE_KERNEL_VERSION,
			minor = FUSE_KERNEL_MINOR_VERSION, max_readahead = 1024*1024,
			max_background=20, max_write=65536, flags = 0)

	def fuse_getattr(self, req, msg):
		node = self.filesystem.getnode(req.nodeid)
		attr, valid = self.filesystem.getattr(node)
		return dict(attr_valid = valid, attr = attr)

	def fuse_setattr(self, req, msg):
		node = self.filesystem.getnode(req.nodeid)
		if not hasattr(node, 'setattr'):
			self.notsupp_or_ro()
		values = {}
		if msg.valid & FATTR_MODE:
			values['mode'] = msg.attr.mode & 0777
		if msg.valid & FATTR_UID:
			values['uid'] = msg.attr.uid
		if msg.valid & FATTR_GID:
			values['gid '] = msg.attr.gid
		if msg.valid & FATTR_SIZE:
			values['size'] = msg.attr.size
		if msg.valid & FATTR_ATIME:
			values['atime'] = msg.attr.atime
		if msg.valid & FATTR_MTIME:
			values['mtime'] = msg.attr.mtime
		node.setattr(**values)
		res = node.getattr()
		attr, valid = res
		return dict(attr_valid = valid, attr = attr)

	def fuse_release(self, req, msg):
		try:
			f = self.filehandles.pop[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		else:
			f.release()

	def fuse_releasedir(self, req, msg):
		try:
			f = self.dirhandles.pop[msg.fh]
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		else:
			f.release()

	def fuse_opendir(self, req, msg):
		node = self.filesystem.getnode(req.nodeid)
		attr, valid = node.getattr()
		if mode2type(attr.mode) != TYPE_DIR:
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
		off = msg.offset
		length = 0
		for name, type, inode in f.listdir(offset=off):
			off += 1
			d_entry = fuse_dirent(ino  = inode,
			                      off  = off,
			                      type = type,
			                      name = name)
			d_len = fuse_dirent.calcsize(len(name))
			if length+d_len < msg.size:
				break
			d_entries.append(d_entry)
			length += fuse_dirent.calcsize(len(name))

		data = ''.join([d.pack() for d in d_entries])
		return data

	def replyentry(self, res):
		subnodeid, valid1 = res
		subnode = self.filesystem.getnode(subnodeid)
		attr, valid2 = subnode.getattr()
		return dict(nodeid = subnodeid, entry_valid = valid1,
					attr_valid = valid2, attr = attr)

	def fuse_lookup(self, req, msg):
		node = self.filesystem.getnode(req.nodeid)
		res = node.lookup(msg)
		return self.replyentry(res)

	def fuse_open(self, req, msg, mask=os.O_RDONLY|os.O_WRONLY|os.O_RDWR):
		node = self.filesystem.getnode(req.nodeid)
		attr, valid = node.getattr()
		if mode2type(attr.mode) != TYPE_REG:
			raise IOError(errno.EPERM, node)
		f = node.open(msg.flags & mask)
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
		attr, valid = node.getattr()
		if mode2type(attr.mode) != TYPE_REG:
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
		f.seek(msg.offset)
		return f.read(msg.size)

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
			if not hasattr(f, 'write'):
				raise IOError(errno.EROFS, "read-only file system")
		except KeyError:
			raise IOError(errno.EBADF, msg.fh)
		f.seek(msg.offset)
		size = f.write(data)
		if size is None: size = len(data)
		return dict(size = size)

	def fuse_mknod(self, req, msg):
		if not hasattr(self.filesystem, 'mknod'):
			self.notsupp_or_ro()
		msg, filename = msg
		node = self.filesystem.getnode(req.nodeid)
		res = node.mknod(filename, msg.mode)
		return self.replyentry(res)

	def fuse_mkdir(self, req, msg):
		if not hasattr(self.filesystem, 'mkdir'):
			self.notsupp_or_ro()
		msg, filename = msg
		node = self.filesystem.getnode(req.nodeid)
		res = node.mkdir(filename, msg.mode)
		return self.replyentry(res)

	def fuse_symlink(self, req, msg):
		if not hasattr(self.filesystem, 'symlink'):
			self.notsupp_or_ro()
		linkname, target = c2pystr2(msg)
		node = self.filesystem.getnode(req.nodeid)
		res = node.symlink(linkname, target)
		return self.replyentry(res)

	def fuse_link(self, req, msg):
		if not hasattr(self.filesystem, 'link'):
			self.notsupp_or_ro()
		filename = c2pystr(msg)
		res = self.filesystem.link(msg.oldnodeid, req.nodeid, target)
		return self.replyentry(res)

	def fuse_unlink(self, req, msg):
		if not hasattr(self.filesystem, 'unlink'):
			self.notsupp_or_ro()
		filename = msg

		node = self.filesystem.getnode(req.nodeid)
		node.unlink(filename)

	def fuse_rmdir(self, req, msg):
		if not hasattr(self.filesystem, 'rmdir'):
			self.notsupp_or_ro()
		dirname = msg

		node = self.filesystem.getnode(req.nodeid)
		node.rmdir(dirname)

	def fuse_access(self, req, msg):
		node = self.filesystem.getnode(req.nodeid)
		node.access(msg.mode)

	def fuse_interrupt(self, req, msg):
		# Pass req.unique into every upcall?
		raise IOError(errno.ENOSYS, "interrupt not supported")

	def fuse_forget(self, req, msg):
		if hasattr(self.filesystem, 'forget'):
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
		if not hasattr(self.filesystem, 'rename'):
			self.notsupp_or_ro()
		msg, oldname, newname = msg
		oldnode = self.filesystem.getnode(req.nodeid)
		newnode = self.filesystem.getnode(msg.newdir)
		self.filesystem.rename(oldnode, oldname, newnode, newname)

	def getxattrs(self, node):
		if not hasattr(node, 'getxattrs'):
			raise IOError(errno.ENOSYS, "xattrs not supported")
		return node.getxattrs(node)

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

		xattrs = self.getxattrs(req.nodeid)
		try:
			del xattrs[msg]
		except KeyError:
			raise IOError(errno.ENODATA, "cannot delete xattr")   # == ENOATTR

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
		

class NoReply(Exception):
	pass
