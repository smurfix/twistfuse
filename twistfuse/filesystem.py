# -*- coding: utf-8 -*-
# vim: set fileencoding=utf-8
# vim: ts=4:sw=4:noet:si

##  Copyright © 2011, Matthias Urlichs <matthias@urlichs.de>
##
## This code descends from an implementation at
## http://codespeak.net/svn/user/arigo/hack/pyfuse.
## which does not have a license statement, but (according to
## personal communication with its author) has been released
## under the 3-clause MIT license.
##
## This file is formatted with tabs. Deal.

import errno
from os import O_RDONLY,O_WRONLY,O_RDWR

__all__ = ("FileSystem","Inode","File","Dir")

O_MODE_MASK = O_RDONLY|O_WRONLY|O_RDWR


class File(object):
	"""\
		I represent an open file.
		"""
	
	def __init__(self,node,mode):
		self.node = node
		self.mode = mode & O_MODE_MASK
	
	def open(self):
		"""\
			Open the file.
			Factored out from __init__ so that it can return a Deferred.
			"""
		pass
	
	def read(self, offset,length):
		"""\
			Return @length bytes at @offset.
			
			You need to employ locking if you cannot do this atomically.
			You might want to do this in a thread if you're reading from
			disk.
			"""
		raise IOError(errno.ENOSYS, "File.read is not implemented")

	def write(self, offset,data):
		"""\
			Write @data at @offset.
			
			You want to employ locking if you cannot do this atomically.
			You might want to do this in a thread if the write goes to disk.
			"""
		raise IOError(errno.EROFS, "File.write is not implemented")

	def release(self):
		"""\
			Close the file.
			"""
		pass

	def flush(self, flags):
		"""\
			Flush cached data from memory.
			"""
		pass

	def fsync(self, flags):
		"""\
			Sync cached data to disk.
			"""
		pass

	def getlock(self, start,end, type):
		"""\
			Return locking state.
			"""
		raise IOError(errno.EROFS, "File.getlock is not implemented")

	def setlock(self, start,end, type, wait=False):
		"""\
			Lock a range. Wait or not.
			"""
		raise IOError(errno.EROFS, "File.setlock is not implemented")

	
class Dir(object):
	"""\
		I represent an open directory.
		"""
	
	def __init__(self,node):
		self.node = node
	
	def open(self):
		"""\
			Open the directory.
			Factored out from __init__ so that it can return a Deferred.
			"""
		pass
		
	def release(self):
		"""\
			Close the file.
			"""
		pass

	def sync(self, flags):
		"""\
			fsync() on myself.
			"""
		pass

	def read(self, offset=0):
		"""\
			Return entries: generate (name,type,inode,offset) tuples.

			Note that the offset points to the _next_ entry.

			Do not return "." or ".." entries.
			"""
		return ()


class Inode(object):
	"""\
		I represent a file, which may have more than one name
		(or zero names, for some file systems)

		"""
	nodeid = None

	def __init__(self,filesystem,nodeid):
		self.filesystem = filesystem
		self.nodeid = nodeid

	def getattr(self):
		"""\
			Return (a dict of) my state.
			Known attributes: mode uid gid size atime mtime ctime

			You may return a (attr, valid_time) tuple.
			In that case, attr_vald() will not be used.
			"""
		raise NotImplementedError("You need to override Inode.getattr")
	
	def setattr(self, **attrs):
		"""\
			Set the given attributes (plus ctime).
			Any not in @attrs should be left alone.
			"""
		raise IOError(errno.EROFS, "Inode.setattr is not implemented")

	def attr_valid(self):
		"""\
			Tell for how long the entry's attributes are supposed to be valid.

			Can be specified as (second,nanosecond).
			"""
		return (10,0)

	def entry_valid(self):
		"""\
			Tell for how long the entry is supposed to be valid.

			Can be specified as (second,nanosecond).

			Technically, this is a feature of a particular directory entry,
			not an inode. Therefore, node.lookup/mkdir/mknod/symlink/link
			may return (inode,valid_time) tuples. In that case,
			entry_valid() will not be called.
			"""
		return (10,0)

	def open(self,mode):
		"""\
			If I am a file, open me.

			The default implementation uses a filesystem.FileType object.
			"""
		f = self.filesystem.FileType(self,mode)
		f.open()
		return f

	def opendir(self):
		"""\
			If I am a directory, open me.

			The default implementation uses a filesystem.DirType object.
			"""
		d = self.filesystem.DirType(self)
		d.open()
		return d

	def lookup(self, name):
		"""\
			Return a named child (if I am a directory).

			The returned node needs to be remembered.
			"""
		raise IOError(errno.ENOENT, "I don't know '%s'" % (name,))

	def remember(self):
		"""\
			This node is being cached.
			"""
		pass

	def forget(self):
		"""\
			This node is being dropped from the cache.
			"""
		pass

	def mknod(self, filename, mode, dev, umask):
		"""\
			Create a new device node.
			"""
		raise IOError(errno.EROFS, "File.mknod is not implemented")

	def mkdir(self, filename, mode, umask):
		"""\
			Create a new directory.
			"""
		raise IOError(errno.EROFS, "File.mkdir is not implemented")

	def symlink(self, filename, target):
		"""\
			Create a new symbolic link.
			"""
		raise IOError(errno.EROFS, "File.symlink is not implemented")

	def readlink(self):
		"""\
			Return my contents, if I am a symlink.
			"""
		raise IOError(errno.ENOSYS, "File.readlink is not implemented")

	def link(self, oldnode, target):
		"""\
			Create a new hard link.
			"""
		raise IOError(errno.EROFS, "File.link is not implemented")

	def unlink(self, target):
		"""\
			Remove a non-directory.
			"""
		raise IOError(errno.EROFS, "File.unlink is not implemented")

	def rmdir(self, target):
		"""\
			Remove a directory.
			"""
		raise IOError(errno.EROFS, "File.rmdir is not implemented")

	def access(self, mask):
		"""\
			Check whether file access is allowed
			"""
		raise IOError(errno.ENOSYS, "File.access is not implemented")

	def getxattrs(self):
		"""\
			Return a (name,value) dictionary for this node.

			You may also seperately implement
			* listxattrs(self)
			* getxattr(self, name)
			* setxattr(self, name,value)
			* removexattr(self, name)
			in which case this method will not be called.

			Note that values may be arbitrary binary data!
			"""
		raise IOError(errno.ENOSYS, "Extended attributes are not implemented")


class FileSystem(object):
	"""\
		I represent a FUSE-mounted file hierarchy.
		
		Note that FUSE defines node #1 as the root inode.
		Your mounting() code needs to set up and remember() it.
		"""

	MOUNT_OPTIONS = {}
	FileType = File
	DirType = Dir
	def __init__(self, root, filetype=None,dirtype=None):
		"""\
			Setup. You need to either pass in a root inode.
			
			If you don't override inode.open(), the given file/dir types
			will be used when opening files / reading directories.
			"""

		self.nodes = {}

		if filetype:
			self.FileType = filetype
		if dirtype:
			self.DirType = dirtype
		assert root.nodeid == 1, "The root node needs to have nodeid==1, not %s" % (repr(root.nodeid),)
		self.remember(root)

	def mount(self, handler, flags):
		"""\
			Called when exchanging initialization messsages.
			You should return a directory of
			* flags: the FUSE_INIT_* flags you support.
			* max_readahead = 1024*1024
			* max_background=20
			* max_write=65536
			"""
		self.handler = handler
		return dict(flags=0)

	def stop(self, force = False):
		"""\
			Called before unmounting the file system.
			If @force is True, you need to do everything necessary
			immediately; otherwise, the system is still live and
			you may return a Deferred.
			"""
		self.handler = None

	def getnode(self, nodeid):
		"""\
			Given an inode (as returned by .lookup()), return the
			corresponding object.
			"""
		return self.nodes[nodeid]

	def remember(self, node):
		"""\
			Remember this node.
			"""
		node.remember()
		self.nodes[node.nodeid] = node

	def forget(self,nodeid):
		"""\
			Drop this node from the cache.
			"""
		if nodeid == 1:
			return # the root node cannot be dropped from the cache
		node = self.nodes.pop(nodeid)
		node.forget()

	def rename(self, oldnode, oldname, newnode, newname):
		"""\
			Rename an entry.
			The destination, if it exists, is overwritten atomically.
			"""
		raise IOError(errno.EROFS, "Filesystem.rename is not implemented")

