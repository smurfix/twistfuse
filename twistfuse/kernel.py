# -*- coding: utf-8 -*-
# vim: set fileencoding=utf-8
# vim: ts=4:sw=4:noet:si

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


from struct import pack, unpack, calcsize
import stat

__all__ = (
	'CUSE_UNRESTRICTED_IOCTL',
	'FATTR_ATIME',
	'FATTR_ATIME_NOW',
	'FATTR_FH',
	'FATTR_GID',
	'FATTR_LOCKOWNER',
	'FATTR_MODE',
	'FATTR_MTIME',
	'FATTR_MTIME_NOW',
	'FATTR_SIZE',
	'FATTR_UID',
	'FOPEN_DIRECT_IO',
	'FOPEN_KEEP_CACHE',
	'FOPEN_NONSEEKABLE',
	'FUSE_ASYNC_READ',
	'FUSE_ATOMIC_O_TRUNC',
	'FUSE_BIG_WRITES',
	'FUSE_DONT_MASK',
	'FUSE_EXPORT_SUPPORT',
	'FUSE_FILE_OPS',
	'FUSE_GETATTR_FH',
	'FUSE_IOCTL_32BIT',
	'FUSE_IOCTL_COMPAT',
	'FUSE_IOCTL_MAX_IOV',
	'FUSE_IOCTL_RETRY',
	'FUSE_IOCTL_UNRESTRICTED',
	'FUSE_KERNEL_MINOR_VERSION',
	'FUSE_KERNEL_VERSION',
	'FUSE_LK_FLOCK',
	'FUSE_MAJOR',
	'FUSE_MAX_IN',
	'FUSE_MINOR',
	'FUSE_NAME_MAX',
	'FUSE_POLL_SCHEDULE_NOTIFY',
	'FUSE_POSIX_LOCKS',
	'FUSE_READ_LOCKOWNER',
	'FUSE_RELEASE_FLUSH',
	'FUSE_ROOT_ID',
	'FUSE_SYMLINK_MAX',
	'FUSE_WRITE_CACHE',
	'FUSE_WRITE_LOCKOWNER',
	'FUSE_XATTR_SIZE_MAX',
	'INVALID_INO',
	'TYPE_DIR',
	'TYPE_LNK',
	'TYPE_REG',
	'XATTR_CREATE',
	'XATTR_REPLACE',
	'c2pystr',
	'c2pystr2',
	'cuse_init_in',
	'cuse_init_out',
	'fuse_attr',
	'fuse_attr_out',
	'fuse_batch_forget_in',
	'fuse_batch_forget_in',
	'fuse_bmap_in',
	'fuse_bmap_out',
	'fuse_create_in',
	'fuse_dirent',
	'fuse_entry_out',
	'fuse_flush_in',
	'fuse_forget_in',
	'fuse_forget_one',
	'fuse_forget_one',
	'fuse_fsync_in',
	'fuse_getattr_in',
	'fuse_getxattr_in',
	'fuse_getxattr_out',
	'fuse_in_header',
	'fuse_init_in',
	'fuse_init_out',
	'fuse_interrupt_in',
	'fuse_ioctl_in',
	'fuse_ioctl_iovec',
	'fuse_ioctl_out',
	'fuse_kstatfs',
	'fuse_link_in',
	'fuse_lk_in',
	'fuse_lk_out',
	'fuse_lk_out',
	'fuse_mkdir_in',
	'fuse_mknod_in',
	'fuse_notify_code',
	'fuse_notify_inval_entry_out',
	'fuse_notify_inval_inode_out',
	'fuse_notify_poll_wakeup_out',
	'fuse_notify_retrieve_in',
	'fuse_notify_retrieve_out',
	'fuse_notify_store_out',
	'fuse_opcode',
	'fuse_opcode2name',
	'fuse_open_in',
	'fuse_open_out',
	'fuse_out_header',
	'fuse_poll_in',
	'fuse_poll_out',
	'fuse_read_in',
	'fuse_release_in',
	'fuse_rename_in',
	'fuse_setattr_in',
	'fuse_setxattr_in',
	'fuse_statfs_out',
	'fuse_write_in',
	'fuse_write_out',
	'mode2type',
	'timeval',
)

class Struct(object):
	__slots__ = []

	def __init__(self, data=None, truncate=False, **fields):
		if data is not None:
			if truncate:
				data = data[:self.calcsize()]
			self.unpack(data)
		for key, value in fields.items():
			setattr(self, key, value)

	def unpack(self, data):
		data = unpack(self.__types__, data)
		for key, value in zip(self.__slots__, data):
			setattr(self, key, value)

	def pack(self):
		try:
			return pack(self.__types__, *[getattr(self, k, 0)
									for k in self.__slots__])
		except Exception as e:
			import sys
			print >>sys.stderr,"E %r: %r %r" % (e,self.__types__, dict(((k,getattr(self, k, 0))
			                                    for k in self.__slots__)))
			raise

	@classmethod
	def calcsize(cls):
		return calcsize(cls.__types__)

	def __repr__(self):
		result = ['%s=%r' % (name, getattr(self, name, None))
				for name in self.__slots__]
		return '<%s %s>' % (self.__class__.__name__, ', '.join(result))

	@classmethod
	def from_param(cls, msg):
		limit = cls.calcsize()
		zero = msg.index('\x00', limit)
		return cls(msg[:limit]), msg[limit:zero]

	@classmethod
	def from_param2(cls, msg):
		limit = cls.calcsize()
		zero1 = msg.index('\x00', limit)
		zero2 = msg.index('\x00', zero1+1)
		return cls(msg[:limit]), msg[limit:zero1], msg[zero1+1:zero2]

	@classmethod
	def from_head(cls, msg):
		limit = cls.calcsize()
		return cls(msg[:limit]), msg[limit:]

	@classmethod
	def from_param_head(cls, msg):
		limit = cls.calcsize()
		zero = msg.index('\x00', limit)
		return cls(msg[:limit]), msg[limit:zero], msg[zero+1:]

class StructWithAttr(Struct):
	def __init__(self, *args, **keys):
		attr = keys.get('attr',None)
		if isinstance(attr,dict):
			keys['attr'] = fuse_attr(**attr)
		super(StructWithAttr,self).__init__(*args,**keys)

	def __repr__(self):
		result = ['%s=%r' % (name, getattr(self, name, None))
				for name in self.__slots__]
		return '<%s %s attr=%s>' % (self.__class__.__name__, ', '.join(result), repr(self.attr))

	def unpack(self, data):
		limit = -fuse_attr.calcsize()
		super(StructWithAttr, self).unpack(data[:limit])
		self.attr = fuse_attr(data[limit:])

	def pack(self):
		return super(StructWithAttr, self).pack() + self.attr.pack()

	@classmethod
	def calcsize(cls):
		return super(StructWithAttr, cls).calcsize() + fuse_attr.calcsize()

class StructWithAttrOpen(StructWithAttr):
	def __init__(self, *args, **keys):
		oattr = keys.get('open',None)
		if isinstance(oattr,dict):
			keys['open'] = fuse_open_out(**oattr)
		super(StructWithAttrOpen,self).__init__(*args,**keys)

	def __repr__(self):
		result = ['%s=%r' % (name, getattr(self, name, None))
				for name in self.__slots__]
		return '<%s %s attr=%s open=%s>' % (self.__class__.__name__, ', '.join(result), repr(self.attr), repr(self.open))

	def unpack(self, data):
		limit = super(StructWithAttrOpen,self).calcsize()
		super(StructWithAttrOpen, self).unpack(data[:limit])
		self.open = fuse_open_out(data[limit:])

	def pack(self):
		return super(StructWithAttrOpen, self).pack() + self.open.pack()

	@classmethod
	def calcsize(cls):
		return super(StructWithAttrOpen, cls).calcsize() + fuse_open_out.calcsize()


def _mkstruct(name, c, base=Struct):
	typ2code = {
		'__u16': 'H',
		'__s16': 'h',
		'__u32': 'I',
		'__s32': 'i',
		'__u64': 'Q',
		'__s64': 'q'}
	slots = []
	types = ['=']
	for line in c.split('\n'):
		line = line.strip()
		if line:
			line, tail = line.split(';', 1)
			typ, nam = line.split()
			slots.append(nam)
			types.append(typ2code[typ])
	cls = type(name, (base,), {'__slots__': slots,
								'__types__': ''.join(types)})
	globals()[name] = cls

class timeval(object):
	def __init__(self, attr1, attr2):
		self.attr_sec = attr1
		self.attr_nsec = attr2

	def __get__(self, obj, typ=None):
		if obj is None:
			return self
		else:
			return (getattr(obj, self.attr_sec),
					getattr(obj, self.attr_nsec))

	def __set__(self, obj, val):
		if isinstance(val,(tuple,list)):
			sec, nsec = val
		else:
			val = int(val * 1000000000)
			sec, nsec = divmod(val, 1000000000)
		setattr(obj, self.attr_sec, sec)
		setattr(obj, self.attr_nsec, nsec)

	def __delete__(self, obj):
		delattr(obj, self.attr_sec)
		delattr(obj, self.attr_nsec)

def _mktimeval(cls, attr):
	tv = timeval("_"+attr, "_"+attr+"_nsec")
	setattr(cls, attr, tv)

INVALID_INO = 0xFFFFFFFFFFFFFFFF

def mode2type(mode):
	return (mode & 0170000) >> 12

TYPE_REG = mode2type(stat.S_IFREG)
TYPE_DIR = mode2type(stat.S_IFDIR)
TYPE_LNK = mode2type(stat.S_IFLNK)

def c2pystr(s):
	n = s.index('\x00')
	return s[:n]

def c2pystr2(s):
	first = c2pystr(s)
	second = c2pystr(s[len(first)+1:])
	return first, second

# ____________________________________________________________

# Version number of this interface
FUSE_KERNEL_VERSION = 7

# Minor version number of this interface
FUSE_KERNEL_MINOR_VERSION = 16

# The node ID of the root inode
FUSE_ROOT_ID = 1

# The major number of the fuse character device
FUSE_MAJOR = 10

# The minor number of the fuse character device
FUSE_MINOR = 229

# Make sure all structures are padded to 64bit boundary, so 32bit
# userspace works under 64bit kernels

_mkstruct('fuse_attr', '''
	__u64	ino;
	__u64	size;
	__u64	blocks;
	__u64	_atime;
	__u64	_mtime;
	__u64	_ctime;
	__u32	_atime_nsec;
	__u32	_mtime_nsec;
	__u32	_ctime_nsec;
	__u32	mode;
	__u32	nlink;
	__u32	uid;
	__u32	gid;
	__u32	rdev;
	__u32	blksize;
	__u32	padding;
''')
_mktimeval(fuse_attr, 'atime')
_mktimeval(fuse_attr, 'mtime')
_mktimeval(fuse_attr, 'ctime')

_mkstruct('fuse_kstatfs', '''
	__u64	blocks;
	__u64	bfree;
	__u64	bavail;
	__u64	files;
	__u64	ffree;
	__u32	bsize;
	__u32	namelen;
	__u32   frsize;
	__u32   padding;
	__u32   spare0;
	__u32   spare1;
	__u32   spare2;
	__u32   spare3;
	__u32   spare4;
	__u32   spare5;
''')

FATTR_MODE	    = 1 << 0
FATTR_UID	    = 1 << 1
FATTR_GID	    = 1 << 2
FATTR_SIZE	    = 1 << 3
FATTR_ATIME	    = 1 << 4
FATTR_MTIME	    = 1 << 5
FATTR_FH        = 1 << 6
FATTR_ATIME_NOW = 1 << 7
FATTR_MTIME_NOW = 1 << 8
FATTR_LOCKOWNER = 1 << 9

#
# INIT request/reply flags
#
# FUSE_ASYNC_READ: perform reading in parallel with other operations.
# FUSE_POSIX_LOCKS: The file system supports locking.
# FUSE_FILE_OPS: (apparently unused)
# FUSE_ATOMIC_O_TRUNC: pass O_TRUNC in flags to open(), instead of calling setattr(size=0)
# FUSE_EXPORT_SUPPORT: the file system handles listing and lookup of "." and ".." itself
# FUSE_BIG_WRITES: support larger-than-pagesized write() calls
# FUSE_DONT_MASK: don't apply umask to file mode within the kernel, userspace code handles it
#
FUSE_ASYNC_READ     = 1 << 0
FUSE_POSIX_LOCKS    = 1 << 1
FUSE_FILE_OPS       = 1 << 2
FUSE_ATOMIC_O_TRUNC = 1 << 3
FUSE_EXPORT_SUPPORT = 1 << 4
FUSE_BIG_WRITES     = 1 << 5
FUSE_DONT_MASK      = 1 << 6

#
# CUSE INIT request/reply flags
#
# CUSE_UNRESTRICTED_IOCTL:  use unrestricted ioctl
#
CUSE_UNRESTRICTED_IOCTL = 1 << 0

#
# Flags returned by the OPEN request
#
# FOPEN_DIRECT_IO: bypass page cache for this open file
# FOPEN_KEEP_CACHE: don't invalidate the data cache on open
#
FOPEN_DIRECT_IO		= 1 << 0
FOPEN_KEEP_CACHE	= 1 << 1
FOPEN_NONSEEKABLE   = 1 << 2

#
# Release flags
#
FUSE_RELEASE_FLUSH = 1 << 0

#
# Getattr flags
#
FUSE_GETATTR_FH = 1 << 0

#
# Lock flags
#
FUSE_LK_FLOCK = 1 << 0

#
#* WRITE flags
#
# FUSE_WRITE_CACHE: delayed write from page cache, file handle is guessed
# FUSE_WRITE_LOCKOWNER: lock_owner field is valid
#
FUSE_WRITE_CACHE     = 1 << 0
FUSE_WRITE_LOCKOWNER = 1 << 1

#
# Read flags
#
FUSE_READ_LOCKOWNER = 1 << 1

#
# Ioctl flags
#
# FUSE_IOCTL_COMPAT: 32bit compat ioctl on 64bit machine
# FUSE_IOCTL_UNRESTRICTED: not restricted to well-formed ioctls, retry allowed
# FUSE_IOCTL_RETRY: retry with new iovecs
# FUSE_IOCTL_32BIT: 32bit ioctl
#
# FUSE_IOCTL_MAX_IOV: maximum of in_iovecs + out_iovecs
#
FUSE_IOCTL_COMPAT       = 1 << 0
FUSE_IOCTL_UNRESTRICTED = 1 << 1
FUSE_IOCTL_RETRY        = 1 << 2
FUSE_IOCTL_32BIT        = 1 << 3

FUSE_IOCTL_MAX_IOV      = 256

#
# Poll flags
#
# FUSE_POLL_SCHEDULE_NOTIFY: request poll notify
#
FUSE_POLL_SCHEDULE_NOTIFY = 1 << 0




fuse_notify_code = {
	'FUSE_NOTIFY_POLL'        : 1,
	'FUSE_NOTIFY_INVAL_INODE' : 2,
	'FUSE_NOTIFY_INVAL_ENTRY' : 3,
	'FUSE_NOTIFY_STORE'       : 4,
	'FUSE_NOTIFY_RETRIEVE'    : 5,
}

# Conservative buffer size for the client
FUSE_MAX_IN = 8192

FUSE_NAME_MAX = 1024
FUSE_SYMLINK_MAX = 4096
FUSE_XATTR_SIZE_MAX = 4096

# setxattr flags
XATTR_CREATE = 1
XATTR_REPLACE = 2

_mkstruct('fuse_entry_out', """
	__u64	nodeid;		/* Inode ID */
	__u64	generation;	/* Inode generation: nodeid:gen must \
				be unique for the fs's lifetime */
	__u64	_entry_valid;	/* Cache timeout for the name */
	__u64	_attr_valid;	/* Cache timeout for the attributes */
	__u32	_entry_valid_nsec;
	__u32	_attr_valid_nsec;
""", base=StructWithAttr)
_mktimeval(fuse_entry_out, 'entry_valid')
_mktimeval(fuse_entry_out, 'attr_valid')

_mkstruct('fuse_forget_in', '''
	__u64	nlookup;
''')

_mkstruct('fuse_forget_one', '''
	__u64   nodeid;
	__u64   nlookup;
''')

_mkstruct('fuse_batch_forget_in', '''
	__u32   count;
	__u32   dummy;
''')

_mkstruct('fuse_forget_one', '''
	__u64	nodeid;
	__u64	nlookup;
''')

_mkstruct('fuse_batch_forget_in', '''
	__u32   count;
	__u32   dummy;
''')

_mkstruct('fuse_attr_out', '''
	__u64	_attr_valid;	/* Cache timeout for the attributes */
	__u32	_attr_valid_nsec;
	__u32	dummy;
''', base=StructWithAttr)
_mktimeval(fuse_attr_out, 'attr_valid')

_mkstruct('fuse_mknod_in', '''
	__u32	mode;
	__u32	rdev;
	__u32   umask;
	__u32   padding;
''')

_mkstruct('fuse_mkdir_in', '''
	__u32	mode;
	__u32	umask;
''')

_mkstruct('fuse_rename_in', '''
	__u64	newdir;
''')

_mkstruct('fuse_link_in', '''
	__u64	oldnodeid;
''')

_mkstruct('fuse_getattr_in', '''
	__u32   getattr_flags;
	__u32   dummy;
	__u64   fh;
''')

_mkstruct('fuse_setattr_in', '''
	__u32	valid;
	__u32	padding;
	__u64   fh;
	__u64   size;
	__u64   lock_owner;
	__u64   _atime;
	__u64   _mtime;
	__u64   unused2;
	__u32   _atime_nsec;
	__u32   _mtime_nsec;
	__u32   unused3;
	__u32   mode;
	__u32   unused4;
	__u32   uid;
	__u32   gid;
	__u32   unused5;
''')
_mktimeval(fuse_setattr_in, 'atime')
_mktimeval(fuse_setattr_in, 'mtime')


_mkstruct('fuse_open_in', '''
	__u32	flags;
	__u32	padding;
''')

_mkstruct('fuse_create_in', '''
	__u32   flags;
	__u32   mode;
	__u32   umask;
	__u32   padding;
''')

_mkstruct('fuse_open_out', '''
	__u64	fh;
	__u32	open_flags;
	__u32	padding;
''')

_mkstruct('fuse_create_out', """
	__u64	nodeid;		/* Inode ID */
	__u64	generation;	/* Inode generation: nodeid:gen must \
				be unique for the fs's lifetime */
	__u64	_entry_valid;	/* Cache timeout for the name */
	__u64	_attr_valid;	/* Cache timeout for the attributes */
	__u32	_entry_valid_nsec;
	__u32	_attr_valid_nsec;
""", base=StructWithAttrOpen)
_mktimeval(fuse_entry_out, 'entry_valid')
_mktimeval(fuse_entry_out, 'attr_valid')

_mkstruct('fuse_release_in', '''
	__u64	fh;
	__u32	flags;
	__u32   release_flags;
	__u64   lock_owner;
''')

_mkstruct('fuse_flush_in', '''
	__u64	fh;
	__u32	flush_flags;
	__u32	padding;
	__u64   lock_owner;
''')

_mkstruct('fuse_read_in', '''
	__u64	fh;
	__u64	offset;
	__u32	size;
	__u32   read_flags;
	__u64   lock_owner;
	__u32   flags;
	__u32   padding;
''')

_mkstruct('fuse_write_in', '''
	__u64	fh;
	__u64	offset;
	__u32	size;
	__u32	write_flags;
	__u64   lock_owner;
	__u32   flags;
	__u32   padding;
''')

_mkstruct('fuse_write_out', '''
	__u32	size;
	__u32	padding;
''')

fuse_statfs_out = fuse_kstatfs

_mkstruct('fuse_fsync_in', '''
	__u64	fh;
	__u32	fsync_flags;
	__u32	padding;
''')

_mkstruct('fuse_setxattr_in', '''
	__u32	size;
	__u32	flags;
''')

_mkstruct('fuse_getxattr_in', '''
	__u32	size;
	__u32	padding;
''')

_mkstruct('fuse_getxattr_out', '''
	__u32	size;
	__u32	padding;
''')

_mkstruct('fuse_init_in', '''
	__u32	major;
	__u32	minor;
	__u32   max_readahead;
	__u32   flags;
''')

_mkstruct('fuse_init_out', '''
	__u32   major;
	__u32   minor;
	__u32   max_readahead;
	__u32   flags;
	__u16   max_background;
	__u16   congestion_threshold;
	__u32   max_write;
''')

_mkstruct('fuse_in_header', '''
	__u32	len;
	__u32	opcode;
	__u64	unique;
	__u64	nodeid;
	__u32	uid;
	__u32	gid;
	__u32	pid;
	__u32	padding;
''')

_mkstruct('fuse_out_header', '''
	__u32	len;
	__s32	error;
	__u64	unique;
''')

_mkstruct('cuse_init_in', '''
	__u32   major;
	__u32   minor;
	__u32   unused;
	__u32   flags;
''')

_mkstruct('cuse_init_out', '''
	__u32   major;
	__u32   minor;
	__u32   unused;
	__u32   flags;
	__u32   max_read;
	__u32   max_write;
	__u32   dev_major;
	__u32   dev_minor;
	__u32   spare0;
	__u32   spare1;
	__u32   spare2;
	__u32   spare3;
	__u32   spare4;
	__u32   spare5;
	__u32   spare6;
	__u32   spare7;
	__u32   spare8;
	__u32   spare9;
''')

_mkstruct('fuse_lk_in', '''
	__u64   fh;
	__u64   owner;

	__u64   start;
	__u64   end;
	__u32   type;
	__u32   pid;

	__u32   lk_flags;
	__u32   padding;
''')

_mkstruct('fuse_lk_out', '''
	__u64   start;
	__u64   end;
	__u32   type;
	__u32   pid; /* tgid */
''')

_mkstruct('fuse_lk_out', '''
	__u32   mask;
	__u32   padding;
''')

_mkstruct('fuse_interrupt_in', '''
	__u64   unique;
''')

_mkstruct('fuse_bmap_in', '''
	__u64   block;
	__u32   blocksize;
	__u32   padding;
''')

_mkstruct('fuse_bmap_out', '''
	__u64   block;
''')

_mkstruct('fuse_access_in', '''
	__u32   mask;
	__u32   padding;
''')

_mkstruct('fuse_ioctl_in', '''
	__u64   fh;
	__u32   flags;
	__u32   cmd;
	__u64   arg;
	__u32   in_size;
	__u32   out_size;
''')

_mkstruct('fuse_ioctl_iovec', '''
	__u64   base;
	__u64   len;
''')

_mkstruct('fuse_ioctl_out', '''
	__s32   result;
	__u32   flags;
	__u32   in_iovs;
	__u32   out_iovs;
''')

_mkstruct('fuse_poll_in', '''
	__u64   fh;
	__u64   kh;
	__u32   flags;
	__u32   padding;
''')

_mkstruct('fuse_poll_out', '''
	__u32   revents;
	__u32   padding;
''')

_mkstruct('fuse_notify_poll_wakeup_out', '''
	__u64   kh;
''')

_mkstruct('fuse_notify_inval_inode_out','''
	__u64   ino;
	__s64   off;
	__s64   len;
''')

_mkstruct('fuse_notify_inval_entry_out','''
	__u64   parent;
	__u32   namelen;
	__u32   padding;
''')

_mkstruct('fuse_notify_store_out','''
	__u64   nodeid;
	__u64   offset;
	__u32   size;
	__u32   padding;
''')

_mkstruct('fuse_notify_retrieve_out','''
	__u64   notify_unique;
	__u64   nodeid;
	__u64   offset;
	__u32   size;
	__u32   padding;
''')

_mkstruct('fuse_notify_retrieve_in','''
	__u64   dummy1;
	__u64   offset;
	__u32   size;
	__u32   dummy2;
	__u64   dummy3;
	__u64   dummy4;
''')

class fuse_dirent(Struct):
	__slots__ = ['ino', 'off', 'type', 'name']

	def unpack(self, data):
		self.ino, self.off, namelen, self.type = struct.unpack('QQII',
															data[:24])
		self.name = data[24:24+namelen]
		assert len(self.name) == namelen

	def pack(self):
		namelen = len(self.name)
		return pack('QQII%ds' % ((namelen+7)&~7,),
					self.ino, getattr(self, 'off', 0), namelen,
					self.type, self.name)

	def calcsize(cls, namelen):
		return 24 + ((namelen+7)&~7)
	calcsize = classmethod(calcsize)

# opcodes and messages
fuse_opcode = {
	'lookup'        : ( 1, c2pystr,         fuse_entry_out),
	'forget'        : ( 2, None,            None),  # no reply
	'getattr'       : ( 3, None,            fuse_attr_out),
	'setattr'       : ( 4, fuse_setattr_in, fuse_attr_out),
	'readlink'      : ( 5, None,            None),
	'symlink'       : ( 6, c2pystr2,        fuse_entry_out),
	'mknod'         : ( 8, fuse_mknod_in.from_param, fuse_entry_out),
	'mkdir'         : ( 9, fuse_mkdir_in.from_param, fuse_entry_out),
	'unlink'        : (10, c2pystr,         None),
	'rmdir'         : (11, c2pystr,         None),
	'rename'        : (12, fuse_rename_in.from_param2, None),
	'link'          : (13, fuse_link_in.from_param,    fuse_entry_out),
	'open'          : (14, fuse_open_in,    fuse_open_out),
	'read'          : (15, fuse_read_in,    None),
	'write'         : (16, fuse_write_in.from_head, fuse_write_out),
	'statfs'        : (17, None,            fuse_statfs_out),
	'release'       : (18, fuse_release_in, None),
	'fsync'         : (20, fuse_fsync_in,   None),
	'setxattr'      : (21, fuse_setxattr_in.from_param_head,None),
	'getxattr'      : (22, fuse_getxattr_in.from_param,None),
	'listxattr'     : (23, fuse_getxattr_in,None),
	'removexattr'   : (24, c2pystr,         None),
	'flush'         : (25, fuse_flush_in,   None),
	'init'          : (26, fuse_init_in,    fuse_init_out),
	'opendir'       : (27, None,            fuse_open_out),
	'readdir'       : (28, fuse_read_in,    None),
	'releasedir'    : (29, fuse_release_in, None),
	'fsyncdir'      : (30, fuse_fsync_in,   None),
	'create'        : (35, fuse_create_in.from_param, fuse_create_out),
	'getlk'         : (31, fuse_lk_in,      fuse_lk_out),
	'setlk'         : (32, fuse_lk_in,      fuse_lk_out),
	'setlkw'        : (33, fuse_lk_in,      fuse_lk_out),
	'access'        : (34, fuse_access_in,  None),
	'interrupt'     : (36, fuse_interrupt_in,None),
	'notify_reply'  : (41, None,            None),
	'batch_forget'  : (42, fuse_batch_forget_in.from_head,None),
	## not implemented yet
	#'bmap'          : (37, None,None),
	#'destroy'       : (38, None,None),
	#'ioctl'         : (39, None,None),
	#'poll'          : (40, None,None),
	#'cuse_init'          : (4096, None,None),
}

fuse_opcode2name = {}
def setup():
	for key, value in fuse_opcode.items():
		fuse_opcode2name[value[0]] = (key,value[1],value[2])
setup()
del setup

