#!/usr/bin/python
# -*- coding: utf-8 -*-

# A simple test program for TwistFUSE.

from twistfuse.handler import Handler
from twistfuse.filesystem import FileSystem,Inode,Dir,File
from twisted.internet import reactor

import errno,os,stat

class DummyMain(Inode):
	def __init__(self,fs):
		super(DummyMain,self).__init__(fs,1)
		
	def lookup(self,name, ctx=None):
		if name == "dummy":
			return DummyFileNode(self.fs,2)
		raise IOError(errno.ENOENT,"No entry named %s" % (repr(name,)))

	def getattr(self):
		return {'mode':stat.S_IFDIR|stat.S_IRWXU}

class DummyFileNode(Inode):
	content = "FooBar\n"
	def getattr(self, ctx=None):
		return dict(size=len(self.content),mode=stat.S_IFREG|stat.S_IRWXU)
	def setattr(self, ctx=None, size=None,**kw):
		if size is not None:
			self.content = self.content[:size]

class DummyFile(File):
	def read(self,offset,length, ctx=None):
		s = self.node.content
		if offset >= len(s): return ""
		if offset > 0: s = s[offset:]
		if length > len(s): length = len(s)
		if length < len(s): s = s[:length]
		return s

	def write(self,offset,data, ctx=None):
		s = self.node.content
		s2 = ""
		e = offset + len(data)
		if e < len(s): s2 = s[e:]
		s = s[:offset] + data + s2
		self.node.content = s

class DummyMainDir(Dir):
	def read(self,callback,offset, ctx=None):
		if offset == 0:
			callback("dummy", stat.S_IFREG|stat.S_IRWXU, 2, 1)

class DummyFS(FileSystem):
	def __init__(self):
		super(DummyFS,self).__init__(root=DummyMain(self), filetype=DummyFile, dirtype=DummyMainDir)


def main():
	h = Handler()
	fs = DummyFS()
	if not os.path.exists("/tmp/dummy"):
		os.mkdir("/tmp/dummy", 0o755)
	h.mount(fs,"/tmp/dummy")
	reactor.run()
	h.umount(True)

main()
