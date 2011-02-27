#!/usr/bin/env python

"""Setup script for smurf's Twisted Fuse stuff"""

from distutils.core import setup

description = "A Twisted/FUSE adapter"
long_description = \
"""
This module allows you to mount a FUSE file system within a
Twisted-based Python programm.
All requests are properly processed with Deferred handlers.

"""

setup (name = "twistfuse",
       version = "0.1",
       description = description,
       long_description = long_description,
       author = "Matthias Urlichs",
       author_email = "smurf@smurf.noris.de",
       url = "http://netz.smurf.noris.de/cgi/gitweb?p=twistfuse.git",
       license = 'Python',
       platforms = ['POSIX'],
       packages = ['twistfuse'],
      )
