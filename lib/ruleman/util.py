# Copyright (c) 2011 Jason Ish
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import os
import tarfile
import fnmatch
import hashlib
import logging
import tempfile
import atexit
import shutil
import subprocess

logger = logging.getLogger("ruleman.util")

def rmpath(path):
    """ Remove the given path, whether it is a directory or a
    file. """
    if os.path.exists(path):
        if os.path.isdir(path):
            logger.debug("Removing directory %s" % (path))
            shutil.rmtree(path)
        else:
            logger.debug("Removing file %s" % (path))
            os.unlink(path)

def get_tmpdir():
    """ Create a temporary directory that will be cleaned up on
    exit. """
    tmpdir = tempfile.mkdtemp(prefix="ruleman.tmp")
    atexit.register(rmpath, tmpdir)
    return tmpdir

def get_tmpfilename(suffix=''):
    """ Basically a wrapper around tempfile.mkstemp that registers a
    cleanup hook. """
    tmpfd, tmpname = tempfile.mkstemp(prefix="ruleman.tmp", suffix=suffix)
    atexit.register(rmpath, tmpname)
    return tmpname

def tar_to_dict(filename):
    """ Convert a tarfile to a dictionary of files keyed by
    filename. """
    files = {}
    tf = tarfile.open(filename)
    for member in tf:
        if member.isreg():
            files[member.name] = tf.extractfile(member).read()
    tf.close()
    return files

def archive_to_dict(filename):
    return tar_to_dict(filename)

def createfile(filename, mkdirs=False):
    """ Create and and open a new file optionally creating all parent
    directories as needed. """
    if mkdirs:
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
    return open(filename, "w")

def extract_archive_tar(filename, path):
    """ Specific variant of extract_archive for tar files. """
    tf = tarfile.open(filename)
    tf.extractall(path=path)
    tf.close()

def extract_archive(filename, path):
    """ Extract archive named in filename to the provided path. """
    return extract_archive_tar(filename, path)

def create_archive_targz(filename, path):
    """ Specific variant of create_archive for creating .tar.gz
    archives. """
    files = " ".join(["'%s'" % f for f in os.listdir(path)])
    args = "tar zcf %s -C %s %s" % (filename, path, files)
    subprocess.check_call(args, shell=True)
    
def create_archive(filename, path):
    """ Create an archive named filename containing the contents of
    the provided path. """
    return create_archive_targz(filename, path)
