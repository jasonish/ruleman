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

def multiFnMatch(name, patterns):
    for p in patterns:
        if fnmatch.fnmatch(name, p):
            return True
    return False

def tar_to_dict(filename, exclude=[]):
    """ Convert a tarfile to a dictionary of files keyed by
    filename. """
    files = {}
    tf = tarfile.open(filename)
    for member in tf:
        if member.isreg():
            if multiFnMatch(member.name, exclude):
                logging.debug("Excluding file %s." % (member.name))
                continue
            files[member.name] = tf.extractfile(member).read()
    return files

def get_md5_file(filename):
    """ Get the MD5 checksum of a file specified by filename. """
    m = hashlib.md5()
    m.update(open(filename).read())
    return m.hexdigest()

def write_file_mkdir(filename, contents):
    """ Write out a file creating parent directories as needed. """
    dirname = os.path.dirname(filename)
    if dirname and not os.path.isdir(dirname):
        os.makedirs(dirname)
    open(filename, "w").write(contents)
