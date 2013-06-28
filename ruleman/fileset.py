# Copyright (c) 2011-2013 Jason Ish
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
import io

def fileset_from_directory(directory):
    """ Create a fileset from a directory. """
    directory = os.path.realpath(directory)
    files = {}
    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in ["%s/%s" % (dirpath, fn) for fn in filenames]:
            files[filename[len(directory)+1:]] = open(filename).read()
    return files

def fileset_from_archive(filename):
    """ Create a fileset from an archive file.

    Only .tar.gz supported right now.
    """
    files = {}

    # Python 2.6 doesn't support 'with' here.
    tf = tarfile.open(filename)
    for member in [member for member in tf if member.isreg()]:
        files[member.name] = tf.extractfile(member).read()
    tf.close()
    return files
    
def load(path):
    if os.path.isfile(path):
        return fileset_from_archive(path)
    elif os.path.isdir(path):
        return fileset_from_directory(path)
        
