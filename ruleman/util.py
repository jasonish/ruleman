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

import urllib2
import hashlib

def get(url, fileobj, progress_hook=None):
    """ Get the contents of a URL storing the content in the provide
    file like object.

    Optionally call a progress_hook which is a function that will be
    called with the arguments content_length, data_read.

    A tuple is returned with the first item being the number of bytes
    read, and the second item being the value of the .info() method
    from the urllib2.urlopen method.
    """
    remote = urllib2.urlopen(url)
    remote_info = remote.info()
    content_length = int(remote_info["content-length"])
    bytes_read = 0
    while 1:
        buf = remote.read(8192)
        if not buf:
            break
        bytes_read += len(buf)
        fileobj.write(buf)
        if progress_hook:
            progress_hook(content_length, bytes_read)
    fileobj.flush()
    remote.close()
    return bytes_read, remote_info

def md5sum_fp(fileobj):
    """ Calculate the md5 sum for the contents of the passed in file
    like object. """
    return hashlib.md5(fileobj.read()).hexdigest()

def md5sum(filename):
    """ Calculate the md5 sum for the file provided by name. """
    return md5sum_fp(open(filename))
