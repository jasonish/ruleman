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
import subprocess
import re
import tempfile
import shutil
import atexit

def rmtree(path):
    print("Removing directory %s." % (path))
    shutil.rmtree(path)

class SnortVersion(object):
    """ A class to represent a Snort version.  The idea being that it
    will allow comparison operations. """

    def __init__(self, version):
        self.version_string = version
        self.version_parts = [int(p) for p in version.split(".")]

    def __repr__(self):
        return self.version_string

class Snort(object):

    def __init__(self, path, dynamic_engine_lib=None):
        self.path = path
        self.dynamic_engine_lib = dynamic_engine_lib

    def get_version(self):
        stdout, stderr = subprocess.Popen(
            [self.path, "-V"], stderr=subprocess.PIPE).communicate()
        m = re.search("Version (\d+\.\d+\.\d+(\.\d+|))", stderr, re.M)
        return SnortVersion(m.group(1))

    def generate_dynamic_rules(self, ostype, files):
        assert(self.dynamic_engine_lib is not None)
        workdir = tempfile.mkdtemp(prefix="ruleman.tmp.")
        atexit.register(rmtree, workdir)
        os.mkdir("%s/lib" % (workdir))
        os.mkdir("%s/so_rules" % (workdir))
        for filename in files:
            if filename.find(ostype) > -1 and filename.endswith(".so"):
                basename = os.path.basename(filename)
                open("%s/lib/%s" % (workdir, basename), "w").write(
                    files[filename])
        subprocess.call(
            [self.path,
             "--dynamic-engine-lib=%s" % (self.dynamic_engine_lib),
             "--dynamic-detection-lib-dir=%s/lib" % (workdir),
             "--dump-dynamic-rules=%s/so_rules" % (workdir)])
        rules = {}
        for filename in os.listdir("%s/so_rules" % (workdir)):
            rules["so_rules/%s" % (filename)] = open(
                "%s/so_rules/%s" % (workdir, filename)).read()
        return rules
