# Copyright (c) 2011-2012 Jason Ish
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

import sys
import os
import os.path
import commands
import re
import tempfile
import shutil

def validate(ctx):
    if not os.path.exists(ctx["path"]):
        return False, "snort path %s does not exist" % (ctx["path"])
    if not os.path.exists(ctx["dynamic-engine"]):
        return False, "dynamic_engine %s not found" % (ctx["dynamic-engine"])
    if get_version(ctx) == None:
        return False, "failed to get version"

def get_version(ctx):
    """ Return the Snort version as reported by snort -V."""
    status, output = commands.getstatusoutput("%s -V" % (ctx["path"]))
    if status == 0:
        return re.search("Version ([0-9\.]+)", output).group(1)
    else:
        return None

def generate_stubs(ctx, files):
    version = get_version(ctx)

    lib_prefix = "so_rules/precompiled/%s/%s" % (ctx["os-type"], version)
    tmpdir = tempfile.mkdtemp()
    os.makedirs("%s/lib" % (tmpdir))
    os.makedirs("%s/stubs" % (tmpdir))
    for filename in files:
        if filename.startswith(lib_prefix):
            outobj = open(
                "%s/lib/%s" % (tmpdir, os.path.basename(filename)), "w")
            outobj.write(files[filename])
            outobj.close()

    args = []
    args.append(ctx["path"])
    args.append("--dump-dynamic-rules=%s/stubs" % (tmpdir))
    args.append("--dynamic-detection-lib-dir=%s/lib" % (tmpdir))
    args.append("--dynamic-engine-lib=%s" % (ctx["dynamic-engine"]))

    print("Executing %s." % " ".join(args))
    if os.system(" ".join(args)) != 0:
        print("\nERROR: Failed to generate SO rule stubs, aborting.")
        sys.exit(1)

    # Suck in the generated stubs.
    stubs = {}
    for filename in os.listdir("%s/stubs" % (tmpdir)):
        dst_filename = "so_rules/%s" % (filename)
        src_filename = "%s/stubs/%s" % (tmpdir, filename)
        stubs[dst_filename] = open(src_filename).read()

    # Cleanup.
    shutil.rmtree(tmpdir)

    return stubs
