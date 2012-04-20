# Copyright (c) 2012 Jason Ish
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
import os.path
import shutil

def do_init():
    current_files = os.listdir(".")
    if current_files:
        r = raw_input("Current directory is not empty, continue [N/y]? ")
        if not r or r != "y":
            print("Directory not initialized.")
            return 1

    data_dir = os.path.abspath(os.path.dirname(__file__)) + "/data"
    if not os.path.exists(data_dir):
        print("ERROR: Template configuration files not found.")
        return 1
    print("Found template configurationf files at\n %s." % data_dir)

    data_files = os.listdir(data_dir)
    for filename in data_files:
        if os.path.exists(filename):
            r = raw_input("%s exists, overwrite [N/y]? " % (filename))
            if not r or r != "y":
                continue
        src_file = "%s/%s" % (data_dir, filename)
        print("Creating %s." % (filename))
        shutil.copyfile(src_file, filename)

def init(*args):
    try:
        do_init()
    except KeyboardInterrupt:
        print("\nInitialization aborted.")
        return 1
