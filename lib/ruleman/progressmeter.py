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

import sys

try:
    import progressbar
    has_progressbar = True
except:
    has_progressbar = False

class NullProgressMeter(object):

    def update(self, transferred, block_size, total_size):
        pass

    def done(self):
        pass

class SimpleProgressMeter(object):

    def __init__(self):
        self.width = 9

    def update(self, transferred, block_size, total_size):
        val = int((transferred * block_size) / float(total_size) * 100)
        sys.stdout.write("\b" * (self.width + 1))
        format = "%%%ds%%%%" % (self.width)
        sys.stdout.write(format % (val))
        sys.stdout.flush()

    def done(self):
        sys.stdout.write("\n")
        sys.stdout.flush()

class FancyProgressMeter(object):

    def __init__(self):
        self.bar = progressbar.ProgressBar(
            widgets=[progressbar.Percentage(),
                     progressbar.Bar()],
            maxval=100)
        self.bar.start()

    def update(self, transferred, block_size, total_size):
        val = int((transferred * block_size) / float(total_size) * 100)
        self.bar.update(val)

    def done(self):
        self.bar.finish()

def get_progressmeter():
    if not sys.stdout.isatty():
        return NullProgressMeter()
    elif has_progressbar:
        return FancyProgressMeter()
    else:
        return SimpleProgressMeter()
