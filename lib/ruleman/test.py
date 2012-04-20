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

import unittest

import fetch

class TestFetch(unittest.TestCase):

    def test_guess_md5_url(self):
        
        url = "http://www.snort.org/sub-rules/snortrules-snapshot-2921.tar.gz/XXXXXX"
        expected = url.replace(".tar.gz", ".tar.gz.md5")
        got = fetch.guess_md5_url(url)
        self.assertEqual(got, expected)

        url = "http://rules.emergingthreats.net/open-nogpl/snort-2.9.0/emerging.rules.tar.gz"
        self.assertEqual(fetch.guess_md5_url(url), url + ".md5")

        url = "http://rules.emergingthreatspro.com/XXXXXXXXXXXXXXX/suricata/etpro.rules.tar.gz"
        self.assertEqual(fetch.guess_md5_url(url), url + ".md5")

if __name__ == "__main__":
    unittest.main()
