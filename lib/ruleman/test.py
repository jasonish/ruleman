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
import rules

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

class TestRuleParsing(unittest.TestCase):

    def test_parse_metadata(self):

        rule1 = """alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET CURRENT_EVENTS Request to .in FakeAV Campaign June 19 2012 exe or zip"; flow:established,to_server; content:"setup."; fast_pattern:only; http_uri; content:".in|0d 0a|"; http_header; pcre:"/\/[a-f0-9]{16}\/([a-z0-9]{1,3}\/)?setup\.(exe|zip)$/U"; pcre:"/^Host\x3a\s.+\.in\r?$/Hmi"; metadata:stage,hostile_download; reference:url,isc.sans.edu/diary/+Vulnerabilityqueerprocessbrittleness/13501; classtype:trojan-activity; sid:2014929; rev:1;)"""
        metadata = rules.parse_metadata(rule1)
        self.assertEqual(len(metadata), 2)
        self.assertEqual(metadata[0], "stage");
        self.assertEqual(metadata[1], "hostile_download")

if __name__ == "__main__":
    unittest.main()
