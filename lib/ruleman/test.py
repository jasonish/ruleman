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
import os
import unittest
import io

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ruleman import fetch
from ruleman import rules
from ruleman import config
from ruleman import core
from ruleman import rulematcher

class TestFetch(unittest.TestCase):

    def test_get_md5_url(self):
        
        url = "http://www.snort.org/snortrules-snapshot-2921.tar.gz/XXXXXX"
        expected = url.replace(".tar.gz", ".tar.gz.md5")
        got = fetch.get_md5_url({"url": url})
        self.assertEqual(got, expected)

        url = "http://rules.emergingthreats.net/emerging.rules.tar.gz"
        self.assertEqual(fetch.get_md5_url({"url": url}), url + ".md5")

        url = "http://emergingthreatspro.com/XXXXXXXXXXXXXXX/etpro.rules.tar.gz"
        self.assertEqual(fetch.get_md5_url({"url": url}), url + ".md5")

class TestRuleParsing(unittest.TestCase):

    def test_parse_metadata(self):

        rule1 = """alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET CURRENT_EVENTS Request to .in FakeAV Campaign June 19 2012 exe or zip"; flow:established,to_server; content:"setup."; fast_pattern:only; http_uri; content:".in|0d 0a|"; http_header; pcre:"/\/[a-f0-9]{16}\/([a-z0-9]{1,3}\/)?setup\.(exe|zip)$/U"; pcre:"/^Host\x3a\s.+\.in\r?$/Hmi"; metadata:stage,hostile_download; reference:url,isc.sans.edu/diary/+Vulnerabilityqueerprocessbrittleness/13501; classtype:trojan-activity; sid:2014929; rev:1;)"""
        metadata = rules.parse_metadata(rule1)
        self.assertEqual(len(metadata), 2)
        self.assertEqual(metadata[0], "stage");
        self.assertEqual(metadata[1], "hostile_download")

    def test_parse_policy(self):
        raw = """alert TCP $HOME_NET any -> $EXTERNAL_NET any (msg:"TEST rule"; flow:established,to_server; metadata:policy balanced-ips alert, policy security-ips drop, service http; sid:999999; rev:1;)"""
        rule = rules.parse_rule(raw)
        self.assertTrue("balanced-ips" in rule.policies)
        self.assertEquals("alert", rule.policies["balanced-ips"])
        self.assertTrue("security-ips" in rule.policies)
        self.assertEquals("drop", rule.policies["security-ips"])

class TestConfig(unittest.TestCase):

    test_config = u"""
[DEFAULT]
ignore-files = ignore1.rules, ignore2.rules, ignore3.rules

[load section test]
string = some string value
int-value = 1
a list of strings = one, two, three
bool-yes = yes
bool-no = no
bool-one = 1
bool-zero = 0
bool-true = true
bool-false = false

[ruleset partial]
url = some url

[ruleset complete]
url = some url
md5-url = md5url

[ruleset without_ignore_files]

[ruleset with_empty_ignore_files]
ignore-files =

[ruleset with_ignore_files]
ignore-files = one.rules, two.rules, three.rules
"""

    def setUp(self):
        config.loadfp(io.StringIO(TestConfig.test_config))

    def test_load_section_basic(self):
        section = config.get_section("load section test")
        self.assertEquals("some string value", section["string"])

    def test_load_section_with_xforms(self):
        xforms = {"int-value": int,
                  "a list of strings": config.xform_stringlist}
        section = config.get_section("load section test", xforms=xforms)
        self.assertEquals(int, type(section["int-value"]))
        self.assertEquals(list, type(section["a list of strings"]))
        self.assertEquals(3, len(section["a list of strings"]))
        self.assertEquals("one", section["a list of strings"][0])

    def test_load_section_bool_xform(self):
        xforms = {"bool-yes": config.xform_bool,
                  "bool-no": config.xform_bool,
                  "bool-one": config.xform_bool,
                  "bool-zero": config.xform_bool,
                  "bool-true": config.xform_bool,
                  "bool-false": config.xform_bool,
                  }
        section = config.get_section("load section test", xforms=xforms)
        self.assertTrue(section["bool-yes"])
        self.assertFalse(section["bool-no"])
        self.assertTrue(section["bool-one"])
        self.assertFalse(section["bool-zero"])
        self.assertTrue(section["bool-true"])
        self.assertFalse(section["bool-false"])

    def test_get_ruleset_unknown(self):
        self.assertRaises(
            config.NoRulesetError,
            config.get_ruleset, "unknown-ruleset-name")

    def test_get_ruleset_partial(self):
        ruleset = config.get_ruleset("partial")
        self.assertEquals("some url", ruleset["url"])

        # Verify that md5-url does not exist.  The non-existence of it
        # means we should guess it.  If it exists we use it, unless
        # its value is None (or an empty string will do), then we
        # don't check for an MD5 at all.
        self.assertFalse("md5-url" in ruleset)

    def test_get_ruleset_complete(self):
        ruleset = config.get_ruleset("complete")
        self.assertEquals("some url", ruleset["url"])
        self.assertEquals("md5url", ruleset["md5-url"])

    def test_get_rulesets(self):
        rulesets = config.get_rulesets()
        self.assertTrue("partial" in rulesets)
        self.assertTrue("complete" in rulesets)

    def test_get_ruleset_without_ignore_files(self):
        # This ruleset did not have an ignore-files section.  We should get
        # the one provided by the [DEFAULT].
        r = config.get_ruleset("without_ignore_files")
        self.assertEquals(["ignore1.rules", "ignore2.rules", "ignore3.rules"],
                          r["ignore-files"])

    def test_get_ruleset_with_empty_ignore_files(self):
        # As this configuration provided an ignore-files with no
        # value, we should not get the default.
        r = config.get_ruleset("with_empty_ignore_files")
        self.assertEquals([], r["ignore-files"])

    def test_get_ruleset_with_ignore_files(self):
        # This ruleset provided its own rule files.
        r = config.get_ruleset("with_ignore_files")
        self.assertEquals(["one.rules", "two.rules", "three.rules"],
                          r["ignore-files"])

class MockRule(object):
    
    def __init__(self, gid=None, sid=None, group=None):
        self.gid = gid
        self.sid = sid
        self.group = group

class TestRuleIdRuleMatcher(unittest.TestCase):

    def test_single_ruleid(self):
        matchers = rulematcher.parse_rule_id_matchers("1:412")

        self.assertEquals(1, len(matchers))

        self.assertEquals(1, matchers[0].gid)
        self.assertEquals(412, matchers[0].sid)
        
        self.assertTrue(matchers[0].match(MockRule(gid=1, sid=412)))

    def test_multiple_ruleid(self):
        matchers = rulematcher.parse_rule_id_matchers("1:412,3:100019, 119:223")
        self.assertEquals(3, len(matchers))

        self.assertEquals(1, matchers[0].gid)
        self.assertEquals(412, matchers[0].sid)
        self.assertTrue(matchers[0].match(MockRule(gid=1, sid=412)))

        self.assertEquals(3, matchers[1].gid)
        self.assertEquals(100019, matchers[1].sid)
        self.assertTrue(matchers[1].match(MockRule(gid=3, sid=100019)))

        self.assertEquals(119, matchers[2].gid)
        self.assertEquals(223, matchers[2].sid)
        self.assertTrue(matchers[2].match(MockRule(gid=119, sid=223)))

    def test_bad_ruleid(self):
        self.assertRaises(
            rulematcher.InvalidRuleMatchError,
            rulematcher.parse_rule_id_matchers, "1:asdf")
        
        self.assertRaises(
            rulematcher.InvalidRuleMatchError,
            rulematcher.parse_rule_id_matchers, "1:412, 1:*")

class TestReRuleMatch(unittest.TestCase):

    test_rule0_raw = """# alert tcp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"GPL DNS zone transfer TCP"; flow:to_server,established; content:"|00 00 FC|"; offset:15; reference:arachnids,212; reference:cve,1999-0532; reference:nessus,10595; classtype:attempted-recon; sid:2100255; rev:14;)"""

    def setUp(self):
        self.test_rule0 = rules.parse_rule(self.test_rule0_raw)

    def test_badre(self):
        self.assertRaises(
            rulematcher.InvalidRuleMatchError,
            rulematcher.parse_rule_re_matcher, "re:.*(")

    def test_some(self):
        matcher = rulematcher.parse_rule_re_matcher("re:GPL DNS")
        self.assertTrue(matcher.match(self.test_rule0))

        matcher = rulematcher.parse_rule_re_matcher("re:DNS")
        self.assertTrue(matcher.match(self.test_rule0))
            
        matcher = rulematcher.parse_rule_re_matcher("re:cve,1999-\d\d\d\d")
        self.assertTrue(matcher.match(self.test_rule0))

        matcher = rulematcher.parse_rule_re_matcher("re:cve,1999-0533")
        self.assertFalse(matcher.match(self.test_rule0))

class TestGroupNameMatcher(unittest.TestCase):

    def test_single_group(self):
        matchers = rulematcher.parse_group_name_matchers("group:icmp.rules")
        self.assertEquals(1, len(matchers))
        self.assertTrue(matchers[0].match(MockRule(group="icmp.rules")))

    def test_multi_group(self):
        matchers = rulematcher.parse_group_name_matchers(
            "group:icmp.rules,x11.rules, emerging-malware.rules")
        self.assertEquals(3, len(matchers))
        self.assertTrue(matchers[0].match(MockRule(group="icmp.rules")))
        self.assertTrue(matchers[1].match(MockRule(group="x11.rules")))
        self.assertTrue(matchers[2].match(MockRule(
                    group="emerging-malware.rules")))

    def test_fnmatch_all_group(self):
        matchers = rulematcher.parse_group_name_matchers("group:*")
        self.assertEquals(1, len(matchers))
        self.assertTrue(matchers[0].match(MockRule(group="icmp.rules")))

    def test_fnmatch_some_group(self):
        matchers = rulematcher.parse_group_name_matchers(
            "group: rules/icmp*.rules")
        self.assertEquals(1, len(matchers))
        self.assertTrue(matchers[0].match(MockRule(group="rules/icmp.rules")))
        self.assertTrue(matchers[0].match(MockRule(
                    group="rules/icmp-info.rules")))

class TestRuleMatcherCollection(unittest.TestCase):

    def test_basic(self):
        input = io.StringIO(u"""
# Some comment.
1:412
3:999, 119:223

# A group..
group:icmp.rules

# Multiple groups.
group: x11.rules, emerging-malware.rules
""")
        matchers = rulematcher.load_collection_from_fp(input)

        self.assertTrue(matchers.match(MockRule(gid=1, sid=412)))
        self.assertTrue(matchers.match(MockRule(gid=3, sid=999)))
        self.assertTrue(matchers.match(MockRule(gid=119, sid=223)))
        self.assertTrue(matchers.match(MockRule(group="icmp.rules")))
        self.assertTrue(matchers.match(MockRule(group="x11.rules")))
        self.assertTrue(matchers.match(MockRule(
                    group="emerging-malware.rules")))

        self.assertFalse(matchers.match(MockRule(gid=1, sid=413)))
        self.assertFalse(matchers.match(MockRule(group="deleted.rules")))

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromName(__name__)
    unittest.TextTestRunner(verbosity=2).run(suite)
