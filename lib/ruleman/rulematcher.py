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

import re

class InvalidRuleMatchError(Exception):
    pass

class RuleMatcher(object):

    def match(self, rule):
        raise NotImplementedError

class RuleIdRuleMatcher(RuleMatcher):

    def __init__(self, gid, sid):
        self.gid = gid
        self.sid = sid

    def match(self, rule):
        if rule.sid == self.sid and rule.gid == self.gid:
            return True
        return False

class ReRuleMatcher(RuleMatcher):

    def __init__(self, regex):
        self.pattern = re.compile(regex, re.IGNORECASE)

    def match(self, rule):
        m = self.pattern.search(str(rule))
        if m:
            return True
        return False

class GroupNameMatcher(RuleMatcher):
    
    def __init__(self, group):
        self.group = group

    def match(self, rule):
        if rule.group == self.group:
            return True
        return False

class RuleMatcherCollection(object):

    def __init__(self, matchers=None):
        if matchers:
            self.matchers = matchers
        else:
            self.matchers = []

    def match(self, rule):
        for matcher in self.matchers:
            if matcher.match(rule):
                return True
        return False
        
def parse_rule_id_matchers(line):
    matchers = []
    for arg in line.split(","):
        try:
            gid, sid = map(int, arg.strip().split(":"))
        except:
            raise InvalidRuleMatchError("%s in %s" % (arg, line))
        matcher = RuleIdRuleMatcher(gid, sid)
        matchers.append(matcher)
    return matchers

def parse_rule_re_matcher(line):
    tag, regex = line.split(":", 1)
    try:
        return ReRuleMatcher(regex)
    except Exception as err:
        raise InvalidRuleMatchError("%s: %s" % (err, line))

def parse_group_name_matchers(line):
    matchers = []
    tag, groups = line.split(":", 1)
    for group in groups.split(","):
        matcher = GroupNameMatcher(group.strip())
        matchers.append(matcher)
    return matchers

def load_collection_from_fp(fileobj):
    """ Load rule matchers from a file object. 

    Returns a RuleMatcherCollection containing the loaded rule
    matchers. """
    matchers = []
    for line in fileobj:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tag = line.split(":")[0]
        if tag.isdigit():
            matchers += parse_rule_id_matchers(line)
        elif tag == "group":
            matchers += parse_group_name_matchers(line)
        elif tag == "re":
            matchers.append(parse_rule_re_matcher(line))
        else:
            raise InvalidRuleMatchError(line)
    return RuleMatcherCollection(matchers)

def load_collection_from_file(filename):
    """ Load rule matchers from a file. 

    Returns a RuleMatcherCollection containing the loaded rule
    matchers. """
    return load_collection_from_fp(open(filename))
