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

""" Module for parsing Snort-like rules. """

from __future__ import print_function

import sys
import re
import logging

logger = logging.getLogger(__name__)

# Rule actions we expect to see.
actions = (
    "alert", "log", "pass", "activate", "dynamic", "drop", "reject", "sdrop")

# Compiled regular expression to detect a rule and break out some of
# its parts.
rule_pattern = re.compile(
    r"^(?P<enabled>#)*\s*"	# Enabled/disabled
    r"(?P<action>%s)\s*"	# Action
    r"[^\s]*\s*"		# Protocol
    r"[^\s]*\s*"		# Source address(es)
    r"[^\s]*\s*"		# Source port
    r"[-><]+\s*"		# Direction
    r"[^\s]*\s*"		# Destination address(es)
    r"[^\s]*\s*" 		# Destination port
    r"\((?P<options>.*)\)\s*" 	# Options
    % "|".join(actions))

# Another compiled pattern to detect preprocessor rules.  We could
# construct the general rule re to pick this up, but its much faster
# this way.
decoder_rule_pattern = re.compile(
    r"^(?P<enabled>#)*\s*"	# Enabled/disabled
    r"(?P<action>%s)\s*"	# Action
    r"\((?P<options>.*)\)\s*" 	# Options
    % "|".join(actions))

# Compiled regular expression to break out the rule options.  Its
# faster if we just pull out what we need.
options = ("msg", "gid", "sid", "rev", "flowbits", "metadata")
option_pattern = re.compile(
    "(%s):(.*?);" % "|".join(options))

class Rule(dict):
    """ Class representing a rule. """

    def __init__(self, enabled=None, action=None):
        dict.__init__(self)
        self["enabled"] = enabled
        self["action"] = action
        self["gid"] = 1
        self["sid"] = None
        self["rev"] = None
        self["msg"] = None,
        self["flowbits"] = []
        self["metadata"] = []

    def __getattr__(self, name):
        return self[name]

    @property
    def id(self):
        """ The ID of the rule (gid, sid). """
        return (int(self.gid), int(self.sid))

def parse(buf):
    """ 
    Parse a single rule for a string buffer. 
    """
    m = rule_pattern.match(buf) or decoder_rule_pattern.match(buf)
    if not m:
        return

    rule = Rule(enabled=True if m.group("enabled") is None else False,
                action=m.group("action"))

    print(m.group("options"))
    for opt, val in option_pattern.findall(m.group("options")):
        print("opt: %s" % (opt))
        print("val: %s" % (val))
        if opt in ["gid", "sid", "rev"]:
            rule[opt] = int(val)
        elif opt == "msg":
            rule[opt] = val
        elif opt == "metadata":
            rule[opt] = [v.strip() for v in val.split(",")]
        elif opt == "flowbits":
            rule.flowbits.append(val)

    return rule

def parse_fp(fileobj):
    """
    Parse multiple rules from a file object, one rule per line.

    Return a list of rules (lines that were parsed into a rule).
    """
    rules = []
    for line in fileobj:
        try:
            rule = parse(line)
            if rule:
                rules.append(rule)
        except:
            logger.error("failed to parse rule: %s" % (line))
            raise
    return rules

def parse_file(filename):
    """
    Parse multiple rules from a file provided by named.

    This is just a wrapper from parse_fp.
    """
    with open(filename) as fileobj:
        return parse_fp(fileobj)

def main():
    """ For crude testing. """
    import time
    logging.basicConfig(logLevel=logging.DEBUG)
    start_time = time.time()
    count = 0
    for filename in sys.argv[1:]:
        rules = parse_file(filename)
        for r in rules:
            print(r.id)
        count += len(rules)
    print("Parsed %d rules: elapsed time=%.3f" % (
            count, time.time() - start_time))

if __name__ == "__main__":
    sys.exit(main())
