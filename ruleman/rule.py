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
    "^(?P<enabled>#)*\s*"	# Enabled/disabled
    "(?P<action>%s)\s*"		# Action
    "[^\s]*\s*"			# Protocol
    "[^\s]*\s*"			# Source address(es)
    "[^\s]*\s*"			# Source port
    "[-><]+\s*"			# Direction
    "[^\s]*\s*"			# Destination address(es)
    "[^\s]*\s*" 		# Destination port
    "\((?P<options>.*)\)\s*" 	# Options
    % "|".join(actions))

# Another compiled pattern to detect preprocessor rules.  We could
# construct the general rule re to pick this up, but its much faster
# this way.
decoder_rule_pattern = re.compile(
    "^(?P<enabled>#)*\s*"	# Enabled/disabled
    "(?P<action>%s)\s*"		# Action
    "\((?P<options>.*)\)\s*" 	# Options
    % "|".join(actions))

# Compiled regular expression to break out the rule options.  Its
# faster if we just pull out what we need.
options = ("msg", "gid", "sid", "rev", "flowbits", "metadata")
option_pattern = re.compile(
    "(%s):(.*?)(?<!\\\);" % "|".join(options))

def parse(buf):
    """ 
    Parse a single rule for a string buffer. 
    """
    m = rule_pattern.match(buf) or decoder_rule_pattern.match(buf)
    if not m:
        return

    rule = {
        "gid": "1",
        "enabled": True if m.group("enabled") is None else False,
        "action": m.group("action"),
        }

    for opt, val in option_pattern.findall(m.group("options")):
        if opt in ["msg", "gid", "sid", "rev"]:
            rule[opt] = val

    return rule

def parse_fp(fileobj):
    """
    Parse multiple rules from a file object, one rule per line.

    Return a list of rules (lines that were parsed into a rule).
    """
    rules = []
    for line in fileobj:
        rule = parse(line)
        if rule:
            rules.append(rule)
    return rules

def parse_file(filename):
    """
    Parse multiple rules from a file provided by named.

    This is just a wrapper from parse_fp.
    """
    with open(filename) as fileobj:
        return parse_fp(fileobj)

# For crude testing.
if __name__ == "__main__":
    import time
    start_time = time.time()
    count = 0
    for filename in sys.argv[1:]:
        rules = parse_file(filename)
        count += len(rules)
    print("Parsed %d rules: elapsed time=%.3f" % (
            count, time.time() - start_time))