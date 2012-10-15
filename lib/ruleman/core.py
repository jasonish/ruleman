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

from __future__ import print_function

import sys
import os
import logging
import types

from ruleman import rules
from ruleman import config
from ruleman import util
from ruleman import snort

logger = logging.getLogger("ruleman.core")

def set_policy(rule_map, policy, inline=False):
    """ Given a map (dict) of rules, enable or disable rules based on
    their policy metadata.

    Returns a tuple (enabled, disabled, dropped) containing the counts
    of rules enabled, rules disabled and rules changed to drop. """

    enabled = 0
    disabled = 0
    dropped = 0

    for rule in rule_map.itervalues():
        if policy in rule.policies:
            if not rule.enabled:
                rule.enabled = True
                enabled += 1
            if inline and rule.policies[policy] == "drop":
                rule.action = "drop"
                dropped += 1
        elif rule.enabled:
            rule.enabled = False
            disabled = False
    return (enabled, disabled, dropped)

def load_ruleset_files(ruleset):
    """ Load the ruleset files into memory, regenerating SO rule stubs
    if required. """
    if "files" in ruleset:
        # Nothing to do.
        return

    ruleset_filename = "%s/%s/ruleset.tar.gz" % (
        config.RULESET_DATA_DIR, ruleset["name"])
    files = util.archive_to_dict(ruleset_filename)
    ruleset["files"] = {}
    for filename in files:
        if filename not in ruleset["ignore-files"]:
            ruleset["files"][filename] = files[filename]
    return ruleset["files"]

def load_ruleset_rules(ruleset):
    """ For the given ruleset, load the individual rules from its rule
    files. """
    if "rules" in ruleset:
        # Already cached.  Return the cached rules.
        return ruleset["rules"]
    ruleset["rules"] = rules.build_rule_map(ruleset["files"])
    return ruleset["rules"]

def fix_flowbit_dependencies(rules):
    """ Fix up flowbit dependencies on the in-memory database of rules.

    This is done by generating a list of all the flowbits that are
    checked by enabled rules, then any rules that modify those
    flowbits will be enabled. """

    assert(type(rules) == types.DictType)

    def __fix_flowbit_dependencies():
        required = []
        n = 0

        # Put all required flowbits into a list.
        for rule in rules.values():
            if rule.enabled:
                for fb in rule.flowbits_checked:
                    if fb not in required:
                        required.append(fb)

        # Make sure any rule that toggles flowbits in the required set
        # is enabled.
        for rule in rules.values():
            if not rule.enabled:
                for fb in rule.flowbits_set:
                    if fb in required:
                        logger.debug(
                            "Enabling rule %s for flowbit dependency" % (
                                str(rule.key)))
                        rule.enabled = True
                        n += 1

        return n

    count = 0
    while 1:
        n = __fix_flowbit_dependencies()
        if n == 0:
            break
        count += n

    return count

def disable_xform(rule):
    if rule.enabled:
        rule.enabled = False
        logger.debug("Disabled rule %s" % (rule.brief()))
        return True
    return False

def enable_xform(rule):
    if not rule.enabled:
        rule.enabled = True
        logger.debug("Enabled rule %s" % (rule.brief()))
        return True
    return False

def drop_xform(rule):
    if rule.enabled and rule.action != "drop":
        rule.action = "drop"
        logger.debug("Set to drop %s" % (rule.brief()))
        return True
    return False

def apply_rule_xform(rule_map, matchers, xform):
    count = 0
    for rule in rule_map.itervalues():
        if matchers.match(rule):
            if xform(rule):
                count += 1
    return count

def disable_rules(rule_map, matchers):
    return apply_rule_xform(rule_map, matchers, disable_xform)

def enable_rules(rule_map, matchers):
    return apply_rule_xform(rule_map, matchers, enable_xform)

def drop_rules(rule_map, matchers):
    return apply_rule_xform(rule_map, matchers, drop_xform)

def build_sid_msg_map(rule_map, file):
    """ Using rule_map, write out a sid-msg.map file to the provided
    file. """
    # Get the keys sorted by sid.
    keys = sorted(rule_map.keys(), key=lambda k: k[1])

    # Dump a sig-msg.map line for each rule in gid 1 or 3.
    for key in keys:
        if not key[0] in [1,3]:
            continue
        rule = rule_map[key]
        parts = [str(rule.sid), rule.msg] + rule.references
        print("%s" % " || ".join(parts), file=file)
