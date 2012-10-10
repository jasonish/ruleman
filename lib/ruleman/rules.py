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
import logging
import types
import io

logger = logging.getLogger("ruleman.rules")

# Regular expressesions for parsing Snort rules.
rule_pattern      = re.compile("^#?\s?((alert|pass)\s+(.*sid:\s?(\d+).*$))")
gid_pattern       = re.compile("gid:\s*(\d+)")
flowbit_pattern   = re.compile("flowbits:(.*?);")
msg_pattern       = re.compile("msg:\s*\"(.*?)\s*\";")
reference_pattern = re.compile("reference:\s*(.*?)\s*;")
metadata_pattern  = re.compile("metadata:\s?(.*?);")

class Rule(object):
    """ Class to represent an individual Snort rule. """
    
    def __init__(self, group=None):
        self.group = group
        self.enabled = False
        self.action = None
        self.body = None
        self.gid = 1
        self.sid = 0
        self.policies = {}
        self.references = []
        self.metadata = []
        self.flowbits = []
        self.flowbits_checked = []
        self.flowbits_set = []

    @property
    def key(self):
        return (self.gid, self.sid)

    def brief(self):
        """ Return a string containing the brief description of the
        rule. """
        return "[%d:%d] %s" % (self.gid, self.sid, self.msg)

    def __str__(self):
        rule = "%s %s" % (self.action, self.body)
        if self.enabled:
            return rule
        else:
            return "# %s" % (rule)

def parse_msg(buf):
    m = msg_pattern.search(buf)
    if m:
        return m.group(1)
    return None

def parse_gid(buf, default=None):
    m = gid_pattern.search(buf)
    if m:
        return int(m.group(1))
    return default

def parse_metadata(buf):
    """ Extract the metadata from a rule.  Returns a list where each
    item is a metadata item. """
    m = metadata_pattern.search(buf)
    if m:
        metadata = [m.strip() for m in m.group(1).split(",")]
        return metadata
    return []

def parse_policies(metadata):
    policies = {}
    for m in metadata:
        # Extract policy information into its own field.
        if m.startswith("policy"):
            key, val = [s.strip() for s in m.split(" ", 1)]
            if key == "policy":
                parts = [s.strip() for s in val.split(" ")]
                policy = parts[0]
                try:
                    action = parts[1]
                except:
                    action = "alert"
                policies[policy] = action
    return policies

def get_checked_flowbits(flowbits):
    checked = []
    for flowbit in flowbits:
        parts = [p.strip() for p in flowbit.split(",")]
        if parts[0] in ["isset", "isnotset"]:
            checked.append(parts[1])
    return checked

def get_set_flowbits(flowbits):
    flowbits_set = []
    for flowbit in flowbits:
        parts = [p.strip() for p in flowbit.split(",")]
        if parts[0] in ["set", "unset", "reset"]:
            flowbits_set.append(parts[1])
    return flowbits_set

def parse_rule(buf, group=None):
    """ Build a rule from the provided buffer.

    If the contents of the buffer is successfully parsed as a rule
    then return a rule object.  Otherwise None will be returned."""

    buf = buf.strip()
    m = rule_pattern.match(buf)
    if not m:
        return None

    rule = Rule(group=group)
    rule.enabled = not buf.startswith("#")
    rule.body = m.group(3)
    rule.action = m.group(2)
    rule.sid = int(m.group(4))
    rule.gid = parse_gid(buf, 1)
    rule.msg = parse_msg(buf)
    rule.references = reference_pattern.findall(buf)
    rule.metadata = parse_metadata(buf)
    rule.policies = parse_policies(rule.metadata)
    rule.flowbits = flowbit_pattern.findall(buf)
    rule.flowbits_checked = get_checked_flowbits(rule.flowbits)
    rule.flowbits_set = get_set_flowbits(rule.flowbits)

    return rule

def build_rule_map(source, rule_map=None):
    """ Build a map of IDS rules from the map of provided files.

    If a rule_map is provided, parsed rules will be added to it
    provided there is no existing rule with the same rule key (gid,
    sid). """

    assert(type(source) == types.DictType)

    if rule_map == None:
        rule_map = {}

    for filename in source:
        if filename.endswith(".rules"):
            for line in io.BytesIO(source[filename]):
                rule = parse_rule(line, group=filename)
                if rule:
                    if rule.key in rule_map:
                        logger.warn("warning: found duplicate rule ID %s." % (
                                str(rule.key)))
                    else:
                        rule_map[rule.key] = rule
            
    return rule_map

