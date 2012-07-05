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

import string
import re
try: from cStringIO import StringIO
except: from StringIO import StringIO

# Regular expressesions for parsing Snort rules.
rulePattern = re.compile("^#?\s?((alert|pass)\s+(.*sid:\s?(\d+).*$))")
gidPattern = re.compile("gid:\s*(\d+)")
flowbitPattern = re.compile("flowbits:(.*?);")
msgPattern = re.compile("msg:\s*\"(.*?)\s*\";")
referencePattern = re.compile("reference:\s*(.*?)\s*;")

fbProvidedKeywords = ["set", "unset", "reset"]
fbUsedKeywords = ["isset", "isnotset"]

class Rule(object):
    """ Class to represent an individual Snort rule. """
    
    def __init__(self):
        self.enabled = False
        self.action = None
        self.body = None
        self.gid = 1
        self.sid = 0
        self.flowbitsProvided = []
        self.flowbitsUsed = []
        self.noalert = False
        self.group = None
        self.policies = {}
        self.references = []

    def __str__(self):
        rule = "%s %s" % (self.action, self.body)
        if self.enabled:
            return rule
        else:
            return "# %s" % (rule)

def parse_metadata(rulebuf):
    """ Extract the metadata from a rule.  Returns a list where each
    item is a metadata item. """

    pattern = "metadata:\s?(.*?);"
    match = re.search(pattern, rulebuf)
    if match:
        metadata = [m.strip() for m in match.group(1).split(",")]
        return metadata
    return []

def parseRule(line):

    line = line.strip()
    m = rulePattern.match(line)
    if not m:
        return None

    rule = Rule()
    rule.enabled = not line.startswith("#")
    rule.body = m.group(3)
    rule.action = m.group(2)
    rule.sid = int(m.group(4))

    m = msgPattern.search(line)
    if m:
        rule.msg = m.group(1)
    else:
        print("ERROR: Rule msg not found: %s" % (line))

    m = gidPattern.search(line)
    if m:
        rule.gid = int(m.group(1))

    rule.references = referencePattern.findall(line)

    # Parse the flowbits.  We record the flowbits this rule may toggle
    # in the flowbitsProvided rule paramater.  Flowbits that are
    # checked will be recorded in the flowbitsUsed rule parameter.
    flowbitMatch = flowbitPattern.findall(line)
    for fb in flowbitMatch:
        parts = [p.strip() for p in fb.split(",")]
        if len(parts) == 1:
            if parts[0] == "noalert":
                rule.noalert = True
        elif len(parts) == 2:
            if parts[0] in fbProvidedKeywords:
                rule.flowbitsProvided.append(parts[1])
            elif parts[0] in fbUsedKeywords:
                rule.flowbitsUsed.append(parts[1])
            else:
                print("WARNING: Unknown flowbit keyword: %s" % (parts[0]))
                
    metadata = parse_metadata(line)
    for m in metadata:
        # Extract policy information into its own field.
        if m.startswith("policy"):
            key, val = [s.strip() for s in string.split(m, " ", maxsplit=1)]
            if key == "policy":
                parts = [s.strip() for s in val.split(" ")]
                policy = parts[0]
                try:
                    action = parts[1]
                except:
                    action = "alert"
                rule.policies[policy] = action

    return rule

def buildRuleDb(files):
    """ Build a database of rules from a set of files.

    The files arguments is a dictionary of files keyed by filename.
    The filename also serves as the group name for each rule found in
    that file.

    The return value is a dict of rules keyed by a rule-id.  The
    rule-id is the tuple (gid, sid).
    """
    ruledb = {}
    for filename in files:
        if filename.endswith(".rules"):
            for line in StringIO(files[filename]):
                rule = parseRule(line)
                if rule:
                    rule.group = filename
                    ruledb[(rule.gid, rule.sid)] = rule
    return ruledb

def fix_flowbit_dependencies(rules):
    """ Fix up flowbit dependencies on the in-memory database of rules.

    This is done by generating a list of all the flowbits that are
    checked by enabled rules, then any rules that modify those
    flowbits will be enabled. """

    def __fix_flowbit_dependencies():
        flowbitsRequired = []
        n = 0

        # Put all required flowbits into a list.
        for rule in rules.values():
            if rule.enabled:
                for fb in rule.flowbitsUsed:
                    if fb not in flowbitsRequired:
                        flowbitsRequired.append(fb)

        # Make sure any rule that toggles flowbits in the required set
        # is enabled.
        for rule in rules.values():
            if not rule.enabled:
                for fb in rule.flowbitsProvided:
                    if fb in flowbitsRequired:
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
