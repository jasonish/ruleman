#! /usr/bin/env python
#
# This Python script will generate a report describing the changes
# between one ruleset (the old one) and another ruleset (the new one).

import sys
import tarfile
import difflib
from cStringIO import StringIO
import re

def usage(fileobj=sys.stderr):
    print >>fileobj, ("USAGE: %s <old> <new>" % sys.argv[0])

def getRuleMsg(rule):
    """ Return the rule msg (description). """
    m = re.search("msg:\s?\"(.*?)\";", rule)
    if m:
        return m.group(1)
    return rule

rulePattern = re.compile("^#?\s?alert.*sid:\s?(\d+)")
gidPattern = re.compile("gid:\s?(\d+)")

def loadRules(ruledb, buf):
    """ Load the rules in buf into the dict ruledb keyed by the
    'gid:sid'.

    Just some simple regex matching, not that fastest rule parsing but
    works. """
    inio = StringIO(buf)
    for line in inio:
        line = line.strip()
        m = rulePattern.match(line)
        if m:
            sid = m.group(1)
            m = gidPattern.match(line)
            if m:
                gid = m.group(1)
            else:
                gid = "1"
            sidgid = "%s:%s" % (gid, sid)
            ruledb[sidgid] = line

def tarToDict(filename):
    """ Convert a tarfile into a dict of file contents keyed by
    filenames. """
    files = {}
    tf = tarfile.open(filename)
    for member in tf:
        if member.isreg():
            files[member.name] = tf.extractfile(member).read()
    tf.close()
    return files

def getModifiedRules(oldRuleDb, newRuleDb):
    """ Return a list of rules that have been modified. """
    rules = []
    for gidsid in newRuleDb:
        if gidsid in oldRuleDb and oldRuleDb[gidsid] != newRuleDb[gidsid]:
            rules.append(gidsid)
    return rules

def getEnabledRules(oldRuleDb, newRuleDb):
    """ Return a list of rules that have gone from disabled to
    enabled. """
    rules = []
    for gidsid in newRuleDb:
        if gidsid in oldRuleDb:
            if oldRuleDb[gidsid].startswith("#") and \
                    not newRuleDb[gidsid].startswith("#"):
                rules.append(gidsid)
    return rules

def getDisabledRules(oldRuleDb, newRuleDb):
    """ Return a list of rules that have gone from enabled to
    disabled. """
    rules = []
    for gidsid in newRuleDb:
        if gidsid in oldRuleDb:
            if not oldRuleDb[gidsid].startswith("#") and \
                    newRuleDb[gidsid].startswith("#"):
                rules.append(gidsid)
    return rules

def main(args, fileobj=sys.stdout):
    try:
        oldFile = args[0]
        newFile = args[1]
    except:
        usage()
        return 1

    oldRuleset = tarToDict(oldFile)
    newRuleset = tarToDict(newFile)
    oldRuleDb = {}
    newRuleDb = {}
    for f in oldRuleset:
        if f.endswith(".rules"):
            loadRules(oldRuleDb, oldRuleset[f])
    print >>fileobj, ("Loaded %d rules from old ruleset." % len(oldRuleDb))
    for f in newRuleset:
        if f.endswith(".rules"):
            loadRules(newRuleDb, newRuleset[f])
    print >>fileobj, ("Loaded %d rules from new ruleset." % len(newRuleDb))

    # Find new files.
    files = set(newRuleset).difference(set(oldRuleset))
    print >>fileobj, ("\nNew files: (%d)" % len(files))
    for f in files: 
        print >>fileobj, ("- %s" % f)

    # Find removed files.
    files = set(oldRuleset).difference(set(newRuleset))
    print >>fileobj, ("\nRemoved files: (%d)" % len(files))
    for f in files: 
        print >>fileobj, ("- %s" % f)

    # New rules.
    rules = set(newRuleDb).difference(set(oldRuleDb))
    print >>fileobj, ("\nNew rules: (%d)" % len(rules))
    for gidsid in rules:
        print >>fileobj, ("- %s: %s" % (gidsid, getRuleMsg(newRuleDb[gidsid])))

    # Deleted rules.
    rules = set(oldRuleDb).difference(set(newRuleDb))
    print >>fileobj, ("\nDeleted rules: (%d)" % len(rules))
    for gidsid in rules:
        print >>fileobj, ("- %s: %s" % (gidsid, getRuleMsg(oldRuleDb[gidsid])))

    # Modified rules.
    rules = getModifiedRules(oldRuleDb, newRuleDb)
    print >>fileobj, ("\nModified rules: (%d)" % len(rules))
    for gidsid in rules:
        print >>fileobj, ("- %s: %s" % (gidsid, getRuleMsg(newRuleDb[gidsid])))

    # Rules now enabled.
    rules = getEnabledRules(oldRuleDb, newRuleDb)
    print >>fileobj, ("\nRules now enabled: (%d)" % len(rules))
    for gidsid in rules:
        print >>fileobj, ("- %s: %s" % (gidsid, getRuleMsg(newRuleDb[gidsid])))

    # Rules now disabled.
    rules = getDisabledRules(oldRuleDb, newRuleDb)
    print >>fileobj, ("\nRules now disabled: (%d)" % len(rules))
    for gidsid in rules:
        print >>fileobj, ("- %s: %s" % (gidsid, getRuleMsg(newRuleDb[gidsid])))

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
