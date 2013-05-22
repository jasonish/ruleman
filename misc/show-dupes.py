# Show duplicate and files in 2 different rule sets.

from __future__ import print_function

import sys
import os
import logging

# This is so we can run out of the source directory, no matter what
# the users current directory is.
sys.path.insert(
    0, os.path.dirname(os.path.abspath(sys.argv[0])) + "/lib")

import ruleman.util
import ruleman.rules

def main():

    try:
        ruleset1_filename = sys.argv[1]
        ruleset2_filename = sys.argv[2]
    except:
        print("USAGE: %s <ruleset1.tar.gz> <ruleset2.tar.gz>" % (
                sys.argv[0]), file=sys.stderr)
        return 1

    ruleset1 = {}
    ruleset2 = {}

    print("Loading ruleset1 from %s." % (sys.argv[1]))
    ruleset1["files"] = ruleman.util.archive_to_dict(sys.argv[1])

    print("Loading ruleset2 from %s." % (sys.argv[2]))
    ruleset2["files"] = ruleman.util.archive_to_dict(sys.argv[2])

    # Find duplicate files.
    for filename in ruleset2["files"]:
        if filename in ruleset1["files"]:
            print("Duplicate file: %s" % (filename))

    # Find duplicate rule IDs.
    ruleset1["rules"] = ruleman.rules.build_rule_map(ruleset1["files"])
    ruleset2["rules"] = ruleman.rules.build_rule_map(ruleset2["files"])
    for rule_id in ruleset2["rules"]:
        if rule_id in ruleset1["rules"]:
            print("Duplicate rule: %s" % (str(rule_id)))
            print(" %s" % (ruleset1["rules"][rule_id].brief()))
            print(" %s" % (ruleset2["rules"][rule_id].brief()))

    return 0

sys.exit(main())
