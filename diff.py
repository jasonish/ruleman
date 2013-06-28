#! /usr/bin/env python

import sys
import io

import ruleman.fileset
import ruleman.rule

def compare(ruleset1, ruleset2):

    changelog = {
        "new-rules-active": [],
        "new-rules-inactive": [],
        "updated-rules-active": [],
        "updated-rules-inactive": [],
        "now-active-rules": [],
        "now-inactive-rules": [],
        "removed-rules": [],
        }

    for rule in ruleset2.itervalues():
        # First look for new rules.
        if rule.id not in ruleset1:
            if rule.enabled:
                changelog["new-rules-active"].append(rule)
            else:
                changelog["new-rules-inactive"].append(rule)
        else:
            # Look for changes to the rules.
            old = ruleset1[rule.id]

            # Look for rules that were modified, other than just
            # toggled from active/inactive.
            if old.raw != rule.raw:
                if rule.enabled:
                    changelog["updated-rules-active"].append(rule)
                else:
                    changelog["updated-rules-inactive"].append(rule)

            # Look for rules that were toggled.
            if not old.enabled and rule.enabled:
                changelog["now-active-rules"].append(rule)
            elif old.enabled and not rule.enabled:
                changelog["now-inactive-rules"].append(rule)

    # Final check for rules that have been removed.
    for rule_id in ruleset1:
        if rule_id not in ruleset2:
            changelog["removed-rules"].append(ruleset1[rule_id])

    return changelog

def load_ruleset(filename):
    files = ruleman.fileset.load(filename)
    rules = {}
    dupes = []
    for filename in [fn for fn in files if fn.endswith(".rules")]:
        for rule in ruleman.rule.parse_fp(io.BytesIO(files[filename])):
            rule.group = filename
            if rule.id in rules:
                dupes.append(rule)
            else:
                rules[rule.id] = rule
    return (files, rules, dupes)

def render_rule_list(prefix, rules):
    for rule in sorted(rules, key=lambda r: r.group):
        print("%s[%d:%d] %s" % (
                prefix, rule.gid, rule.sid, rule.msg))

def main(args=sys.argv[1:]):

    fileset0, rules0, dupes0 = load_ruleset(args[0])
    if dupes0:
        for dupe in dupes0:
            print("Warning: Found duplicate SID %s in %s." % (
                    dupe.id, args[0]))

    fileset1, rules1, dupes1 = load_ruleset(args[1])
    if dupes1:
        for dupe in dupes1:
            print("Warning: Found duplicate SID %s in %s." % (
                    dupe.id, args[1]))

    # Get the files that in fileset1 but not in fileset0 (new files).
    new_files = set(fileset1).difference(set(fileset0))
    
    # Get the files that are in fileset0 but not in fileset1 (files
    # removed).
    removed_files = set(fileset0).difference(set(fileset1))
    
    print("* Files added: %d" % (len(new_files)))
    for filename in sorted(new_files):
        print("  - %s" % (filename))
    print("* Files removed: %d" % (len(removed_files)))
    for filename in sorted(removed_files):
        print("  - %s" % (filename))

    changelog = compare(rules0, rules1)

    print("* New active rules: %d" % (len(changelog["new-rules-active"])))
    render_rule_list("  - ", changelog["new-rules-active"])

    print("* New inactive rules: %d" % (len(changelog["new-rules-inactive"])))
    render_rule_list("  - ", changelog["new-rules-inactive"])

    print("* Updated active rules: %d" % (
            len(changelog["updated-rules-active"])))
    render_rule_list("  - ", changelog["updated-rules-active"])

    print("* Updated inactive rules: %d" % (
            len(changelog["updated-rules-inactive"])))
    render_rule_list("  - ", changelog["updated-rules-inactive"])

    print("* Rules changed inactive -> active: %d" % (
            len(changelog["now-active-rules"])))
    render_rule_list("  - ", changelog["now-active-rules"])

    print("* Rules changed active-> inactive: %d" % (
            len(changelog["now-inactive-rules"])))
    render_rule_list("  - ", changelog["now-inactive-rules"])

    print("* Removed rules: %d" % (len(changelog["removed-rules"])))
    render_rule_list("  - ", changelog["removed-rules"])

if __name__ == "__main__":
    sys.exit(main())
