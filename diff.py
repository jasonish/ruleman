#! /usr/bin/env python

import sys
import io

import ruleman.fileset
import ruleman.rule

def render_rule_list(prefix, rules):
    for rule in sorted(rules, key=lambda r: r.group):
        print("%s[%d:%d] %s" % (
                prefix, rule.gid, rule.sid, rule.msg))

def main(args=sys.argv[1:]):
    
    fileset0 = ruleman.fileset.load(args[0])
    fileset1 = ruleman.fileset.load(args[1])

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

    rules0 = {}
    for filename in fileset0:
        if filename.endswith(".rules"):
            rules = ruleman.rule.parse_fp(io.BytesIO(fileset0[filename]))
            for rule in rules:
                if rule.id in rules0:
                    print("WARNING: Duplicate rule ID found: %s" % (rule.id))
                else:
                    rules0[rule.id] = rule

    rules1 = {}
    for filename in fileset1:
        if filename.endswith(".rules"):
            rules = ruleman.rule.parse_fp(io.BytesIO(fileset1[filename]))
            for rule in rules:
                rule.group = filename
                if rule.id in rules1:
                    print("WARNING: Duplicate rule ID found: %s" % (rule.id))
                else:
                    rules1[rule.id] = rule

    # Find the new rules.
    new_rules_enabled = []
    new_rules_disabled = []
    updated_enabled_rules = []
    updated_disabled_rules = []
    now_active_rules = []
    now_inactive_rules = []
    for rule_id in rules1:
        if rule_id not in rules0:
            rule = rules1[rule_id]
            if rule.enabled:
                new_rules_enabled.append(rule)
            else:
                new_rules_disabled.append(rule)
        else:
            rule0 = rules0[rule_id]
            rule1 = rules1[rule_id]

            # Record which rules have been turned active.
            if not rule0.enabled and rule1.enabled:
                now_active_rules.append(rule1)

            # Record rules that are no longer active.
            if rule0.enabled and not rule1.enabled:
                now_inactive_rules.append(rule)

            if rule0.raw != rule1.raw:
                if rule1.enabled:
                    updated_enabled_rules.append(rule1)
                else:
                    updated_disabled_rules.append(rule1)

    print("* New active rules: %d" % (len(new_rules_enabled)))
    render_rule_list("  - ", new_rules_enabled)

    print("* New inactive rules: %d" % (len(new_rules_disabled)))
    render_rule_list("  - ", new_rules_disabled)

    print("* Updated active rules: %d" % (len(updated_enabled_rules)))
    render_rule_list("  - ", updated_enabled_rules)

    print("* Updated inactive rules: %d" % (len(updated_disabled_rules)))
    render_rule_list("  - ", updated_disabled_rules)

    print("* Rules changed inactive -> active: %d" % (len(now_active_rules)))
    render_rule_list("  - ", now_active_rules)

    print("* Rules changed active-> inactive: %d" % (len(now_inactive_rules)))
    render_rule_list("  - ", now_inactive_rules)

if __name__ == "__main__":
    sys.exit(main())
