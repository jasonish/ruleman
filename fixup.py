#! /usr/bin/env python
#
# A script to fix up a Snort policy:
# - Resolve flowbit dependencies.

from __future__ import print_function

import sys
import os
import os.path
import io

import ruleman.fileset
import ruleman.rule
import ruleman.flowbit
import ruleman.snort

SNORT_PATH = "/opt/nsm/bin/snort"
SNORT_DYNAMIC_ENGINE = "/opt/nsm/lib/snort_dynamicengine/libsf_engine.so"

def main(args=sys.argv[1:]):

    snort = ruleman.snort.Snort(SNORT_PATH, SNORT_DYNAMIC_ENGINE)

    in_rules = args[0]
    if os.path.isdir(in_rules):
        print("Loading files from directory %s." % (in_rules))
        files = ruleman.fileset.fileset_from_directory(in_rules)
    elif os.path.isfile(in_rules):
        print("Loading files from archive %s." % (in_rules))
        files = ruleman.fileset.fileset_from_archive(in_rules)

    snort.path = "/bin/asdf"
    generated_rules = snort.generate_dynamic_rules("FC-14/x86-64", files)
    for filename in generated_rules:
        print(filename)

    for filename in generated_rules:
        rules0 = ruleman.rule.parse_fp(io.BytesIO(files[filename]))
        rules1 = ruleman.rule.parse_fp(io.BytesIO(generated_rules[filename]))
        if len(rules0) != len(rules1):
            print("Found %d rules in original %s; %d in new." % (
                    len(rules0), filename, len(rules1)))

    #return

    # Parse the rules.
    rules = {}
    enabled = 0
    for filename in [fn for fn in files if fn.endswith(".rules")]:
        for rule in ruleman.rule.parse_fp(io.BytesIO(files[filename])):
            if rule.id in rules:
                print("Duplicate rule %s." % (rule.id))
            rules[rule.id] = rule
            if rule.enabled:
                enabled += 1
    print("Loaded %d rules." % len(rules))
    print("  Enabled: %d" % enabled)

    print("Fix flowbit dependencies.")
    # Hmm.. Here we have the rules in a different format than the
    # flowbit resolver expects.
    enabled = ruleman.flowbit.resolve_dependencies({"rules": rules.values()})
    print("  Enabled %d rules." % (len(enabled)))

    enabled = 0
    with open("test.rules", "w") as output:
        for rule_id in rules:
            if rules[rule_id].enabled:
                enabled += 1
            print(rules[rule_id], file=output)
    print("Enabled: %d" % (enabled))


if __name__ == "__main__":
    sys.exit(main())
