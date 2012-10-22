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

from ruleman import core
from ruleman import util

def usage(fileobj=sys.stderr):
    print("USAGE: %s <old> <new>" % sys.argv[0], file=fileobj)

def get_modified_rules(old_rules, new_rules):
    """ Return a list of rules that have been modified. """
    rules = []
    for key in new_rules:
        if key in old_rules and str(old_rules[key]) != str(new_rules[key]):
            rules.append(key)
    return rules

def get_enabled_rules(old_rules, new_rules):
    """ Return a list of rules that have gone from disabled to
    enabled. """
    rules = []
    for key in new_rules:
        if key in old_rules:
            if not old_rules[key].enabled and new_rules[key].enabled:
                rules.append(key)
    return rules

def get_disabled_rules(old_rules, new_rules):
    """ Return a list of rules that have gone from enabled to
    disabled. """
    rules = []
    for key in new_rules:
        if key in old_rules:
            if old_rules[key].enabled and not new_rules[key].enabled:
                rules.append(key)
    return rules

def main(args, fileobj=sys.stdout):
    try:
        old_file = args[0]
        new_file = args[1]
    except:
        usage()
        return 1

    old_files = util.archive_to_dict(old_file)
    new_files = util.archive_to_dict(new_file)

    old_rules = core.load_ruleset_rules({"files": old_files})
    new_rules = core.load_ruleset_rules({"files": new_files})

    # Find new files.
    files = set(new_files).difference(set(old_files))
    print("\nNew files: (%d)" % len(files), file=fileobj)
    for f in files: 
        print("- %s" % f, file=fileobj)

    # Find removed files.
    files = set(old_files).difference(set(new_files))
    print("\nRemoved files: (%d)" % len(files), file=fileobj)
    for f in files: 
        print("- %s" % f, file=fileobj)

    # New rules.
    rules = set(new_rules).difference(set(old_rules))
    print("\nNew rules: (%d)" % len(rules), file=fileobj)
    for gid, sid in rules:
        print("- %d:%d: %s" % (gid, sid, new_rules[(gid, sid)].msg),
              file=fileobj)

    # Deleted rules.
    rules = set(old_rules).difference(set(new_rules))
    print("\nDeleted rules: (%d)" % len(rules), file=fileobj)
    for gid, sid in rules:
        print("- %d:%d: %s" % (gid, sid, old_rules[(gid, sid)].msg), 
              file=fileobj)

    # Modified rules.
    rules = get_modified_rules(old_rules, new_rules)
    print("\nModified rules: (%d)" % len(rules), file=fileobj)
    for gid, sid in rules:
        print("- %d:%d: %s" % (gid, sid, new_rules[(gid, sid)].msg),
              file=fileobj)

    # Rules now enabled.
    rules = get_enabled_rules(old_rules, new_rules)
    print("\nRules now enabled: (%d)" % len(rules), file=fileobj)
    for gid, sid in rules:
        print("- %d:%d: %s" % (gid, sid, new_rules[(gid, sid)].msg), 
              file=fileobj)

    # Rules now disabled.
    rules = get_disabled_rules(old_rules, new_rules)
    print("\nRules now disabled: (%d)" % len(rules), file=fileobj)
    for gid, sid in rules:
        print("- %d:%d: %s" % (gid, sid, new_rules[(gid, sid)].msg), 
              file=fileobj)

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
