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

import sys
import os
import getopt
import string
import tempfile
import shutil
import subprocess
import tarfile
import fnmatch
import copy
import re
import logging
import pickle
import time
from cStringIO import StringIO

from ruleman import fetch
from ruleman import rules
from ruleman import util
from ruleman import config
from ruleman import init
from ruleman import snort

from ruleman import _version
try:
    from _buildtime import __buildtime__
except:
    __buildtime__ = None

# Prefix to the precompiled SO rules.
soPrefix = "so_rules/precompiled"

# Configure logging.
if os.getenv("RULEMAN_DEBUG") in ["1", "yes", "YES"]:
    print >>sys.stderr, "Debug logging enabled."
    log_level = logging.DEBUG
else:
    log_level = logging.INFO
logging.basicConfig(level=log_level, format="%(message)s")

def setBasePolicy(policy, inline, rules):
    enabledCount = 0
    disabledCount = 0
    actionCount = 0
    for r in rules.values():
        if policy in r.policies:
            if not r.enabled:
                r.enabled = True
                enabledCount += 1
            if inline:
                if r.action != r.policies[policy]:
                    r.action = r.policies[policy]
                    actionCount += 1
        else:
            if r.enabled:
                r.enabled = False
                disabledCount += 1
    return (enabledCount, disabledCount, actionCount)

def toggleRules(ruledb, ruleIds, toggle):
    count = 0
    for r in ruleIds:
        gid, sid = r.split(":")
        key = (int(gid), int(sid))
        if ruledb[key].enabled != toggle:
            ruledb[key].enabled = toggle
            count += 1
    return count

def enableRuleXform(rule):
    if not rule.enabled:
        rule.enabled = True
        return True
    else:
        return False

def disableRuleXform(rule):
    if rule.enabled:
        rule.enabled = False
        return True
    else:
        return False

def xformRulesByGroup(rules, groups, xform):
    result = {}
    for r in rules.values():
        if util.multi_fnmatch(r.group, groups):
            if not r.group in result:
                result[r.group] = 0
            if xform(r):
                result[r.group] += 1
    return result

def exportProfile(profile, files, ruledb):

    print("Exporting profile %s." % (profile["name"]))

    # Make sure output directories exists.
    prefix = profile["prefix"]
    if not os.path.exists(prefix):
        print("  Creating directory %s." % (prefix))
        os.makedirs(prefix)
    for d in ["rules", "so_rules", "preproc_rules"]:
        dirname = "%s/%s" % (prefix, d)
        if not os.path.exists(dirname):
            print("  Creating directory %s." % (dirname))
            os.makedirs(dirname)

    if profile["policy"]:
        print("  Setting base policy of %s." % (profile["policy"]))
        (enabledCount, disabledCount, actionChangeCount) = setBasePolicy(
            profile["policy"], profile["inline"], ruledb)
        print("    %d rules enabled." % (enabledCount))
        print("    %d rules disabled." % (disabledCount))
        print("    %d rules action changes." % (actionChangeCount))

    print("  Disabling rules by group.")
    r = xformRulesByGroup(ruledb, profile["disable-groups"], disableRuleXform)
    for group in r:
        if r[group] > 0:
            print("    %d rules disabled in group %s." % (r[group], group))

    print("  Enabling rules by group.")
    r = xformRulesByGroup(ruledb, profile["enable-groups"], enableRuleXform)
    for group in r:
        if r[group] > 0:
            print("    %d rules enabled in group %s." % (r[group], group))

    print("  Disabling rules.")
    count = toggleRules(ruledb, profile["disable-rules"], False)
    print("    %d rules disabled." % (count))

    print("  Enabling rules.")
    count = toggleRules(ruledb, profile["enable-rules"], True)
    print("    %d rules enabled." % (count))

    print("  Converting rules to drop.")
    count = 0
    for ruleId in profile["drop-rules"]:
        gid, sid = map(int, ruleId.split(":"))
        if (gid, sid) in ruledb:
            rule = ruledb[(gid, sid)]
            if rule.action != "drop":
                rule.action = "drop"
                count += 1
    print("    %d rules modified to drop." % (count))

    print("  Fixing flowbit dependencies.")
    count = rules.fix_flowbit_dependencies(ruledb)
    print("    %d rules enabled." % (count))

    print("  Rewriting files.")
    for filename in files:
        if filename.endswith(".rules"):
            newContent = []
            for line in StringIO(files[filename]):
                line = line.strip()
                rule = rules.parseRule(line)
                if rule:
                    newContent.append(str(ruledb[(rule.gid, rule.sid)]))
                else:
                    newContent.append(line)
            newContent.append("\n")
            files[filename] = "\n".join(newContent)

    print("  Writing all (fused) rules to file %s/all.rules." % (prefix))
    print("  Writing basic rules to directory %s/rules." % (prefix))
    print("  Writing SO rule stubs to directory %s/so_rules." % (prefix))
    print("  Writing preproc rules to directory %s/preproc_rules." % (prefix))

    fusedOutput = open("%s/all.rules" % (prefix), "w")
    for filename in files:
        if filename.endswith(".rules"):
            fusedOutput.write("# Fused from file %s.\n" % (filename))
            fusedOutput.write(files[filename])
            fusedOutput.write("\n")
            basename = os.path.basename(filename)
            if filename.startswith("rules/"):
                open("%s/rules/%s" % (prefix, basename), "w").write(
                    files[filename])
            elif filename.startswith("so_rules/"):
                open("%s/so_rules/%s" % (prefix, basename), "w").write(
                    files[filename])
            elif filename.startswith("preproc_rules/"):
                open("%s/preproc_rules/%s" % (prefix, basename), "w").write(
                    files[filename])
        elif filename.startswith("rules/"):
            # For convenience write out the non-rules files in rules/
            # as found in ET rulesets.
            dirname = "%s/%s" % (prefix, os.path.dirname(filename))
            if not os.path.exists(dirname):
                os.makedirs(dirname)
            open("%s/%s" % (prefix, filename), "w").write(files[filename])
    fusedOutput.close()

    # Write out SO lib files.
    if "os-type" in profile and profile["os-type"]:
        soLibDir = "%s/snort_dynamicrules" % (prefix)
        soType = profile["os-type"]

        print("  Writing SO library files to %s." % (soLibDir))
        if os.path.exists(soLibDir):
            shutil.rmtree(soLibDir)
        os.mkdir(soLibDir)
        for filename in files:
            if filename.startswith("%s/%s" % (soPrefix, soType)):
                dest = "%s/%s" % (soLibDir, os.path.basename(filename))

                # If we unlink the existing SO lib file first, the running
                # Snort won't complain about it.
                if os.path.exists(dest):
                    os.unlink(dest)

                open(dest, "w").write(files[filename])

    # Write out a sid-msg.map file.
    sidMsgMapFilename = "%s/sid-msg.map" % (prefix)
    print("  Writing %s." % (sidMsgMapFilename))
    with open(sidMsgMapFilename, "w") as out:
        out.write("# Generated by ruleman at %s.\n" % (
                time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime())))
        for rule in sorted(ruledb.values(), key=lambda rule: rule.sid):
            if rule.gid in [1, 3]:
                parts = [str(rule.sid), rule.msg]
                parts += rule.references
                out.write("%s\n" % " || ".join(parts))

    print("")
    stats = {
        "enabled": 0,
        "disabled": 0,
        }
    for r in ruledb.values():
        if r.enabled:
            stats["enabled"] += 1
        else:
            stats["disabled"] += 1
    print("  Stats:")
    print("    %d total rules." % (stats["enabled"] + stats["disabled"]))
    print("    %d rules enabled." % (stats["enabled"]))
    print("    %d rules disabled." % (stats["disabled"]))

def load_ruleset_files(ctx):

    latest_filename = "%s/%s/latest" % (config.RULESET_DATA_DIR, ctx["name"])
    files = util.tar_to_dict(latest_filename, ctx["ignore-files"])

    return files

def cmd_export(args):
    """ Entry point for the "export" command.

    If no args are present then all enabled profiles will be exported,
    otherwise only the named profiles will be exported.
    """

    config.init()

    rulesets = config.get_rulesets().values()
    if not rulesets:
        print("Nothing to do.  No rulesets enabled.")
        return 1

    profiles = config.get_profiles().values()
    if not profiles:
        print("Nothing to do.  No profiles enabled.")
        return 1

    db = {"files": {},
          "rules": {},
          }

    # Load all the files from the rulesets.
    for r in [ruleset for ruleset in rulesets if ruleset["enabled"]]:
        logging.info("Loading files for ruleset %s" % (r["name"]))
        db["files"][r["name"]] = load_ruleset_files(r)
        logging.info("  Loaded %d files" % (len(db["files"][r["name"]])))

    for ruleset in db["files"]:
        print("Loading rules from ruleset %s." % (ruleset))
        db["rules"][ruleset] = rules.buildRuleDb(db["files"][ruleset])
        print("  %d rules loaded." % len(db["rules"][ruleset]))

    for profile in profiles:
        if not args or profile["name"] in args:
            files = {}
            for ruleset in db["files"]:
                if ruleset in profile["rulesets"]:
                    files.update(copy.deepcopy(db["files"][ruleset]))
            ruledb = {}
            for ruleset in db["files"]:
                if ruleset in profile["rulesets"]:
                    ruledb.update(copy.deepcopy(db["rules"][ruleset]))
            exportProfile(profile, files, ruledb)

def cmd_update(args):
    """ The update command checks all rulesets that are in use by a
    profile for a new version.  Profiles that use a ruleset that was
    updated will be re-exported. """

    config.init()

    rulesets = []
    profiles = config.get_profiles()
    for profile in profiles.values():
        if profile["enabled"]:
            for ruleset in profile["rulesets"]:
                if ruleset not in rulesets:
                    rulesets.append(ruleset)

    fetched = []
    for ruleset in rulesets:
        ruleset_ctx = config.get_ruleset_ctx(ruleset)
        if fetch.fetch_ruleset(ruleset_ctx):
            fetched.append(ruleset)

    for profile in profiles.values():
        if len(set.intersection(set(profile["rulesets"]), set(fetched))):
            cmd_export([profile["name"]])

def cmd_search(args):

    usage = """
ruleman search [options] <regex>

    Options:
        -h,--help          This help.
        --brief            Just print the rule msg instead of the complete
                           rule.
        -i,--ignore-case   Ignore case.
"""

    brief = False
    reFlags = 0

    try:
        opts, args = getopt.getopt(
            args, "hik", ["brief", "help", "ignore-case"])
    except getopt.GetoptError, err:
        print("Invalid command line: %s" % (err))
        return 1
    for o, a in opts:
        if o == "--brief":
            brief = True
        elif o in ["-i", "--ignore-case"]:
            reFlags |= re.IGNORECASE

    if not args:
        print(usage)
        return 1

    try:
        pattern = re.compile(args[0], reFlags)
    except re.error, err:
        print "regex error: %s" % (err)
        return 1
    
    ruledb = {}
    rulesets = config.get_rulesets().values()
    for r in rulesets:
        files = load_ruleset_files(r)
        ruledb[r["name"]] = rules.buildRuleDb(files)
        print("Loaded %d rules from ruleset %s." % (
                len(ruledb[r["name"]]), r["name"]))

    count = 0
    for ruleset in ruledb:
        for rule in ruledb[ruleset].values():
            m = pattern.search(str(rule))
            if m:
                count += 1
                if brief:
                    if rule.enabled:
                        enabled = ""
                    else:
                        enabled = "# "
                    output = "[%d:%d] %s%s" % (
                        rule.gid, rule.sid, enabled, rule.msg)
                else:
                    output = str(rule)
                print("%s:%s: %s" % (
                        ruleset, rule.group, output))
    print("Matches found: %d" % (count))

def cmd_list_rulesets(args):

    rulesets = config.get_rulesets()
    for ruleset in rulesets.values():
        print("%s (enabled: %s)" % (
                ruleset["name"], "yes" if ruleset["enabled"] else "no"))

    return 0

def cmd_list_os_types(args):

    files = {}
    rulesets = config.get_rulesets()
    for ruleset in rulesets.values():
        logging.info("Loading ruleset %s" % (ruleset["name"]))
        files[ruleset["name"]] = load_ruleset_files(ruleset)

    os_types = set()
    for ruleset in files:
        for filename in files[ruleset]:
            m = re.match("so_rules/precompiled/(.*?/.*?)/.*", filename)
            if m:
                os_types.add(m.group(1))

    for ot in os_types:
        print("%s" % (ot))

def command_fetch(args):
    config.init()
    fetch.main(args)

def cmd_extract_ruleset(args):
    
    usage = """
ruleman extract <ruleset> [filenames...]

Extracts <ruleset> into the current directory. If filenames are
provided only those files will be extracted.
"""

    if len(args) < 1:
        print >>sys.stderr, usage
        return 1
    rulesetname = args[0]

    config.init()

    # Each filename file is broken down into its path parts so
    # matching, so we can match against a directory.
    filenames = [[b for b in a.split("/") if b] for a in args[1:]]

    rulesets = config.get_rulesets()
    if rulesetname not in rulesets:
        print >>sys.stderr, "Ruleset %s does not exist." % (rulesetname)
        return 1

    # Inner function to test is a filename matches the user provided
    # list of filenames.
    def is_match(filename):
        if not filenames:
            return True
        for dst_filename in filenames:
            if dst_filename == filename.split("/")[0:len(dst_filename)]:
                return True
        return False

    file_count = 0
    files = load_ruleset_files(rulesets[rulesetname])
    for filename in [filename for filename in files if is_match(filename)]:
            print("Extracting %s" % (filename))
            util.write_file_mkdir(filename, files[filename])
            file_count += 1
    print("%s files extracted." % (
            "No" if file_count == 0 else str(file_count)))

commands = {
    "fetch": command_fetch,
    "export": cmd_export,
    "update": cmd_update,
    "search": cmd_search,
    "init": init.init,
    "list-rulesets": cmd_list_rulesets,
    "list-os-types": cmd_list_os_types,
    "extract": cmd_extract_ruleset,
}

def usage(output):
    output.write("""
ruleman [options] <command>

    Options:
        -h, --help          This help.
        -V                  Print the version.

    Commands:
        fetch               Fetch (download) rulesets.
        export              Export policies.
        update              Fetch and export.
        search              Search rules.
        init                Initialize a ruleman data directory.

""")

def print_version():
    print("version %s" % (_version.__version__))
    if __buildtime__:
        print("built: %s" % (__buildtime__))

def main(args):

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hV", ["help"])
    except getopt.GetoptError, err:
        print("ERROR: %s" % err)
        return 1
    for o, a in opts:
        if o in ["-h", "--help"]:
            usage(sys.stdout)
            return 0
        elif o == "-V":
            print_version()
            return 0

    if not args:
        usage(sys.stderr)
        return 1
    elif args[0] in commands:
        try:
            return commands[args[0]](args[1:])
        except config.NoConfigurationFileException:
            print >>sys.stderr, "ERROR: Configuration file not found." \
                " Consider running \"ruleman init\"."
            return 1
    else:
        print >>sys.stderr, "\nUnknown command: %s" % (args[0])
        usage(sys.stderr)
        return 1

    # Not reached.
