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
import getopt
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
try:
    import configparser
except:
    import ConfigParser as configparser
import atexit
import io

from ruleman import fetch
from ruleman import rules
from ruleman import util
from ruleman import config
from ruleman import snort
from ruleman import core
from ruleman import rulematcher

from ruleman import _version
try:
    from _buildtime import __buildtime__
except:
    __buildtime__ = None

logging.basicConfig(level=logging.INFO, format="%(message)s")

logger = logging.getLogger("ruleman.main")

class InitCommand(object):

    skel_files = (
        "disable-rules",
        "enable-rules",
        "drop-rules",
        "ruleman.conf",
        )

    def __init__(self, args):
        self.args = args
        self.target = "."
        self.skel_dir = os.path.abspath(os.path.dirname(__file__)) + "/data"

    def init_args(self):
        if self.args:
            self.target = self.args[0]

    def get_skeleton_files(self):
        return ["%s/%s" % (self.skel_dir, f) for f in self.skel_files]

    def run(self):
        if not os.path.exists(self.target):
            os.mkdir(self.target, mode=0o755)
            print("created directory %s" % (self.target))
        skel_files = self.get_skeleton_files()
        for src_file in skel_files:
            dst_file = "%s/%s" % (self.target, os.path.basename(src_file))
            if not os.path.exists(dst_file):
                print("creating %s" % (dst_file))
                shutil.copyfile(src_file, dst_file)
            else:
                print("warning: "
                      "%s already exists and will not be overwritten" % (
                        dst_file))

class FetchCommand(object):

    def __init__(self, args):
        self.args = args
        config.init()

    def run(self):
        fetch.main(self.args)

class SearchCommand(object):

    def __init__(self, args):
        self.args = args
        config.init()

        # By default the brief version of the rule will be displayed.
        self.brief = True

    def usage(self, fileobj=sys.stderr):
        usage = """
usage: ruleman search [-f] [-i] <regex> [regex ...]

Search for rules (case insensitve) using a provided regular
expression.  If multiple regular expressions are provided they must
all match.

Options:

    -f        display the full rule instead of a brief version
    -i        make the search case sensitive
"""
        print(usage, file=fileobj)

    def run(self):

        opt_ignorecase = True
        
        try:
            opts, args = getopt.getopt(self.args, "fhi")
        except getopt.GetoptError as err:
            print("error:", err, file=sys.stderr)
            self.usage()
            return False
        for o, a in opts:
            if o == "-f":
                self.brief = False
            elif o == "-h":
                self.usage(sys.stdout)
                return 0
            elif o == "-i":
                opt_ignorecase = False
        
        re_flags = 0
        if opt_ignorecase:
            re_flags |= re.IGNORECASE

        if len(args) < 1:
            self.usage()
            return 1

        self.patterns = []
        for a in args:
            try:
                self.patterns.append(re.compile(a, re_flags))
            except Exception as err:
                print("failed to compile regular expression: %s: %s" % (
                        a, err), file=sys.stderr)
                return 1

        self.search()
        
        return 0

    def search(self):

        rulesets = config.get_rulesets()
        for ruleset in rulesets.itervalues():
            core.load_ruleset_files(ruleset)
            core.load_ruleset_rules(ruleset)
            logger.info("Loaded ruleset %s: %d files; %d rules" % (
                    ruleset["name"], len(ruleset["files"]), 
                    len(ruleset["rules"])))

        match_count = 0
        for ruleset in rulesets.itervalues():
            for rule in ruleset["rules"].itervalues():
                if self.is_match(rule):
                    match_count += 1
                    self.print_rule(ruleset["name"], rule)

        print("Found %d rules." % (match_count))

    def is_match(self, rule):
        for pattern in self.patterns:
            if not pattern.search(str(rule)):
                return False
        return True

    def print_rule(self, ruleset, rule):
        if self.brief:
            print("%s:%s: [%d:%d] %s%s" % (
                    ruleset, 
                    rule.group, 
                    rule.gid,
                    rule.sid,
                    "" if rule.enabled else "# ",
                    rule.msg))
        else:
            print("%s:%s: %s" % (ruleset, rule.group, str(rule)))

class DeployCommand(object):

    def __init__(self, args):
        self.args = args
        config.init()

    def load_rules(self):
        self.files = {}
        for ruleset in self.profile["rulesets"]:
            ruleset = config.get_ruleset(ruleset)
            files = core.load_ruleset_files(ruleset)
            for filename in files:
                if filename not in self.files:
                    self.files[filename] = files[filename]
                else:
                    logger.warn(
                        "Ignoring file %s from ruleset %s: already present" % (
                            filename, ruleset))
        self.rule_map = rules.build_rule_map(self.files)
        logger.info("Loaded %d rules from rulesets %s" % (
                len(self.rule_map),
                ", ".join(self.profile["rulesets"])))

    def set_dynamic_rule_link(self):
        """ If the profile has an os-type parameter, attempt to link
        the dynamic rules into a predictable location. """
        os_type = self.profile["os-type"]
        if os_type:
            logger.debug("Looking for %s dyanmic rules" % (os_type))
            dynamicrules_dir = snort._find_dynamic_rules(
                self.prefix, os_type)
            logger.debug("Found %s" % (dynamicrules_dir))
            if dynamicrules_dir:
                link_src = dynamicrules_dir.replace(self.prefix, "")
                if link_src[0] == "/":
                    link_src = link_src[1:]
                link_dst = "%s/dynamicrules" % (self.prefix)
                logger.info("Linking %s to %s/%s" % (
                        link_dst, self.prefix, link_src))
                os.symlink(link_src, link_dst)

    def write_sid_msg_map(self):
        """ Write out a sid-msg.map file to
        <profile>/etc/sid-msg.map. """
        sid_msg_map_file = util.createfile("%s/etc/sid-msg.map" % (
                self.prefix), mkdirs=True)
        logger.info("Writing sid-msg.map to %s" % (sid_msg_map_file.name))
        print("# Generated by ruleman", file=sid_msg_map_file)
        core.build_sid_msg_map(self.rule_map, sid_msg_map_file)
        sid_msg_map_file.close()

    def export(self):
        if os.path.exists(self.prefix):
            logger.info("Cleaning output directory %s" % (self.prefix))
            shutil.rmtree(self.prefix)
        os.makedirs(self.prefix)

        self.merged = util.createfile(
            "%s/merged.rules" % (self.prefix), mkdirs=True)

        for filename in self.files:
            dst = util.createfile("%s/%s" % (self.prefix, filename), 
                                  mkdirs=True)
            if filename.endswith(".rules"):
                self.export_rulefile(filename, dst)
            else:
                dst.write(self.files[filename])
            dst.close()

        self.merged.close()

        self.write_sid_msg_map()
        self.set_dynamic_rule_link()

    def export_rulefile(self, filename, dst):
        print("# Merged from %s by ruleman" % (filename), file=self.merged)
        for line in io.BytesIO(self.files[filename]):
            rule = rules.parse_rule(line)
            if rule:
                print(self.rule_map[rule.key], file=dst)
                print(self.rule_map[rule.key], file=self.merged)
            else:
                print(line.rstrip(), file=dst)
                print(line.rstrip(), file=self.merged)

        # Add a blank lines between merged files.
        print("", file=self.merged)

    def fix_flowbits(self):
        n = core.fix_flowbit_dependencies(self.rule_map)
        if n:
            logger.info("Enabled %d rules to satisfy flowbit dependencies" % n)

    def enabled_rule_count(self):
        count = 0
        for rule in self.rule_map.itervalues():
            if rule.enabled:
                count += 1
        return count

    def set_policy(self):
        policy = self.profile["policy"]
        inline = self.profile["inline"]
        if policy:
            logger.info("Initializing profile to policy %s, inline=%s" % (
                    policy, str(inline).lower()))
            enabled, disabled, dropped = core.set_policy(
                self.rule_map, policy, inline=inline)
            logger.info(" %d rules enabled" % (enabled))
            logger.info(" %d rules disabled" % (disabled))
            if inline:
                logger.info(" %d rules set to drop" % (dropped))

    def apply_disable_rules(self):
        count = 0
        for actionfile in self.profile["disable-rules"]:
            logger.info("Applying disable definitions in %s" % (actionfile))
            matchers = rulematcher.load_collection_from_file(actionfile)
            count = core.disable_rules(self.rule_map, matchers)
            logger.info(" Disabled %d rules" % (count))

    def apply_enable_rules(self):
        count = 0
        for actionfile in self.profile["enable-rules"]:
            logger.info("Applying enable definitions in %s" % (actionfile))
            matchers = rulematcher.load_collection_from_file(actionfile)
            count = core.enable_rules(self.rule_map, matchers)
            logger.info(" Enabled %d rules" % (count))

    def apply_drop_rules(self):
        count = 0
        for actionfile in self.profile["drop-rules"]:
            logger.info("Applying drop definitions in %s" % (actionfile))
            matchers = rulematcher.load_collection_from_file(actionfile)
            count = core.drop_rules(self.rule_map, matchers)
            logger.info(" Set %d rules to drop" % (count))

    def run(self):
        self.profile = config.get_profile()
        self.prefix = "./profiles/default"
        self.load_rules()
        self.set_policy()
        self.apply_disable_rules()
        self.apply_enable_rules()
        self.apply_drop_rules()
        self.fix_flowbits()
        self.export()
        logger.info("Profile deployed to %s" % (self.prefix))

class ExportRulesetCommand(object):

    def __init__(self, args):
        self.args = args
        config.init()

        # By default we export to the current directory.
        self.output = "."

        # Don't print filenames by default.
        self.verbose = False

    def usage(self, file=sys.stderr):
        usage = """
usage: ruleman export-ruleset [-o dir] <ruleset> [filenames...]

Extracts <ruleset> into the current directory. If filenames are
provided only those files will be extracted.

Options:

    -o <dir>       extract ruleset to <dir>
    -v             be more verbose (print filenames)
"""
        print(usage, file=file)

    def init_args(self):
        try:
            opts, args = getopt.getopt(self.args, "o:v")
        except getopt.GetoptError as err:
            print("error: %s" % (err))
            return False
        for o, a in opts:
            if o == "-o":
                self.output = a
            elif o == "-v":
                self.verbose = True

        if len(args) < 1:
            return False
        try:
            self.ruleset = config.get_ruleset(args[0])
        except config.NoRulesetError as err:
            print("error: ruleset %s does not exist." % err)
            return False
        self.filenames = [f.split("/") for f in args[1:]]
        return True

    def is_match(self, filename):
        if not self.filenames:
            return True
        for f in self.filenames:
            if filename.split("/")[0:len(f)] == f:
                return True
        return False

    def run(self):
        if not self.init_args():
            self.usage()
            return 1
        files = core.load_ruleset_files(self.ruleset)
        count = 0
        for filename in sorted(files.keys()):
            if not self.is_match(filename):
                continue
            if self.verbose:
                print("exporting %s to %s" % (filename, self.output))
            target_filename = "%s/%s" % (self.output, filename)
            target = util.createfile(target_filename, mkdirs=True)
            target.write(files[filename])
            target.close()
            count += 1
        print("Exported %d files to %s." % (count, self.output))

class DumpDynamicRulesCommand(object):
    """ User command to dump dynamic rules to a directory. """

    def __init__(self, args):
        self.args = args
        config.init()

    def usage(self, fileobj=sys.stderr):
        usage = """
usage: ruleman dump-dynamic-rules <ruleset> <output-directory>
"""
        print(usage, file=fileobj)

    def init_args(self):
        if len(self.args) < 2:
            self.usage()
            return False
        self.ruleset_name = self.args[0]
        self.output = self.args[1]
        return True

    def run(self):
        if not self.init_args():
            return 1
        try:
            snort_config = config.get_section("snort")
        except configparser.NoSectionError:
            logger.error(
                "Snort not configured.  Unabled to dump dynamic rules.")
            return 1;
        ruleset_filename = "./rulesets/%s/ruleset.tar.gz" % (self.ruleset_name)
        if not os.path.exists(ruleset_filename):
            logger.error("Error: Ruleset %s has no files." % (
                    self.ruleset_name))
        if not os.path.exists(self.output):
            logger.info("Creating directory %s." % (self.output))
            os.makedirs(self.output)
        if not snort.dump_stubs(
            ruleset_filename, snort_config["path"], 
            snort_config["dynamic-engine"], snort_config["os-type"],
            dest_dir=self.output, verbose=True):
            logger.error("Failed to dump dynamic rule stubs.")
            return 1
        logger.info("Dynamic rule stubs dumped to %s." % (self.output))

class UpdateCommand(object):

    def __init__(self, args):
        self.args = args
        config.init()

    def run(self):
        FetchCommand([]).run()
        DeployCommand([]).run()

def usage(file=sys.stderr):
    print("""
usage: ruleman [options] <command>

Options:
    -h, --help          this help
    -v                  verbose (debug) output
    -V                  print the version

Commands:
    init                initialize a ruleman directory

    update              fetch and deploy

    fetch               fetch (download) rulesets
    deploy              deploy a profile

    search              search rules
    dump-dynamic-rules  dump dynamic rule stubs
    export-ruleset      export a ruleset
""", file=file)

def print_version():
    print("version %s" % (_version.__version__))
    if __buildtime__:
        print("built: %s" % (__buildtime__))

def main(args):

    try:
        opts, args = getopt.getopt(sys.argv[1:], "Vhv", ["help"])
    except getopt.GetoptError as err:
        print("error: %s" % err)
        usage()
        return 1
    for o, a in opts:
        if o == "-V":
            print_version()
            return 0
        elif o in ["-h", "--help"]:
            usage(sys.stdout)
            return 0
        elif o == "-v":
            logging.getLogger().setLevel(logging.DEBUG)

    if not args:
        usage(sys.stderr)
        return 1
    elif args[0] == "init":
        return InitCommand(args[1:]).run()
    elif args[0] == "fetch":
        return FetchCommand(args[1:]).run()
    elif args[0] == "deploy":
        return DeployCommand(args[1:]).run()
    elif args[0] == "update":
        return UpdateCommand(args[1:]).run()
    elif args[0] == "search":
        return SearchCommand(args[1:]).run()
    elif args[0] == "dump-dynamic-rules":
        return DumpDynamicRulesCommand(args[1:]).run()
    elif args[0] == "export-ruleset":
        return ExportRulesetCommand(args[1:]).run()
    else:
        print("\nerror: unknown command: %s" % (args[0]), file=sys.stderr)
        usage(sys.stderr)
        return 1

    # Not reached.
