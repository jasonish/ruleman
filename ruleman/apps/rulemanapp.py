# Copyright (c) 2011-2013 Jason Ish
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
import io
import re
import time
import tempfile
import shutil
import ConfigParser

import ruleman.util
import ruleman.progressbar

class SourceRuleset(object):

    def __init__(self, config):
        self.name = config["name"]
        self.url = config["url"]
        self.fetch_interval = config["fetch-interval"]
        self.filename = ".sources/%s/ruleset%s" % (self._get_extension)

    def _get_extension(self):
        if ".tar.gz" in self.url:
            return ".tar.gz"
        else:
            return None

class Config(object):
    """ An abstraction over the basic ConfigParser configuration
    classes to return configuration sections as dicts or application
    specific objects. """

    defaults = {
        "fetch-interval": "10",
        }

    def __init__(self):
        self.config = ConfigParser.SafeConfigParser(self.defaults)
        self.read = self.config.read

    def dump(self):
        for section in self.config.sections():
            for option in self.config.options(section):
                print("%s.%s = %s" % (
                        section, option, self.config.get(section, option)))

    def get_list(self, section, option):
        values = self.config.get(section, option).split(",")
        return [v.strip() for v in values]

    def get_source(self, name):
        """ Get a ruleset source by name. """
        section = "source %s" % name
        source = {}
        source["name"] = name
        for option in self.config.options(section):
            if option == "fetch-interval":
                source[option] = self.config.getint(section, option)
            else:
                source[option] = self.config.get(section, option)
        return source

    def get_sources(self):
        """ Return all ruleset sources as a dict keyed by name. """
        sources = {}
        for section in self.config.sections():
            if section.startswith("source"):
                name = section.split(" ")[1].strip()
                sources[name] = self.get_source(name)
        return sources

    def get_ruleset(self):
        ruleset = {}
        for option in self.config.options("ruleset"):
            if option == "sources":
                ruleset[option] = self.get_list("ruleset", option)
            else:
                ruleset[option] = self.config.get("ruleset", option)
        return ruleset

class RulesetUpdater(object):

    def __init__(self, ruleset):
        self.ruleset = ruleset
        self.filename = os.path.basename(ruleset["url"])
        
    def update(self):
        if os.path.exists(self.filename):
            mtime = os.stat(self.filename).st_mtime
            last_check = time.time() - mtime
            if last_check < self.ruleset["fetch-interval"]:
                print("Not fetching ruleset %s, "
                      "last checked only %d seconds ago." % (
                        self.ruleset["name"], last_check))
                return

        if self.get_local_md5() == self.get_remote_md5():
            print("Not fetching ruleset %s, remote MD5 has not changed." % (
                    self.ruleset["name"]))
            os.utime(self.filename, None)
        else:
            self.fetch()

    def fetch(self):
        print("Fetching ruleset %s:" % (self.ruleset["name"]))
        ruleset = tempfile.NamedTemporaryFile()
        bytes_read, info = ruleman.util.get(
            self.ruleset["url"], ruleset, progress_hook=self.progress)
        ruleman.progressbar.finish()
        shutil.copy(ruleset.name, self.filename)

    def get_local_md5(self):
        if os.path.exists(self.filename):
            return ruleman.util.md5sum(self.filename)
        else:
            return None

    def get_remote_md5(self):
        url = "%s.md5" % (self.ruleset["url"])
        buf = io.BytesIO()
        bytes_read, remote_info = ruleman.util.get(url, buf)
        return re.search("[A-Za-z0-9]+", buf.getvalue()).group(0)

    def progress(self, total, current):
        ruleman.progressbar.update(total, current)

def main(args):
    config = Config()
    if "config" not in config.read("config"):
        print("Error: Configuration file not found.")
        return 1
    sources = config.get_sources()
    for source in sources:
        updater = RulesetUpdater(sources[source])
        updater.update()

    ruleset = config.get_ruleset()
    


if __name__ == '__main__':
    sys.exit(main(sys.args[1:]))
