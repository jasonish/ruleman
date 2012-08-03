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

import os
import string
import ConfigParser

CONFIG_FILENAME  = "ruleman.conf"

DATA_DIR         = "."
RULESET_DATA_DIR = "%s/rulesets" % DATA_DIR

# Default check interval in seconds.
DEFAULT_CHECK_INTERVAL = 900

DEFAULTS = {
    "check-interval": str(DEFAULT_CHECK_INTERVAL),
    }

config = None

# A list of filenames that contain the actions to perform on a
# ruleset.  The filenames are pretty self explanatory of what they do.
profile_action_filenames = (
    "disable-groups",
    "enable-groups",
    "disable-rules",
    "enable-rules",
    "drop-rules",
    )

# Ruleset context template.
ruleset_ctx_template = {
    "name": None,
    "enabled": False,
    "url": None,
    "md5-url": None,
    "ignore-files": [],
    "regen-stubs": False,
    "snort": None
}

# Profile context template.
profile_ctx_template = {
    "name": None,
    "enabled": False,
    "config": None,
    "prefix": None,
    "os-type": None,
    "policy": None,
    "inline": False,
    "rulesets": [],
    
    "disable-groups": [],
    "enable-groups": [],
    "disable-rules": [],
    "enable-rules": [],
    "drop-rules": [],
}

# Snort context template.
snort_ctx_template = {
    "name": None,
    "path": None,
    "dynamic-engine": None,
    "os-type": None,
}

class NoConfigurationFileException(Exception):
    pass

def load_section(section, list_options=[], bool_options=[], int_options=[]):

    data = {}
    options = config.options(section)
    for opt in options:
        if opt in list_options:
            data[opt] = map(string.strip, config.get(section, opt).split(","))
        elif opt in bool_options:
            data[opt] = config.getboolean(section, opt)
        elif opt in int_options:
            data[opt] = config.getint(section, opt)
        else:
            data[opt] = config.get(section, opt)
    return data

def get_ruleset_ctx(name):

    section = "ruleset %s" % (name)

    bool_options = ["enabled", "regen-stubs"]
    list_options = ["ignore-files"]
    int_options = ["check-interval"]

    ctx = load_section(section, 
                       list_options=list_options,
                       bool_options=bool_options,
                       int_options=int_options)
            
    for key in ruleset_ctx_template:
        if key not in ctx:
            ctx[key] = ruleset_ctx_template[key]

    ctx["name"] = name

    return ctx

def get_rulesets():
    rulesets = {}
    for section in config.sections():
        if section.startswith("ruleset "):
            name = string.split(section, " ", maxsplit=1)[1].strip()
            rulesets[name] = get_ruleset_ctx(name)
    return rulesets

def load_action_file(filename):
    actions = []
    with open(filename) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                actions.append(line)
    return actions

def get_snort_ctx(name=None):
    if name:
        section = "snort %s" % (name)
    else:
        section = "snort"

    ctx = load_section(section)
    for key in snort_ctx_template:
        if key not in ctx:
            ctx[key] = snort_ctx_template[key]

    ctx["name"] = "default" if name == None else name
    
    return ctx

def get_profile_ctx(name):

    section = "profile %s" % (name)

    lists = ["rulesets"]
    bools = ["enabled", "inline"]
    ctx = load_section(section, list_options=lists, bool_options=bools)

    for filename in profile_action_filenames:
        full_path = "%s/%s" % (ctx["config"], filename)
        if os.path.exists(full_path):
            ctx[filename] = load_action_file(full_path)

    for key in profile_ctx_template:
        if key not in ctx:
            ctx[key] = profile_ctx_template[key]

    ctx["name"] = name

    return ctx

def get_profiles():
    profiles = {}
    for section in config.sections():
        if section.startswith("profile "):
            name = string.split(section, " ", maxsplit=1)[1].strip()
            ctx = get_profile_ctx(name)
            if ctx["enabled"]:
                profiles[name] = ctx
    return profiles

def get(section, option, default=None):
    if config.has_option(section, option):
        return config.get(section, option)
    else:
        return default

def get_ruleset_dir(ruleset_ctx):
    return "%s/%s" % (RULESET_DATA_DIR, ruleset_ctx["name"])

def init(config_filename=CONFIG_FILENAME):
    global config
    config = ConfigParser.SafeConfigParser(DEFAULTS)
    if config_filename not in config.read(config_filename):
        raise NoConfigurationFileException()
