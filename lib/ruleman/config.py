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
try:
    import configparser
except:
    import ConfigParser as configparser
import logging

logger = logging.getLogger("ruleman.fetch")

CONFIG_FILENAME  = "ruleman.conf"
DATA_DIR         = "."
RULESET_DATA_DIR = "%s/rulesets" % DATA_DIR

# Default check interval in seconds.
DEFAULT_FETCH_INTERVAL = 900

DEFAULTS = {}

_config_parser = None

class NoRulesetError(Exception):
    pass

ruleset_template = {
    "url": None,
    "fetch-interval": DEFAULT_FETCH_INTERVAL,
    "ignore-files": []
}

# Profile configuration template
profile_template = {
    "rulesets": [],
    "policy": None,
    "inline": False,
    "os-type": None,

    "disable-rules": [],
    "enable-rules": [],
    "drop-rules": [],
}

# Snort configuration template
snort_template = {
    "path": None,
    "dynamic-engine": None,
    "os-type": None,
}

def xform_bool(val):
    if val.lower() in ["1", "true", "yes", "on"]:
        return True
    return False

def xform_stringlist(val):
    return [s.strip() for s in val.split(",") if s]

def has_section(section):
    return _config_parser.has_section(section)

def get_section(section, template={}, xforms={}):
    optvals = dict(template)
    for opt, val in _config_parser.items(section):
        if opt in xforms:
            optvals[opt] = xforms[opt](val)
        else:
            optvals[opt] = val
    return optvals

def get_profile():
    xforms = {
        "rulesets": xform_stringlist,
        "inline": xform_bool,
        "disable-rules": xform_stringlist,
        "enable-rules": xform_stringlist,
        "drop-rules": xform_stringlist,
        }
    profile = get_section("profile", xforms=xforms, template=profile_template)
    return profile

def get_ruleset(name):
    xforms = {
        "fetch-interval": int,
        "ignore-files": xform_stringlist,
        }
    try:
        ruleset = get_section(
            "ruleset %s" % (name), xforms=xforms, template=ruleset_template)
    except configparser.NoSectionError:
        raise NoRulesetError(name)
    ruleset["name"] = name
    return ruleset

def get_rulesets():
    rulesets = {}
    for section in _config_parser.sections():
        if section.startswith("ruleset "):
            name = section.split(" ", 1)[1].strip()
            rulesets[name] = get_ruleset(name)
    return rulesets

def get_snort():
    if has_section("snort"):
        return get_section("snort")
    return None

def get(section, option, default=None):
    if _config_parser.has_option(section, option):
        return _config_parser.get(section, option)
    else:
        return default

def get_ruleset_dir(ruleset_ctx):
    return "%s/%s" % (RULESET_DATA_DIR, ruleset_ctx["name"])

def loadfp(fileobj):
    global _config_parser

    _config_parser = configparser.SafeConfigParser(DEFAULTS)
    _config_parser.readfp(fileobj)

def load(filename):
    loadfp(open(filename))

def init(config_filename=CONFIG_FILENAME):
    load(config_filename)
