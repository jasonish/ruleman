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

import re
import logging

LOGGER = logging.getLogger(__name__)

FB_TOKENIZE_PATTERN = re.compile("[,&|]")

def get_required_flowbits(ruleset):
    """ Return a set of all the required flowbits for enabled rules.

    The argument ruleset is a dict of filenames (groups) that contains
    a list of Rule objects.
    """
    required = set()
    for group in ruleset:
        for rule in ruleset[group]:
            if rule.enabled and rule.flowbits:
                for fb in rule.flowbits:
                    tokens = FB_TOKENIZE_PATTERN.split(fb)
                    if tokens[0] in ["isset", "isnotset"]:
                        for bit in tokens[1:]:
                            required.add(bit)
    return required

def set_required_flowbits(ruleset, required):
    """ Make sure all rules that may set or unset a required flowbit
    is enabled.

    A list of the rules that were enabled is returned.
    """
    enabled = []
    for group in ruleset:
        for rule in ruleset[group]:
            if not rule.enabled and rule.flowbits:
                for fb in rule.flowbits:
                    tokens = FB_TOKENIZE_PATTERN.split(fb)
                    if tokens[0] in ["set", "setx", "unset", "reset"]:
                        if set(tokens[1:]).issubset(required):
                            rule.enabled = True
                            enabled.append(rule)
    return enabled

def resolve_dependencies(ruleset):
    rules_enabled = []
    rpass = 0
    while True:
        enabled = set_required_flowbits(
            ruleset, get_required_flowbits(ruleset))
        LOGGER.debug("pass %d: enabled %d rules to satisfy flowbits" % (
                rpass, len(enabled)))
        if enabled:
            rules_enabled += enabled
        else:
            break

    return rules_enabled
