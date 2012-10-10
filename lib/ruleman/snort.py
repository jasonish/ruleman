# Copyright (c) 2011-2012 Jason Ish
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
import logging
import subprocess
import util
import io

from ruleman import config

logger = logging.getLogger("ruleman.snort")

def _find_dynamic_rules(rule_dir, os_type):
    prefix = "%s/so_rules/precompiled/%s" % (rule_dir, os_type)
    if os.path.exists(prefix):
        versions = os.listdir(prefix)
        if versions:
            return "%s/%s" % (prefix, versions[0])
    return None

def _extract_to_temp(filename):
    """ Extract an archive to a temporary directory returning the name
    of that directory. """
    temp_rule_dir = util.get_tmpdir()
    status = subprocess.call("tar zxf %s -C %s" % (
            filename, temp_rule_dir), shell=True)
    return temp_rule_dir

def dump_stubs(ruleset, snort_path, snort_dynamicengine, os_type, 
                dest_dir=None, verbose=False):

    if os.path.isdir(ruleset):
        rule_dir = ruleset
    else:
        rule_dir = _extract_to_temp(ruleset)

    dynamic_rules_dir = _find_dynamic_rules(rule_dir, os_type)
    if not dynamic_rules_dir:
        # No dynamic rules found. Don't log anything here. Let the
        # caller do that if wanted.
        return None
    if not dest_dir:
        dest_dir = util.get_tmpdir()
    args = (snort_path,
            "--dump-dynamic-rules=%s" % (dest_dir),
            "--dynamic-detection-lib-dir=%s" % (dynamic_rules_dir),
            "--dynamic-engine-lib=%s" % (snort_dynamicengine))
    logger.info("Running %s" % (" ".join(args)))

    child = subprocess.Popen(
        " ".join(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
        shell=True)
    output = io.StringIO()
    while True:
        line = child.stdout.readline()
        if not line:
            break
        output.write(unicode(line))
        if verbose:
            logger.info(line.strip())
        else:
            logger.debug(line.strip())
    if child.wait() != 0:
        # An error occurred.  We need to trim the output displayed...
        error_lines = output.getvalue().split("\n")
        if len(error_lines) > 12:
            error_lines = error_lines[0:12]
            error_lines.append("<remainder of output trimmed>")
        logger.error("\nFailed to dump dynamic rule stubs:")
        logger.error("\n".join(error_lines))
        return False

    return dest_dir
        
