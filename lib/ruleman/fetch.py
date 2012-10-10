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
import os.path
import urllib2
import time
import getopt
import re
import hashlib
import logging
import tempfile
import shutil
import glob

from ruleman import config
from ruleman import util
from ruleman import snort
from ruleman import progressmeter

logger = logging.getLogger("ruleman.fetch")

valid_content_types = [
    "application/x-gzip",
    "application/x-tar",
    "application/octet-stream",
    "binary/octet-stream",
    ]

def get_file_md5(filename):
    """ Return MD5 hex digest for the contexts of filename.

    If a file by the name of filename suffixed with .md5 exists, its
    contents will be used as the MD5 rather than computing the
    md5. """

    md5_filename = "%s.md5" % (filename)
    if os.path.exists(md5_filename):
        return open(md5_filename).read()
    return hashlib.md5(open(filename).read()).hexdigest()

def get_md5_url(ruleset):
    """ Given a ruleset configuration return the URL of the MD5 file
    which may be a guess if its not provided in the configuration. """
    if "md5-url" in ruleset:
        return ruleset["md5-url"]
    extensions = (".tar.gz", ".tar.bz2", ".zip")
    for ext in extensions:
        if ruleset["url"].find(ext) >= 0:
            return ruleset["url"].replace(ext, ext + ".md5")
    return None

def fetch_to_fileobj(url, fileobj, progress_hook=None):
    block_size = 8192
    remote = urllib2.urlopen(url)
    remote_info = remote.info()
    content_length = int(remote_info["content-length"])
    bytes_read = 0
    blocks_read = 0
    while 1:
        buf = remote.read(block_size)
        if not buf:
            break
        bytes_read += len(buf)
        blocks_read += 1
        fileobj.write(buf)
        if progress_hook:
            progress_hook.update(blocks_read, block_size, content_length)
    fileobj.flush()
    return (bytes_read, remote_info)

def fetch_to_buffer(url):
    """ Fetch the contents of a URL and return it as a buffer. """
    return urllib2.urlopen(url).read()

def extract_md5(buf):
    """ Extract the MD5 from a buffer. """
    if buf:
        m = re.search("([a-fA-F0-9]+)", buf)
        if m:
            return m.group(1)
    return None

def get_ruleset_md5(url):
    return extract_md5(fetch_to_buffer(url))

def fetch_ruleset(ruleset_ctx, force=False):
    """ Fetch (download) the ruleset described by ruleset_ctx.

    If a new version of the ruleset was downloaded return True.
    Otherwise False will be returned indicating that no newer ruleset
    was available for download.
    """

    ruleset_dir = config.get_ruleset_dir(ruleset_ctx)
    if not os.path.exists(ruleset_dir):
        print("Creating directory %s." % ruleset_dir)
        os.makedirs(ruleset_dir)

    ruleset_filename = "./rulesets/%s/ruleset.tar.gz" % (ruleset_ctx["name"])

    if not force and os.path.exists(ruleset_filename):

        last_check_time = os.stat(ruleset_filename).st_mtime
        last_checked = int(time.time() - last_check_time)
        if last_checked < ruleset_ctx["fetch-interval"]:
            logger.info(
                "Not fetching ruleset %s, last checked only %d seconds ago" % (
                    ruleset_ctx["name"], last_checked))
            return False

        # Check the MD5 URL.
        try:
            md5_url = get_md5_url(ruleset_ctx)
            if md5_url:
                remote_md5 = extract_md5(fetch_to_buffer(md5_url))
                local_md5 = get_file_md5(ruleset_filename)
                if remote_md5 == local_md5:
                    logger.info(
                        "Not fetching ruleset %s, "
                        "remote MD5 has not changed" % (ruleset_ctx["name"]))
                    os.utime(ruleset_filename, None)
                    return False
        except Exception as err:
            logger.warn("Failed to download MD5 URL, will proceed: %s",
                        err)
        
    dest_file = tempfile.NamedTemporaryFile()

    logger.info("Fetching %s." % (ruleset_ctx["url"]))

    progress_meter = progressmeter.get_progressmeter()
    try:
        bytes_read, remote_info = fetch_to_fileobj(
            ruleset_ctx["url"], dest_file, progress_meter)
    except Exception as err:
        logger.info("Failed to fetch %s: %s" % (
                ruleset_ctx["url"], err))
        raise
    finally:
        progress_meter.done()

    if remote_info["content-type"] not in valid_content_types:
        logger.error(
            "Discarding downloaded ruleset due to bad content-type: %s" % (
                remote_info["content-type"]))
        return

    rotate_files(ruleset_dir)
    dest_filename = "%s/ruleset.tar.gz" % (ruleset_dir)

    # Write out a file containing the MD5 checksum before we rebuild
    # the archive with regenerated rule stubs.
    open("%s.md5" % (dest_filename), "w").write(get_file_md5(dest_file.name))

    rebuilt_rule_archive = rebuild_so_rule_stubs(dest_file.name)

    logger.debug("Copying %s to %s" % (rebuilt_rule_archive, dest_filename))
    shutil.copy(rebuilt_rule_archive, dest_filename)

    return True

def rebuild_so_rule_stubs(filename):
    snort_config = config.get_snort()
    if not snort_config:
        logger.warn("No snort configuration found. "
                    "dynamic rule stubs will not be rebuilt.")
        return filename
    tmpdir = util.get_tmpdir()
    logger.debug("Extracting %s to %s" % (filename, tmpdir))
    util.extract_archive(filename, tmpdir)

    stub_dir = snort.dump_stubs(tmpdir, snort_config["path"], 
                                snort_config["dynamic-engine"],
                                snort_config["os-type"])
    if stub_dir == None:
        logger.info("No dynamic rules were found, "
                    "dynamic rule stubs will not be generated.")
        # No dynamic rules were found.
        return filename

    old_stub_filenames = glob.glob("%s/so_rules/*.rules" % (tmpdir))
    for filename in old_stub_filenames:
        logger.debug("Removing existing SO rule stub %s" % filename)
        os.unlink(filename)

    new_stub_filenames = glob.glob("%s/*.rules" % (stub_dir))
    for filename in new_stub_filenames:
        logger.debug("Adding new SO rule stub so_rules/%s" % (
                os.path.basename(filename)))
        new_stub = open(
            "%s/so_rules/%s" % (tmpdir, os.path.basename(filename)), "w")
        new_stub.write("# Generated by ruleman at %s\n" % (
                time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime())))
        new_stub.write(open(filename).read())
        new_stub.close()
        
    logger.info("Regenerated dynamic rule stubs %s" % (
            ", ".join([os.path.basename(f) for f in new_stub_filenames])))

    rebuilt_filename = util.get_tmpfilename(suffix=".tar.gz")
    logger.debug("Creating archive %s from %s" % (rebuilt_filename, tmpdir))
    util.create_archive(rebuilt_filename, tmpdir)

    return rebuilt_filename

def rotate_files(directory):
    for i in reversed(range(1, 9)):
        filename = "%s/ruleset.tar.gz.%d" % (directory, i)
        next_filename = "%s/ruleset.tar.gz.%d" % (directory, i + 1)
        if os.path.exists(filename):
            print("Renaming %s to %s" % (
                    os.path.basename(filename), 
                    os.path.basename(next_filename)))
            os.rename(filename, next_filename)
    
    filename = "%s/ruleset.tar.gz" % (directory)
    next_filename = "%s/ruleset.tar.gz.1" % (directory)
    if os.path.exists(filename):
        print("Renaming %s to %s" % (
                os.path.basename(filename), os.path.basename(next_filename)))
        os.rename(filename, next_filename)

def main(args):
    usage = """
usage: ruleman fetch [options] [ruleset0 ruleset1 ...]

Options:

    -f, --force

If no ruleset names are specified the only those enabled will be
fetched, otherwise only the specified rulesets will be fetched even if
not enabld.
"""

    force = False

    try:
        opts, args = getopt.getopt(args, "hf", ["help", "force"])
    except getopt.GetoptError as err:
        print(usage, file=sys.stderr)
        return 1
    for o, a in opts:
        if o in ["-h", "--help"]:
            print(usage)
            return 0
        elif o in ["-f", "--force"]:
            force = True

    if not os.path.exists(config.RULESET_DATA_DIR):
        print("Creating directory %s." % config.RULESET_DATA_DIR)
        os.makedirs(config.RULESET_DATA_DIR)

    rulesets = config.get_rulesets()
    fetched = []
    for ruleset in rulesets.values():
        ret = False
        if args:
            if ruleset["name"] in args:
                ret = fetch_ruleset(ruleset, force=force)
        else:
            ret = fetch_ruleset(ruleset, force=force)
        if ret:
            fetched.append(ruleset["name"])

    # Return a list of ruleset names that were actually fetched.
    return fetched
