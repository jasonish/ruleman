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
import os.path
import urllib
import urllib2
import time
import getopt
import re
import hashlib
import logging
import pickle

try:
    import progressbar
    has_progressbar = True
except:
    has_progressbar = False

from ruleman import config
from ruleman import util
from ruleman import snort

logger = logging.getLogger("ruleman.fetch")

DEFAULT_CHECK_INTERVAL = 15

validContentTypes = ["application/x-gzip",
                     "application/x-tar",
                     "application/octet-stream",
                     "binary/octet-stream"]

class NullProgressMeter(object):

    def update(self, transferred, block_size, total_size):
        pass

    def done(self):
        pass

class SimpleProgressMeter(object):

    def __init__(self):
        self.width = 9

    def update(self, transferred, block_size, total_size):
        val = int((transferred * block_size) / float(total_size) * 100)
        sys.stdout.write("\b" * (self.width + 1))
        format = "%%%ds%%%%" % (self.width)
        sys.stdout.write(format % (val))
        sys.stdout.flush()

    def done(self):
        sys.stdout.write("\n")
        sys.stdout.flush()

class FancyProgressMeter(object):

    def __init__(self):
        self.bar = progressbar.ProgressBar(
            widgets=[progressbar.Percentage(),
                     progressbar.Bar()],
            maxval=100)
        self.bar.start()

    def update(self, transferred, block_size, total_size):
        val = int((transferred * block_size) / float(total_size) * 100)
        self.bar.update(val)

    def done(self):
        self.bar.finish()

def get_progress_meter():
    if not sys.stdout.isatty():
        return NullProgressMeter()
    elif has_progressbar:
        return FancyProgressMeter()
    else:
        return SimpleProgressMeter()

def guess_md5_url(url):
    """ Guess the MD5 URL based on the rule file URL. """
    extensions = (".tar.gz",
                  ".tar.bz2",
                  ".zip")
    for ext in extensions:
        if url.find(ext) >= 0:
            return url.replace(ext, ext + ".md5")
    return None

def get_ruleset_md5(url):
    """ Get the MD5 of a ruleset file.  This assumes that VRT style of
    file where the contents of the URL contains the MD5 in hex
    format. """
    try:
        ruleset = urllib2.urlopen(url)
    except urllib2.URLError, err:
        print("Failed to download MD5 URL: %s" % err)
        return None
    output = ruleset.read()
    m = re.search("([a-zA-Z0-9]+)", output)
    if m:
        return m.group(1)
    else:
        return None

def cache_ruleset_so_stubs(ruleset_ctx, rulefile):

    logging.info("Generating and caching SO rule stubs")
    md5 = util.get_md5_file(rulefile)
    stub_cache_filename = "%s/%s.%s" % (
        os.path.dirname(rulefile), md5, config.STUB_CACHE_EXT)
    snort_ctx = config.get_snort_ctx(ruleset_ctx["snort"])
    stubs = snort.generate_stubs(snort_ctx, util.tar_to_dict(rulefile))
    pickle.dump(stubs, open(stub_cache_filename, "w"))
    logging.info("SO rule stubs cached")

def fetch_ruleset(ruleset_ctx, force=False):
    """ Fetch (download) the ruleset described by ruleset_ctx.

    If a new version of the ruleset was downloaded return True.
    Otherwise False will be returned indicating that no newer ruleset
    was available for download.
    """

    logger.info("Fetching ruleset %s." % (ruleset_ctx["name"]))

    ruleset_dir = "%s/%s" % (config.RULESET_DATA_DIR, ruleset_ctx["name"])
    if not os.path.exists(ruleset_dir):
        print("Creating directory %s." % ruleset_dir)
        os.makedirs(ruleset_dir)

    latestFilename = "%s/latest" % ruleset_dir
    last_check_filename = "%s/last_check" % ruleset_dir

    # Don't retry the download if its been less than 15 minutes.
    if not force and os.path.exists(last_check_filename):
        lastUpdateTime = os.stat(last_check_filename).st_mtime
        diff = int(time.time() - lastUpdateTime)
        if diff < ruleset_ctx["check-interval"]:
            logger.info("Skipping %s: Last check only %d seconds ago." % (
                    ruleset_ctx["name"], diff))
            return False

    # If we have a hash-url, check that now.
    if not force and os.path.exists(latestFilename):    
        if ruleset_ctx["md5-url"] == None:
            md5_url = guess_md5_url(ruleset_ctx["url"])
        else:
            md5_url = ruleset_ctx["md5-url"]
        if md5_url:
            logger.info("Checking MD5 URL: %s" % (md5_url))
            rulesetHash = get_ruleset_md5(md5_url)
            print("Ruleset MD5: %s" % rulesetHash)
            if rulesetHash:
                localHash = util.get_md5_file(latestFilename)
                if localHash == rulesetHash:
                    logger.info(
                        "Ruleset hash unchanged, will not download %s." % (
                            ruleset_ctx["name"]))
                    open(last_check_filename, "w").close()
                    return False

    dest_filename = "%s/%s.tar.gz" % (
        ruleset_dir, time.strftime("%Y%m%d.%H%M%S", time.localtime()))

    logger.info("Fetching %s." % (ruleset_ctx["url"]))

    try:
        url = urllib2.urlopen(ruleset_ctx["url"])
    except urllib2.HTTPError, err:
        print("ERROR: Failed to fetch %s." % (ruleset_ctx["url"]))
        print("%s:\n%s" % (err, err.read()))
        url.close()
        return False

    content_type = url.info()["content-type"]
    if content_type not in validContentTypes:
         print("ERROR: Invalid content type %s." % (content_type))
         return False

    content_length = int(url.info()["content-length"])
    read_length = 0
    progress_meter = get_progress_meter()
    block_size = 8192
    block_count = 0
    with open(dest_filename, "w") as fout:
        while 1:
            data = url.read(block_size)
            if not data:
                break
            block_count += 1
            fout.write(data)
            read_length += len(data)
            progress_meter.update(block_count, block_size, content_length)
            time.sleep(0.001)
    progress_meter.done()
    url.close()
    if os.path.exists(latestFilename):
        os.unlink(latestFilename)
    os.symlink(os.path.basename(dest_filename), latestFilename)
    open(last_check_filename, "w").close()

    if ruleset_ctx["regen-stubs"]:
        cache_ruleset_so_stubs(ruleset_ctx, latestFilename)
        
    return True
