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
import tempfile
import shutil
import tarfile
import subprocess
import time

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

def copy_fileobj(src, dst, expected_size):
    """ Write the data read from fileobj src to fileobj dst.
    - expected_size is used to display a progress meter.
    - the number of bytes read is returned.
    """
    read_length = 0
    progress_meter = get_progress_meter()
    block_size = 8192
    block_count = 0
    while 1:
        data = src.read(block_size)
        if not data:
            break
        block_count += 1
        dst.write(data)
        read_length += len(data)
        progress_meter.update(block_count, block_size, expected_size)
    progress_meter.done()

    return read_length

def update_so_stubs(ruleset_ctx, rulefile):

    logging.info("Generating and caching SO rule stubs")

    tmpdir = extract_archive(rulefile)
    snort_ctx = config.get_snort_ctx(ruleset_ctx["snort"])
    stubs = snort.generate_stubs(snort_ctx, tmpdir)

    # Copy in the newly generated stubs..  Rename existing SO stubs
    # with a .orig extension, unless .orig files already exist.
    for filename in stubs:
        dest_filename = "%s/%s" % (tmpdir, filename)
        orig_filename = "%s.orig" % (dest_filename)
        if os.path.exists(dest_filename) and not os.path.exists(orig_filename):
            os.rename(dest_filename, orig_filename)
        open(dest_filename, "w").write(stubs[filename])

    # Use tar to rebuild the tarball.  Its much faster than the
    # tarfile module.
    p = subprocess.Popen(
        "tar cf - -C %s %s | gzip > %s" % (
            tmpdir, " ".join(os.listdir(tmpdir)), rulefile),
        shell=True)
    os.waitpid(p.pid, 0)

    # Cleanup.
    shutil.rmtree(tmpdir)

    logging.info("SO rule stubs cached")

def extract_archive(filename):

    tmpdir = tempfile.mkdtemp()

    def filename_filter(members):
        # Simple filter to prevent extraction of files with a leading /.
        for tarinfo in members:
            if tarinfo.isreg() and tarinfo.name[0] != "/":
                yield tarinfo

    tf = tarfile.open(filename)
    tf.extractall(path=tmpdir, members=filename_filter(tf))
    tf.close()

    return tmpdir

def fetch_ruleset(ruleset_ctx, force=False):
    """ Fetch (download) the ruleset described by ruleset_ctx.

    If a new version of the ruleset was downloaded return True.
    Otherwise False will be returned indicating that no newer ruleset
    was available for download.
    """

    logger.info("Fetching ruleset %s." % (ruleset_ctx["name"]))

    ruleset_dir = config.get_ruleset_dir(ruleset_ctx)
    if not os.path.exists(ruleset_dir):
        print("Creating directory %s." % ruleset_dir)
        os.makedirs(ruleset_dir)

    latest_filename = "%s/latest" % ruleset_dir
    last_check_filename = "%s/last-check" % ruleset_dir

    # Don't retry the download if its been less than 15 minutes.
    if not force and os.path.exists(last_check_filename):
        lastUpdateTime = os.stat(last_check_filename).st_mtime
        diff = int(time.time() - lastUpdateTime)
        if diff < ruleset_ctx["check-interval"]:
            logger.info("Skipping %s: Last check only %d seconds ago." % (
                    ruleset_ctx["name"], diff))
            return False

    # If we have a hash-url, check that now.
    if not force and os.path.exists(latest_filename):    
        if ruleset_ctx["md5-url"] == None:
            md5_url = guess_md5_url(ruleset_ctx["url"])
        else:
            md5_url = ruleset_ctx["md5-url"]
        if md5_url:
            logger.info("Checking MD5 URL: %s" % (md5_url))
            rulesetHash = get_ruleset_md5(md5_url)
            print("Ruleset MD5: %s" % rulesetHash)
            if rulesetHash:
                localHash = util.get_md5_file(latest_filename)
                if localHash == rulesetHash:
                    logger.info(
                        "Ruleset hash unchanged, will not download %s." % (
                            ruleset_ctx["name"]))
                    open(last_check_filename, "w").close()
                    return False

    
    dest_file = tempfile.NamedTemporaryFile(dir=ruleset_dir)

    logger.info("Fetching %s." % (ruleset_ctx["url"]))

    try:
        url = urllib2.urlopen(ruleset_ctx["url"])
    except urllib2.HTTPError, err:
        print("ERROR: Failed to fetch %s." % (ruleset_ctx["url"]))
        print("%s:\n%s" % (err, err.read()))
        return False

    content_type = url.info()["content-type"]
    if content_type not in validContentTypes:
         print("ERROR: Invalid content type %s." % (content_type))
         return False

    content_length = int(url.info()["content-length"])
    copy_fileobj(url, dest_file, content_length)
    url.close()
    dest_file.flush()

    rotate_files(ruleset_dir)

    dest_filename = "%s/ruleset.tar.gz" % (ruleset_dir)
    shutil.copy(dest_file.name, dest_filename)

    if os.path.exists(latest_filename):
        os.unlink(latest_filename)
    os.symlink(os.path.basename(dest_filename), latest_filename)
    open(last_check_filename, "w").close()

    if ruleset_ctx["regen-stubs"]:
        update_so_stubs(ruleset_ctx, dest_filename)
        
    return True

def rotate_files(directory):
    for i in reversed(range(1, 9)):
        filename = "%s/ruleset.tar.gz.%d" % (directory, i)
        next_filename = "%s/ruleset.tar.gz.%d" % (directory, i + 1)
        if os.path.exists(filename):
            print("Renaming %s to %s" % (
                    os.path.basename(filename), os.path.basename(next_filename)))
            os.rename(filename, next_filename)
    
    filename = "%s/ruleset.tar.gz" % (directory)
    next_filename = "%s/ruleset.tar.gz.1" % (directory)
    if os.path.exists(filename):
        print("Renaming %s to %s" % (
                os.path.basename(filename), os.path.basename(next_filename)))
        os.rename(filename, next_filename)

def cleanup(ruleset_ctx):
    """ Cleanup the ruleset download directory.  Trims previously
    downloaded rulesets and removes unknown files.

    Could probably be a little cleaner/smarter.
    """

    def known_file_filter(filename):
        if filename.startswith("ruleset."):
            return True
        if filename in ["latest", "last-check"]:
            return True
        return False

    ruleset_dir = config.get_ruleset_dir(ruleset_ctx)
    if not os.path.exists(ruleset_dir):
        return

    filelist = os.listdir(ruleset_dir)
    known_files = filter(known_file_filter, filelist)
    for filename in filelist:
        if filename not in known_files:
            path = "%s/%s" % (ruleset_dir, filename)
            if os.path.isdir(path):
                print("Deleting unknown directory %s." % (path))
                shutil.rmtree(path)
            else:
                print("Deleting unkonwn file %s." % (path))
                os.unlink(path)

def main(args):
    usage = """
ruleman fetch [options] [ruleset0 ruleset1 ...]

Options:

    -f, --force

If no ruleset names are specified the only those enabled will be
fetched, otherwise only the specified rulesets will be fetched even if
not enabld.
"""

    force = False

    try:
        opts, args = getopt.getopt(args, "hf", ["help", "force"])
    except getopt.GetoptError, err:
        print >>sys.stderr, usage
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
        elif ruleset["enabled"]:
            cleanup(ruleset)
            ret = fetch_ruleset(ruleset, force=force)
        if ret:
            fetched.append(ruleset["name"])

    # Return a list of ruleset names that were actually fetched.
    return fetched
