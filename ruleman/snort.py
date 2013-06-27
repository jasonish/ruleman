import os
import subprocess
import re
import tempfile
import shutil
import atexit

def rmtree(path):
    print("Removing directory %s." % (path))
    shutil.rmtree(path)

class SnortVersion(object):
    """ A class to represent a Snort version.  The idea being that it
    will allow comparison operations. """

    def __init__(self, version):
        self.version_string = version
        self.version_parts = [int(p) for p in version.split(".")]

    def __repr__(self):
        return self.version_string

class Snort(object):

    def __init__(self, path, dynamic_engine_lib=None):
        self.path = path
        self.dynamic_engine_lib = dynamic_engine_lib

    def get_version(self):
        stdout, stderr = subprocess.Popen(
            [self.path, "-V"], stderr=subprocess.PIPE).communicate()
        m = re.search("Version (\d+\.\d+\.\d+(\.\d+|))", stderr, re.M)
        return SnortVersion(m.group(1))

    def generate_dynamic_rules(self, ostype, files):
        assert(self.dynamic_engine_lib is not None)
        workdir = tempfile.mkdtemp()
        atexit.register(rmtree, workdir)
