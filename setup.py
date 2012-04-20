from distutils.core import setup
from distutils.core import Command
from unittest import TextTestRunner, TestLoader
import subprocess
import sys
import os

# For unit tests.
sys.path.insert(0, "./lib")
import ruleman.test

# Yes, deprecated - but targetting Python 2.6 here.
import commands

version = commands.getoutput("./ruleman -V").strip()

class TestCommand(Command):

    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        tests = TestLoader().loadTestsFromModule(ruleman.test)
        TextTestRunner(verbosity=2).run(tests)

setup(name="ruleman",
      version=version,
      scripts=["ruleman"],
      package_dir={'': 'lib'},
      packages=["ruleman"],
      package_data={"ruleman": ["data/*"]},

      cmdclass = {"test": TestCommand},
      )
