from distutils.core import setup

import time
import commands

version = commands.getoutput("./ruleman -V").strip()

build_time = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime())
open("lib/ruleman/_buildtime.py", "w").write(
    "__buildtime__ = '%s'" % (build_time))

setup(name="ruleman",
      version=version,
      scripts=["ruleman"],
      package_dir={'': 'lib'},
      packages=["ruleman"],
      package_data={"ruleman": ["data/*"]},
      )
