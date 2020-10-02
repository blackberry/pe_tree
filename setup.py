#
#   Copyright (c) 2020 BlackBerry Limited.  All Rights Reserved.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

"""Install PE Tree standalone application or IDAPython plugin"""

# Standard imports
import os
import sys

# Setuptools imports
from setuptools import setup
from setuptools.command.install import install
from setuptools.command.develop import develop

# PE Tree imports
import pe_tree.info

# Common requirements for IDAPython plugin and standalone application
with open("requirements.txt") as f:
    install_requires = f.read().splitlines()

INSTALL_FOR_IDA = False

if "--ida" in sys.argv:
    sys.argv.remove("--ida")

    # Setup for IDAPython plugin
    entry_points = {}

    INSTALL_FOR_IDA = True
else:
    # Setup for standalone application
    entry_points = {"console_scripts": ["pe-tree=pe_tree.__main__:main"]}
    install_requires.extend(["pyqt5", "capstone"])

# Long description
with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), "README.md")) as f:
    long_description = f.read()

def find_ida():
    """Search for possible IDA Pro installations"""
    if INSTALL_FOR_IDA:
        paths = ["/opt/ida-7.{}/plugins",
                 "~/.idapro/plugins",
                 "%ProgramFiles%\\IDA Pro 7.{}\\plugins"]

        found = []

        for path in paths:
            if "{}" in path:
                for i in range(0, 10):
                    new_path = os.path.expandvars(path.format(i))

                    if os.path.exists(new_path):
                        found.append(new_path)
            else:
                if os.path.exists(path):
                    found.append(path)

        if len(found) > 0:
            print("\nTo complete the IDAPython plugin installation copy pe_tree_ida.py to:\n{}".format("\n".join(found)))

def do_post_setup():
    """Search for IDA installations post setup"""
    find_ida()

class InstallCommand(install):
    """Extend install command"""
    def run(self):
        install.run(self)
        do_post_setup()

class DevelopCommand(develop):
    """Extend develop command"""
    def run(self):
        develop.run(self)
        do_post_setup()

setup(name="pe-tree",
      version=pe_tree.info.__version__,
      description="View Portable Executable (PE) files in a tree-view using pefile and PyQt5.",
      license=pe_tree.info.__license__,
      url=pe_tree.info.__url__,
      author=pe_tree.info.__author__,
      author_email=pe_tree.info.__email__,
      packages=["pe_tree"],
      py_modules=["pe_tree"],
      install_requires=install_requires,
      entry_points=entry_points,
      cmdclass={"install": InstallCommand, "develop": DevelopCommand},
      python_requires=">=2.7",
      long_description=long_description,
      long_description_content_type="text/markdown",
      keywords=["pe_tree",
                "petree",
                "pefile",
                "exe",
                "dll",
                "malware",
                "pedump",
                "unpacker",
                "iat",
                "rekall"],
      classifiers=[
          "Intended Audience :: Developers",
          "Intended Audience :: Science/Research",
          "Development Status :: 4 - Beta",
          "Programming Language :: Python",
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 3.5",
          "Programming Language :: Python :: 3.6",
          "Programming Language :: Python :: 3.7",
          "Programming Language :: Python :: 3.8",
          "Environment :: X11 Applications :: Qt",
          "Environment :: Plugins",
          "Operating System :: Microsoft :: Windows",
          "Operating System :: MacOS :: MacOS X",
          "Operating System :: POSIX :: Linux",
          "Topic :: Security",
          "Topic :: Utilities",
          "Natural Language :: English"],
      include_package_data=True
      )
