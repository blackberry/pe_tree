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

"""PE Tree standalone application"""

# Standard imports
import os
import sys
from argparse import ArgumentParser

# Qt imports
from PyQt5 import QtWidgets

# QDarkStyle
try:
    import qdarkstyle

    HAVE_DARKSTYLE = True
except:
    HAVE_DARKSTYLE = False

# PE Tree imports
import pe_tree.window
import pe_tree.runtime

class ApplicationRuntime(pe_tree.runtime.Runtime):
    """Standalone application runtime"""
    def __init__(self, widget, args):
        # Load configuration
        self.config_file = os.path.join(self.get_temp_dir(), "pe_tree.ini")

        super(ApplicationRuntime, self).__init__(widget, args)

        self.pe_tree_form = None

def main(args=None):
    """Create PE Tree Qt standalone application"""
    # Check command line arguments
    parser = ArgumentParser(description="PE-Tree")
    parser.add_argument("filenames", nargs="*", help="Path(s) to file/folder/zip")
    args = parser.parse_args()

    # Create PE Tree application
    application = QtWidgets.QApplication(sys.argv)
    window = pe_tree.window.PETreeWindow(application, ApplicationRuntime, args)
    sys.exit(application.exec_())

if __name__ == "__main__":
    main()
