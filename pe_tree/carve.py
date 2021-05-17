#
#   Copyright (c) 2021 BlackBerry Limited.  All Rights Reserved.
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

"""PE Tree Carve application"""

# Standard imports
import os
import sys
import re
from argparse import ArgumentParser, FileType

# Qt imports
from PyQt5 import QtCore, QtWidgets

# PE Tree imports
import pe_tree.window
import pe_tree.runtime

class CarveRuntime(pe_tree.runtime.Runtime):
    """Carve runtime callbacks"""
    def __init__(self, widget, args):
        # Load configuration
        self.config_file = os.path.join(self.get_temp_dir(), "pe_tree_carve.ini")
        super(CarveRuntime, self).__init__(widget, args)

        # Read input file
        self.data = self.args.filename.read()

    @QtCore.pyqtSlot(object, object)
    def get_bytes(self, start, size):
        """Read bytes from memory"""
        try:
            self.ret = self.data[start:start+size]
        except:
            self.ret = None

        return self.ret

def main():
    """PE Tree Carve script entry-point"""
    # Check command line arguments
    parser = ArgumentParser(description="PE-Tree (Carve)")
    parser.add_argument("filename", help="Path to file to carve", type=FileType("rb"))
    args = parser.parse_args()

    # Create PE Tree Qt application
    application = QtWidgets.QApplication(sys.argv)
    window = pe_tree.window.PETreeWindow(application, CarveRuntime, args, open_file=False)

    # Determine architecture specifics
    ptr_width = 16

    # Iterate over all MZ bytes in the input file
    for match in re.compile(b"MZ").finditer(window.runtime.data):
        # Determine image base
        image_base = int(match.start())

        # Attempt to map PE
        window.pe_tree_form.map_pe(filename="Offset {} ({:#08x})".format(image_base, image_base), image_base=image_base, disable_dump=True)

    sys.exit(application.exec_())

if __name__ == "__main__":
    main()
