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

"""PE Tree Minidump application"""

# Standard imports
import os
import sys
from argparse import ArgumentParser, FileType

# pefile
import pefile

# Qt imports
from PyQt5 import QtCore, QtWidgets, QtGui

# Minidump imports
try:
    from minidump.minidumpfile import MinidumpFile
    from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE
    from minidump.streams.MemoryInfoListStream import AllocationProtect
except ModuleNotFoundError:
    print("pip install minidump!")
    exit()

# PE Tree imports
import pe_tree.window
import pe_tree.runtime
import pe_tree.form
import pe_tree.info

class MinidumpRuntime(pe_tree.runtime.Runtime):
    """Minidump runtime callbacks"""
    def __init__(self, widget, args):
        # Load configuration
        self.config_file = os.path.join(self.get_temp_dir(), "pe_tree_minidump.ini")
        super(MinidumpRuntime, self).__init__(widget, args)

        # Exported symbols table
        self.exports = {}

        # Initialise minidump
        try:
            self.mf = MinidumpFile.parse(self.args.filename.name)
        except:
            print("Not a valid Minidump file?")
            exit()

        self.reader = self.mf.get_reader()

    @QtCore.pyqtSlot(object, object)
    def get_bytes(self, start, size):
        """Read bytes from memory"""
        self.ret = b""

        offset = 0

        # Iterate over segments
        while size > 0:
            # Create buffered segment reader
            reader = self.reader.get_buffered_reader()

            # Move to segment
            reader.move(start + offset)

            # Calculate remaining data in the segment
            remaining = reader.current_segment.remaining_len(start + offset)
  
            if not remaining:
                break

            if remaining >= size:
                # No more data required, read and break
                self.ret += reader.peek(size)
                break

            # More data required, read and continue
            self.ret += reader.peek(remaining)

            offset += remaining
            size -= remaining

        self.ret = b"" if self.ret is None else self.ret
        return self.ret

    @QtCore.pyqtSlot(object)
    def is_writable(self, offset):
        """Determine if memory address is writable"""
        self.ret = False

        for info in self.mf.memory_info.infos:
            if offset >= info.BaseAddress and offset <= info.BaseAddress + info.RegionSize:
                if info.Protect is AllocationProtect.PAGE_EXECUTE_READWRITE:
                    self.ret = True
                    break

        return self.ret

    def _build_export_symbol_table(self):
        """Iterate over all load order modules in the processes address space and construct an exported function symbol table"""
        if len(self.exports.keys()) > 0:
            return

        # Iterate over all modules
        for module in self.mf.modules.modules:
            try:
                # Ensure the module has an MZ header
                if self.get_word(module.baseaddress) != 0x5a4d:
                    continue

                # Dump and re-parse the PE
                pe_file = pefile.PE(data=self.read_pe(module.baseaddress))

                # Check for exports data directory
                if hasattr(pe_file, "DIRECTORY_ENTRY_EXPORT"):
                    # Iterate over all exports
                    for export in pe_file.DIRECTORY_ENTRY_EXPORT.symbols:
                        # Determine the export name and address
                        export_name = export.name.decode("utf-8") if export.name is not None else ""
                        export_address = export.address if export.address < pe_file.OPTIONAL_HEADER.ImageBase else export.address - pe_file.OPTIONAL_HEADER.ImageBase

                        # Log the module name and export name for the given address
                        self.exports[module.baseaddress + export_address] = [os.path.basename(module.name), export_name]
            except:
                continue

    @QtCore.pyqtSlot(object)
    def resolve_address(self, offset):
        """Get module/symbol name for address"""
        module = ""
        api = ""

        # Construct an exports symbol table if required
        self._build_export_symbol_table()

        # Search exports for offset
        if offset in self.exports:
            module, api = self.exports[offset]

        self.ret = (module, api)

        return self.ret

class SelectProcess(pe_tree.dialogs.ModulePicker):
    """Process/module picker dialog"""
    def __init__(self, window, parent=None):
        super(SelectProcess, self).__init__(window, "Select module...", ["Module", "Image base"], parent=parent)

    def populate_processes(self):
        """Populate the tree view with processes"""
        root = self.model.invisibleRootItem()

        # Determine architecture specifics
        if self.window.runtime.reader.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
            ptr_mask = 0xffffffffffffffff
            ptr_width = 16
        else:
            ptr_mask = 0xffffffff
            ptr_width = 8

        # Iterate over all modules
        for module in self.window.runtime.mf.modules.modules:
            # Determine image base (ignore if null)
            image_base = int(module.baseaddress)

            if image_base == 0:
                continue

            # Create internal filename
            filename = "{} - {:#08x}".format(str(module.name), image_base)

            # Create process tree view item
            process_item = QtGui.QStandardItem("{}".format(str(module.name)))
            process_item.setData({"filename": filename, "module": module, "image_base": image_base}, QtCore.Qt.UserRole)
            process_item.setCheckable(True)
            if root == self.model.invisibleRootItem():
                process_item.setUserTristate(True)

            root.appendRow([process_item, QtGui.QStandardItem("0x{:0{w}x}".format(image_base & ptr_mask, w=ptr_width))])

            if root == self.model.invisibleRootItem():
                root = process_item

        self.treeview.resizeColumnToContents(0)

    def invoke(self):
        """Display the select process/modules dialog"""
        super(SelectProcess, self).invoke()

        # Has the user accepted, i.e. pressed "Dump"?
        if self.exec_() != 0:
            # Dump selected processes/modules
            for item in self.items:
                args = item.item.data(QtCore.Qt.UserRole)
                self.window.pe_tree_form.map_pe(filename=args["filename"], image_base=args["image_base"], opaque={"module": args["module"]})

            self.close()

def main():
    """PE Tree Minidump script entry-point"""
    # Check command line arguments
    parser = ArgumentParser(description="PE-Tree (Minidump)")
    parser.add_argument("filename", help="Path to .dmp file", type=FileType("rb"))
    args = parser.parse_args()

    # Create PE Tree Qt application
    application = QtWidgets.QApplication(sys.argv)
    window = pe_tree.window.PETreeWindow(application, MinidumpRuntime, args, open_file=False)

    # Extend menu to include open process
    select_process = SelectProcess(window)

    open_process_action = QtWidgets.QAction("Process", window)
    open_process_action.setShortcut("Ctrl+Shift+P")
    open_process_action.setStatusTip("Open process")
    open_process_action.triggered.connect(select_process.invoke)
    window.open_menu.addAction(open_process_action)

    # Invoke the process/module picker dialog
    select_process.invoke()

    sys.exit(application.exec_())

if __name__ == "__main__":
    main()
