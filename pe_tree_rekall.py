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

"""PE Tree Rekall plugin"""

# Standard imports
import os
import io
import sys
import struct
import builtins

# pefile
import pefile

# Capstone imports
import capstone

# Qt imports
from PyQt5 import QtCore, QtWidgets, QtGui

# Rekall imports
from rekall_lib import utils

# PE Tree imports
import pe_tree.__main__
import pe_tree.runtime
import pe_tree.form
import pe_tree.info

class RekallRuntime(pe_tree.runtime.Runtime):
    """IDA runtime callbacks"""
    def __init__(self, widget):
        # Load configuration
        self.config_file = os.path.join(self.get_temp_dir(), "pe_tree_rekall.ini")
        super(RekallRuntime, self).__init__(widget)
        
        # Initialise Rekall
        self.cc = session.plugins.cc()
        self.pedump = session.plugins.pedump()

    def jumpto(self, item, offset):
        """Disassemble using capstone"""
        if item.tree.disasm:
            for i in item.tree.disasm.disasm(item.get_data(size=0x100), offset):
                item.tree.form.runtime.log("0x{:x}:\t{}\t{}".format(i.address, i.mnemonic, i.op_str))

        self.ret = True
        return self.ret

    @QtCore.pyqtSlot(str)
    def log(self, output):
        """Append log message to the output view"""
        output_view = self.pe_tree_form.output_stack.currentWidget()
        if output_view:
            output_view.append(output)
            output_view.moveCursor(QtGui.QTextCursor.End)

        self.ret = True
        return self.ret

    @QtCore.pyqtSlot(object, object)
    def read_pe(self, image_base, size=0):
        """Read PE image from memory"""
        outfd = io.BytesIO()

        self.pedump.WritePEFile(outfd, self.opaque["address_space"], image_base)

        self.ret = bytearray(outfd.getbuffer())

        return self.ret

    @QtCore.pyqtSlot(object, object)
    def get_bytes(self, start, end):
        """Read bytes from memory"""
        task = self.opaque["task"]
        if task:
            self.cc.SwitchProcessContext(self.opaque["task"])

        self.ret = self.opaque["address_space"].read(start, end)
        self.ret = b"" if self.ret is None else self.ret
        return self.ret

    @QtCore.pyqtSlot(object)
    def get_byte(self, offset):
        """Read byte from memory"""
        return self.get_bytes(offset, offset + 1)

    @QtCore.pyqtSlot(object)
    def get_word(self, offset):
        """Read word from memory"""
        return struct.unpack("<H", self.get_bytes(offset, 2))[0]

    @QtCore.pyqtSlot(object)
    def get_dword(self, offset):
        """Read dword from memory"""
        return struct.unpack("<I", self.get_bytes(offset, 4))[0]

    @QtCore.pyqtSlot(object)
    def get_qword(self, offset):
        """Read qword from memory"""
        return struct.unpack("<Q", self.get_bytes(offset, 8))[0]

    @QtCore.pyqtSlot(object)
    def is_writable(self, offset):
        """Determine if memory address is writable"""
        self.ret = False

        task = self.opaque["task"]
        if task is not None:
            self.cc.SwitchProcessContext(task)

            # Traverse VADs
            for vad in task.RealVadRoot.traverse():
                # Is address within the VAD region?
                if vad.Start <= offset <= vad.End:
                    # Is the VAD region writable?
                    if "WRITE" in str(vad.u.VadFlags.ProtectionEnum):
                        self.ret = True

        return self.ret

    @QtCore.pyqtSlot(object)
    def resolve_address(self, offset):
        """Get module/symbol name for address"""
        module = ""
        api = ""

        task = self.opaque["task"]
        if task is not None:
            self.cc.SwitchProcessContext(task)

        symbols = session.address_resolver.format_address(offset)

        if len(symbols) > 0:
            symbol = symbols[0]

            if "!" in symbol:
                split_symbol = symbol.split("!")
                module = "{}.dll".format(split_symbol[0])
                api = "".join(split_symbol[1:])

        self.ret = (module, api)
        return self.ret

    @QtCore.pyqtSlot(object, object, object, object)
    def find_iat_ptrs(self, pe, image_base, size, get_word):
        """Find all likely IAT pointers"""
        # Initialise capstone
        disasm = self.init_capstone(pe)
        disasm.detail = True

        iat_ptrs = []

        # Traverse sections
        for section in pe.sections:
            # Is the section executable?
            if not section.Characteristics & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]:
                continue

            # Does the section contain anything?
            data = section.get_data()

            if not data:
                continue

            # Disassemble section
            for i in disasm.disasm(section.get_data(), image_base + section.VirtualAddress):
                # Attempt to read the current instruction's effective memory address operand (if present)
                ptr = 0

                if i.mnemonic in ["call", "push", "jmp"]:
                    if i.operands[0].type == capstone.x86.X86_OP_MEM:
                        # Get memory offset for branch instructions
                        ptr = i.operands[0].value.mem.disp
                elif i.mnemonic in ["mov", "lea"]:
                    if i.operands[0].type == capstone.x86.X86_OP_REG and i.operands[1].type == capstone.x86.X86_OP_MEM:
                        # Get memory offset for mov/lea instructions
                        ptr = i.operands[1].value.mem.disp

                # Does the instruction's memory address operand seem somewhat valid?!
                if ptr < 0x1000:
                    continue

                # Resolve pointer from memory operand
                iat_offset = get_word(ptr)

                # Ignore offset if it is in our image
                if image_base <= iat_offset <= image_base + size:
                    continue

                # Get module and API name for offset
                module, api = self.resolve_address(iat_offset)

                # Ignore the offset if it is in a debug segment or stack etc
                if api and module and module.endswith(".dll"):
                    if not iat_offset in iat_ptrs:
                        # Add IAT offset, address to patch, module name and API name to list
                        iat_ptrs.append((iat_offset, i.address + len(i.bytes) - 4, module, api))

        self.ret = iat_ptrs
        return self.ret

class ExpandableStandardItemModel(QtGui.QStandardItemModel):
    """Set expandable role on process items to force the drawing of expand/collapse arrows without child items present (allows for lazy loading of modules)"""
    ExpandableRole = QtCore.Qt.UserRole + 500

    def hasChildren(self, index):
        """Determine if the item has children or is expandable

        Args:
            index (QModelIndex): Index of item

        Returns:
            bool: True if the item has children or is expandable

        """
        if self.data(index, ExpandableStandardItemModel.ExpandableRole):
            return True

        return super(ExpandableStandardItemModel, self).hasChildren(index)

class HashableQStandardItem():
    """Hashable QStandardItem wrapper for storing in a set()"""
    def __init__(self, item):
        self.item = item
        self.args = item.data(QtCore.Qt.UserRole)

    def __hash__(self):
        """Filename is hash"""
        return builtins.hash(self.args["filename"])

    def __eq__(self, other):
        """Test if items are equal"""
        if not isinstance(other, type(self)):
            return NotImplemented

        return self.args["filename"] == other.item.data(QtCore.Qt.UserRole)["filename"]

    def __ne__(self, other):
        return not self.__eq__(other)

class SelectProcess(QtWidgets.QDialog):
    """Process/module picker dialog"""
    def __init__(self, window, parent=None):
        super(SelectProcess, self).__init__(parent)

        self.window = window
        self.items = set()

        # Initialise the dialog
        self.setWindowTitle("Select process...")

        self.setMinimumWidth(400)
        self.setMinimumHeight(600)

        # Create the process/module tree view and model
        self.treeview = QtWidgets.QTreeView()
        self.model = ExpandableStandardItemModel(self.treeview)
        self.model.setHorizontalHeaderLabels(["Name", "PID", "Image base"])
        self.model.itemChanged.connect(self.item_changed)
        self.treeview.setModel(self.model)
        self.treeview.expanded.connect(self.populate_modules)
        self.treeview.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.treeview.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        # Create the buttons
        button_box = QtWidgets.QDialogButtonBox()
        button_box.addButton("Dump", QtWidgets.QDialogButtonBox.AcceptRole)
        button_box.addButton("Cancel", QtWidgets.QDialogButtonBox.RejectRole)

        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        # Create the layout
        grid = QtWidgets.QGridLayout()
        grid.setSpacing(10)

        grid.addWidget(self.treeview, 0, 0)
        grid.addWidget(button_box, 1, 0)

        self.setLayout(grid)

        self.populate_processes()

    def populate_processes(self):
        """Populate the tree view with processes"""
        root = self.model.invisibleRootItem()

        # Iterate over all processes
        for task in session.plugins.pslist(proc_regex="").filter_processes():
            # Determine image base (ignore if null)
            image_base = int(task.Peb.ImageBaseAddress) if int(task.Peb.ImageBaseAddress) else 0

            if image_base == 0:
                continue

            # Create internal filename
            filename = "{} ({}) - 0x{:#08x}".format(str(task.name), task.pid, image_base)

            # Create process tree view item
            process_item = QtGui.QStandardItem("{}".format(str(task.name)))
            process_item.setData({"filename": filename, "address_space": task.get_process_address_space(), "task": task, "image_base": image_base}, QtCore.Qt.UserRole)
            process_item.setUserTristate(True)
            process_item.setCheckable(True)
            process_item.setData(True, ExpandableStandardItemModel.ExpandableRole)

            # Determine architecture specifics
            if task.address_mode == "AMD64":
                ptr_mask = 0xffffffffffffffff
                ptr_width = 16
            else:
                ptr_mask = 0xffffffff
                ptr_width = 8

            root.appendRow([process_item, QtGui.QStandardItem("{}".format(task.pid)), QtGui.QStandardItem("0x{:0{w}x}".format(image_base & ptr_mask, w=ptr_width))])

        self.treeview.resizeColumnToContents(0)

    def populate_drivers(self, parent):
        """Populate the tree view with drivers"""
        # Build a list of all address spaces
        address_spaces = [session.kernel_address_space]
        for task in session.plugins.pslist().filter_processes():
            address_spaces.append(task.get_process_address_space())

        # Determine architecture specifics
        if session.profile.metadata("arch") == "AMD64":
            ptr_mask = 0xffffffffffffffff
            ptr_width = 16
        else:
            ptr_mask = 0xffffffff
            ptr_width = 8

        for module in session.plugins.modules().lsmod():
            # Ensure the driver's image base is non-null
            image_base = int(module.DllBase) if int(module.DllBase) else 0

            if image_base == 0:
                continue

            # Locate the address space
            address_space = None

            for a in address_spaces:
                if a.is_valid_address(image_base):
                    address_space = a

            if not address_space:
                continue

            # Create internal filename
            base_name = os.path.basename(utils.SmartUnicode(module.BaseDllName))
            filename = "{} - 0x{:0x}".format(utils.EscapeForFilesystem(base_name), int(module.DllBase))

            # Create driver tree view item
            driver_item = QtGui.QStandardItem("{}".format(utils.EscapeForFilesystem(base_name)))
            driver_item.setData({"filename": filename, "task": None, "address_space": address_space, "image_base": image_base}, QtCore.Qt.UserRole)
            driver_item.setCheckable(True)
            driver_item.setCheckState(QtCore.Qt.Checked if parent.checkState() == QtCore.Qt.Checked else QtCore.Qt.Unchecked)
            if parent.checkState() == QtCore.Qt.Checked:
                    self.items.add(HashableQStandardItem(driver_item))

            parent.appendRow([driver_item, QtGui.QStandardItem("N/A"), QtGui.QStandardItem("0x{:0{w}x}".format(image_base & ptr_mask, w=ptr_width))])

    def populate_dlls(self, parent, task):
        """Populate the tree view with DLLs"""
        task_as = task.get_process_address_space()

        # Determine architecture specifics
        if task.address_mode == "AMD64":
            ptr_mask = 0xffffffffffffffff
            ptr_width = 16
        else:
            ptr_mask = 0xffffffff
            ptr_width = 8

        # Iterate over loaded modules (use ldrmodules plugin)
        for module in session.plugins.ldrmodules(pids=[task.pid]):
            if module.get("in_mem") and module.get("base") > 0:
                 # Ensure the image base is non-null and not the parent process
                image_base = int(module.get("base"))

                if image_base == 0 or image_base == int(task.Peb.ImageBaseAddress):
                    continue

                 # Create internal filename
                base_name = os.path.basename(utils.SmartUnicode(module.get("in_mem_path")))
                filename = "{} ({} - {}) - 0x{:0x}".format(utils.EscapeForFilesystem(base_name), task.name, task.pid, image_base)

                # Create DLL tree view item
                dll_item = QtGui.QStandardItem("{}".format(utils.EscapeForFilesystem(base_name)))
                dll_item.setData({"filename": filename, "task": task, "address_space": task_as, "image_base": image_base}, QtCore.Qt.UserRole)
                dll_item.setCheckable(True)
                dll_item.setCheckState(QtCore.Qt.Checked if parent.checkState() == QtCore.Qt.Checked else QtCore.Qt.Unchecked)
                if parent.checkState() == QtCore.Qt.Checked:
                    self.items.add(HashableQStandardItem(dll_item))

                parent.appendRow([dll_item, QtGui.QStandardItem("{}".format(task.pid)), QtGui.QStandardItem("0x{:0{w}x}".format(image_base & ptr_mask, w=ptr_width))])

        return

        # Iterate over loaded modules (via PEB in-order module list)
        for module in task.get_load_modules():
            process_offset = task_as.vtop(task.obj_offset)
            if process_offset:
                # Ensure the image base is non-null and not the parent process
                image_base = int(module.DllBase) if int(module.DllBase) else 0

                if image_base == 0 or image_base == int(task.Peb.ImageBaseAddress):
                    continue

                # Create internal filename
                base_name = os.path.basename(utils.SmartUnicode(module.BaseDllName))
                filename = "{} ({} - {}) - 0x{:0x}".format(utils.EscapeForFilesystem(base_name), task.name, task.pid, int(module.DllBase))

                # Create DLL tree view item
                dll_item = QtGui.QStandardItem("{}".format(utils.EscapeForFilesystem(base_name)))
                dll_item.setData({"filename": filename, "task": task, "address_space": task_as, "image_base": image_base}, QtCore.Qt.UserRole)
                dll_item.setCheckable(True)
                dll_item.setCheckState(QtCore.Qt.Checked if parent.checkState() == QtCore.Qt.Checked else QtCore.Qt.Unchecked)
                if parent.checkState() == QtCore.Qt.Checked:
                    self.items.add(HashableQStandardItem(dll_item))

                parent.appendRow([dll_item, QtGui.QStandardItem("{}".format(task.pid)), QtGui.QStandardItem("0x{:0{w}x}".format(image_base & ptr_mask, w=ptr_width))])

    def populate_modules(self, index):
        """Lazy load modules to the tree view when the user expands a process"""
        # Find the parent item
        parent = self.model.itemFromIndex(index)
        args = parent.data(QtCore.Qt.UserRole)

        # Ensure the parent is a root item without any children
        if parent.parent() is not None or parent.rowCount() > 0:
            return

        # Get the associated task and address space
        task = args["task"]

        if task.pid == 4:
            # Load drivers under the system process
            self.populate_drivers(parent)
        else:
            # Load DLLs under the parent process
            self.populate_dlls(parent, task)

        # Expand the tree view and resize the filename column
        self.treeview.expand(index)
        self.treeview.resizeColumnToContents(0)

    def item_changed(self, item):
        """Record selected items in the tree view"""
        if item.checkState() == QtCore.Qt.PartiallyChecked:
            # Add to list of selected items
            self.items.add(HashableQStandardItem(item))

            # If parent item then unselect all children
            if item.hasChildren():
                for row in range(0, item.rowCount()):
                    child = item.child(row)
                    child.setCheckState(QtCore.Qt.Unchecked)
                    self.items.discard(HashableQStandardItem(child))

        elif item.checkState() == QtCore.Qt.Checked:
            # Add to list of selected items
            self.items.add(HashableQStandardItem(item))

            # If parent item then select all children
            if item.hasChildren():
                for row in range(0, item.rowCount()):
                    child = item.child(row)
                    child.setCheckState(QtCore.Qt.Checked)
                    self.items.add(HashableQStandardItem(child))

            elif item.parent() is None:
                # Expand the root item
                self.treeview.setExpanded(item.index(), True)

        elif item.checkState() == QtCore.Qt.Unchecked:
            # Remove from list of selected items
            self.items.discard(HashableQStandardItem(item))

            # If parent item then unselect all children
            if item.hasChildren():
                for row in range(0, item.rowCount()):
                    child = item.child(row)
                    child.setCheckState(QtCore.Qt.Unchecked)
                    self.items.discard(HashableQStandardItem(child))

    def invoke(self):
        """Display the select process/modules dialog"""
        # Has the user accepted, i.e. pressed "Dump"?
        if self.exec_() != 0:
            # Dump selected processes/modules
            for item in self.items:
                args = item.item.data(QtCore.Qt.UserRole)
                self.window.pe_tree_form.map_pe(filename=args["filename"], image_base=args["image_base"], opaque={"address_space": args["address_space"], "task": args["task"]})

            self.close()

def main():
    """PE Tree Rekall script entry-point"""
    # Create PE Tree Qt application
    application = QtWidgets.QApplication(sys.argv)
    window = pe_tree.__main__.PETreeWindow(application, RekallRuntime, open_file=False)
    window.showMaximized()

    select_process = SelectProcess(window)

    # Extend menu to include open process
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
