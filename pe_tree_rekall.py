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

# Qt imports
from PyQt5 import QtCore, QtWidgets, QtGui

# Rekall imports
from rekall_lib import utils

# PE Tree imports
import pe_tree.window
import pe_tree.runtime
import pe_tree.form
import pe_tree.info

# pylint: disable=undefined-variable

class RekallRuntime(pe_tree.runtime.Runtime):
    """Rekall runtime callbacks"""
    def __init__(self, widget, args):
        # Load configuration
        self.config_file = os.path.join(self.get_temp_dir(), "pe_tree_rekall.ini")
        super(RekallRuntime, self).__init__(widget, args)

        # Initialise Rekall
        self.cc = session.plugins.cc()
        self.pedump = session.plugins.pedump()

    @QtCore.pyqtSlot(object, object)
    def read_pe(self, image_base, size=0):
        """Read PE image from memory"""
        outfd = io.BytesIO()

        self.pedump.WritePEFile(outfd, self.opaque["address_space"], image_base)

        self.ret = bytearray(outfd.getbuffer())

        return self.ret

    @QtCore.pyqtSlot(object, object)
    def get_bytes(self, start, size):
        """Read bytes from memory"""
        task = self.opaque["task"]
        if task:
            self.cc.SwitchProcessContext(self.opaque["task"])

        self.ret = self.opaque["address_space"].read(start, size)
        self.ret = b"" if self.ret is None else self.ret
        return self.ret

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

class SelectProcess(pe_tree.dialogs.ModulePicker):
    """Process/module picker dialog"""
    def __init__(self, window, parent=None):
        super(SelectProcess, self).__init__(window, "Select process...", ["Name", "PID", "Image base"], model=ExpandableStandardItemModel, parent=parent)

        self.treeview.expanded.connect(self.populate_modules)

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
            filename = "{} ({}) - {:#08x}".format(str(task.name), task.pid, image_base)

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
                self.items.add(pe_tree.qstandarditems.HashableQStandardItem(driver_item))

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
                    self.items.add(pe_tree.qstandarditems.HashableQStandardItem(dll_item))

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

    def invoke(self):
        """Display the select process/modules dialog"""
        super(SelectProcess, self).invoke()

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
    window = pe_tree.window.PETreeWindow(application, RekallRuntime, {}, open_file=False)

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
