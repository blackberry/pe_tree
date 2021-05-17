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

"""PE Tree Volatility3 application"""

# Standard imports
import os
import sys
from argparse import ArgumentParser, FileType

# pefile
import pefile

# Qt imports
from PyQt5 import QtCore, QtWidgets, QtGui

# Volatility3 imports
try:
    from volatility3 import framework, plugins
    from volatility3.framework import contexts, interfaces, symbols
    from volatility3.plugins.windows import pslist, modules, vadinfo
except ModuleNotFoundError:
    print("volatility3 is required")
    exit()

# PE Tree imports
import pe_tree.window
import pe_tree.dialogs
import pe_tree.runtime
import pe_tree.form
import pe_tree.qstandarditems
import pe_tree.info

class VolatilityRuntime(pe_tree.runtime.Runtime):
    """Volatility runtime callbacks"""
    def __init__(self, widget, args):
        # Load configuration
        self.config_file = os.path.join(self.get_temp_dir(), "pe_tree_volatility.ini")
        super(VolatilityRuntime, self).__init__(widget, args)

        # Initialise Volatility3
        framework.require_interface_version(1, 0, 0)
        self.context = contexts.Context()

        # Input file in URI format
        single_location = "file:///{}".format(self.args.filename.name)
        self.context.config["automagic.LayerStacker.single_location"] = single_location
        self.context.config["single_location"] = single_location

        # Find supported plugins
        plugins.__path__ = framework.constants.PLUGINS_PATH
        framework.import_files(plugins, True)
        self.plugin_list = framework.list_plugins()

        # Initialise required plugins configuration
        self._automagic("windows.pslist.PsList")
        self._automagic("windows.vadinfo.VadInfo")
        self._automagic("windows.modules.Modules")

    @QtCore.pyqtSlot(object, object)
    def get_bytes(self, start, size):
        """Read bytes from memory"""
        # Create the process layer if required
        if "proc" in self.opaque and "proc_layer_name" not in self.opaque:
            if self.opaque["proc"]:
                self.opaque["proc_layer_name"] = self.opaque["proc"].add_process_layer()

        # Find the process' layer
        proc_layer = self.context.layers[self.opaque["proc_layer_name"]]

        try:
            # Read from the process layer
            self.ret = proc_layer.read(start, size, pad=True)
        except (framework.exceptions.PagedInvalidAddressException, framework.exceptions.InvalidAddressException):
            # Might be the page isn't available, fake it
            self.ret = b"\0" * size

        self.ret = b"" if self.ret is None else self.ret
        return self.ret

    @QtCore.pyqtSlot(object)
    def is_writable(self, offset):
        """Determine if memory address is writable"""
        self.ret = False

        # Require a process
        if "proc" in self.opaque:
            # Iterate over VADs
            for vad in self.get_vads(self.opaque["proc"]):
                # Does the VAD contain the offset?
                if offset >= vad.get_start() and offset < vad.get_end():
                    # Check for write protection flag
                    if "WRITE" in vad.get_protection(vadinfo.VadInfo.protect_values(self.context, self.context.config["plugins.VadInfo.VadInfo.primary"], self.context.config["plugins.VadInfo.VadInfo.nt_symbols"]), vadinfo.winnt_protections):
                        self.ret = True
                        break

        return self.ret

    def _build_export_symbol_table(self):
        """Iterate over all load order modules in a processes address space and construct an exported function symbol table"""
        # Require an export symbols table
        if "exports" not in self.opaque:
            return

        # Require a process
        if "proc" not in self.opaque or self.opaque["proc"] is None:
            return

        # Skip if already built
        if len(self.opaque["exports"]) > 0:
            return

        if self.opaque["proc"].UniqueProcessId == 4:
            # Find all kernel modules
            export_modules = self.get_modules()

            # Find the kernel layer name
            self.opaque["proc_layer_name"] = self.context.config["plugins.Modules.Modules.primary"]
        else:
            # Find all process load order modules
            export_modules = self.opaque["proc"].load_order_modules()

        # Iterate over all modules
        for entry in export_modules:
            try:
                # Ensure the module has an MZ header
                if self.get_word(entry.DllBase) != 0x5a4d:
                    continue

                # Dump and re-parse the PE
                pe_file = pefile.PE(data=self.read_pe(entry.DllBase))

                # Check for exports data directory
                if hasattr(pe_file, "DIRECTORY_ENTRY_EXPORT"):
                    # Iterate over all exports
                    for export in pe_file.DIRECTORY_ENTRY_EXPORT.symbols:
                        # Determine the export name and address
                        export_name = export.name.decode("utf-8") if export.name is not None else ""
                        export_address = export.address if export.address < pe_file.OPTIONAL_HEADER.ImageBase else export.address - pe_file.OPTIONAL_HEADER.ImageBase

                        # Log the module name and export name for the given address
                        self.opaque["exports"][entry.DllBase + export_address] = [entry.BaseDllName.get_string(), export_name]
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
        if "exports" in self.opaque:
            exports = self.opaque["exports"]
            if offset in exports:
                module, api = exports[offset]

        self.ret = (module, api)

        return self.ret

    def _automagic(self, plugin_name):
        """Use automagic to initialise volatility plugin configuration"""
        plugin = self.plugin_list[plugin_name]
        available_automagics = framework.automagic.available(self.context)
        framework.automagic.choose_automagic(available_automagics, plugin)
        framework.automagic.run(available_automagics, self.context, plugin, interfaces.configuration.path_join("plugins", plugin.__name__))

    def get_procs(self):
        """Run windows.pslist.PsList plugin"""
        return pslist.PsList.list_processes(context=self.context, layer_name=self.context.config["plugins.PsList.PsList.primary"], symbol_table=self.context.config["plugins.PsList.PsList.nt_symbols"])

    def get_modules(self):
        """Run windows.modules.Modules plugin"""
        return modules.Modules.list_modules(context=self.context, layer_name=self.context.config["plugins.Modules.Modules.primary"], symbol_table=self.context.config["plugins.Modules.Modules.nt_symbols"])

    def get_vads(self, proc):
        """Run windows.vadinfo.VadInfo plugin"""
        return vadinfo.VadInfo.list_vads(proc)

class SelectProcess(pe_tree.dialogs.ModulePicker):
    """Process/module picker dialog"""
    def __init__(self, window, parent=None):
        super(SelectProcess, self).__init__(window, "Select process...", ["Name", "PID", "PPID", "Image base", "Threads", "Handles", "Create time", "IsWow64"], parent=parent)

    def make_process_item(self, proc, entry, exports, expandable=False):
        image_base = int(entry.DllBase)
        # Create internal filename
        filename = "{} ({}) - {:#08x}".format(str(entry.BaseDllName.get_string()), proc.UniqueProcessId, image_base)

        # Create process tree view item
        process_item = QtGui.QStandardItem("{}".format(str(entry.BaseDllName.get_string())))
        process_item.setData({"filename": filename, "proc": proc, "entry": entry, "exports": exports, "image_base": image_base}, QtCore.Qt.UserRole)
        process_item.setCheckable(True)
        if expandable:
            process_item.setUserTristate(True)

        return process_item

    def populate_processes(self):
        """Populate the tree view with processes"""
        root = self.model.invisibleRootItem()

        for proc in self.window.runtime.get_procs():
            root = self.model.invisibleRootItem()

            # This will hold the export symbol table for an entire process
            exports = {}

            # System process?
            if proc.UniqueProcessId == 4:
                image_base = self.window.runtime.context.config["plugins.PsList.PsList.primary.kernel_virtual_offset"]

                # Create internal filename
                filename = "{} ({}) - {:#08x}".format("System", proc.UniqueProcessId, image_base)

                # Create process tree view item
                process_item = QtGui.QStandardItem("System")
                process_item.setData({"filename": filename, "proc": proc, "entry": None, "exports": exports, "image_base": image_base}, QtCore.Qt.UserRole)
                process_item.setUserTristate(True)
                process_item.setCheckable(True)

                # Determine kernel architecture specifics
                if symbols.symbol_table_is_64bit(self.window.runtime.context, self.window.runtime.context.config["plugins.PsList.PsList.nt_symbols"]):
                    ptr_mask = 0xffffffffffffffff
                    ptr_width = 16
                else:
                    ptr_mask = 0xffffffff
                    ptr_width = 8

                root.appendRow([process_item,
                                QtGui.QStandardItem("{}".format(proc.UniqueProcessId)),
                                QtGui.QStandardItem("{}".format(proc.InheritedFromUniqueProcessId)),
                                QtGui.QStandardItem("0x{:0{w}x}".format(image_base & ptr_mask, w=ptr_width)),
                                QtGui.QStandardItem(""),
                                QtGui.QStandardItem(""),
                                QtGui.QStandardItem(""),
                                QtGui.QStandardItem("")])

                root = process_item

                # Iterate over kernel modules
                for module in self.window.runtime.get_modules():
                    try:
                        process_item = self.make_process_item(proc, module, exports)

                        root.appendRow([process_item,
                                        QtGui.QStandardItem("{}".format(proc.UniqueProcessId)),
                                        QtGui.QStandardItem(""),
                                        QtGui.QStandardItem("0x{:0{w}x}".format(int(module.DllBase) & ptr_mask, w=ptr_width)),
                                        QtGui.QStandardItem(""),
                                        QtGui.QStandardItem(""),
                                        QtGui.QStandardItem(""),
                                        QtGui.QStandardItem("")])

                    except framework.exceptions.PagedInvalidAddressException:
                        pass

            # Iterate over load order modules
            for entry in proc.load_order_modules():
                try:
                    process_item = self.make_process_item(proc, entry, exports, expandable=bool(root == self.model.invisibleRootItem()))
                except framework.exceptions.PagedInvalidAddressException:
                    continue

                # Determine process architecture specifics
                if proc.get_is_wow64():
                    ptr_mask = 0xffffffffffffffff
                    ptr_width = 16
                else:
                    ptr_mask = 0xffffffff
                    ptr_width = 8


                if root == self.model.invisibleRootItem():
                    # Include full details for the main process
                    root.appendRow([process_item,
                                    QtGui.QStandardItem("{}".format(proc.UniqueProcessId)),
                                    QtGui.QStandardItem("{}".format(proc.InheritedFromUniqueProcessId)),
                                    QtGui.QStandardItem("0x{:0{w}x}".format(int(entry.DllBase) & ptr_mask, w=ptr_width)),
                                    QtGui.QStandardItem("{}".format(proc.ActiveThreads)),
                                    QtGui.QStandardItem("{}".format(proc.get_handle_count())),
                                    QtGui.QStandardItem("{}".format(proc.get_create_time())),
                                    QtGui.QStandardItem("{}".format(proc.get_is_wow64()))])

                    root = process_item
                else:
                    # Add details for the DLL
                    root.appendRow([process_item,
                                    QtGui.QStandardItem("{}".format(proc.UniqueProcessId)),
                                    QtGui.QStandardItem("{}".format(proc.InheritedFromUniqueProcessId)),
                                    QtGui.QStandardItem("0x{:0{w}x}".format(int(entry.DllBase) & ptr_mask, w=ptr_width)),
                                    QtGui.QStandardItem(""),
                                    QtGui.QStandardItem(""),
                                    QtGui.QStandardItem(""),
                                    QtGui.QStandardItem("")])

            for i in range(0, 7):
                self.treeview.resizeColumnToContents(i)

    def invoke(self):
        """Display the select process/modules dialog"""
        super(SelectProcess, self).invoke()

        # Has the user accepted, i.e. pressed "Dump"?
        if self.exec_() != 0:
            # Dump selected processes/modules
            for item in self.items:
                args = item.item.data(QtCore.Qt.UserRole)
                self.window.pe_tree_form.map_pe(filename=args["filename"], image_base=args["image_base"], opaque={"proc": args["proc"], "entry": args["entry"], "exports": args["exports"]})

            self.close()

def main():
    """PE Tree Volatility script entry-point"""
    # Check command line arguments
    parser = ArgumentParser(description="PE-Tree (Volatility)")
    parser.add_argument("filename", help="Path to memory dump", type=FileType("rb"))
    args = parser.parse_args()

    # Create PE Tree Qt application
    application = QtWidgets.QApplication(sys.argv)

    window = pe_tree.window.PETreeWindow(application, VolatilityRuntime, args, open_file=False)

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

if __name__ == '__main__':
    main()
