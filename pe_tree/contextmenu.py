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

"""PE Tree right-click context menu"""

# Standard imports
import sys
import base64
import binascii
import webbrowser

try:
    from urllib import quote
except ImportError:
    from urllib.parse import quote

# pefile
import pefile

# IDA imports
try:
    import ida_idaapi
    import idc
    import idautils
    import ida_bytes

    have_ida = True
except ImportError:
    have_ida = False

# Qt imports
from PyQt5 import QtWidgets, Qt

# PE Tree imports
import pe_tree.form
import pe_tree.utils
import pe_tree.dump_pe

class CommonStandardItemContextMenu():
    """Context menu actions for pe_tree.qstandarditems.CommonStandardItem
    
    Instantiate once and re-use for each tree item right-click action by calling new_menu().

    Args:
        form (pe_tree.form): PE Tree form
        
   """

    def __init__(self, form):
        self.form = form
        self.point = None
        self.item = None
        self.index = None
        self.menu = None
        self.actions = []
        self.altitudes = {}

        style = form.widget.style()

        # Create actions/menus
        self.save_dump_action = QtWidgets.QAction(style.standardIcon(QtWidgets.QStyle.SP_DialogSaveButton), "Dump...", form.widget)
        self.expand_all_action = QtWidgets.QAction(style.standardIcon(QtWidgets.QStyle.SP_DirOpenIcon), "Expand all", form.widget)
        self.remove_action = QtWidgets.QAction(style.standardIcon(QtWidgets.QStyle.SP_DialogCancelButton), "Remove", form.widget)
        self.copy_action = QtWidgets.QAction("Copy", form.widget)
        self.hexdump_action = QtWidgets.QAction("Hex-dump", form.widget)
        self.disassemble_action = QtWidgets.QAction("Disassemble", form.widget)
        self.search_idb_action = QtWidgets.QAction(style.standardIcon(QtWidgets.QStyle.SP_FileDialogContentsView), "Search IDB", form.widget)
        self.map_pe_from_cursor_action = QtWidgets.QAction(style.standardIcon(QtWidgets.QStyle.SP_ArrowRight), "From cursor", form.widget)
        self.map_pe_from_file_action = QtWidgets.QAction("From file", form.widget)
        self.add_pe_menu = QtWidgets.QMenu("Add PE")
        self.add_pe_menu.addAction(self.search_idb_action)
        self.add_pe_menu.addAction(self.map_pe_from_cursor_action)
        self.add_pe_menu.addAction(self.map_pe_from_file_action)
        self.rva_action = QtWidgets.QAction("RVA", form.widget)
        self.rva_action.setCheckable(True)
        self.va_action = QtWidgets.QAction("VA", form.widget)
        self.va_action.setCheckable(True)
        self.addressing_menu = QtWidgets.QMenu("Addressing")
        self.addressing_menu.addAction(self.rva_action)
        self.addressing_menu.addAction(self.va_action)
        self.about_action = QtWidgets.QAction("About", form.widget)

        if have_ida == False:
            self.add_pe_menu.menuAction().setVisible(False)

        self.save_action = QtWidgets.QAction(style.standardIcon(QtWidgets.QStyle.SP_DialogSaveButton), "Save", form.widget)
        self.search_vt_action = QtWidgets.QAction(self.form.vt_icon, "VirusTotal", form.widget)
        self.cyberchef_action = QtWidgets.QAction(self.form.cyberchef_icon, "CyberChef", form.widget)

        self.toggle_debug_action = QtWidgets.QAction("Debug", form.widget)
        self.toggle_debug_action.setCheckable(True)

        self.toggle_enable_dump_action = QtWidgets.QAction("Enable dump", form.widget)
        self.toggle_enable_dump_action.setCheckable(True)

        self.toggle_recalculate_pe_checksum_action = QtWidgets.QAction("Recalculate PE checksum", form.widget)
        self.toggle_recalculate_pe_checksum_action.setCheckable(True)

        self.options_menu = QtWidgets.QMenu("Options")
        self.options_menu.addAction(self.toggle_debug_action)
        self.options_menu.addAction(self.toggle_enable_dump_action)
        self.options_menu.addAction(self.toggle_recalculate_pe_checksum_action)

        if have_ida == False:
            self.options_menu.menuAction().setVisible(False)

        # Connect triggers
        self.save_dump_action.triggered.connect(self.save_dump)
        self.expand_all_action.triggered.connect(self.expand_all)
        self.remove_action.triggered.connect(self.remove_root_item)
        self.copy_action.triggered.connect(self.copy_to_clipboard)
        self.hexdump_action.triggered.connect(self.hexdump)
        self.disassemble_action.triggered.connect(self.disassemble)
        self.search_idb_action.triggered.connect(self.search_idb)
        self.map_pe_from_cursor_action.triggered.connect(self.map_pe_from_cursor)
        self.map_pe_from_file_action.triggered.connect(self.map_pe_from_file)
        self.save_action.triggered.connect(self.save_to_file)
        self.search_vt_action.triggered.connect(self.search_vt)
        self.cyberchef_action.triggered.connect(self.cyberchef)
        self.toggle_debug_action.triggered.connect(self.toggle_debug)
        self.toggle_enable_dump_action.triggered.connect(self.toggle_enable_dump)
        self.toggle_recalculate_pe_checksum_action.triggered.connect(self.toggle_recalculate_pe_checksum)
        self.rva_action.triggered.connect(self.toggle_rva)
        self.va_action.triggered.connect(self.toggle_va)
        self.about_action.triggered.connect(self.about_box)

        # Set altitudes
        self.altitudes[self.expand_all_action] = 0
        self.altitudes[self.save_dump_action] = 1
        self.altitudes[self.save_action] = 2
        self.altitudes[self.remove_action] = 3
        self.altitudes[self.copy_action] = 4
        self.altitudes[self.hexdump_action] = 5
        self.altitudes[self.disassemble_action] = 6
        self.altitudes[self.search_vt_action] = 7
        self.altitudes[self.cyberchef_action] = 8
        self.altitudes[self.add_pe_menu] = 9
        self.altitudes[self.addressing_menu] = 10
        self.altitudes[self.options_menu] = 11

    def show_menu(self):
        """Display context menu"""
        actions_by_altitude = {}

        # Determine altitude for actions
        for action in self.actions:
            actions_by_altitude[action] = self.altitudes[action]

        # Add actions/sub-menus to the menu by altitude
        visible = 0

        for action in sorted(actions_by_altitude, key=actions_by_altitude.get):
            if isinstance(action, QtWidgets.QAction):
                self.menu.addAction(action)
                visible += 1 if action.isVisible() else 0
            else:
                self.menu.addMenu(action)
                visible += 1 if action.menuAction().isVisible() else 0

        if have_ida != False:
            # Add about to IDA context menu
            self.menu.addSeparator()
            self.menu.addAction(self.about_action)
            visible += 1

        if visible == 0:
            return

        # Read the config file again
        self.form.runtime.read_config()

        # Set config checkboxes
        self.toggle_debug_action.setChecked(self.form.runtime.get_config_option("config", "debug", False))
        self.toggle_enable_dump_action.setChecked(self.form.runtime.get_config_option("config", "enable_dump", True))
        self.toggle_recalculate_pe_checksum_action.setChecked(self.form.runtime.get_config_option("config", "recalculate_pe_checksum", False))

        # Set addressing checkboxes
        self.rva_action.setChecked(self.item.tree.show_rva)
        self.va_action.setChecked(True if self.item.tree.show_rva == False else False)

        # Show the menu
        self.menu.exec_(self.point)

    def new_menu(self, form, point, item, index):
        """Initialise a new context menu upon right clicking the tree view
        
        Args:
            form (pe_tree.form.PETreeForm): PE Tree form
            point (QPoint): Mouse click co-ordinates
            item (pe_tree.tree.PETree): Item that was right-clicked
            index (QModelIndex): Item model index

        Returns:
            CommonStandardItemContextMenu: self

        """
        self.menu = QtWidgets.QMenu()

        self.form = form
        self.point = point
        self.item = item
        self.index = index
        self.actions = []

        return self

    def toggle_option(self, section, option):
        """Toggle boolean config option
        
        Args:
            section (str): Section name
            option (str): Option name

        """
        self.form.runtime.set_config_option(section, option, str(not self.form.runtime.get_config_option(section, option, False)))

    def toggle_debug(self):
        """Enable/disable debug config option"""
        self.toggle_option("config", "debug")

    def toggle_enable_dump(self):
        """Enable/disable enable_dump config option"""
        self.toggle_option("dump", "enable")

    def toggle_recalculate_pe_checksum(self):
        """Enable/disable recalculate_pe_checksum config option"""
        self.toggle_option("dump", "recalculate_pe_checksum")

    def toggle_rva(self):
        """Enable RVA addressing"""
        self.item.tree.show_rva = True

    def toggle_va(self):
        """Enable VA addressing"""
        self.item.tree.show_rva = False

    def save_dump(self):
        """Find PE root item in list"""
        for tree in self.form.tree_roots:
            if self.item.text() == tree.filename:
                if tree.org_data != None:
                    pe_tree.dump_pe.DumpPEForm(pefile.PE(data=tree.org_data), tree.image_base, tree.size, tree.filename, tree.ptr_size, self.form).invoke()

    def expand_all(self):
        """Expand all nodes beneath the selected node"""
        self.form.treeview.setExpanded(self.index, True)
        self.form.expanding = True
        self.form.expand_items(self.index)
        self.form.expanding = False
        self.form.treeview.resizeColumnToContents(0)
        self.form.treeview.resizeColumnToContents(1)

    def remove_root_item(self):
        """Remove PE file from tree"""
        tree = self.item.tree
        self.form.tree_roots.remove(tree)
        self.form.map_stack.removeWidget(tree.map)
        if hasattr(self.form, "output_stack"):
            self.form.output_stack.removeWidget(tree.output_view)

        self.form.model.removeRow(self.index.row())

    def copy_to_clipboard(self):
        """Copy item text to clipboard and print to IDA output"""
        Qt.QApplication.clipboard().setText(self.item.text())
        self.item.tree.form.runtime.log(self.item.text())

    def hexdump(self):
        """Print hexdump to IDA output"""
        self.item.tree.form.runtime.log(pe_tree.utils.hexdump(self.item.get_data(), self.item.tree.image_base + self.item.offset))

    def disassemble(self):
        """Disassemble using capstone"""
        if self.item.tree.disasm:
            for i in self.item.tree.disasm.disasm(self.item.get_data(size=max(self.item.size, 0x100)), self.item.offset):
                self.item.tree.form.runtime.log("0x{:x}:\t{}\t{}".format(i.address, i.mnemonic, i.op_str))

    def search_idb(self):
        """Search IDB for possible MZ/PE headers"""
        # Search all segments
        for seg in idautils.Segments():
            s = idc.get_segm_start(seg)
            e = idc.get_segm_end(seg)
            addr = s

            while True:
                # Find first byte of MZ header
                addr = ida_bytes.find_byte(addr, e-addr, 0x4d, 0)

                if addr == ida_idaapi.BADADDR or addr >= e:
                    break

                # Check for MZ magic
                if ida_bytes.get_word(addr) == 0x5a4d:
                    # Ensure the PE header is in the segment
                    e_lfanew = ida_bytes.get_dword(addr + 0x3c)

                    if addr + e_lfanew + 1 < e:
                        # Check for PE magic
                        if ida_bytes.get_word(addr + e_lfanew) == 0x4550:
                            # Found possible MZ/PE file
                            self.form.runtime.log("0x{:08x} - {}".format(addr, idc.get_segm_name(s)))

                            self.form.map_pe(image_base=addr)

                # Resume search from next address
                addr += 1

    def map_pe_from_cursor(self):
        """Map PE file from current cursor position"""
        # Is the cursor on an MZ file?
        current = idc.here()

        if ida_bytes.get_word(current) == 0x5a4d:
            self.form.map_pe(image_base=current, priority=1)

    def map_pe_from_file(self):
        """Prompt user to select a file and attempt to map"""
        self.form.map_pe(filename=self.form.runtime.ask_file("*.*", "Open file"))

    def save_to_file(self):
        """Ask user where to save data"""
        filename = self.item.tree.form.runtime.ask_file(self.item.filename, "Save to file", save=True)
        if filename:
            with open(filename, "wb") as ofile:
                # Write data to file
                ofile.write(self.item.get_data())

    def search_vt(self):
        """Search value using VirusTotal"""
        try:
            url = self.form.runtime.get_config_option("config", "virustotal_url", None)

            if url:
                webbrowser.open_new_tab("{}/{}".format(url, quote(quote(self.item.vt_query))))
        except:
            pass

    def cyberchef(self):
        """Open data in CyberChef"""
        if sys.version_info > (3,):
            equals = b"="
        else:
            equals = "="

        try:
            url = self.form.runtime.get_config_option("config", "cyberchef_url", None)

            if url:
                webbrowser.open_new_tab("{}/#recipe=From_Hex('Auto'){}&input={}".format(url, self.item.cyberchef_recipe, base64.b64encode(binascii.hexlify(self.item.get_data())).rstrip(equals).decode("ascii")))
        except:
            pass

    def about_box(self):
        """Display application about box"""
        self.item.tree.form.runtime.about_box()
