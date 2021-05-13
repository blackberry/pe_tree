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

"""PE Tree IDAPython plugin"""

# Standard imports
import os
import sys

# Qt imports
from PyQt5 import QtCore, QtWidgets

# IDAPython imports

# pylint: disable=import-error

import idaapi
import ida_idaapi
import idc
import ida_bytes
import ida_name
import ida_kernwin
import idautils
import sip

# PE Tree imports
if "pe_tree" in sys.modules:
    # Reload all PE Tree modules as IDA will keep them loaded
    try:
        from importlib import reload
    except ImportError:
        from imp import reload

    try:
        reload(pe_tree)
        reload(pe_tree.runtime)
        reload(pe_tree.form)
        reload(pe_tree.info)
        reload(pe_tree.contextmenu)
        reload(pe_tree.dump_pe)
        reload(pe_tree.exceptions)
        reload(pe_tree.hash_pe)
        reload(pe_tree.map)
        reload(pe_tree.qstandarditems)
        reload(pe_tree.tree)
        reload(pe_tree.utils)
        reload(pe_tree.dialogs)
    except NameError:
        pass

import pe_tree.runtime
import pe_tree.form
import pe_tree.info

class IDARuntime(pe_tree.runtime.Runtime):
    """IDA runtime callbacks"""
    def __init__(self, widget, args):
        # Load configuration
        self.config_file = os.path.join(self.get_temp_dir(), "pe_tree.ini")
        super(IDARuntime, self).__init__(widget, args)

    def get_temp_dir(self):
        """Get path to temporary directory"""
        self.ret = idaapi.get_user_idadir()
        return self.ret

    def ask_file(self, filename, caption, filter="", save=False):
        """Open/save file dialog"""
        if not save:
            # Open file dialog
            self.ret = ida_kernwin.ask_file(0, os.path.basename(str(filename)), str(caption))
        else:
            # Save file dialog
            if filename[0] == ".":
                # Remove leading dot from section names
                filename = filename[1:]

            self.ret = ida_kernwin.ask_file(1, os.path.basename(str(filename)), str(caption))

        return self.ret

    def show_widget(self):
        """Display the PE Tree widget"""
        self.ret = idaapi.display_widget(self.widget, (idaapi.PluginForm.WOPN_TAB | idaapi.PluginForm.WOPN_MENU | idaapi.PluginForm.WOPN_RESTORE | idaapi.PluginForm.WOPN_PERSIST))

        return self.ret

    @QtCore.pyqtSlot(object, int)
    def jumpto(self, item, offset):
        """Jump to offset in IDA view"""
        try:
            self.ret = idc.jumpto(offset)
        except:
            self.ret = False

        return self.ret

    @QtCore.pyqtSlot(str)
    def log(self, output):
        """Print to output"""
        print(output)

    @QtCore.pyqtSlot(object, object)
    def get_bytes(self, start, size):
        """Read bytes from IDB"""
        self.ret = idc.get_bytes(start, size)
        return self.ret

    @QtCore.pyqtSlot(object)
    def get_byte(self, offset):
        """Read byte from IDB"""
        self.ret = ida_bytes.get_byte(offset)
        return self.ret

    @QtCore.pyqtSlot(object)
    def get_word(self, offset):
        """Read word from IDB"""
        self.ret = ida_bytes.get_word(offset)
        return self.ret

    @QtCore.pyqtSlot(object)
    def get_dword(self, offset):
        """Read dword from IDB"""
        self.ret = ida_bytes.get_dword(offset)
        return self.ret

    @QtCore.pyqtSlot(object)
    def get_qword(self, offset):
        """Read qword from IDB"""
        self.ret = ida_bytes.get_qword(offset)
        return self.ret

    @QtCore.pyqtSlot(object)
    def get_name(self, offset):
        """Get name for offset from IDB"""
        self.ret = idc.get_name(offset, ida_name.GN_VISIBLE)
        return self.ret

    @QtCore.pyqtSlot(object)
    def get_segment_name(self, offset):
        """Get segment name for offset from IDB"""
        self.ret = idc.get_segm_name(offset)
        return self.ret

    @QtCore.pyqtSlot(object)
    def is_writable(self, offset):
        """Determine if memory address is writable"""
        self.ret = bool(idaapi.getseg(offset).perm & idaapi.SEGPERM_WRITE)
        return self.ret

    @QtCore.pyqtSlot(object)
    def resolve_address(self, offset):
        """Get module/symbol name for address"""
        symbol = self.get_name(offset)
        module = self.get_segment_name(offset)

        if not module and  "_" in symbol:
            # No module name for the segment, try to determine from the symbol name
            symbol_split = symbol.split("_")

            # Given a symbol, i.e. ws2_32_WSAStartup, can we find ws2_32.dll in the list of segments?
            for segment in idautils.Segments():
                segment_name = idc.get_segm_name(segment).lower()

                if segment_name.startswith(symbol_split[0].lower()):
                    new_name = ""
                    for i in range(0, len(symbol_split)):
                        new_name = "{}.dll".format("_".join(symbol_split[0:i]))
                        if new_name == segment_name:
                            break

                    if new_name == segment_name:
                        module = new_name
                        break

        # Still nothing?!
        if not module and  "_" in symbol:
            symbol_split = symbol.split("_")

            j = 1
            if symbol_split[0] == "ws2":
                j += 1
                module = "{}.dll".format("_".join(symbol_split[0:j]))
            else:
                module = "{}.dll".format(symbol_split[0])

        # Strip module name from symbol name
        if module:
            module_name = module.split(".")[0].lower()

            if symbol[:len(module_name)].lower().startswith(module_name):
                symbol = symbol[len(module_name) + 1:]

        if not symbol:
            symbol = "{:x}".format(offset)

        self.ret = (module, symbol)
        return self.ret

    @QtCore.pyqtSlot(object)
    def get_label(self, offset):
        """Get label for offest from IDB"""
        self.ret = idc.GetDisasm(offset).replace("extrn ", "").split(":")[0]
        return self.ret

    @QtCore.pyqtSlot(object, object)
    def make_string(self, offset, size):
        """Convert range to byte string in IDB"""
        self.ret = idc.create_strlit(offset, offset + size)
        return self.ret

    @QtCore.pyqtSlot(object, object, str, str, bytes)
    def make_segment(self, offset, size, class_name="DATA", name="pe_map", data=None):
        """Create a new section in the IDB"""
        idc.AddSeg(offset, offset + size, 0, 1, 0, idaapi.scPub)
        idc.RenameSeg(offset, str(name))
        idc.SetSegClass(offset, str(class_name))
        #idc.SegAlign(offset, idc.saRelPara)
        if data:
            idaapi.patch_many_bytes(offset, bytes(data))

        self.ret = None
        return self.ret

    @QtCore.pyqtSlot(object)
    def make_qword(self, offset):
        """Create a qword at the given offset in the IDB"""
        self.ret = idaapi.create_qword(offset, 8)
        return self.ret

    @QtCore.pyqtSlot(object)
    def make_dword(self, offset):
        """Create a dword at the given offset in the IDB"""
        self.ret = idaapi.create_dword(offset, 4)
        return self.ret

    @QtCore.pyqtSlot(object)
    def make_word(self, offset):
        """Create a word at the given offset in the IDB"""
        self.ret = idaapi.create_word(offset, 2)
        return self.ret

    @QtCore.pyqtSlot(object)
    def make_byte(self, offset, size=1):
        """Create a byte at the given offset in the IDB"""
        self.ret = idaapi.create_byte(offset, size)
        return self.ret

    @QtCore.pyqtSlot(object, str)
    def make_comment(self, offset, comment):
        """Create a comment at the given offset in the IDB"""
        #self.ret = idc.MakeComm(offset, comment)
        return self.ret

    @QtCore.pyqtSlot(object, str, int)
    def make_name(self, offset, name, flags=0):
        """Name the given offset in the IDB"""
        self.ret = idc.set_name(offset, str(name), idc.SN_NOCHECK | idc.SN_NOWARN | 0x800)
        return self.ret

    @QtCore.pyqtSlot()
    def get_names(self):
        self.ret = list(idautils.Names())
        return self.ret

    @QtCore.pyqtSlot(object, object, object, object)
    def find_iat_ptrs(self, pe, image_base, size, get_word):
        """Find all likely IAT pointers"""
        iat_ptrs = []

        next_offset = image_base

        while next_offset < image_base + size:
            offset = next_offset
            next_offset = ida_bytes.next_addr(offset)

            # Attempt to read the current instruction's effective memory address operand (if present)
            mnem = idc.print_insn_mnem(offset).lower()
            ptr = 0

            if mnem in ["call", "push", "jmp"]:
                if idc.get_operand_type(offset, 0) == idc.o_mem:
                    # Get memory offset for branch instructions
                    ptr = idc.get_operand_value(offset, 0)
            elif mnem in ["mov", "lea"]:
                if idc.get_operand_type(offset, 0) == idc.o_reg and idc.get_operand_type(offset, 1) == idc.o_mem:
                    # Get memory offset for mov/lea instructions
                    ptr = idc.get_operand_value(offset, 1)

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
                    iat_ptrs.append((iat_offset, offset + idc.get_item_size(offset) - 4, module, api))

        self.ret = iat_ptrs
        return self.ret

    @QtCore.pyqtSlot(object)
    def find_pe(self, cursor=False):
        """Search IDB for possible MZ/PE headers"""
        info = idaapi.get_inf_structure()

        mz_headers = []

        # Check current cursor for MZ/PE?
        if cursor:
            # Get IDA cursor address
            addr = idc.here()

            # Get segment and end address
            s = idaapi.getseg(addr)
            e = idc.get_segm_end(addr)

            # Check for MZ magic
            if ida_bytes.get_word(addr) == 0x5a4d:
                # Ensure the PE header is in the segment
                e_lfanew = ida_bytes.get_dword(addr + 0x3c)

                if addr + e_lfanew + 1 < e:
                    # Check for PE magic
                    if ida_bytes.get_word(addr + e_lfanew) == 0x4550:
                        # Found possible MZ/PE header
                        mz_headers.append([addr, idc.get_segm_name(addr), info.is_64bit()])

            self.ret = mz_headers
            return self.ret

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
                            # Found possible MZ/PE header
                            mz_headers.append([addr, idc.get_segm_name(s), info.is_64bit()])

                # Resume search from next address
                addr += 1

        self.ret = mz_headers
        return self.ret

class pe_tree_plugin_t(idaapi.plugin_t):
    """Main IDAPro plugin class for PE Tree"""
    wanted_name = pe_tree.info.__title__
    comment = pe_tree.info.__title__
    version = pe_tree.info.__version__
    website = pe_tree.info.__url__
    help = pe_tree.info.__title__
    wanted_hotkey = ""
    flags = 0

    def __init__(self):
        self.pe_tree_form = None

    def init(self):
        """Initialise PE Tree IDA plugin"""
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        """Terminate PE Tree IDA plugin"""
        # Wait for plugin threads to complete
        if self.pe_tree_form:
            self.pe_tree_form.wait_for_threads()

    def run(self, arg):
        """Run PE Tree IDA plugin"""
        # Get form and widget
        form = idaapi.create_empty_widget(self.comment)
        widget = sip.wrapinstance(int(form), QtWidgets.QWidget)

        runtime = IDARuntime(form, {})

        self.pe_tree_form = pe_tree.form.PETreeForm(widget, None, runtime)

        # Try to find the IDA input file
        filename = idaapi.get_input_file_path()

        if filename:
            if not os.path.isfile(filename):
                filename = os.path.basename(filename)

                if not os.path.isfile(filename):
                    filename = runtime.ask_file(os.path.basename(filename), "Where is the input file?")

            if os.path.isfile(filename):
                # Map input file
                self.pe_tree_form.map_pe(image_base=idaapi.get_imagebase(), filename=filename)

        self.pe_tree_form.treeview.setVisible(True)
        self.pe_tree_form.show()

def PLUGIN_ENTRY():
    """PE Tree IDAPython plugin entry-point"""
    return pe_tree_plugin_t()

def main():
    """PE Tree IDAPython script entry-point"""
    PLUGIN_ENTRY().run("")

if __name__ == "__main__":
    main()
