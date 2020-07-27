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

# IDAPython imports
import idaapi
import ida_idaapi
import idc
import ida_bytes
import ida_name
import ida_kernwin
import idautils

# Qt imports
from PyQt5 import QtCore, QtWidgets
import sip

# PE Tree imports
if "pe_tree" in sys.modules:
    # Reload all PE Tree modules as IDA will keep them loaded
    try:
        from importlib import reload
    except:
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
    except NameError:
        pass

import pe_tree.runtime
import pe_tree.form
import pe_tree.info

class IDARuntime(pe_tree.runtime.Runtime):
    """IDA runtime callbacks"""
    def __init__(self, widget):
        # Load configuration
        self.config_file = os.path.join(self.get_temp_dir(), "pe_tree.ini")
        super(IDARuntime, self).__init__(widget)

    def get_temp_dir(self):
        """Get path to temporary directory"""
        self.ret = idaapi.get_user_idadir()
        return self.ret

    def get_script_dir(self):
        self.ret = os.path.dirname(os.path.realpath(pe_tree.info.__file__))
        return self.ret

    def ask_file(self, filename, caption, filter="", save=False):
        """Open/save file dialog"""
        if save == False:
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
        """Display the widget"""
        self.ret = idaapi.display_widget(self.widget, (idaapi.PluginForm.WOPN_TAB | idaapi.PluginForm.WOPN_MENU | idaapi.PluginForm.WOPN_RESTORE | idaapi.PluginForm.WOPN_PERSIST))

        return self.ret

    def jumpto(self, item, offset):
        """Jump to offset in IDA view"""
        try:
            self.ret = idc.jumpto(offset)
        except:
            self.ret = False

        return self.ret

    @QtCore.pyqtSlot(object)
    def calc_pe_size(self, image_base):
        # Blind guess at PE size based on contigious segments
        size = idc.get_segm_end(image_base) - image_base
        prev = idc.get_segm_start(image_base)
        offset = idc.get_next_seg(image_base)

        if offset == ida_idaapi.BADADDR:
            size = 0

        # Size based on contigious segments by address
        while offset != ida_idaapi.BADADDR and idc.get_segm_end(prev) == offset:
            size += idc.get_segm_end(offset) - offset
            prev = offset
            offset = idc.get_next_seg(offset)

        if size <= 0x1000:
            name = idc.get_segm_name(image_base)
            prev = idc.get_segm_start(image_base)
            offset = idc.get_next_seg(image_base)
            start = offset

            # Size based on contigious segments by name
            while offset != ida_idaapi.BADADDR and idc.get_segm_name(prev) == name:
                prev = offset
                offset = idc.get_next_seg(offset)

            size = idc.get_segm_end(offset) - start

        self.ret = size
        return self.ret

    @QtCore.pyqtSlot(object, object)
    def get_bytes(self, start, end):
        """Read bytes from IDB"""
        self.ret = idc.get_bytes(start, end)
        return self.ret

    @QtCore.pyqtSlot(object)
    def get_byte(self, offset):
        """Read byte from IDB"""
        self.ret = ida_bytes.get_byte(offset)
        return self.ret

    @QtCore.pyqtSlot(object)
    @QtCore.pyqtSlot(int)
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
        self.ret = False

        segment = idaapi.getseg(offset)
        
        self.ret = True if segment.perm & idaapi.SEGPERM_WRITE else False
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
                        new_name = "{}.dll".format("_".join(names[0:i]))
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

    @QtCore.pyqtSlot(object)
    def get_mnemonic(self, offset):
        """Get opcode mnemonic for given offset"""
        self.ret = idc.print_insn_mnem(offset)
        return self.ret

    @QtCore.pyqtSlot(object)
    def get_opcode_length(self, offset):
        """Get opcode length for given offset"""
        self.ret = idc.get_item_size(offset)
        return self.ret

    @QtCore.pyqtSlot(object)
    def get_opcode_omem(self, offset):
        """Get opcode's direct memory address"""
        mnem = self.get_mnemonic(offset).lower()
        ptr = 0

        if mnem in ["call", "push", "jmp"]:
            if idc.get_operand_type(offset, 0) == idc.o_mem:
                ptr = idc.get_operand_value(offset, 0)
        elif mnem in ["mov", "lea"]:
            if idc.get_operand_type(offset, 0) == idc.o_reg and idc.get_operand_type(offset, 1) == idc.o_mem:
                ptr = idc.get_operand_value(offset, 1)

        self.ret = ptr
        return self.ret

    @QtCore.pyqtSlot(object)
    def next_addr(self, offset):
        """Find next address in IDB"""
        self.ret = ida_bytes.next_addr(offset)
        return self.ret

    @QtCore.pyqtSlot(object, object, object)
    def find_iat_ptrs(self, image_base, size, get_word):
        """Find all likely IAT pointers"""
        iat_ptrs = []

        next_offset = image_base

        while next_offset < image_base + size:
            offset = next_offset
            next_offset = self.next_addr(offset)

            # Get address from opcode with memory operand
            ptr = self.get_opcode_omem(offset)

            if ptr < 0x1000:
                continue

            # Resolve pointer from memory operand
            iat_offset = get_word(ptr)

            # Ignore offset if it is in our image
            if iat_offset >= image_base and iat_offset < image_base + size:
                continue

            # Get module and api name for offset
            module, api = self.resolve_address(iat_offset)

            # Ignore the offset if it is in a debug segment or stack etc
            if api and module and module.endswith(".dll"):
                if not iat_offset in iat_ptrs:
                    # Add IAT offset to list
                    iat_ptrs.append((iat_offset, offset, module, api))

        self.ret = iat_ptrs
        return self.ret

    @QtCore.pyqtSlot(object, object, object, object, object, object)
    def patch_iat_ptrs(self, image_base, size, iat_ptrs, name_to_iat, get_word, set_word):
        """Find and patch all IAT pointers"""
        patched = []

        next_offset = image_base

        while next_offset < image_base + size:
            offset = next_offset
            next_offset = self.next_addr(offset)

            # Resolve pointer from memory operand
            ptr = self.get_opcode_omem(offset)

            if ptr < 0x1000:
                continue

            # Get IAT pointer
            iat_offset = get_word(ptr)

            # Ignore offset if it is in our image
            if iat_offset >= image_base and iat_offset < image_base + size:
                continue

            for iat_ptr, _, module, api in iat_ptrs:
                # Is IAT pointer in list?
                if iat_offset != iat_ptr:
                    continue

                # Get opcode bytes
                opcode = self.get_bytes(offset, self.get_opcode_length(offset))

                if len(opcode) <= 4:
                    break

                try:
                    # Patch IAT offset
                    offset += len(opcode) - 4

                    if offset not in patched:
                        set_word(offset - image_base, image_base + name_to_iat["{}!{}".format(module, api)])
                        patched.append(offset)

                    break
                except KeyError:
                    break

        self.ret = patched
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

    def init(self):
        self.pe_tree_form = None

        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        # Wait for plugin threads to complete
        if self.pe_tree_form:
            self.pe_tree_form.wait_for_threads()

    def run(self, arg):
        # Get form and widget
        form = idaapi.create_empty_widget(self.comment)
        widget = sip.wrapinstance(int(form), QtWidgets.QWidget)

        runtime = IDARuntime(form)

        # Try to find the IDA input file
        filename = idaapi.get_input_file_path()

        if not filename:
            return

        if not os.path.isfile(filename):
            filename = os.path.basename(filename)

            if not os.path.isfile(filename):
                filename = runtime.ask_file(os.path.basename(filename), "Where is the input file?")

        if not filename:
            return

        # Map input file
        self.pe_tree_form = pe_tree.form.PETreeForm(widget, None, runtime)
        self.pe_tree_form.map_pe(image_base=idaapi.get_imagebase(), filename=filename)
        self.pe_tree_form.show()

def PLUGIN_ENTRY():
    """PE Tree IDAPython plugin entry-point"""
    return pe_tree_plugin_t()

def main():
    """PE Tree IDAPython script entry-point"""
    PLUGIN_ENTRY().run("")

if __name__ == "__main__":
    main()