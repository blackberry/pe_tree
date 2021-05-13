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

"""PE Tree Ghidra application"""

# Standard imports
import os
import sys
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

# Qt imports
from PyQt5 import QtCore, QtWidgets

# Ghidra imports
try:
    import ghidra_bridge
except ModuleNotFoundError:
    print("ghidra_bridge is required")
    exit()

import pe_tree.window
import pe_tree.runtime
import pe_tree.form
import pe_tree.info

class GhidraRuntime(pe_tree.runtime.Runtime):
    """Ghidra runtime callbacks"""
    def __init__(self, widget, args):
        # Load configuration
        self.config_file = os.path.join(self.get_temp_dir(), "pe_tree_ghidra.ini")
        super(GhidraRuntime, self).__init__(widget, args)

        # Initialise Ghidra bridge
        try:
            self.bridge = ghidra_bridge.GhidraBridge(connect_to_host=self.args.server, connect_to_port=self.args.port, namespace=globals(), response_timeout=20)
        except ConnectionRefusedError:
            print("Please run ghidra_bridge_server_background.py under Ghidra -> Window -> Script Manager")
            exit()

        state = getState()
        currentProgram = state.getCurrentProgram()

        self.address_factory = currentProgram.getAddressFactory()
        self.function_manager = currentProgram.getFunctionManager()
        self.data_type_manager = currentProgram.getDataTypeManager()
        self.listing = currentProgram.getListing()
        self.memory = currentProgram.getMemory()
        self.address_space = currentProgram.getAddressFactory().getDefaultAddressSpace()

    def jumpto(self, item, offset):
        """Jump to offset in Ghidra listing view"""
        try:
            self.ret = goTo(currentProgram.addressFactory.getAddress(hex(offset)))
        except:
            self.ret = False

        return self.ret

    @QtCore.pyqtSlot(object, object)
    def get_bytes(self, start, size):
        """Read bytes from memory"""
        array = self.bridge.remote_import("array")
        buffer = self.bridge.remote_eval("array.array('b', data)", array=array, data=b"\0" * size)

        read = self.memory.getBytes(self.address_space.getAddress(hex(start)), buffer)

        if read > 0:
            self.ret = bytearray(self.bridge.remote_eval("[ b & 0xff for b in data]", data=buffer))
        else:
            self.ret = b""

        return self.ret

    @QtCore.pyqtSlot(object)
    def get_name(self, offset):
        """Get name for offset from Ghidra"""
        self.ret = ""
        return self.ret

    @QtCore.pyqtSlot(object)
    def get_segment_name(self, offset):
        """Get segment name for offset from Ghidra"""
        self.ret = ""
        return self.ret

    @QtCore.pyqtSlot(object)
    def is_writable(self, offset):
        """Determine if memory address is writable"""
        self.ret = False
        return self.ret

    @QtCore.pyqtSlot(object)
    def resolve_address(self, offset):
        """Get module/symbol name for address"""
        symbol = ""
        module = ""

        ref = currentProgram.referenceManager.getReferencesFrom(self.address_factory.getAddress(hex(offset)))

        if ref:
            ref = ref[0].toString()

            # Should look something like.. "->MSVCRT.DLL::__setusermatherr"
            if ref.startswith("->"):
                # Remove ->
                ref = ref[2:]

                # Split into module/API
                elements = ref.split("::")

                module = elements[0]
                symbol = elements[1].split(" ")[0]

        self.ret = (module, symbol)
        return self.ret

    @QtCore.pyqtSlot(object)
    def get_label(self, offset):
        """Get label for offest from Ghidra"""
        self.ret = getSymbolAt(self.address_space.getAddress(hex(offset)))
        return self.ret

    @QtCore.pyqtSlot(object, object)
    def make_string(self, offset, size):
        """Convert range to byte string in Ghidra"""
        self.ret = self.listing.createData(self.address_space.getAddress(hex(offset)), ghidra.program.model.data.StringDataType, size)
        return self.ret

    @QtCore.pyqtSlot(object, object, str, str, bytes)
    def make_segment(self, offset, size, class_name="DATA", name="pe_map", data=None):
        """Create a new section in Ghidra - Not implemented"""
        self.ret = None
        return self.ret

    @QtCore.pyqtSlot(object)
    def make_qword(self, offset):
        """Create a qword at the given offset in the listing"""
        self.ret = self.listing.createData(self.address_space.getAddress(hex(offset)), ghidra.program.model.data.QWordDataType)
        return self.ret

    @QtCore.pyqtSlot(object)
    def make_dword(self, offset):
        """Create a dword at the given offset in the listing"""
        self.ret = self.listing.createData(self.address_space.getAddress(hex(offset)), ghidra.program.model.data.DWordDataType)
        return self.ret

    @QtCore.pyqtSlot(object)
    def make_word(self, offset):
        """Create a word at the given offset in the listing"""
        self.ret = self.listing.createData(self.address_space.getAddress(hex(offset)), ghidra.program.model.data.WordDataType)
        return self.ret

    @QtCore.pyqtSlot(object)
    def make_byte(self, offset, size=1):
        """Create a byte at the given offset in the listing"""
        self.ret = self.listing.createData(self.address_space.getAddress(hex(offset)), ghidra.program.model.data.ByteDataType)
        return self.ret

    @QtCore.pyqtSlot(object, str)
    def make_comment(self, offset, comment):
        """Create a comment at the given offset in the listing"""
        self.ret = self.listing.setComment(self.address_space.getAddress(hex(offset)), ghidra.program.model.listing.CodeUnit.REPEATABLE_COMMENT, comment)
        return self.ret

    def find_iat_ptrs_remote(self, image_base, size, get_word, namespace=globals()):
        """Find all likely IAT pointers
        
        Note! For performance reasons this code should be executed remotely under the Ghidra python interpreter using bridge.remoteify()

        """
        address_space = currentProgram.getAddressFactory().getDefaultAddressSpace()

        address_set = ghidra.program.model.address.AddressSet()
        address_set.addRange(address_space.getAddress(hex(image_base)), address_space.getAddress(hex(image_base + size)))

        opcode_iterator = currentProgram.getListing().getInstructions(address_set, True)

        # Iterate over all opcodes in the image
        iat_ptrs = []

        while opcode_iterator.hasNext():
            opcode = opcode_iterator.next()

            # Get the opcode mnemonic
            mnem = opcode.getMnemonicString().lower()

            # Does the opcode contain a memory address?
            ptr = 0

            if mnem in ["call", "push", "jmp"]:
                if opcode.getOperandType(0) & ghidra.program.model.lang.OperandType.ADDRESS:
                    # Get memory offset for branch instructions
                    ptr = opcode.getOpObjects(0)

            elif mnem in ["mov", "lea"]:
                if opcode.getOperandType(0) & ghidra.program.model.lang.OperandType.REGISTER and opcode.getOperandType(1) & ghidra.program.model.lang.OperandType.ADDRESS:
                    # Get memory offset for mov/lea instructions
                    ptr = opcode.getOpObjects(1)

            if ptr == 0:
                continue

            # Get the memory address value/offset
            try:
                ptr = int(ptr[0].getUnsignedValue())
            except:
                ptr = int(ptr[0].getOffset())

            # Does the instruction's memory address operand seem somewhat valid?!
            if ptr < 0x1000:
                continue

            # Read pointer from memory address
            try:
                # TODO: Ensure this is dynamic for x86/64!
                iat_offset = getInt(currentProgram.addressFactory.getAddress(hex(ptr)))
            except:
                iat_offset = 0

            if iat_offset == 0:
                continue

            # Ignore offset if it is in our image
            if iat_offset >= image_base and iat_offset < image_base + size:
                continue

            # Attempt to resolve reference (Note! do not use self.resolve_address, as this code is executed remotely ;)
            ref = currentProgram.referenceManager.getReferencesFrom(currentProgram.addressFactory.getAddress(hex(ptr)))

            if ref:
                ref = ref[0].toString()

                # Should look something like.. "->MSVCRT.DLL::__setusermatherr"
                if ref.startswith("->"):
                    # Remove ->
                    ref = ref[2:]

                    # Split into module/API
                    elements = ref.split("::")

                    module = elements[0]
                    api = elements[1].split(" ")[0]

                    # Add IAT offset, address to patch, module name and API name to list
                    iat_ptrs.append([iat_offset, ptr + opcode.getAddress().add(opcode.getLength() - 4).getOffset(), module, api])

        return iat_ptrs

    @QtCore.pyqtSlot(object, object, object, object)
    def find_iat_ptrs(self, pe, image_base, size, get_word):
        """Find all likely IAT pointers"""
        # Perform IAT search under Ghidra python interpreter 
        self.ret = self.bridge.remoteify(self.find_iat_ptrs_remote)(self, image_base, size, get_word)
        return self.ret

def main():
    """PE Tree Ghidra script entry-point"""
    # Check command line arguments
    parser = ArgumentParser(description="PE-Tree (Ghidra)", formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument("--server", help="Ghidra bridge server IP", default="127.0.0.1")
    parser.add_argument("--port", help="Ghidra bridge server port", default=4768, type=int)
    args = parser.parse_args()

    # Create PE Tree Qt application
    application = QtWidgets.QApplication(sys.argv)
    window = pe_tree.window.PETreeWindow(application, GhidraRuntime, args, open_file=False)

    # Try to locate the input file
    filename = currentProgram.getExecutablePath()

    if filename:
        # No input file found?
        if not os.path.isfile(filename):
            filename = os.path.basename(filename)

            if not os.path.isfile(filename):
                filename = runtime.ask_file(os.path.basename(filename), "Where is the input file?")

        if os.path.isfile(filename):
            # Map input file
            window.pe_tree_form.map_pe(image_base=currentProgram.getImageBase().getOffset(), filename=filename)

    sys.exit(application.exec_())

if __name__ == "__main__":
    main()