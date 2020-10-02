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

"""Dump PE file from memory/IDB and reconstruct import address table/hint name table/directory table"""

# Standard imports
import sys
import struct

# pefile
import pefile

# Qt imports
from PyQt5 import QtWidgets

# PE Tree imports
import pe_tree.form

class DumpPEForm(QtWidgets.QDialog):
    """Display simple dialog for dumping PE files

    Args:
        pe (pefile.PE): Parsed PE file
        image_base (int): Base address of PE file in-memory
        size (int): Size of PE file in-memory
        filename (str): Name of PE file/memory segment
        ptr_size (int): Width of pointer in characters, 8 = 32-bit, 16 = 64-bit
        form (pe_tree.form.PETreeForm): PE Tree main form
        parent (QWidget, optional): Dialog parent widget

    """
    def __init__(self, pe, image_base, size, filename, ptr_size, form, parent=None):
        super(DumpPEForm, self).__init__(parent)

        self.pe = pe
        self.size = size
        self.image_base = image_base
        self.filename = filename
        self.form = form
        self.runtime = form.runtime
        self.ptr_size = ptr_size

        self.iat_ptrs = []

        self.setWindowTitle("Dump PE - {}".format(filename))

        self.image_base_edit = QtWidgets.QLineEdit("{:0{w}x}".format(image_base, w=self.ptr_size))
        self.image_base_edit.setInputMask("H" * self.ptr_size)
        self.image_base_edit.setWhatsThis("New image-base for the dumped PE file")

        self.entry_point_edit = QtWidgets.QLineEdit("{:0{w}x}".format(pe.OPTIONAL_HEADER.AddressOfEntryPoint, w=self.ptr_size))
        self.entry_point_edit.setInputMask("H" * self.ptr_size)
        self.entry_point_edit.setWhatsThis("New entry-point for the dumped PE file")

        self.size_of_optional_header_edit = QtWidgets.QLineEdit("{:0{w}x}".format(pe.FILE_HEADER.SizeOfOptionalHeader, w=self.ptr_size))
        self.size_of_optional_header_edit.setInputMask("H" * self.ptr_size)
        self.size_of_optional_header_edit.setWhatsThis("FILE_HEADER.SizeOfOptionalHeader to use when parsing the PE file")

        self.iat_rva_edit = QtWidgets.QLineEdit("{:0{w}x}".format(pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]].VirtualAddress, w=self.ptr_size))
        self.iat_rva_edit.setInputMask("H" * self.ptr_size)
        self.iat_rva_edit.setWhatsThis("RVA of IAT to rebuild imports from.")
        self.iat_rva_edit.setDisabled(True)

        self.iat_size_edit = QtWidgets.QLineEdit("{:0{w}x}".format(pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]].Size, w=self.ptr_size))
        self.iat_size_edit.setInputMask("H" * self.ptr_size)
        self.iat_size_edit.setWhatsThis("Size of IAT to rebuild imports from.")
        self.iat_size_edit.setDisabled(True)

        self.use_existing_imports_radio = QtWidgets.QRadioButton("Use existing imports:")
        self.use_existing_imports_radio.setWhatsThis("Use existing IAT to rebuild imports")
        self.use_existing_imports_radio.toggled.connect(self.toggle_iat_radios)

        self.no_imports_radio = QtWidgets.QRadioButton("No imports")
        self.no_imports_radio.setWhatsThis("Do not rebuild IAT")
        self.no_imports_radio.toggled.connect(self.toggle_iat_radios)

        self.rebuild_imports_radio = QtWidgets.QRadioButton("Rebuild imports")
        self.rebuild_imports_radio.setWhatsThis("Scan PE for IAT pointers and rebuild IAT")
        self.rebuild_imports_radio.toggled.connect(self.toggle_iat_radios)
        self.rebuild_imports_radio.setChecked(True)

        self.save_to_file_checkbox = QtWidgets.QCheckBox("Save to file")
        self.save_to_file_checkbox.setWhatsThis("Save dumped PE file to disk")
        self.save_to_file_checkbox.setChecked(True)

        self.add_to_tree_checkbox = QtWidgets.QCheckBox("Add to PE Tree")
        self.add_to_tree_checkbox.setWhatsThis("Add dumped PE file to tree.\n\nWarning! Addresses may be incorrect in current IDA context if image is rebased!")

        button_box = QtWidgets.QDialogButtonBox()
        button_box.addButton("Dump", QtWidgets.QDialogButtonBox.AcceptRole)
        button_box.addButton("Cancel", QtWidgets.QDialogButtonBox.RejectRole)

        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        grid = QtWidgets.QGridLayout()
        grid.setSpacing(10)

        widgets = [
            (QtWidgets.QLabel("ImageBase:"), self.image_base_edit),
            (QtWidgets.QLabel("AddressOfEntryPoint:"), self.entry_point_edit),
            (QtWidgets.QLabel("SizeOfOptionalHeader:"), self.size_of_optional_header_edit),
            (self.no_imports_radio, QtWidgets.QWidget()),
            (self.rebuild_imports_radio, QtWidgets.QWidget()),
            (self.use_existing_imports_radio, QtWidgets.QWidget()),
            (QtWidgets.QLabel("IAT:"), self.iat_rva_edit),
            (QtWidgets.QLabel("IAT Size:"), self.iat_size_edit),
            (QtWidgets.QLabel("Output:"), QtWidgets.QWidget()),
            (self.save_to_file_checkbox, QtWidgets.QWidget()),
            (self.add_to_tree_checkbox, QtWidgets.QWidget()),
            (QtWidgets.QWidget(), button_box)
            ]

        for row, (left, right) in enumerate(widgets):
            grid.addWidget(left, row, 0)
            grid.addWidget(right, row, 1)

        self.setLayout(grid)

    def toggle_iat_radios(self):
        """IAT radio button toggle"""
        self.iat_rva_edit.setEnabled(self.use_existing_imports_radio.isChecked())
        self.iat_size_edit.setEnabled(self.use_existing_imports_radio.isChecked())

    def invoke(self):
        """Display the dump PE dialog"""
        # Has the user accepted, i.e. pressed "Dump"?
        if self.exec_() != 0:
            # Read values from edit controls
            image_base = int(self.image_base_edit.text(), 16)
            entry_point = int(self.entry_point_edit.text(), 16)
            size_of_optional_header = int(self.size_of_optional_header_edit.text(), 16)

            # Determine what the user wants to do about IAT reconstruction
            find_patch_iat = False

            if self.rebuild_imports_radio.isChecked():
                # Scan/rebuild IAT
                find_patch_iat = True

            iat_rva = 0
            iat_size = 0

            if self.use_existing_imports_radio.isChecked():
                # Use existing IAT
                iat_rva = int(self.iat_rva_edit.text(), 16)
                iat_size = int(self.iat_size_edit.text(), 16)

            # Dump the PE file
            pe_data = DumpPEFile(self.pe,
                                 self.image_base,
                                 self.size,
                                 self.runtime,
                                 find_iat_ptrs=find_patch_iat,
                                 patch_iat_ptrs=find_patch_iat,
                                 iat_rva=iat_rva,
                                 iat_size=iat_size,
                                 new_image_base=image_base,
                                 new_ep=entry_point,
                                 recalculate_pe_checksum=self.runtime.get_config_option("dump", "recalculate_pe_checksum", False),
                                 size_of_optional_header=size_of_optional_header).dump()

            # Add to tree
            if self.add_to_tree_checkbox.isChecked():
                self.form.map_pe(image_base=image_base, data=pe_data, priority=1, filename=self.filename, opaque=self.runtime.opaque)

            # Save to file
            if self.save_to_file_checkbox.isChecked():
                filename = self.runtime.ask_file("{}.dmp".format(self.filename), "Save dump", save=True)
                if filename:
                    with open(filename, "wb") as ofile:
                        ofile.write(pe_data)

            self.close()

class DumpPEFile():
    """Dump PE file from memory and optionally rebuild imports.

    There are a number of ways to perform IAT reconstruction:

    1. By default the IAT will be rebuilt from the IMAGE_DIRECTORY_ENTRY_IAT virtual address, if possible.
    2. If `find_iat_ptrs/patch_iat_ptrs` is set then the image disassembly will be searched for IAT xrefs which are used to construct a new IAT.
    3. It is possible to override the IMAGE_DIRECTORY_ENTRY_IAT virtual address and size using `iat_rva/iat_size`. This may be useful for malware that has set the IMAGE_DIRECTORY_ENTRY_IAT entry to 0 after loading.
    4. Alternatively, it is possible to specify all IAT locations in the image via `iat_ptrs`, a list of tuples containing the IAT offset, xref, module name and API name

    Args:
        pe (pefile.PE): Parsed PE file
        image_base (int): Base address of PE file in-memory
        size (int): Size of PE file in-memory
        runtime (pe_tree.runtime.RuntimeSignals): Runtime callbacks
        find_iat_ptrs (bool, optional): Scan in-memory PE for IAT references (no need for iat_ptrs or iat_rva arguments)
        iat_ptrs ([(int, int, str, str)], optional): Specify IAT pointers using tuple containing IAT offset, xref, module name and API name
        iat_rva (int, optional): Specify address of the import address table (iat_size must be > 0)
        iat_size (int, optional): Specify size of the import address table (iat_rva must be != 0)
        new_image_base (int, optional): New OPTIONAL_HEADER.ImageBase value
        new_ep (int, optional): New OPTIONAL_HEADER.AddressOfEntryPoint value
        size_of_optional_header_edit (int, optional): New FILE_HEADER.SizeOfOptionalHeader value
        recalculate_pe_checksum (bool, optional): Recalculate OPTIONAL_HEADER.CheckSum (warning, this is slow!)

    Returns:
        bytes: PE data

    """
    def __init__(self, pe, image_base, size, runtime, **kwargs):
        self.pe = pe
        self.image_base = image_base
        self.runtime = runtime
        self.size = size

        # Get optional arguments
        self.iat_ptrs = kwargs.get("iat_ptrs", [])
        self.iat_rva = kwargs.get("iat_rva", 0)
        self.iat_size = kwargs.get("iat_size", 0)
        self.find_iat_ptrs = kwargs.get("find_iat_ptrs", False)
        self.patch_iat_ptrs = kwargs.get("patch_iat_ptrs", False)
        self.new_image_base = kwargs.get("new_image_base", 0)
        self.new_ep = kwargs.get("new_ep", 0)
        self.size_of_optional_header = kwargs.get("size_of_optional_header", 0)
        self.recalculate_pe_checksum = kwargs.get("recalculate_pe_checksum", False)

        # Determine architecture
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            self.ptr_size = 8
            self.ptr_format = "<Q"
            self.set_word = pe.set_qword_at_rva
            self.get_word = self.runtime.get_qword
        else:
            self.ptr_size = 4
            self.ptr_format = "<I"
            self.set_word = pe.set_dword_at_rva
            self.get_word = self.runtime.get_dword

    def dump(self):
        """Dump PE file"""
        pe = self.pe

        # Some samples might mess with the PE headers after loading, attempt to fix!
        if self.size_of_optional_header != 0:
            if self.size_of_optional_header != pe.FILE_HEADER.SizeOfOptionalHeader:
                pe.FILE_HEADER.SizeOfOptionalHeader = self.size_of_optional_header
                pe = pefile.PE(data=pe.write())

        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint if self.new_ep == 0 else self.new_ep

        # Fix section pointers and sizes
        for section in pe.sections:
            if pe_tree.form.HAVE_IDA:
                section.PointerToRawData = section.VirtualAddress
                section.SizeOfRawData = section.Misc_VirtualSize

            # Ensure entry-point section is executable
            if section.contains_offset(ep):
                section.Characteristics |= pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]

                # Is the segment in which the entry-point resides writable? (likely from a packer)
                if self.runtime.is_writable(self.image_base + ep):
                    # Make the entry-point section writable
                    section.Characteristics |= pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"]

        # Find IAT pointers
        if self.find_iat_ptrs:
            self.iat_ptrs = self.runtime.find_iat_ptrs(pe, self.image_base, self.size, self.get_word)

        # Found anything?
        if len(self.iat_ptrs) == 0:
            # Attempt to use existing IAT if specified/present
            iat_rva = self.iat_rva
            iat_size = self.iat_size

            # IAT RVA specified?
            if iat_rva == 0 or iat_size == 0:
                # Use IAT RVA from DATA_DIRECTORY
                iat_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]].VirtualAddress
                iat_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]].Size

            if iat_rva != 0 and iat_size != 0:
                # Read IAT
                iat_data = self.runtime.get_bytes(self.image_base + iat_rva, iat_size)

                if len(iat_data) == iat_size:
                    last_module = ""
                    next_module = None
                    next_api = None

                    # Resolve IAT pointers
                    for i in range(0, iat_size, self.ptr_size):
                        # Get IAT pointer
                        iat_ptr = struct.unpack(self.ptr_format, iat_data[i:i + self.ptr_size])[0]

                        # Last entry for module?
                        if iat_ptr == 0:
                            if i < iat_size - self.ptr_size:
                                j = i + self.ptr_size

                                next_iat_ptr = struct.unpack(self.ptr_format, iat_data[j:j + self.ptr_size])[0]

                                # Get the next module name
                                next_module, next_api = self.runtime.resolve_address(next_iat_ptr)

                                next_module = next_module.lower().replace("kernelbase", "kernel32")

                                # Does the module after the null match our current module?
                                if next_module == last_module or next_iat_ptr == 0:
                                    # Insert a dummy "nullptr" import to keep things nicely aligned
                                    self.iat_ptrs.append((iat_ptr, i, last_module, "nullptr"))
                                    continue

                            last_module = ""
                            next_module = None
                            continue

                        # Add IAT pointer to list
                        if not next_module or not next_api:
                            module, api = self.runtime.resolve_address(iat_ptr)

                            module = module.lower().replace("kernelbase", "kernel32")
                        else:
                            module, api = next_module, next_api
                            next_module, next_api = None, None

                        # After imports are loaded they may well have been forwarded to other modules
                        if last_module == "":
                            # Use a common module name when resolving imports in-place, otherwise the IAT/IDT will not be in sync
                            last_module = module

                        self.iat_ptrs.append((iat_ptr, 0, last_module, api))
        else:
            # Create empty IAT pointer table
            iat_data = len(self.iat_ptrs) * (b"\x00" * self.ptr_size)

        if len(self.iat_ptrs) > 0:
            # Build list of modules/API names
            modules = []

            for iat_ptr, offset, module, api in self.iat_ptrs:
                if len(modules) == 0:
                    modules.append({"name": module, "apis": [], "offset": offset})

                if self.find_iat_ptrs:
                    # Building our own IAT we can combine all modules/APIs
                    found_module = False

                    for _module in modules:
                        if _module["name"] == module:
                            if api not in _module["apis"]:
                                _module["apis"].append(api)
                            found_module = True
                            break

                    if not found_module:
                        modules.append({"name": module, "apis": [api], "offset": offset})
                else:
                    # Using an existing IAT we need to keep modules/APIs in order
                    prev_module = modules[-1]

                    if prev_module["name"] == module:
                        prev_module["apis"].append(api)
                    else:
                        modules.append({"name": module, "apis": [api], "offset": offset})

            # Construct hint/name table
            name_table = bytearray()
            for module in modules:
                # Add module name and align
                name_table += module["name"].encode() + b"\0"
                name_table += (len(name_table) % 2) * b"\0"
                name_table += b"\0\0"
                for api in module["apis"]:
                    # Add hint and API name and align
                    name_table += b"\0\0" + api.encode() + b"\0"
                    name_table += (len(name_table) % 2) * b"\0"

            # Construct IDT
            import_rva = self.align((pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize), pe.OPTIONAL_HEADER.SectionAlignment)
            idt_data = bytearray()
            name_table_offset = 0
            name_table_len = len(name_table)
            name_to_iat = {}

            iat_index = 0

            if self.find_iat_ptrs:
                # IAT will be at the end of the image in a new section
                iat_base = import_rva
            else:
                # IAT remains wherever it is in the image
                iat_base = iat_rva

            for module in modules:
                #iat_index = module["offset"]

                # Add descriptor - OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk
                idt_data += struct.pack("<LLLLL",
                                        import_rva + len(iat_data) + name_table_len + iat_index,
                                        0,
                                        0,
                                        import_rva + len(iat_data) + name_table.find(module["name"].encode()),
                                        iat_base + iat_index)

                name_table_offset += len(module["name"].encode() + b"\0")
                name_table_offset += name_table_offset % 2
                name_table_offset += 2

                for api in module["apis"]:
                    # Add name table offset
                    name_table += struct.pack(self.ptr_format, import_rva + len(iat_data) + name_table_offset)
                    name_table_offset += len(api.encode()) + 1
                    name_table_offset += name_table_offset % 2
                    name_table_offset += 2
                    name_to_iat["{}!{}".format(module["name"], api)] = iat_base + iat_index

                    iat_index += self.ptr_size

                name_table += struct.pack(self.ptr_format, 0)
                pe.set_dword_at_offset(iat_base + iat_index, 0)
                iat_index += self.ptr_size

            # Construct import section data - IAT + Name table + IDT
            import_data = iat_data + name_table + idt_data

            # Patch addresses to point to new IAT
            patched = []
            for iat_ptr, offset, module, api in self.iat_ptrs:
                if offset and offset not in patched:
                    # Update IAT pointer in PE
                    self.set_word(offset - self.image_base, self.image_base + name_to_iat["{}!{}".format(module, api)])
                    patched.append(offset)

            # Update imports and IAT directory entries
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]].VirtualAddress = import_rva + len(iat_data) + len(name_table)
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]].Size = len(modules) * 20

            pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]].VirtualAddress = iat_base
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]].Size = len(iat_data)
        else:
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]].VirtualAddress = 0
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]].Size = 0

            pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]].VirtualAddress = 0
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]].Size = 0

        # Update image base and entry-point
        if self.new_image_base != 0:
            pe.OPTIONAL_HEADER.ImageBase = self.new_image_base
        else:
            pe.OPTIONAL_HEADER.ImageBase = self.image_base

        if self.new_ep != 0:
            pe.OPTIONAL_HEADER.AddressOfEntryPoint = self.new_ep

        # Image cannot be rebased
        pe.OPTIONAL_HEADER.DllCharacteristics &= ~pefile.DLL_CHARACTERISTICS["IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"]

        # Remove base relocs, bound imports and security directories, as they are somewhat meaningless now
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]].VirtualAddress = 0
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]].Size = 0

        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"]].VirtualAddress = 0
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"]].Size = 0

        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].VirtualAddress = 0
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].Size = 0

        overlay = pe.get_overlay()
        overlay = overlay if overlay is not None else bytearray()

        if len(self.iat_ptrs) > 0:
            # Add new .idata section to hold IAT + IDT + hint name table
            pe_data = pe.trim()

            # Create empty section
            section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
            section.__unpack__(bytearray(section.sizeof()))
            section.set_file_offset(pe.sections[-1].get_file_offset() + pe.sections[-1].sizeof())

            # Fill in section details
            section.Name = b".pe_tree"
            section.Misc_VirtualSize = len(import_data)
            section.VirtualAddress = pe.sections[-1].VirtualAddress + self.align(pe.sections[-1].Misc_VirtualSize, pe.OPTIONAL_HEADER.SectionAlignment)
            section.SizeOfRawData = self.align(len(import_data), pe.OPTIONAL_HEADER.FileAlignment)
            section.PointerToRawData = self.align(len(pe_data), pe.OPTIONAL_HEADER.FileAlignment)
            section.Characteristics = pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_CNT_INITIALIZED_DATA"] | pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_READ"] | pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]

            # Update PE headers
            pe.FILE_HEADER.NumberOfSections += 1
            pe.OPTIONAL_HEADER.SizeOfImage += section.VirtualAddress + self.align(len(import_data), pe.OPTIONAL_HEADER.SectionAlignment)

            # Append import data
            pe_data += (self.align(len(pe_data), pe.OPTIONAL_HEADER.FileAlignment) - len(pe_data)) * b"\0"
            pe_data += import_data
            pe_data += (self.align(len(pe_data), pe.OPTIONAL_HEADER.FileAlignment) - len(pe_data)) * b"\0"
            pe.__data__ = pe_data

            # Add section to pefile
            pe.sections.append(section)
            pe.__structures__.append(section)

        # Recalculate PE checksum if enabled (warning, very slow!)
        if self.recalculate_pe_checksum:
            pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()

        # Put any overlay back
        pe.__data__ += overlay

        # Return data
        if sys.version_info > (3,):
            return pe.write()

        return "".join(map(chr, pe.write()))

    def align(self, val_to_align, alignment):
        """Align value

        Arguments:
            val_to_align (int): Value
            alignment (int): Alignment multiple

        Returns:
            int: Value rounded to alignment

        """
        return ((val_to_align + alignment - 1) // alignment) * alignment
