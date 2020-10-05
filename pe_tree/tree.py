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

"""QRunnable for constructing the PE treeview and region map"""

# Standard imports
import sys
import os
import time
import re
import json
import hashlib
import binascii
from datetime import datetime
import traceback

# pefile <3
import pefile

# Cryptography imports
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from asn1crypto import cms

# Qt imports
from PyQt5 import QtCore, QtWidgets

# PE Tree imports
import pe_tree.form
import pe_tree.qstandarditems
import pe_tree.map
import pe_tree.utils
import pe_tree.dump_pe
import pe_tree.hash_pe
import pe_tree.exceptions

if sys.version_info > (3,):
    long = int

class PETreeSignals(QtCore.QObject):
    """PE Tree PyQt5 signals"""
    update_ui = QtCore.pyqtSignal("PyQt_PyObject")
    process_file = QtCore.pyqtSignal(str)

class PETree(QtCore.QRunnable):
    """QRunnable to parse/map a PE file into the tree view and create map regions

    The PE file data can be supplied in the following manner:

        1. On-disk via `filename`
        2. In-memory via `image_base` (uses runtime pe_tree.runtime.Runtime.calc_pe_size/pe_tree.runtime.Runtime.get_bytes to obtain data)
        3. Directly via `data`

    If the dump option is enabled in the config then any in-memory PE files will be dumped automatically, with the imports rebuilt from
    the existing IAT (so addresses should be correct in IDA-view)x.

    Args:
        form (pe_tree.form.PETreeForm): Main form
        filename (str): Path to PE file to map (or name of segment if image_base != 0)
        image_base (int): Image-base of PE to map (overrides filename)
        data (bytes): PE file data (overrides filename and image_base)
        opaque (object, optional): Opaque pointer to an object to supply to runtime callbacks

    """
    def __init__(self, form, filename, image_base, data=None, opaque=None):
        super(PETree, self).__init__()
        self.form = form
        self.filename = filename
        self.image_base = image_base
        self.runtime = pe_tree.runtime.RuntimeSignals(form.runtime, opaque)
        self.loaded_from_idb = False
        self.pe = None
        self.data = data
        self.org_data = None

        self.root_item = None
        self.root_value_item = None

        # Default text width of a pointer for formatting
        self.ptr_size = 8

        # PE file has not been dumped (yet!)
        self.dumped = False

        # Pointer display mode
        self.show_rva = True

        # Signals
        self.signals = form.signals

        # Disassembler
        self.disasm = None

        # File regions
        self.regions = []

        self.size = 0

    @QtCore.pyqtSlot()
    def run(self):
        """Thread to parse PE file and construct tree/map regions"""
        try:
            # Have we been signaled to stop?
            if self.form.stop_event.is_set():
                raise pe_tree.exceptions.ThreadStopping()

            image_base = self.image_base
            filename = self.filename

            # Ensure we have a valid image base or file path
            if image_base == 0 and (filename and not os.path.isfile(filename)):
                return

            if self.image_base > 0 and filename and not os.path.isfile(filename):
                # Working from memory/supplied data
                if self.data:
                    # Data already supplied
                    self.dumped = True
                else:
                    # Read PE data from memory
                    self.data = self.runtime.read_pe(image_base)

                if self.data is None:
                    return

                # Length of PE file in bytes
                self.size = len(self.data)

                if not filename:
                    filename = "{}-0x{:0{w}x}".format(self.runtime.get_segment_name(image_base), image_base, w=self.ptr_size)

                self.signals.process_file.emit(filename)

                # Parse PE file
                try:
                    self.pe = pefile.PE(data=self.data)
                except:
                    self.signals.update_ui.emit(None)
                    return

                self.org_data = self.data

                # Attempt to automatically dump if enabled (for IDA Pro plugin only)
                if not self.dumped and pe_tree.form.HAVE_IDA and self.runtime.get_config_option("dump", "enable", True):
                    # Re-initialise pefile based on dumped PE
                    try:
                        pe_data = pe_tree.dump_pe.DumpPEFile(self.pe, self.image_base, self.size, self.runtime, recalculate_pe_checksum=self.runtime.get_config_option("dump", "recalculate_pe_checksum", False)).dump()

                        if pe_data:
                            self.pe = pefile.PE(data=pe_data)

                            self.data = pe_data

                            self.dumped = True
                    except:
                        print(traceback.format_exc())

                self.size = len(self.data)

                # Hash PE data
                pe_hashes = pe_tree.hash_pe.hash_pe_file(None, data=self.data, pe=self.pe, json_dumps=False)

                self.loaded_from_idb = True
            else:
                # Load PE from file
                try:
                    self.signals.process_file.emit(filename)

                    self.pe = pefile.PE(filename)
                except:
                    self.signals.update_ui.emit(None)
                    return

                self.size = os.path.getsize(filename)

                if pe_tree.form.HAVE_IDA:
                    # Read PE data from memory
                    self.org_data = self.runtime.read_pe(image_base)

                if self.form.processpool:
                    # Hash input file and calculate entropy in a separate process
                    pe_hashes = json.loads(self.form.processpool.apply_async(pe_tree.hash_pe.hash_pe_file, (filename,)).get())
                else:
                    # Hash input file and calculate entropy
                    pe_hashes = pe_tree.hash_pe.hash_pe_file(filename, data=None, pe=self.pe, json_dumps=False)

                # Use image base from optional header
                image_base = self.pe.OPTIONAL_HEADER.ImageBase

                self.image_base = image_base

                self.loaded_from_idb = False

            pe = self.pe
            self.filename = os.path.basename(filename)
            self.disasm = self.runtime.init_capstone(pe)

            # Determine pointer size based on architecture (note, this is printable width for format())
            self.ptr_size = 16 if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"] else 8

            # Dump pefile information to output
            if self.runtime.get_config_option("config", "debug", False):
                self.runtime.log(pe.dump_info())

            # Create the root nodes
            file_item = pe_tree.qstandarditems.HeaderItem(self, name=self.filename, filepath=filename, is_root=True)

            self.root_item = file_item

            self.root_value_item = pe_tree.qstandarditems.PEFileItem(self, name="")

            try:
                warnings = pe.get_warnings()
            except:
                warnings = []

            if self.dumped:
                if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                        self.root_value_item = pe_tree.qstandarditems.WarningItem(self, name="Missing imports/exports", tooltip="\n".join(warnings))
                    else:
                        self.root_value_item = pe_tree.qstandarditems.WarningItem(self, name="Missing imports", tooltip="\n".join(warnings))
                else:
                    self.root_value_item = pe_tree.qstandarditems.InformationItem(self, name="Dumped/IAT repaired", tooltip="\n".join(warnings))
            elif len(warnings) > 0:
                self.root_value_item = pe_tree.qstandarditems.WarningItem(self, name="{} warning{}".format(len(warnings), "s" if len(warnings) > 1 else ""), tooltip="\n".join(warnings))

            # File information
            file_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Size"), pe_tree.qstandarditems.SizeItem(self, size=self.size, show_hex=False)])
            file_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="MD5"), pe_tree.qstandarditems.PEFileItem(self, name=pe_hashes["file"]["md5"], vt_query="{}")])
            file_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="SHA1"), pe_tree.qstandarditems.PEFileItem(self, name=pe_hashes["file"]["sha1"], vt_query="{}")])
            file_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="SHA256"), pe_tree.qstandarditems.PEFileItem(self, name=pe_hashes["file"]["sha256"], vt_query="{}")])
            file_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Imphash"), pe_tree.qstandarditems.PEFileItem(self, name=pe.get_imphash(), vt_query="imphash:\"{}\"")])
            file_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Entropy"), pe_tree.qstandarditems.EntropyItem(self, pe_hashes["file"]["entropy"])])

            if pe_hashes["file_no_overlay"]["size"] > 0:
                file_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="MD5 (no overlay)"), pe_tree.qstandarditems.PEFileItem(self, name=pe_hashes["file_no_overlay"]["md5"], vt_query="{}")])
                file_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="SHA1 (no overlay)"), pe_tree.qstandarditems.PEFileItem(self, name=pe_hashes["file_no_overlay"]["sha1"], vt_query="{}")])
                file_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="SHA256 (no overlay)"), pe_tree.qstandarditems.PEFileItem(self, name=pe_hashes["file_no_overlay"]["sha256"], vt_query="{}")])
                file_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Entropy (no overlay)"), pe_tree.qstandarditems.EntropyItem(self, pe_hashes["file_no_overlay"]["entropy"])])

            file_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Compiled"), pe_tree.qstandarditems.PEFileItem(self, name=datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).strftime("%Y-%m-%dT%H:%M:%S"), vt_query="generated:\"{}\"")])

            if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
                for debug in pe.DIRECTORY_ENTRY_DEBUG:
                    if debug.struct.Type == 2:
                        if hasattr(debug, "entry") and hasattr(debug.entry, "PdbFileName"):
                            file_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="PdbFilePath"), pe_tree.qstandarditems.PEFileItem(self, name=pe_tree.qstandarditems.PEFileString(debug.entry.PdbFileName.rstrip(b"\x00")), vt_query="\"{}\"")])

            # Root items
            mz_item = pe_tree.qstandarditems.HeaderItem(self, name="IMAGE_DOS_HEADER")
            dos_item = pe_tree.qstandarditems.SaveableHeaderItem(self, name="DOS_STUB", offset=64, size=pe.DOS_HEADER.e_lfanew - 64)
            pe_item = pe_tree.qstandarditems.HeaderItem(self, name="IMAGE_NT_HEADERS")

            file_item.appendRow([mz_item, pe_tree.qstandarditems.PEFileItem(self, name="")])
            file_item.appendRow([dos_item, pe_tree.qstandarditems.PEFileItem(self, name="")])
            file_item.appendRow([pe_item, pe_tree.qstandarditems.PEFileItem(self, name="", offset=pe.DOS_HEADER.e_lfanew)])

            # DOS_HEADER
            self.regions.append(pe_tree.map.FileRegion("DOS_HEADER", item=mz_item, rva=image_base + 0, start=0, end=64))

            for item in self.dump(pe.DOS_HEADER):
                if item["key"] == "e_magic":
                    item["name"] += " MZ"

                mz_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name=item["key"]), pe_tree.qstandarditems.PEFileItem(self, **item)])

                # Comment the structure in the IDB
                self.comment_item(item)

            # DOS STUB
            dos_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Size"), pe_tree.qstandarditems.SizeItem(self, size=pe.DOS_HEADER.e_lfanew - 64, show_hex=False)])
            dos_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Ratio"), pe_tree.qstandarditems.RatioItem(self, size=pe.DOS_HEADER.e_lfanew - 64, offset=64)])

            dos_stub = pe.get_data(64, pe.DOS_HEADER.e_lfanew)

            dos_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="MD5"), pe_tree.qstandarditems.PEFileItem(self, name=pe_hashes["dos_stub"]["md5"])])
            dos_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="SHA1"), pe_tree.qstandarditems.PEFileItem(self, name=pe_hashes["dos_stub"]["sha1"])])
            dos_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="SHA256"), pe_tree.qstandarditems.PEFileItem(self, name=pe_hashes["dos_stub"]["sha256"], vt_query="{}")])

            dos_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Entropy"), pe_tree.qstandarditems.EntropyItem(self, pe_hashes["dos_stub"]["entropy"])])

            self.regions.append(pe_tree.map.FileRegion("DOS_STUB", item=dos_item, rva=image_base + 64, start=0, end=pe.DOS_HEADER.e_lfanew - 64))

            ascii_re = re.compile(bytes(str(r"([ !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t]{6,})").encode("utf-8")))

            for match in ascii_re.finditer(dos_stub):
                dos_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Message"), pe_tree.qstandarditems.PEFileItem(self, name=match.group())])

            # RICH_HEADER
            if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER:
                rich_header_item = pe_tree.qstandarditems.HeaderItem(self, name="RICH_HEADER")

                rich_md5 = hashlib.md5()
                rich_md5.update(pe.RICH_HEADER.raw_data)
                rich_header_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="MD5"), pe_tree.qstandarditems.PEFileItem(self, name=rich_md5.hexdigest())])
                rich_header_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Checksum"), pe_tree.qstandarditems.PEFileItem(self, name="0x{:08x}".format(pe.RICH_HEADER.checksum))])

                dos_item.appendRow([rich_header_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

                if self.form.compiler_ids is not None:
                    tools = {}

                    # Parse value:count
                    it = iter(pe.RICH_HEADER.values)
                    for value in it:
                        count = next(it)

                        # Find tool/lang/description
                        try:
                            description = self.form.compiler_ids["{0:08x}".format(value)]
                            lang_tool = description.split("] ")
                            lang = lang_tool[0][1:]
                            tool = lang_tool[1]
                        except:
                            description = "N/A"
                            lang = "N/A"
                            tool = "UNKNOWN"

                        if not tool in tools:
                            tools[tool] = []

                        tools[tool].append([lang.strip(), count])

                    # Add compiler tools to tree
                    for tool in tools:
                        tool_header_item = pe_tree.qstandarditems.HeaderItem(self, name=tool)

                        for lang, count in tools[tool]:
                            tool_header_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name=lang), pe_tree.qstandarditems.PEFileItem(self, name="{}".format(count))])

                        rich_header_item.appendRow([tool_header_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

            # NT_HEADER
            nt_header_item = pe_tree.qstandarditems.HeaderItem(self, name="NT_HEADERS")
            self.regions.append(pe_tree.map.FileRegion("NT_HEADERS", item=nt_header_item, rva=image_base + pe.NT_HEADERS.get_file_offset(), start=pe.NT_HEADERS.get_file_offset(), size=pe.NT_HEADERS.sizeof()))

            for item in self.dump(pe.NT_HEADERS):
                if item["key"] == "Signature":
                    item["name"] += " PE"
                nt_header_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name=item["key"]), pe_tree.qstandarditems.PEFileItem(self, **item)])

                self.comment_item(item)

            pe_item.appendRow([nt_header_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

            # FILE_HEADER
            file_header_item = pe_tree.qstandarditems.HeaderItem(self, name="FILE_HEADER")
            self.regions.append(pe_tree.map.FileRegion("FILE_HEADER", item=file_header_item, rva=image_base + pe.FILE_HEADER.get_file_offset(), start=pe.FILE_HEADER.get_file_offset(), size=pe.FILE_HEADER.sizeof()))

            for item in self.dump(pe.FILE_HEADER):
                if item["key"] == "Machine":
                    if pe.FILE_HEADER.Machine in pefile.MACHINE_TYPE:
                        item["name"] += " {}".format(pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine].replace("IMAGE_FILE_MACHINE_", ""))
                elif item["key"] == "Characteristics":
                    characteristics = []
                    for name, val in pefile.image_characteristics:
                        if val & pe.FILE_HEADER.Characteristics:
                            characteristics.append(name.replace("IMAGE_FILE_", ""))
                    item["name"] += " {}".format(" | ".join(characteristics))

                file_header_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name=item["key"]), pe_tree.qstandarditems.PEFileItem(self, **item)])

            nt_header_item.appendRow([file_header_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

            # OPTIONAL_HEADER
            optional_header_item = pe_tree.qstandarditems.HeaderItem(self, name="OPTIONAL_HEADER")
            self.regions.append(pe_tree.map.FileRegion("OPTIONAL_HEADER", item=optional_header_item, rva=image_base + pe.OPTIONAL_HEADER.get_file_offset(), start=pe.OPTIONAL_HEADER.get_file_offset(), size=pe.OPTIONAL_HEADER.sizeof()))

            for item in self.dump(pe.OPTIONAL_HEADER):
                if item["key"] == "Subsystem":
                    item["name"] += " {}".format(pefile.SUBSYSTEM_TYPE[pe.OPTIONAL_HEADER.Subsystem].replace("IMAGE_SUBSYSTEM_", ""))
                elif item["key"] == "MajorLinkerVersion":
                    versions = dict([
                        (5.0, "Visual Studio 97"),
                        (6.0, "Visual Studio"),
                        (7.0, "Visual Studio .NET 2002"),
                        (7.0, "Visual Studio .NET 2003"),
                        (8.0, "Visual Studio 2005"),
                        (9.0, "Visual Studio 2008"),
                        (10.0, "Visual Studio 2010"),
                        (11.0, "Visual Studio 2012"),
                        (12.0, "Visual Studio 2013"),
                        (14.0, "Visual Studio 2015"),
                        (14.1, "Visual Studio 2017"),
                        (14.2, "Visual Studio 2019")
                    ])
                    try:
                        key = float(int(float("{}.{}".format(pe.OPTIONAL_HEADER.MajorLinkerVersion, pe.OPTIONAL_HEADER.MinorLinkerVersion)) * 10) / 10)
                        item["name"] += " {} {}.{}".format(versions[key], pe.OPTIONAL_HEADER.MajorLinkerVersion, pe.OPTIONAL_HEADER.MinorLinkerVersion)
                    except:
                        item["name"] += " {}.{}".format(pe.OPTIONAL_HEADER.MajorLinkerVersion, pe.OPTIONAL_HEADER.MinorLinkerVersion)
                elif item["key"] == "MajorOperatingSystemVersion":
                    versions = dict([
                        (5, ["Windows 2000", "Windows XP", "Windows Server 2003"]),
                        (6, ["Windows Vista/Windows Server 2008", "Windows 7/Windows Server 2008 R2", "Windows 8/Windows Server 2012", "Windows 8.1/Windows Server 2012 R2"]),
                        (10, ["Windows 10/Windows Server 2016",])
                    ])
                    try:
                        item["name"] += " {}".format(versions[pe.OPTIONAL_HEADER.MajorOperatingSystemVersion][pe.OPTIONAL_HEADER.MinorOperatingSystemVersion])
                    except:
                        pass
                elif item["key"] == "DllCharacteristics":
                    characteristics = []
                    for name, val in pefile.dll_characteristics:
                        if val & pe.OPTIONAL_HEADER.DllCharacteristics:
                            characteristics.append(name.replace("IMAGE_DLLCHARACTERISTICS_", ""))
                    item["name"] += " {}".format(" | ".join(characteristics))
                elif item["key"] == "Magic":
                    if pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE:
                        item["name"] += " PE"
                    elif pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
                        item["name"] += " PE+"

                optional_header_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name=item["key"]), pe_tree.qstandarditems.PEFileItem(self, **item)])

                self.comment_item(item)

            # DATA_DIRECTORY
            data_directory_item = pe_tree.qstandarditems.HeaderItem(self, name="DATA_DIRECTORY")

            for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                if entry.VirtualAddress > 0:
                    directory_item = pe_tree.qstandarditems.HeaderItem(self, name=entry.name)

                    if entry != pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]:
                        # We will add this region properly later!
                        self.regions.append(pe_tree.map.FileRegion(entry.name, item=directory_item, rva=image_base + entry.VirtualAddress, start=self.get_offset_from_rva(entry.VirtualAddress), size=entry.Size))

                    directory_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="VirtualAddress"), pe_tree.qstandarditems.PEFileItem(self, name="0x{:0{w}x}".format(entry.VirtualAddress, w=8), offset=entry.VirtualAddress, size=entry.Size, valid_va=True)])
                    directory_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Size"), pe_tree.qstandarditems.SizeItem(self, size=entry.Size, width=8)])

                    data_directory_item.appendRow([directory_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

            optional_header_item.appendRow([data_directory_item, pe_tree.qstandarditems.PEFileItem(self, name="")])


            nt_header_item.appendRow([optional_header_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

            # Sections
            if hasattr(pe, "sections") and len(pe.sections) > 0:
                sections_item = pe_tree.qstandarditems.HeaderItem(self, name="IMAGE_SECTION_HEADER")
                self.regions.append(pe_tree.map.FileRegion("IMAGE_SECTION_HEADER", item=sections_item, rva=image_base + pe.sections[0].get_file_offset(), start=pe.sections[0].get_file_offset(), size=pe.sections[-1].get_file_offset() + pe.sections[-1].sizeof()))

                section_hashes_iter = iter(pe_hashes["sections"])

                for section in pe.sections:
                    dump = self.dump(section)

                    # Find section name
                    name = ""

                    for item in dump:
                        if item["key"] == "Name":
                            name = item["name"]

                    if not sys.version_info > (3,):
                        name = str(name)

                    section_item = pe_tree.qstandarditems.SaveableHeaderItem(self, name=name, offset=section.VirtualAddress, size=section.Misc_VirtualSize, vt_query="section:\"{}\"")

                    for item in dump:
                        if item["key"] == "Characteristics":
                            characteristics = []
                            for _item in section.__dict__:
                                if _item.startswith("IMAGE_SCN_") and section.__dict__[_item]:
                                    _item = _item.replace("IMAGE_SCN_CNT_", "").replace("IMAGE_SCN_MEM_", "").replace("IMAGE_SCN_", "")
                                    characteristics.append(_item)

                            item["name"] = "{} {}".format(item["name"], " | ".join(characteristics))

                        section_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name=item["key"]), pe_tree.qstandarditems.PEFileItem(self, **item)])

                        self.comment_item(item)

                    self.regions.append(pe_tree.map.FileRegion(name, item=section_item, rva=image_base + section.VirtualAddress, start=section.PointerToRawData, size=section.SizeOfRawData))

                    section_hashes = next(section_hashes_iter)

                    section_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Entropy"), pe_tree.qstandarditems.EntropyItem(self, section_hashes["entropy"])])
                    section_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="SHA256"), pe_tree.qstandarditems.PEFileItem(self, name=section_hashes["sha256"])])
                    section_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="MD5"), pe_tree.qstandarditems.PEFileItem(self, name=section_hashes["md5"], vt_query="sectionmd5:\"{}\"")])
                    section_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Ratio"), pe_tree.qstandarditems.RatioItem(self, size=section.SizeOfRawData, offset=section.PointerToRawData, entropy=section_hashes["entropy"])])

                    sections_item.appendRow([section_item, pe_tree.qstandarditems.PEFileItem(self, name="", offset=section.VirtualAddress)])

                pe_item.appendRow([sections_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

            # Imports
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                imports_item = pe_tree.qstandarditems.HeaderItem(self, name="IMAGE_IMPORT_DESCRIPTOR")

                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_item = pe_tree.qstandarditems.HeaderItem(self, name=entry.dll, vt_query="imports:\"{}\"")

                    for item in self.dump(entry.struct):
                        dll_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name=item["key"]), pe_tree.qstandarditems.PEFileItem(self, **item)])

                    for imp in entry.imports:
                        name = imp.name

                        if pe_tree.form.HAVE_IDA:
                            if name is None:
                                # Ordinal import - get name from disassembly
                                name = self.runtime.get_label(imp.address)
                            else:
                                name = name.decode()

                            if self.ptr_size == 8:
                                offset = self.runtime.get_dword(imp.address)
                            else:
                                offset = self.runtime.get_qword(imp.address)

                            # Name import address in IDA
                            if offset > 0:
                                imp_name = self.runtime.get_name(offset)

                                if imp_name:
                                    imp_name = imp_name[name.find("_") + 1:]

                                    # strip "32_" prefix
                                    if imp_name.find("32_") == 0:
                                        imp_name = imp_name[3:]

                                    if self.ptr_size == 8:
                                        self.runtime.make_dword(imp.address)
                                    else:
                                        self.runtime.make_qword(imp.address)

                                    # Make name
                                    self.runtime.make_name(imp.address, imp_name)

                            if name == None:
                                name = ""

                        address = imp.address if imp.address < pe.OPTIONAL_HEADER.ImageBase else imp.address - pe.OPTIONAL_HEADER.ImageBase

                        dll_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name=name, vt_query="imports:\"{}\""), pe_tree.qstandarditems.PEFileItem(self, name="0x{:0{w}x}".format(address, w=self.ptr_size), offset=address, valid_va=True)])

                    imports_item.appendRow([dll_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

                pe_item.appendRow([imports_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

            # Exports
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                exports_item = pe_tree.qstandarditems.HeaderItem(self, name="IMAGE_EXPORT_DESCRIPTOR")

                for item in self.dump(pe.DIRECTORY_ENTRY_EXPORT.struct):
                    exports_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name=item["key"]), pe_tree.qstandarditems.PEFileItem(self, **item)])

                dll_items = pe_tree.qstandarditems.HeaderItem(self, name=pe_tree.qstandarditems.PEFileString(pe.get_string_at_rva(pe.DIRECTORY_ENTRY_EXPORT.struct.Name)), vt_query="exports:\"{}\"")

                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    export_name = pe_tree.qstandarditems.PEFileString(exp.name).string if exp.name is not None else ""

                    if exp.forwarder is not None:
                        # Forwarded
                        export_item = pe_tree.qstandarditems.PEFileItem(self, name="{} -> {}".format(export_name, pe_tree.qstandarditems.PEFileString(exp.forwarder).string), vt_query="exports:\"{}\"".format(export_name))
                    elif exp.ordinal != "":
                        # Ordinal
                        export_item = pe_tree.qstandarditems.PEFileItem(self, name="{}@{}".format(export_name, exp.ordinal), vt_query="exports:\"{}\"")
                    else:
                        # Name
                        export_item = pe_tree.qstandarditems.PEFileItem(self, name=export_name, vt_query="exports:\"{}\"")

                    address = exp.address if exp.address < self.pe.OPTIONAL_HEADER.ImageBase else exp.address - self.pe.OPTIONAL_HEADER.ImageBase

                    dll_items.appendRow([export_item, pe_tree.qstandarditems.PEFileItem(self, name="0x{:0{w}x}".format(address, w=self.ptr_size), offset=address, valid_va=True)])

                exports_item.appendRow([dll_items, pe_tree.qstandarditems.PEFileItem(self, name="")])

                pe_item.appendRow([exports_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

            # IMAGE_DIRECTORY_ENTRY_DEBUG
            if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
                debug_items = pe_tree.qstandarditems.HeaderItem(self, name="IMAGE_DIRECTORY_ENTRY_DEBUG")

                i = 0
                for debug in pe.DIRECTORY_ENTRY_DEBUG:
                    try:
                        name = pefile.DEBUG_TYPE[debug.struct.Type]
                    except:
                        name = None

                    debug_item = pe_tree.qstandarditems.HeaderItem(self, name="{}".format(i))

                    for item in self.dump(debug.struct):
                        if item["key"] == "Type":
                            if name:
                                item["name"] += " {}".format(name)

                        debug_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name=item["key"]), pe_tree.qstandarditems.PEFileItem(self, **item)])

                        self.comment_item(item)

                    if debug.entry and name:
                        debug_item2 = pe_tree.qstandarditems.HeaderItem(self, name=name)

                        for item in self.dump(debug.entry):
                            debug_item2.appendRow([pe_tree.qstandarditems.PEFileItem(self, name=item["key"]), pe_tree.qstandarditems.PEFileItem(self, **item)])

                            self.comment_item(item)

                        debug_item.appendRow([debug_item2, pe_tree.qstandarditems.PEFileItem(self, name="")])


                    debug_items.appendRow([debug_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

                    i += 1

                pe_item.appendRow([debug_items, pe_tree.qstandarditems.PEFileItem(self, name="")])

            # IMAGE_DIRECTORY_ENTRY_TLS
            if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
                tls_items = pe_tree.qstandarditems.HeaderItem(self, name="IMAGE_DIRECTORY_ENTRY_TLS")

                for item in self.dump(pe.DIRECTORY_ENTRY_TLS.struct):
                    tls_items.appendRow([pe_tree.qstandarditems.PEFileItem(self, name=item["key"]), pe_tree.qstandarditems.PEFileItem(self, **item)])

                    self.comment_item(item)

                pe_item.appendRow([tls_items, pe_tree.qstandarditems.PEFileItem(self, name="")])


            # IMAGE_LOAD_CONFIG_DIRECTORY
            if hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
                load_config_items = pe_tree.qstandarditems.HeaderItem(self, name="IMAGE_LOAD_CONFIG_DIRECTORY")

                for item in self.dump(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct):
                    load_config_items.appendRow([pe_tree.qstandarditems.PEFileItem(self, name=item["key"]), pe_tree.qstandarditems.PEFileItem(self, **item)])

                    self.comment_item(item)

                pe_item.appendRow([load_config_items, pe_tree.qstandarditems.PEFileItem(self, name="")])

            # Resources
            resources_hashes_iter = iter(pe_hashes["resources"])

            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                resources_item = pe_tree.qstandarditems.HeaderItem(self, name="IMAGE_RESOURCE_DIRECTORY")

                mapped_data = pe.get_memory_mapped_image()

                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if not hasattr(resource_type, "directory"):
                        continue

                    try:
                        if resource_type.name:
                            entry_name = str(resource_type.name)
                        else:
                            entry_name = pefile.RESOURCE_TYPE.get(resource_type.struct.Id)

                        entry_name = entry_name if entry_name else "UNKNOWN"
                    except:
                        continue

                    resource_item = pe_tree.qstandarditems.HeaderItem(self, name=entry_name)

                    for resource_id in resource_type.directory.entries:
                        if not hasattr(resource_id, "directory"):
                            continue

                        for resource_language in resource_id.directory.entries:
                            if not hasattr(resource_language, "data"):
                                continue

                            lang_str = pefile.LANG.get(resource_language.data.lang)

                            lang_str = lang_str.replace("LANG_", "") if lang_str else "UNKNOWN"

                            if resource_id.name:
                                name = "{} ({})".format(resource_id.name, lang_str)
                                save_filename = "{}_{}_{}".format(entry_name, resource_id.name, lang_str)
                            else:
                                name = "{} ({})".format(resource_id.struct.Id, lang_str)
                                save_filename = "{}_{}_{}".format(entry_name, resource_id.struct.Id, lang_str)

                            next_item = pe_tree.qstandarditems.PEFileItem(self, name=name)

                            # Get resource
                            offset = resource_language.data.struct.OffsetToData
                            size = resource_language.data.struct.Size
                            offset_to_data = self.va_to_rva(offset)

                            try:
                                data = mapped_data[offset:offset + size]
                            except:
                                data = ""

                            # Attempt to draw icon
                            if resource_type.struct.Id == pefile.RESOURCE_TYPE["RT_ICON"]: #or resource_type.struct.Id == pefile.RESOURCE_TYPE["RT_GROUP_ICON"]:
                                ext = "bin"
                                if data not in (None, ""):
                                    if data[1:4] == "PNG":
                                        ext = "png"
                                    else:
                                        ext = "bmp"

                                value_item = pe_tree.qstandarditems.SaveableHeaderItem(self, name=name, filename=save_filename, ext=ext, data=data, offset=offset_to_data, size=size)
                                value_item.setIcon(pe_tree.utils.qicon_from_ico_data(data))
                            else:
                                cyberchef_recipe = ""
                                # Convert manifest to ASCII string
                                if resource_type.struct.Id == pefile.RESOURCE_TYPE["RT_MANIFEST"]:
                                    if pe_tree.form.HAVE_IDA:
                                        self.runtime.make_string(image_base + offset, size)
                                    cyberchef_recipe = "XML_Beautify('%5C%5Ct')"

                                value_item = pe_tree.qstandarditems.SaveableHeaderItem(self, name=name, filename=save_filename, offset=offset_to_data, size=size, cyberchef_recipe=cyberchef_recipe)

                            resource_hashes = next(resources_hashes_iter)

                            value_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Offset"), pe_tree.qstandarditems.PEFileItem(self, name="0x{:0{w}x}".format(offset_to_data, w=self.ptr_size), filename=save_filename, offset=offset_to_data, size=size, valid_va=True)])
                            value_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Size"), pe_tree.qstandarditems.SizeItem(self, size=size)])
                            value_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Entropy"), pe_tree.qstandarditems.EntropyItem(self, resource_hashes["entropy"])])
                            value_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="SHA256"), pe_tree.qstandarditems.PEFileItem(self, name=resource_hashes["sha256"], vt_query="resource:\"{}\"")])
                            value_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Ratio"), pe_tree.qstandarditems.RatioItem(self, size=size, offset=self.get_offset_from_rva(offset_to_data), entropy=resource_hashes["entropy"])])
                            self.regions.append(pe_tree.map.FileRegion(save_filename, item=value_item, rva=image_base + offset_to_data, start=self.get_offset_from_rva(offset_to_data), size=size))

                            resource_item.appendRow([value_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

                            # List strings in string table
                            if resource_type.struct.Id == pefile.RESOURCE_TYPE["RT_STRING"]:
                                for rt_string in resource_id.directory.strings:
                                    next_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name=resource_id.directory.strings[rt_string]), pe_tree.qstandarditems.PEFileItem(self, name="")])

                    resources_item.appendRow([resource_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

                pe_item.appendRow([resources_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

            language_ids = {
                "0x0401": "Arabic",
                "0x0415": "Polish",
                "0x0402": "Bulgarian",
                "0x0416": "Portuguese (Brazil)",
                "0x0403": "Catalan",
                "0x0417": "Rhaeto-Romanic",
                "0x0404": "Traditional Chinese",
                "0x0418": "Romanian",
                "0x0405": "Czech",
                "0x0419": "Russian",
                "0x0406": "Danish",
                "0x041A": "Croato-Serbian (Latin)",
                "0x0407": "German",
                "0x041B": "Slovak",
                "0x0408": "Greek",
                "0x041C": "Albanian",
                "0x0409": "U.S. English",
                "0x041D": "Swedish",
                "0x040A": "Castilian Spanish",
                "0x041E": "Thai",
                "0x040B": "Finnish",
                "0x041F": "Turkish",
                "0x040C": "French",
                "0x0420": "Urdu",
                "0x040D": "Hebrew",
                "0x0421": "Bahasa",
                "0x040E": "Hungarian",
                "0x0804": "Simplified Chinese",
                "0x040F": "Icelandic",
                "0x0807": "Swiss German",
                "0x0410": "Italian",
                "0x0809": "U.K. English",
                "0x0411": "Japanese",
                "0x080A": "Spanish (Mexico)",
                "0x0412": "Korean",
                "0x080C": "Belgian French",
                "0x0413": "Dutch",
                "0x0C0C": "Canadian French",
                "0x0414": "Norwegian - Bokmal",
                "0x100C": "Swiss French",
                "0x0810": "Swiss Italian",
                "0x0816": "Portuguese (Portugal)",
                "0x0813": "Belgian Dutch",
                "0x081A": "Serbo-Croatian (Cyrillic)",
                "0x0814": "Norwegian - Nynorsk"
                }

            charset_ids = {
                "0x0000": "7-bit ASCII",
                "0x03a4": "Japan (Shift - JIS X-0208)",
                "0x03b5": "Korea (Shift - KSC 5601)",
                "0x03b6": "Taiwan (Big5)",
                "0x04b0": "Unicode",
                "0x04e2": "Latin-2 (Eastern European)",
                "0x04e3": "Cyrillic",
                "0x04e4": "Multilingual",
                "0x04e5": "Greek",
                "0x04e6": "Turkish",
                "0x04e7": "Hebrew",
                "0x04e8": "Arabic"
                }

             # VS_VERSIONINFO
            if hasattr(pe, "VS_VERSIONINFO") and hasattr(pe, "FileInfo"):
                versionifo_item = pe_tree.qstandarditems.HeaderItem(self, name="VS_VERSIONINFO")

                versionifo_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Length"), pe_tree.qstandarditems.PEFileItem(self, name="0x{:08x}".format(pe.VS_VERSIONINFO[0].Length, w=self.ptr_size))])
                versionifo_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Type"), pe_tree.qstandarditems.PEFileItem(self, name="0x{:08x}".format(pe.VS_VERSIONINFO[0].Type, w=self.ptr_size))])

                if len(pe.FileInfo) > 0:
                    for fileinfo in pe.FileInfo[0]:
                        if hasattr(fileinfo, "StringTable"):
                            for st in fileinfo.StringTable:
                                for entry in st.entries.items():
                                    versionifo_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name=pe_tree.qstandarditems.PEFileString(entry[0])), pe_tree.qstandarditems.PEFileItem(self, name=pe_tree.qstandarditems.PEFileString(entry[1]))])

                        elif hasattr(fileinfo, "Var"):
                            for var in fileinfo.Var:
                                if not hasattr(var, "entry"):
                                    continue

                                for key in var.entry:
                                    values = []

                                    # Convert language and charset IDs
                                    for code in var.entry[key].split(" "):
                                        if code in language_ids:
                                            values.append("{} ({})".format(language_ids[code], code))
                                        elif code in charset_ids:
                                            values.append("{} ({})".format(charset_ids[code], code))
                                        else:
                                            values.append(code)

                                    versionifo_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name=pe_tree.qstandarditems.PEFileString(key)), pe_tree.qstandarditems.PEFileItem(self, name=", ".join(values))])

                file_item.appendRow([versionifo_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

            # Is overlay present?
            offset = pe.get_overlay_data_start_offset()

            if offset is not None:
                data = pe.get_overlay()

                # Certificate
                security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]

                if security.VirtualAddress != 0 and security.Size != 0:
                    size = min(security.Size, len(data))
                    cert_data = data[:size]

                    data = data[size:]
                    offset += size

                    certificates_item = pe_tree.qstandarditems.SaveableHeaderItem(self, name="SECURITY_DIRECTORY", data=cert_data, offset=security.VirtualAddress, size=security.Size)
                    self.regions.append(pe_tree.map.FileRegion("IMAGE_DIRECTORY_ENTRY_SECURITY", item=certificates_item, rva=image_base + offset, start=offset, size=security.Size))

                    certificates_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Offset"), pe_tree.qstandarditems.PEFileItem(self, name="0x{:0{w}x}".format(security.VirtualAddress, w=self.ptr_size), offset=security.VirtualAddress, size=security.Size)])
                    certificates_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Size"), pe_tree.qstandarditems.SizeItem(self, size=security.Size, offset=security.VirtualAddress + security.Size, show_hex=False)])
                    certificates_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Ratio"), pe_tree.qstandarditems.RatioItem(self, size=security.Size, offset=security.VirtualAddress, entropy=pe_hashes["security_directory"]["entropy"])])
                    certificates_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="MD5"), pe_tree.qstandarditems.PEFileItem(self, name=pe_hashes["security_directory"]["md5"])])
                    certificates_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="SHA1"), pe_tree.qstandarditems.PEFileItem(self, name=pe_hashes["security_directory"]["sha1"])])
                    certificates_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="SHA256"), pe_tree.qstandarditems.PEFileItem(self, name=pe_hashes["security_directory"]["sha256"], vt_query="{}")])

                    certificates_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Entropy"), pe_tree.qstandarditems.EntropyItem(self, pe_hashes["security_directory"]["entropy"])])

                    try:
                        # Load certificate/parse ASN.1
                        try:
                            signature = cms.ContentInfo.load(bytes(cert_data[8:]))
                        except:
                            # For some reason the overlay data sometimes contains 0x40 bytes of the final section?
                            data = pe.get_overlay()
                            cert_data = data[0x48:size + 0x48]
                            data = data[size + 0x48:]
                            signature = cms.ContentInfo.load(cert_data)

                        if signature:
                            # Iterate over certificates
                            for cert in signature["content"]["certificates"]:
                                try:
                                    x509_cert = x509.load_der_x509_certificate(cert.dump(), default_backend())

                                    certificate_item = pe_tree.qstandarditems.SaveableHeaderItem(self, name="{}".format(x509_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value), data=x509_cert.public_bytes(serialization.Encoding.PEM), ext="cer", cyberchef_recipe="Parse_X.509_certificate('PEM')")

                                    # Certificate information
                                    # pylint: disable=protected-access
                                    certificate_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Not valid before"), pe_tree.qstandarditems.PEFileItem(self, name="{}".format(x509_cert.not_valid_before), time=time.mktime(x509_cert.not_valid_before.timetuple()), vt_query="signature:\"{}\"")])
                                    certificate_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Not valid after"), pe_tree.qstandarditems.PEFileItem(self, name="{}".format(x509_cert.not_valid_after), time=time.mktime(x509_cert.not_valid_after.timetuple()), vt_query="signature:\"{}\"")])
                                    certificate_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Serial number"), pe_tree.qstandarditems.PEFileItem(self, name="{0:x}".format(x509_cert.serial_number), vt_query="signature:\"{}\"")])
                                    certificate_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Fingerprint"), pe_tree.qstandarditems.PEFileItem(self, name=binascii.hexlify(x509_cert.fingerprint(hashes.SHA256())))])
                                    certificate_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Signature algorithm"), pe_tree.qstandarditems.PEFileItem(self, name="{}".format(x509_cert.signature_algorithm_oid._name))])
                                    certificate_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Signature hash algorithm"), pe_tree.qstandarditems.PEFileItem(self, name="{}".format(x509_cert.signature_hash_algorithm.name))])

                                    # Subject information
                                    subject_item = pe_tree.qstandarditems.HeaderItem(self, name="Subject")
                                    for attribute in x509_cert.subject:
                                        subject_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="{}".format(attribute.oid._name)), pe_tree.qstandarditems.PEFileItem(self, name="{}".format(attribute.value))])
                                    certificate_item.appendRow([subject_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

                                    # Issuer information
                                    issuer_item = pe_tree.qstandarditems.HeaderItem(self, name="Issuer")
                                    for attribute in x509_cert.issuer:
                                        issuer_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="{}".format(attribute.oid._name)), pe_tree.qstandarditems.PEFileItem(self, name="{}".format(attribute.value))])
                                    certificate_item.appendRow([issuer_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

                                    certificates_item.appendRow([certificate_item, pe_tree.qstandarditems.PEFileItem(self, name="")])
                                except:
                                    continue

                            file_item.appendRow([certificates_item, pe_tree.qstandarditems.PEFileItem(self, name="")])
                    except Exception as e:
                        # Report exception to user
                        file_item.appendRow([certificates_item, pe_tree.qstandarditems.ErrorItem(self, name=str(e), tooltip=traceback.format_exc())])

                # Overlay. ToDo: properly verify this offset is sane!
                if len(data) > 0:
                    overlay_item = pe_tree.qstandarditems.SaveableHeaderItem(self, name="OVERLAY", data=data, offset=offset)
                    self.regions.append(pe_tree.map.FileRegion("OVERLAY", item=overlay_item, rva=image_base + offset, start=offset, size=len(data)))

                    overlay_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Offset"), pe_tree.qstandarditems.PEFileItem(self, name="0x{:0{w}x}".format(offset, w=self.ptr_size), offset=offset, size=len(data))])
                    overlay_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Size"), pe_tree.qstandarditems.SizeItem(self, size=len(data), offset=offset + len(data), show_hex=False)])
                    overlay_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Ratio"), pe_tree.qstandarditems.RatioItem(self, size=len(data), offset=offset, entropy=pe_hashes["overlay"]["entropy"])])
                    overlay_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="MD5"), pe_tree.qstandarditems.PEFileItem(self, name=pe_hashes["overlay"]["md5"])])
                    overlay_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="SHA1"), pe_tree.qstandarditems.PEFileItem(self, name=pe_hashes["overlay"]["sha1"])])
                    overlay_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="SHA256"), pe_tree.qstandarditems.PEFileItem(self, name=pe_hashes["overlay"]["sha256"], vt_query="{}")])
                    overlay_item.appendRow([pe_tree.qstandarditems.PEFileItem(self, name="Entropy"), pe_tree.qstandarditems.EntropyItem(self, pe_hashes["overlay"]["entropy"])])

                    file_item.appendRow([overlay_item, pe_tree.qstandarditems.PEFileItem(self, name="")])

        except pe_tree.exceptions.ThreadStopping:
            # Stop event has been set, bail
            self.signals.update_ui.emit(None)
            return

        except Exception as e:
            # Display exception in the treeview
            self.root_item = pe_tree.qstandarditems.HeaderItem(self, name=self.filename, filepath=filename, is_root=True)
            self.root_value_item = pe_tree.qstandarditems.ErrorItem(self, name=str(e), tooltip=traceback.format_exc())
            self.regions = []

        finally:
            # Signal back to the UI thread that we're ready to be added to the treeview
            self.signals.update_ui.emit(self)

    def comment_item(self, item):
        """Convert item to correct type and comment in IDA

        Args:
            item (object): pefile.PE structure item

        """
        if self.loaded_from_idb is False or not pe_tree.form.HAVE_IDA:
            return

        if item["width"] == 16:
            self.runtime.make_qword(self.image_base + item["file_offset"])
        elif item["width"] == 8:
            if item["key"] == "Name":
                self.runtime.make_string(self.image_base + item["file_offset"], 8)
            else:
                self.runtime.make_dword(self.image_base + item["file_offset"])
        elif item["width"] == 4:
            self.runtime.make_word(self.image_base + item["file_offset"])
        elif item["width"] == 2:
            self.runtime.make_byte(self.image_base + item["file_offset"], size=item["width"] / 2)
        else:
            self.runtime.make_string(self.image_base + item["file_offset"], item["width"])

        self.runtime.make_comment(self.image_base + item["file_offset"], item["key"])

    def dump(self, obj):
        """Dump pefile structure

        Args:
            obj (object): pefile.PE structure

        Return:
            object: Dumped structure

        """
        dump = []

        if hasattr(self.pe, "__{}_format__".format(obj.name)):
            formats = getattr(self.pe, "__{}_format__".format(obj.name))
            widths = {"B": 2, "H": 4, "I": 8, "Q": 16}

        for keys in obj.__keys__:
            for key in keys:
                val = getattr(obj, key)

                timestamp = -1
                va = 0
                valid_va = False

                # Try to determine width of item
                width = 8

                if hasattr(self.pe, "__{}_format__".format(obj.name)):
                    for format_str in formats[1]:
                        if key in format_str:
                            size = format_str.split(",")[0]

                            if size[-1] == "s":
                                width = int(size[:-1])
                            elif size in widths:
                                width = widths[size]

                            break

                if isinstance(val, (int, long)):
                    if key in ["VirtualAddress", "ImageBase", "e_lfanew", "Offset", "Name", "SecurityCookie", "SEHandlerTable"] or "AddressOf" in key or "Thunk" in key:
                        if val > self.pe.OPTIONAL_HEADER.ImageBase:
                            va = (val - self.pe.OPTIONAL_HEADER.ImageBase) + self.image_base
                        else:
                            va = val if va < self.image_base else val + self.image_base

                            valid_va = True

                    text = "0x{:0{w}x}".format(val, w=width)

                    if key in ["TimeDateStamp", "dwTimeStamp"]:
                        try:
                            text = "{} {} UTC".format(text.strip(), time.asctime(time.gmtime(val)))
                        except ValueError:
                            text = "{} (INVALID TIME)".format(text.strip())

                        timestamp = val

                    elif key in ["Size", "Misc_VirtualSize"] or key.startswith("SizeOf"):
                        text = "0x{:0{w}x} {}".format(val, pe_tree.utils.human_readable_filesize(val), w=width)

                else:
                    text = bytearray(val)

                    if obj.name.startswith("IMAGE_SECTION_HEADER") and key.startswith("Name"):
                        text = text.rstrip(b"\x00")

                    if key.startswith("PdbFileName"):
                        text = text.rstrip(b"\x00")

                dump.append({"file_offset": obj.__field_offsets__[key] + obj.get_file_offset(),
                             "field_offset": obj.__field_offsets__[key],
                             "key": key,
                             "name": pe_tree.qstandarditems.PEFileString(text),
                             "time": timestamp,
                             "offset": va,
                             "width": width,
                             "valid_va": valid_va})

        return dump

    def va_to_rva(self, offset):
        """Convert virtual address to relative virtual address

        Args:
            offset (int): Virtual address

        Return:
            int: Relative virtual address

        """
        if self.pe.OPTIONAL_HEADER.ImageBase <= offset <= self.pe.OPTIONAL_HEADER.ImageBase + self.size:
            return offset - self.pe.OPTIONAL_HEADER.ImageBase
        else:
            return offset

    def get_offset_from_rva(self, rva):
        """Get file offset from RVA using pefile without generating an exception

        Args:
            rva (int): Relative virtual address

        Returns:
            int: File offset if successful, otherwise -1

        """
        try:
            return self.pe.get_offset_from_rva(rva)
        except:
            # This will cause the region to appear at the start of the map view, but there should be warnings from pefile ;)
            return -1

class TreeViewDelegate(QtWidgets.QStyledItemDelegate):
    """Extended QStyledItemDelegate class for providing a custom painter for CommonStandardItems in the tree view

    Args:
        tree (pe_tree.tree.PETree): PE Tree

    """

    def __init__(self, tree):
        QtWidgets.QStyledItemDelegate.__init__(self)
        self.tree = tree

    def paint(self, painter, option, index):
        """Call StandardItem paint (if implemented) or pass to TreeView

        Args:
            painter (QPainter): Item painter
            option (QStyleOptionViewItem): Item style option
            index (QModelIndex): Item model index

        """
        # Find item
        item = self.tree.model.itemFromIndex(index.sibling(index.row(), index.column()))

        painted = False

        if hasattr(item, "paint"):
            # Does the item draw itself?
            painted = item.paint(painter, option, index)

        if painted is False:
            # Draw standard item
            super(TreeViewDelegate, self).paint(painter, option, index)

    def sizeHint(self, option, index):
        """Set height of root item

        Args:
            option (QStyleOptionViewItem): Item style option
            index (QModelIndex): Item model index

        Returns:
            QSize: Width and height of the tree view item

        """
        if not index:
            return QtCore.QSize(0, 0)

        # Find item
        item = self.tree.model.itemFromIndex(index.sibling(index.row(), index.column()))

        size = super(TreeViewDelegate, self).sizeHint(option, index)

        if item.is_root:
            # Set height of root item
            size.setHeight(24)
            return size

        return size
