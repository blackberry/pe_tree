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

"""PE Tree application dialogs"""

# pefile
import pefile

# Qt imports
from PyQt5 import QtGui, QtWidgets, QtCore

# PE Tree imports
import pe_tree.form
import pe_tree.dump_pe

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

        self.setWindowTitle("Dump - {}".format(filename))

        # Construct widgets
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

        self.use_existing_imports_radio = QtWidgets.QRadioButton("Rebuild IDT from existing IAT:")
        self.use_existing_imports_radio.setWhatsThis("Use existing IAT to construct a new IDT")
        self.use_existing_imports_radio.toggled.connect(self.toggle_iat_radios)

        self.no_imports_radio = QtWidgets.QRadioButton("Keep existing IDT/IAT")
        self.no_imports_radio.setWhatsThis("Do not rebuild IDT/IAT")
        self.no_imports_radio.toggled.connect(self.toggle_iat_radios)

        self.rebuild_imports_radio = QtWidgets.QRadioButton("Rebuild IDT/IAT")
        self.rebuild_imports_radio.setWhatsThis("Disassemble PE, search for IAT pointers and construct a new IDT/IAT")
        self.rebuild_imports_radio.toggled.connect(self.toggle_iat_radios)
        self.rebuild_imports_radio.setChecked(True)

        self.recalculate_pe_checksum = QtWidgets.QCheckBox("Recalculate PE header checksum (slow!)")
        self.recalculate_pe_checksum.setWhatsThis("Recalculate PE header checksum (slow!)")
        self.recalculate_pe_checksum.setChecked(False)

        self.save_to_file_checkbox = QtWidgets.QCheckBox("Save to file")
        self.save_to_file_checkbox.setWhatsThis("Save dumped PE file to disk")
        self.save_to_file_checkbox.setChecked(True)

        self.add_to_tree_checkbox = QtWidgets.QCheckBox("Add to PE Tree")
        self.add_to_tree_checkbox.setWhatsThis("Add dumped PE file to tree.\n\nWarning! Addresses may be incorrect in current IDA context if image is rebased!")
        self.add_to_tree_checkbox.setChecked(True)

        button_box = QtWidgets.QDialogButtonBox()

        dump_button = QtWidgets.QPushButton("Dump")
        dump_button.setFixedHeight(25)

        cancel_button = QtWidgets.QPushButton("Cancel")
        cancel_button.setFixedHeight(25)

        button_box.addButton(dump_button, QtWidgets.QDialogButtonBox.AcceptRole)
        button_box.addButton(cancel_button, QtWidgets.QDialogButtonBox.RejectRole)

        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        # Create layout
        layout = QtWidgets.QVBoxLayout()

        widgets = [
            {"PE Headers": [
                (QtWidgets.QLabel("ImageBase:"), self.image_base_edit),
                (QtWidgets.QLabel("AddressOfEntryPoint:"), self.entry_point_edit),
                (QtWidgets.QLabel("SizeOfOptionalHeader:"), self.size_of_optional_header_edit),
                (self.recalculate_pe_checksum, None)
                ]},
            {"Imports": [
                (self.no_imports_radio, None),
                (self.rebuild_imports_radio, None),
                (self.use_existing_imports_radio, None),
                (QtWidgets.QLabel("IAT:"), self.iat_rva_edit),
                (QtWidgets.QLabel("IAT Size:"), self.iat_size_edit)
                ]},
            {"Output": [
                (self.save_to_file_checkbox, None),
                (self.add_to_tree_checkbox, None)
                ]}
            ]

        # Construct groups
        for widget in widgets:
            group_name = list(widget)[0]
            
            groupbox = QtWidgets.QGroupBox(group_name)
            grid = QtWidgets.QGridLayout()
            grid.setSpacing(10)

            # Add group widgets
            for row, (left, right) in enumerate(widget[group_name]):
                if right == None:
                    # Single widget, span 2 columns
                    grid.addWidget(left, row, 0, 1, 2)
                else:
                    # Pair of widgets
                    grid.addWidget(left, row, 0)
                    grid.addWidget(right, row, 1)

            groupbox.setLayout(grid)
            layout.addWidget(groupbox)

        layout.addWidget(button_box)

        self.setLayout(layout)

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
            pe_data = pe_tree.dump_pe.DumpPEFile(self.pe,
                                 self.image_base,
                                 self.size,
                                 self.runtime,
                                 find_iat_ptrs=find_patch_iat,
                                 keep_iat_ptrs=self.no_imports_radio.isChecked(),
                                 patch_iat_ptrs=find_patch_iat,
                                 iat_rva=iat_rva,
                                 iat_size=iat_size,
                                 new_image_base=image_base,
                                 new_ep=entry_point,
                                 recalculate_pe_checksum=self.recalculate_pe_checksum.isChecked(),
                                 size_of_optional_header=size_of_optional_header).dump()

            # Add to tree
            if self.add_to_tree_checkbox.isChecked():
                self.form.map_pe(image_base=image_base, data=pe_data, priority=1, filename=self.filename, opaque=self.runtime.opaque, disable_dump=True)

            # Save to file
            if self.save_to_file_checkbox.isChecked():
                filename = self.runtime.ask_file("{}.dmp".format(self.filename), "Save dump", save=True)
                if filename:
                    with open(filename, "wb") as ofile:
                        ofile.write(pe_data)

        self.close()

class ModulePicker(QtWidgets.QDialog):
    """Process/module picker dialog"""
    def __init__(self, window, title, columns, model=QtGui.QStandardItemModel, parent=None):
        super(ModulePicker, self).__init__(parent)

        self.window = window
        self.items = set()

        # Initialise the dialog
        self.setWindowTitle(title)

        self.setMinimumWidth(400)
        self.setMinimumHeight(600)

        # Create the process/module tree view and model
        self.treeview = QtWidgets.QTreeView()
        self.model = model(self.treeview)
        self.model.setHorizontalHeaderLabels(columns)
        self.model.itemChanged.connect(self.item_changed)
        self.treeview.setModel(self.model)
        self.treeview.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.treeview.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        # Create the buttons
        button_box = QtWidgets.QDialogButtonBox()

        dump_button = QtWidgets.QPushButton("Dump")
        dump_button.setFixedHeight(25)

        cancel_button = QtWidgets.QPushButton("Cancel")
        cancel_button.setFixedHeight(25)

        button_box.addButton(dump_button, QtWidgets.QDialogButtonBox.AcceptRole)
        button_box.addButton(cancel_button, QtWidgets.QDialogButtonBox.RejectRole)

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
        pass

    def item_changed(self, item):
        """Record selected items in the tree view"""
        if item.checkState() == QtCore.Qt.PartiallyChecked:
            # Add to list of selected items
            self.items.add(pe_tree.qstandarditems.HashableQStandardItem(item))

            # If parent item then deselect all children
            if item.hasChildren():
                for row in range(0, item.rowCount()):
                    child = item.child(row)
                    child.setCheckState(QtCore.Qt.Unchecked)
                    self.items.discard(pe_tree.qstandarditems.HashableQStandardItem(child))

        elif item.checkState() == QtCore.Qt.Checked:
            # Add to list of selected items
            self.items.add(pe_tree.qstandarditems.HashableQStandardItem(item))

            # If parent item then select all children
            if item.hasChildren():
                for row in range(0, item.rowCount()):
                    child = item.child(row)
                    child.setCheckState(QtCore.Qt.Checked)
                    self.items.add(pe_tree.qstandarditems.HashableQStandardItem(child))

            elif item.parent() is None:
                # Expand the root item
                self.treeview.setExpanded(item.index(), True)

        elif item.checkState() == QtCore.Qt.Unchecked:
            # Remove from list of selected items
            self.items.discard(pe_tree.qstandarditems.HashableQStandardItem(item))

            # If parent item then deselect all children
            if item.hasChildren():
                for row in range(0, item.rowCount()):
                    child = item.child(row)
                    child.setCheckState(QtCore.Qt.Unchecked)
                    self.items.discard(pe_tree.qstandarditems.HashableQStandardItem(child))

    def invoke(self):
        # Clear selection
        for item in self.items.copy():
            item.item.setCheckState(QtCore.Qt.Unchecked)
