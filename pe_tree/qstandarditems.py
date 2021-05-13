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

"""PE Tree QStandardItems for QTreeView"""

# Standard imports
import sys
import string
from datetime import datetime
import builtins

try:
    from urllib import quote
except ImportError:
    from urllib.parse import quote

# Qt imports
from PyQt5 import QtCore, QtGui, QtWidgets

# PE Tree imports
import pe_tree.form
import pe_tree.tree
import pe_tree.exceptions
import pe_tree.utils

class PEFileString():
    """Sanitise strings from pefile"""
    def __init__(self, buffer):
        self.whitespace = string.whitespace.replace(" ", "")
        self.string = self.sanitise(buffer)

    def sanitise(self, buffer):
        """Convert chr or int string arrays into something printable"""
        if not buffer:
            return ""

        if isinstance(buffer, int):
            return str(buffer)

        if not buffer[0] == 0:
            try:
                if buffer.encode("utf-8"):
                    return buffer
            except:
                pass

            try:
                return buffer.decode("utf-8")
            except:
                pass

        if isinstance(buffer[0], int):
            return "".join([chr(i) if (chr(i) in string.printable and chr(i) not in self.whitespace) else "\\x{0:02x}".format(i) for i in buffer])

        return "".join([i if (i in string.printable and i not in self.whitespace) else "\\x{0:02x}".format(ord(i)) for i in buffer])

    def __str__(self):
        """Return internal sanitised string"""
        return self.string

    def __add__(self, buffer):
        """Sanitise string and append to internal sanitised string"""
        return self.string + self.sanitise(buffer)

class CommonStandardItem(QtGui.QStandardItem):
    """Base class for all tree view items

    Args:
        tree (pe_tree.tree.PETree): Parent PE Tree
        name (str): Display name

    """

    def __init__(self, tree, **kwargs):
        # Check if the application is signaled to stop and bail if so
        if tree.form.stop_event.is_set():
            raise pe_tree.exceptions.ThreadStopping()

        # Ensure the name is of type PEFileString
        self.name = kwargs.get("name", "")

        if not isinstance(self.name, PEFileString):
            self.name = PEFileString(self.name)

        # Initialise QStandardItem with sanitised ASCII name
        super(CommonStandardItem, self).__init__(self.name.string)

        # Read values from kwargs
        self.tree = tree
        self.offset = kwargs.get("offset", -1)
        self.file_offset = kwargs.get("file_offset", -1)
        self.field_offset = kwargs.get("field_offset", -1)
        self.size = kwargs.get("size", 0)
        self.key = kwargs.get("key", "")
        self.width = kwargs.get("width", tree.ptr_size)
        self.valid_va = kwargs.get("valid_va", False)
        self.filename = kwargs.get("filename", None)
        self.ext = kwargs.get("ext", "bin")
        self.data = kwargs.get("data", None)
        self.is_root = kwargs.get("is_root", False)
        self.cyberchef_recipe = kwargs.get("cyberchef_recipe", "")
        self.vt_query = kwargs.get("vt_query", "")
        self.highlight = kwargs.get("highlight", False)
        self.time = kwargs.get("time", -1)
        self.url = kwargs.get("url", None)

        if self.time != -1:
            if not self.vt_query:
                self.vt_query = "generated:\"{}\""

            self.vt_query = self.vt_query.format(datetime.utcfromtimestamp(self.time).strftime("%Y-%m-%dT%H:%M:%S"))

        if self.is_root:
            self.setToolTip(kwargs.get("filepath", ""))
        else:
            self.setToolTip(kwargs.get("tooltip", ""))

        # Set font
        self.setFont(tree.form.font)

        # Set VT query
        if self.vt_query != "":
            self.vt_query = self.vt_query.format(self.name)
            self.url = "https://www.virustotal.com/gui/search/{}".format(quote(quote(self.vt_query)))

            # Use italic font for VT search-able items
            font = self.font()
            font.setItalic(True)
            font.setUnderline(True)
            self.setFont(font)

            self.setForeground(QtGui.QColor("#0477BF"))

        # Set save filename
        if self.filename is not None:
            self.filename = "{}.{}".format(self.filename, self.ext)

    def appendRow(self, items):
        """Append row items and set/unset bold row text"""
        # If the first item in the row is bold then set the next item to bold as well
        if len(items) > 1:
            if items[1].valid_va is not False:
                font = items[0].font()
                font.setBold(True)
                items[0].setFont(font)
                font = items[1].font()
                font.setBold(True)
                items[1].setFont(font)

        super(CommonStandardItem, self).appendRow(items)

    def get_data(self, offset=0, size=0):
        """Return the PE data associated with the item, or attempt to read from pefile/IDA runtime"""
        offset = offset if offset != 0 else self.offset
        size = size if size != 0 else self.size

        try:
            if self.data is not None:
                # Item has data associated
                return self.data

            # Try to read the data from pefile
            return self.tree.pe.get_memory_mapped_image()[offset:offset + size]
        except Exception:
            # Try to read the data from IDA runtime
            return self.tree.runtime.get_bytes(offset, size)

    def context_menu(self, actions):
        """Display context menu"""
        if self.vt_query != "":
            # Add VT search action to menu
            actions.actions.append(actions.search_vt_action)

        if pe_tree.runtime.HAVE_CAPSTONE and self.valid_va and self.offset != 0:
            actions.actions.append(actions.disassemble_action)

        actions.actions.append(actions.addressing_menu)

        # Display menu
        actions.show_menu()

    def paint(self, painter, option, index):
        """Paint callback to adjust between VA/RVA"""
        if self.valid_va and self.offset > 0:
            if self.offset >= self.tree.image_base or self.tree.show_rva:
                self.setText("0x{:0{w}x}{}".format(self.offset, self.resolve(self.offset), w=self.width))
            else:
                self.setText("0x{:0{w}x}{}".format(self.tree.image_base + self.offset, self.resolve(self.offset), w=self.width))

        return False

    def resolve(self, address):
        """Resolve an RVA/VA to section name + offset"""
        if address > self.tree.image_base:
            address -= self.tree.image_base

        # Resolve section name
        for section in self.tree.pe.sections:
            if section.VirtualAddress <= address < section.VirtualAddress + section.Misc_VirtualSize:
                if sys.version_info > (3,):
                    printable_bytes = [ord(i) for i in string.printable if i not in string.whitespace]

                    name = "".join([chr(i) if (i in printable_bytes) else "\\x{0:02x}".format(i) for i in section.Name.rstrip(b"\x00")])
                else:
                    name = section.Name

                return " -> {}+0x{:0{w}x}".format(name, address - section.VirtualAddress, w=self.tree.ptr_size)

        return ""

class PEFileItem(CommonStandardItem):
    """Extended CommonStandardItem class"""

    def context_menu(self, actions):
        """Item right clicked"""
        actions.actions.append(actions.copy_action)

        super(PEFileItem, self).context_menu(actions)

class RatioItem(CommonStandardItem):
    """Extended CommonStandardItem class for displaying ratios"""

    def __init__(self, tree, **kwargs):
        """Initialise super and store offset/size"""
        super(RatioItem, self).__init__(tree, name="{:.2f}%".format(float(100.0 / float(tree.size)) * float(kwargs.get("size", 0))), **kwargs)

        self.entropy = kwargs.get("entropy", -1)

        if self.entropy > 7:
            # Red
            self.colour = QtGui.QColor("#F21B2D")
        elif self.entropy > 6:
            # Orange
            self.colour = QtGui.QColor("#F67B16")
        elif self.entropy > 5:
            # Blue
            self.colour = QtGui.QColor("#0477BF")
        else:
            # Green
            self.colour = QtGui.QColor("#038C3E")

    def paint(self, painter, option, index):
        """Draw the ratio box"""
        pen = painter.pen()

        x = option.rect.x()
        y = option.rect.y()

        width = option.rect.width()
        height = option.rect.height()

        bar_width = width / 2

        # Determine width per byte of file size
        delta = float(bar_width - 1) / float(max(self.tree.size, self.offset + self.size))

        # Draw the inner ratio portion
        painter.setPen(QtGui.QPen(self.colour, 1, QtCore.Qt.SolidLine))
        painter.setBrush(QtGui.QBrush(self.colour, QtCore.Qt.SolidPattern))
        painter.drawRect(x + 5 + int(self.offset * delta), y, int(self.size * delta), height - 1)

        # Draw the outer ratio container box
        painter.setPen(QtGui.QPen(pen.color(), 1, QtCore.Qt.SolidLine))
        painter.setBrush(QtGui.QBrush(QtGui.QColor("white"), QtCore.Qt.NoBrush))
        painter.drawRect(x + 4, y, int(bar_width), height - 1)

        # Draw the ratio text
        painter.setFont(self.font())
        painter.setPen(pen)
        painter.drawText(QtCore.QRect(x, y, int(width / 2), height), QtCore.Qt.AlignCenter, index.data())

        return True

    def context_menu(self, actions):
        """Item right clicked"""
        actions.actions.append(actions.copy_action)

        super(RatioItem, self).context_menu(actions)

class SizeItem(CommonStandardItem):
    """Extended CommonStandardItem class for displaying sizes"""

    def __init__(self, tree, **kwargs):
        """Initialise super and store offset/size"""
        size = kwargs.get("size", 0)
        name = pe_tree.utils.human_readable_filesize(size)

        if kwargs.get("show_hex", False):
            name = "0x{:0{w}x} {}".format(size, name, w=kwargs.get("width", tree.ptr_size))

        kwargs.update(name=name)

        super(SizeItem, self).__init__(tree, **kwargs)

    def context_menu(self, actions):
        """Item right clicked"""
        actions.actions.append(actions.copy_action)

        super(SizeItem, self).context_menu(actions)

class SaveablePEFileItem(PEFileItem):
    """Extended PEFileItem class for saving items"""

    def __init__(self, tree, **kwargs):
        """Initialise super and store offset/size"""
        if not kwargs.get("filename", False):
            kwargs.update(filename=kwargs.get("name", ""))

        super(SaveablePEFileItem, self).__init__(tree, **kwargs)
        
        self.setIcon(tree.form.widget.style().standardIcon(QtWidgets.QStyle.SP_DialogSaveButton))

    def context_menu(self, actions):
        """Item right clicked"""
        actions.actions.append(actions.save_action)
        actions.actions.append(actions.copy_action)
        actions.actions.append(actions.hexdump_action)
        actions.actions.append(actions.cyberchef_action)

        super(SaveablePEFileItem, self).context_menu(actions)

class InformationItem(CommonStandardItem):
    """Extended CommonStandardItem class for displaying information"""

    def __init__(self, tree, **kwargs):
        """Initialise super and store offset/size"""
        super(InformationItem, self).__init__(tree, **kwargs)

        self.setIcon(tree.form.widget.style().standardIcon(QtWidgets.QStyle.SP_MessageBoxInformation))

        # Bold/blue
        font = self.font()
        font.setBold(True)
        self.setFont(font)
        self.setForeground(QtGui.QColor("#0477BF"))

    def context_menu(self, actions):
        """Item right clicked"""
        actions.actions.append(actions.copy_action)

        super(InformationItem, self).context_menu(actions)

class MimeTypeItem(CommonStandardItem):
    """Extended CommonStandardItem class for displaying MIME type information"""

    def __init__(self, tree, **kwargs):
        """Initialise super and store offset/size"""
        super(MimeTypeItem, self).__init__(tree, **kwargs)

        # Highlight executable MIME types bold/red
        if kwargs.get("name", "") in ["application/x-msdownload", "application/vnd.microsoft.portable-executable"]:
            font = self.font()
            font.setBold(True)
            self.setFont(font)
            self.setForeground(QtGui.QColor("red"))

class WarningItem(CommonStandardItem):
    """Extended CommonStandardItem class for displaying warnings"""

    def __init__(self, tree, **kwargs):
        """Initialise super and store offset/size"""
        super(WarningItem, self).__init__(tree, **kwargs)

        self.setIcon(tree.form.widget.style().standardIcon(QtWidgets.QStyle.SP_MessageBoxWarning))

        # Bold/orange
        font = self.font()
        font.setBold(True)
        self.setFont(font)
        self.setForeground(QtGui.QColor("#F67B16"))

    def context_menu(self, actions):
        """Item right clicked"""
        actions.actions.append(actions.copy_action)

        super(WarningItem, self).context_menu(actions)

class ErrorItem(CommonStandardItem):
    """Extended CommonStandardItem class for displaying warnings"""

    def __init__(self, tree, **kwargs):
        """Initialise super and store offset/size"""
        super(ErrorItem, self).__init__(tree, **kwargs)

        self.setIcon(tree.form.widget.style().standardIcon(QtWidgets.QStyle.SP_MessageBoxCritical))

        # Bold/red
        font = self.font()
        font.setBold(True)
        self.setFont(font)
        self.setForeground(QtGui.QColor("#F21B2D"))

    def context_menu(self, actions):
        """Item right clicked"""
        actions.actions.append(actions.copy_action)

        super(ErrorItem, self).context_menu(actions)

class HeaderItem(CommonStandardItem):
    """Extended CommonStandardItem class for displaying headers with icons"""

    def __init__(self, tree, **kwargs):
        """Initialise super"""
        super(HeaderItem, self).__init__(tree, **kwargs)

        icon = kwargs.get("icon", None)
        if icon is not None:
            self.setIcon(tree.form.widget.style().standardIcon(getattr(QtWidgets.QStyle, icon)))

        # Bold/Cylance green
        self.setForeground(QtGui.QColor("#69d03c"))
        font = self.font()
        font.setBold(True)
        self.setFont(font)

    def context_menu(self, actions):
        """Item right clicked"""
        actions.actions.append(actions.expand_all_action)

        if self.is_root and not self.tree.disable_dump:
            actions.actions.append(actions.save_dump_action)

        actions.actions.append(actions.copy_action)

        if self.is_root:
            actions.actions.append(actions.remove_action)
            actions.actions.append(actions.add_pe_menu)
            actions.actions.append(actions.options_menu)

        super(HeaderItem, self).context_menu(actions)

class SaveableHeaderItem(HeaderItem):
    """Extended HeaderItem class for displaying headers but with ability to save data"""

    def __init__(self, tree, **kwargs):
        """Initialise super"""
        if not kwargs.get("filename", False):
            kwargs["filename"] = kwargs.get("name", "")

        super(SaveableHeaderItem, self).__init__(tree, **kwargs)

        #self.setIcon(tree.form.widget.style().standardIcon(QtWidgets.QStyle.SP_DialogSaveButton))

    def context_menu(self, actions):
        """Item right clicked"""
        actions.actions.append(actions.save_action)
        actions.actions.append(actions.hexdump_action)
        actions.actions.append(actions.cyberchef_action)

        super(SaveableHeaderItem, self).context_menu(actions)

class NoItem(CommonStandardItem):
    """Extended CommonStandardItem class for displaying generic menu"""

    def context_menu(self, actions):
        """No item was right clicked"""
        actions.actions.append(actions.add_pe_menu)
        actions.actions.append(actions.options_menu)

        super(NoItem, self).context_menu(actions)

class EntropyItem(CommonStandardItem):
    """Extended CommonStandardItem class for setting entropy"""

    def __init__(self, tree, value):
        """Initialise super"""
        super(EntropyItem, self).__init__(tree, name="{0:f}".format(value))

        # Highlight entropy
        if value > 7:
            # Red
            self.setForeground(QtGui.QColor("#F21B2D"))
        elif value > 6:
            # Orange
            self.setForeground(QtGui.QColor("#F67B16"))
        elif value > 5:
            # Blue
            self.setForeground(QtGui.QColor("#0477BF"))
        else:
            # Green
            self.setForeground(QtGui.QColor("#038C3E"))

        font = self.font()
        font.setBold(True)
        self.setFont(font)

    def context_menu(self, actions):
        """Item right clicked"""
        actions.actions.append(actions.copy_action)

        super(EntropyItem, self).context_menu(actions)

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