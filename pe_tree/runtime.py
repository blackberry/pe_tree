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

"""PE Tree runtime abstraction layer"""

# Standard imports
import os
import tempfile
import threading

# Config parser imports
try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser

# pefile
import pefile

# Qt imports
from PyQt5 import QtCore, Qt, QtGui, QtWidgets

# Capstone imports
try:
    import capstone

    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False

# PE Tree imports
import pe_tree.info

class RuntimeSignals(QtCore.QObject):
    """Allows worker threads to invoke runtime methods on the UI thread.

    Warning:
        This class must be instantiated from the UI thread!

    """
    def __init__(self, runtime, opaque={}):
        super(RuntimeSignals, self).__init__()

        self.opaque = opaque
        self.runtime = runtime

    def invoke_method(self, method, *args):
        """Invoke runtime method on the UI thread"""

        # Ensure only 1 thread at a time can access runtime.ret
        self.runtime.lock.acquire()

        self.runtime.opaque = self.opaque

        # Invoke the runtime method in the UI thread
        QtCore.QMetaObject.invokeMethod(self.runtime, method, Qt.Qt.BlockingQueuedConnection, *args)

        # Get the method result
        ret = self.runtime.ret

        self.runtime.lock.release()

        return ret

    def get_temp_dir(self):
        return self.invoke_method("get_temp_dir")

    def ask_file(self, filename, caption, filter="All Files (*)", save=False):
        return self.invoke_method("ask_file", Qt.Q_ARG(str, filename), Qt.Q_ARG(str, caption), Qt.Q_ARG(str, filter), Qt.Q_ARG(bool, save))

    def read_pe(self, image_base, size=0):
        return self.invoke_method("read_pe", Qt.Q_ARG(object, image_base), Qt.Q_ARG(object, size))

    def get_bytes(self, start, end):
        return self.invoke_method("get_bytes", Qt.Q_ARG(object, start), Qt.Q_ARG(object, end))

    def get_byte(self, offset):
        return self.invoke_method("get_byte", Qt.Q_ARG(object, offset))

    def get_word(self, offset):
        return self.invoke_method("get_word", Qt.Q_ARG(object, offset))

    def get_dword(self, offset):
        return self.invoke_method("get_dword", Qt.Q_ARG(object, offset))

    def get_qword(self, offset):
        return self.invoke_method("get_qword", Qt.Q_ARG(object, offset))

    def get_name(self, offset):
        return self.invoke_method("get_name", Qt.Q_ARG(object, offset))

    def get_segment_name(self, offset):
        return self.invoke_method("get_segment_name", Qt.Q_ARG(object, offset))

    def is_writable(self, offset):
        return self.invoke_method("is_writable", Qt.Q_ARG(object, offset))

    def get_label(self, offset):
        return self.invoke_method("get_label", Qt.Q_ARG(object, offset))

    def jumpto(self, item, offset):
        return self.invoke_method("jumpto", Qt.Q_ARG(object, offset))

    def log(self, output):
        return self.invoke_method("log", Qt.Q_ARG(str, output))

    def make_string(self, offset, size):
        return self.invoke_method("make_string", Qt.Q_ARG(object, offset), Qt.Q_ARG(object, size))

    def make_comment(self, offset, comment):
        return self.invoke_method("make_comment", Qt.Q_ARG(object, offset), Qt.Q_ARG(str, str(comment)))

    def make_segment(self, offset, size, class_name="DATA", name="pe_map", data=None):
        return self.invoke_method("make_segment", Qt.Q_ARG(object, offset), Qt.Q_ARG(object, size), Qt.Q_ARG(str, class_name), Qt.Q_ARG(str, name), Qt.Q_ARG(bytes, data))

    def resolve_address(self, offset):
        return self.invoke_method("resolve_address", Qt.Q_ARG(object, offset))

    def make_qword(self, offset):
        return self.invoke_method("make_qword", Qt.Q_ARG(object, offset))

    def make_dword(self, offset):
        return self.invoke_method("make_dword", Qt.Q_ARG(object, offset))

    def make_word(self, offset):
        return self.invoke_method("make_word", Qt.Q_ARG(object, offset))

    def make_byte(self, offset, size=1):
        return self.invoke_method("make_byte", Qt.Q_ARG(object, offset))

    def make_name(self, offset, name, flags=0):
        return self.invoke_method("make_name", Qt.Q_ARG(object, offset), Qt.Q_ARG(str, name), Qt.Q_ARG(int, flags))

    def patch_iat_ptrs(self, pe, image_base, size, iat_ptrs, name_to_iat, get_word, set_word):
        return self.invoke_method("patch_iat_ptrs", Qt.Q_ARG(object, pe), Qt.Q_ARG(object, image_base), Qt.Q_ARG(object, size), Qt.Q_ARG(object, iat_ptrs), Qt.Q_ARG(object, name_to_iat), Qt.Q_ARG(object, get_word), Qt.Q_ARG(object, set_word))

    def init_capstone(self, pe):
        return self.invoke_method("init_capstone", Qt.Q_ARG(object, pe))

    def get_config_option(self, section, option, fallback):
        return self.invoke_method("get_config_option", Qt.Q_ARG(str, section), Qt.Q_ARG(str, option), Qt.Q_ARG(object, fallback))

class Runtime(QtCore.QObject):
    """Base runtime class"""
    def __init__(self, widget):
        super(Runtime, self).__init__()

        self.widget = widget
        self.ret = None
        self.lock = threading.Lock()
        self.config_lock = threading.RLock()
        self.signals = RuntimeSignals(self)
        self.opaque = {}

        self.read_config()
        self.save_config()

    @QtCore.pyqtSlot()
    def get_temp_dir(self):
        """Get temporary directory path

        Returns:
            str: Temporary directory path

        """
        self.ret = tempfile.gettempdir()
        return self.ret

    @QtCore.pyqtSlot()
    def get_script_dir(self):
        """Get script directory

        Returns:
            str: Script directory path

        """
        self.ret = os.path.dirname(os.path.realpath(pe_tree.info.__file__))
        return self.ret

    def show_widget(self):
        """Display the widget"""
        self.widget.show()

        self.ret = True
        return self.ret

    @QtCore.pyqtSlot(str, str, str, bool)
    def ask_file(self, filename, caption, filter="All Files (*)", save=False):
        """Ask user to select a filename via open/save dialog

        Args:
            filename (str): Preferred filename
            caption (str): Save/open dialog caption
            filter (str): File extension filter
            save (bool): Present the save dialog if True, otherwise open

        Returns:
            str: Filename if successful, otherwise None

        """
        dialog = QtWidgets.QFileDialog()
        options = QtWidgets.QFileDialog.Options()

        if not save:
            # Open file dialog
            filename, _ = dialog.getOpenFileName(self.widget, caption, filename, filter, options=options)
        else:
            # Save file dialog
            if filename[0] == ".":
                # Remove leading dot from section names
                filename = filename[1:]

            filename, _ = dialog.getSaveFileName(self.widget, caption, filename, filter, options=options)

        if filename:
            self.ret = filename
        else:
            self.ret = ""

        return self.ret

    @QtCore.pyqtSlot(int, int)
    def read_pe(self, image_base, size=0):
        """Read PE image from memory

        Args:
            image_base (int): Address of PE file in-memory
            size (int, optional): Size of PE file in-memory

        Returns:
            bytearray: Data of PE image if successful, otherwise None

        """
        self.ret = None
        return self.ret

    @QtCore.pyqtSlot(int, int)
    def get_bytes(self, start, end):
        """Read a sequence of bytes from memory

        Args:
            start (int): Start address
            end (int): End address

        Returns:
            int: Array of bytes if successful, otherwise None

        """
        self.ret = None
        return self.ret

    @QtCore.pyqtSlot(int)
    def get_byte(self, offset):
        """Read 8-bits from memory

        Args:
            offset (int): Offset to read from

        Returns:
            int: Byte value

        """
        self.ret = 0
        return self.ret

    @QtCore.pyqtSlot(int)
    def get_word(self, offset):
        """Read 16-bits from memory

        Args:
            offset (int): Offset to read from

        Returns:
            int: Word value

        """
        self.ret = 0
        return self.ret

    @QtCore.pyqtSlot(int)
    def get_dword(self, offset):
        """Read 32-bits from memory

        Args:
            offset (int): Offset to read from

        Returns:
            int: Dword value

        """
        self.ret = 0
        return self.ret

    @QtCore.pyqtSlot(int)
    def get_qword(self, offset):
        """Read 64-bits from memory

        Args:
            offset (int): Offset to read from

        Returns:
            int: Qword value

        """
        self.ret = 0
        return self.ret

    @QtCore.pyqtSlot(int)
    def get_name(self, offset):
        """Get symbol name for the given address

        Args:
            offset (int): Address to get name for

        Returns:
            str: Name of symbol if successful, otherwise an empty string

        """
        self.ret = ""
        return self.ret

    @QtCore.pyqtSlot(int)
    def get_segment_name(self, offset):
        """Get segment/module name for the given address

        Args:
            offset (int): Address to get name for

        Returns:
            str: Name of segment/module if successful, otherwise an empty string

        """
        self.ret = ""
        return self.ret

    @QtCore.pyqtSlot(int)
    def is_writable(self, offset):
        """Determine if the memory address is write-able

        Args:
            offset (int): Address to check for write permissions

        Returns:
            bool: True if the memory address resides in writable page of memory, otherwise False

        """
        self.ret = False
        return self.ret

    @QtCore.pyqtSlot(int)
    def get_label(self, offset):
        """Get the disassembly label for the given address

        Args:
            offset (int): Address to get label for

        Returns:
            str: Label name if successful, otherwise an empty string

        """
        self.ret = ""
        return self.ret

    @QtCore.pyqtSlot(object, int)
    def jumpto(self, item, offset):
        """User double-clicked an item in the tree

        Args:
            item (pe_tree.tree): Item that was double-clicked by the user
            offset (int): Address to jump to

        """
        self.ret = None
        return self.ret

    @QtCore.pyqtSlot(str)
    def log(self, output):
        """Print to output"""
        print(output)

    @QtCore.pyqtSlot(int, int)
    def make_string(self, offset, size):
        """Convert the data at the given offset to an ASCII string

        Args:
            offset (int): Address to convert to string
            size (int): Length of the string in bytes

        """
        self.ret = None
        return self.ret

    @QtCore.pyqtSlot(int, str)
    def make_comment(self, offset, comment):
        """Add a comment to the disassembly

        Args:
            offset (int): Address to comment
            comment (str): Comment string

        """
        self.ret = None
        return self.ret

    @QtCore.pyqtSlot(int, int, str, str, bytes)
    def make_segment(self, offset, size, class_name="DATA", name="pe_map", data=None):
        """Add a segment in the IDB

        Args:
            offset (int): Base address of the new segment
            size (int): Size of the new segment in bytes
            class_name (str): "CODE" or "DATA" (default)
            name (str): Name of the segment, default is "pe_map"
            data (bytes): Data to populate the segment with (optional)

        """
        self.ret = None
        return self.ret

    @QtCore.pyqtSlot(int)
    def resolve_address(self, offset):
        """Get module/symbol name for the given address

        Args:
            offset (int): Address to get module and symbol name for

        Returns:
            (str,str): Tuple containing module name and API name. Either name may be "" if not available.

        """
        self.ret = ("", "")
        return self.ret

    @QtCore.pyqtSlot(int)
    def make_qword(self, offset):
        """Convert data at the specified address to a Qword

        Args:
            offset (int): Offset to convert

        """
        self.ret = None
        return self.ret

    @QtCore.pyqtSlot(int)
    def make_dword(self, offset):
        """Convert data at the specified address to a Dword

        Args:
            offset (int): Offset to convert

        """
        self.ret = None
        return self.ret

    @QtCore.pyqtSlot(int)
    def make_word(self, offset):
        """Convert data at the specified address to a Word

        Args:
            offset (int): Offset to convert

        """
        self.ret = None
        return self.ret

    @QtCore.pyqtSlot(int, int)
    def make_byte(self, offset, size=1):
        """Convert data at the specified address to a byte

        Args:
            offset (int): Offset to convert

        """
        self.ret = None
        return self.ret

    @QtCore.pyqtSlot(int, str, int)
    def make_name(self, offset, name, flags=0):
        """Name the given offset

        Args:
            name (str): Name of offset
            offset (int): Offset to name
            flags (int): Optional flags to pass to idc.set_name

        """
        self.ret = None
        return self.ret

    @QtCore.pyqtSlot()
    def get_names(self):
        """Get list of all available symbols/name"""
        self.ret = None
        return self.ret

    @QtCore.pyqtSlot(object, object, object, object)
    def find_iat_ptrs(self, pe, image_base, size, get_word):
        """Find likely IAT pointers

        Args:
            pe (pefile): Parsed PE file
            image_base (int): Base address of image
            size (int): Size of image
            get_word (object): Callback routine to read a Dword/Qword from memory (depending on the image architecture)

        Returns:
            [(int, int, str, str)]: Tuple containing IAT offset, xref, module name and API name

        """
        self.ret = None
        return self.ret

    @QtCore.pyqtSlot(object)
    def init_capstone(self, pe):
        """ Initialise capstone disassembler

        Args:
            pe (pefile): PE file whose machine type is used to initialise capstone

        Returns:
            [capstone.Cs]: Capstone disassembler or None if unavailable/not supported

        """
        if HAVE_CAPSTONE:
            mt = pefile.MACHINE_TYPE

            if pe.FILE_HEADER.Machine == mt["IMAGE_FILE_MACHINE_I386"]:
                return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            elif pe.FILE_HEADER.Machine == mt["IMAGE_FILE_MACHINE_AMD64"]:
                return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            elif pe.FILE_HEADER.Machine == mt["IMAGE_FILE_MACHINE_ARM"]:
                return capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            elif pe.FILE_HEADER.Machine == mt["IMAGE_FILE_MACHINE_POWERPC"]:
                return capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_LITTLE_ENDIAN)
            elif pe.FILE_HEADER.Machine in [mt["IMAGE_FILE_MACHINE_THUMB"], mt["IMAGE_FILE_MACHINE_ARMNT"]]:
                return capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
            elif pe.FILE_HEADER.Machine in [mt["IMAGE_FILE_MACHINE_R3000"], mt["IMAGE_FILE_MACHINE_R4000"], mt["IMAGE_FILE_MACHINE_R10000"]]:
                return capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32)

        return None

    @QtCore.pyqtSlot(str, str, object)
    def get_config_option(self, section, option, fallback):
        """Read configuration option from INI file

        Args:
            section (str): Name of config section
            option (str): Name of config option
            fallback (object): Default fallback value if option is non-existing

        Returns:
            object: Configuration option if present, otherwise fallback argument

        Warning:
            Only invoke from UI thread

        """
        self.config_lock.acquire()

        if self.config.has_section(section) and self.config.has_option(section, option):
            if isinstance(fallback, bool):
                self.ret = self.config.getboolean(section, option)
            else:
                self.ret = self.config.get(section, option)
        else:
            self.ret = fallback

        self.config_lock.release()

        return self.ret

    def set_config_option(self, section, option, value):
        """Set configuration option in INI file

        Args:
            section (str): Name of config section
            option (str): Name of config option
            value (object): Default config value

        Warning:
            Only invoke from UI thread

        """
        self.config_lock.acquire()

        self.config.set(section, option, str(value))
        self.save_config()

        self.config_lock.release()

    def read_config(self):
        """Load configuration from INI file

        Warning:
            Only invoke from UI thread

        """
        self.config_lock.acquire()

        # Initialise and parse config
        self.config = ConfigParser()
        self.config.read(self.config_file)

        self.config_lock.release()

    def set_default_config_option(self, config, section, option, default):
        """Set config option, fallback to default. Used internally to save config.

        Args:
            config (ConfigParser): Configuration parser
            section (str): Name of config section
            option (str): Name of config option
            default (object): Default value to use if option is non-existing

        Warning:
            Only invoke from UI thread

        """
        config.set(section, option, self.get_config_option(section, option, default))

    def save_config(self):
        """Save all configuration options to INI file

        Warning:
            Only invoke from UI thread

        """
        self.config_lock.acquire()

        try:
            with open(self.config_file, "w") as config_file:
                config = ConfigParser()
                config.add_section("config")
                self.set_default_config_option(config, "config", "debug", "False")
                self.set_default_config_option(config, "config", "fonts", ",".join(["Consolas", "Monospace", "Courier"]))
                self.set_default_config_option(config, "config", "virustotal_url", "https://www.virustotal.com/gui/search")
                self.set_default_config_option(config, "config", "cyberchef_url", "https://gchq.github.io/CyberChef")

                config.add_section("dump")
                self.set_default_config_option(config, "dump", "enable", "True")
                self.set_default_config_option(config, "dump", "recalculate_pe_checksum", "False")

                config.write(config_file)
                self.config = config
        except EnvironmentError:
            pass

        self.config_lock.release()

    def get_available_font(self, families=None):
        """Read fonts from config and return first available font in Qt

        Args:
            families (list): Optional list of default fonts, otherwise this is read using get_config_option

        Returns:
            QtGui.QFont: QFont initialised using the family specified via config/families argument

        Warning:
            Only invoke from UI thread

        """
        if not families:
            # Read fonts from config
            families = self.get_config_option("config", "fonts", None)

            if families:
                families = families.split(",")

        if not families:
            # Fallback to some sane fonts
            families = ["Consolas", "Monospace", "Courier"]

        # Check if fonts are available in Qt font database
        for family in families:
            family = family.strip()
            if family in QtGui.QFontDatabase().families():
                return QtGui.QFont(family)

        return QtGui.QFont()

    def about_box(self):
        """Show application about box

        Warning:
            Only invoke from UI thread

        """
        message_box = QtWidgets.QMessageBox()
        message_box.setIcon(QtWidgets.QMessageBox.Information)
        message_box.setWindowTitle("About {}".format(pe_tree.info.__title__))
        message_box.setText("<a href={}>{} - {}</a>".format(pe_tree.info.__url__, pe_tree.info.__title__, pe_tree.info.__version__))
        message_box.setInformativeText("<span style=\"white-space: nowrap;\">Developed by <a href=\"{}\">BlackBerry Research and Intelligence Team</a></span><br><br>{}".format("https://www.blackberry.com/us/en/company/research-and-intelligence", pe_tree.info.__copyright__))
        message_box.setStandardButtons(QtWidgets.QMessageBox.Ok)
        message_box.exec_()