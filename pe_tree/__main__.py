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

"""PE Tree standalone application"""

# Standard imports
import os
import sys
import scandir

# Qt imports
from PyQt5 import QtCore, QtGui, QtWidgets

# QDarkStyle
try:
    import qdarkstyle

    HAVE_DARKSTYLE = True
except:
    HAVE_DARKSTYLE = False

# PE Tree imports
import pe_tree.runtime
import pe_tree.form
import pe_tree.info

class ApplicationRuntime(pe_tree.runtime.Runtime):
    """Standalone application runtime"""
    def __init__(self, widget):
        # Load configuration
        self.config_file = os.path.join(self.get_temp_dir(), "pe_tree.ini")

        super(ApplicationRuntime, self).__init__(widget)

        self.pe_tree_form = None

    def jumpto(self, item, offset):
        """Disassemble using capstone"""
        if item.tree.disasm:
            for i in item.tree.disasm.disasm(item.get_data(size=0x100), offset):
                item.tree.form.runtime.log("0x{:x}:\t{}\t{}".format(i.address, i.mnemonic, i.op_str))

        self.ret = True
        return self.ret

    @QtCore.pyqtSlot(str)
    def log(self, output):
        """Append log message to the output view"""
        output_view = self.pe_tree_form.output_stack.currentWidget()
        if output_view:
            output_view.append(output)
            output_view.moveCursor(QtGui.QTextCursor.End)

        self.ret = True
        return self.ret

class ScanDir(QtCore.QRunnable):
    """Scan directory thread

    Args:
        pe_tree_form (pe_tree.form): PE Tree form
        filename (str): Path to file/folder to scan for PE files

    """
    def __init__(self, pe_tree_form, filename):
        super(ScanDir, self).__init__()

        self.filename = filename
        self.pe_tree_form = pe_tree_form

    def run(self):
        """Iterate over all files/folders and map PE files"""
        if os.path.isdir(self.filename):
            for root, dirs, files in scandir.walk(self.filename):
                for file in files:
                    # Have we been signalled to stop?
                    if self.pe_tree_form.stop_event.is_set():
                        return

                    # Map PE file
                    self.pe_tree_form.map_pe(filename=os.path.join(root, file))
        else:
            # Map PE file
            self.pe_tree_form.map_pe(filename=self.filename)

class PETreeWindow(QtWidgets.QMainWindow):
    """Main window for the PE Tree application"""

    def __init__(self, application, runtime, open_file=True):
        super(PETreeWindow, self).__init__()

        self.application = application

        # Create container widget, runtime and PE Tree form
        widget = QtWidgets.QWidget()
        self.runtime = runtime(widget)
        self.pe_tree_form = pe_tree.form.PETreeForm(widget, application, self.runtime)
        self.pe_tree_form.dispatcher = application.eventDispatcher()
        application.aboutToQuit.connect(self.pe_tree_form.wait_for_threads)
        self.runtime.pe_tree_form = self.pe_tree_form

        if HAVE_DARKSTYLE:
            application.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())

        self.setWindowTitle(pe_tree.info.__title__)
        self.resize(1024, 768)
        self.setCentralWidget(widget)
        self.setAcceptDrops(True)

        # Construct application main menu
        self.open_menu = QtWidgets.QMenu("Open", self)

        open_file_action = QtWidgets.QAction("File", self)
        open_file_action.setShortcut("Ctrl+O")
        open_file_action.setStatusTip("Open PE file")
        open_file_action.triggered.connect(self.open_file)

        open_directory_action = QtWidgets.QAction("Folder", self)
        open_directory_action.setShortcut("Ctrl+Shift+O")
        open_directory_action.setStatusTip("Scan folder for PE files")
        open_directory_action.triggered.connect(self.open_folder)

        self.open_menu.addAction(open_file_action)
        self.open_menu.addAction(open_directory_action)

        exit_action = QtWidgets.QAction("Exit", self)
        exit_action.setShortcut("Ctrl+X")
        exit_action.setStatusTip("Exit")
        exit_action.triggered.connect(application.quit)

        about_action = QtWidgets.QAction("About", self)
        about_action.triggered.connect(self.runtime.about_box)

        menu = self.menuBar()
        file_menu = menu.addMenu("&File")
        file_menu.addMenu(self.open_menu)
        file_menu.addAction(exit_action)

        help_menu = menu.addMenu("&Help")
        help_menu.addAction(about_action)

        # Process command line
        if len(sys.argv) > 1:
            # Map all files/folders specified on the command line
            for filename in sys.argv[1:]:
                self.pe_tree_form.threadpool.start(ScanDir(self.pe_tree_form, filename))
        elif open_file is not False:
            # Ask user to select file/folder
            self.open_file()

    def dragEnterEvent(self, e):
        """Accept drag events containing URLs"""
        if e.mimeData().hasUrls:
            e.accept()
        else:
            e.ignore()

    def dragMoveEvent(self, e):
        """Accept drag events containing URLs"""
        if e.mimeData().hasUrls:
            e.accept()
        else:
            e.ignore()

    def dropEvent(self, e):
        """File drag/dropped onto the main form, attempt to map as PE"""
        if e.mimeData().hasUrls:
            e.accept()

            for url in e.mimeData().urls():
                self.pe_tree_form.threadpool.start(ScanDir(self.pe_tree_form, QtCore.QDir.toNativeSeparators(str(url.toLocalFile()))), priority=1)
        else:
            e.ignore()

    def exec_open_dialog(self, dialog):
        """Execute open dialog and map PE files"""
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            for filename in dialog.selectedFiles():
                self.pe_tree_form.threadpool.start(ScanDir(self.pe_tree_form, QtCore.QDir.toNativeSeparators(filename)))

            return True

        return False

    def open_file(self):
        """Prompt user to select file to map files from"""
        options = QtWidgets.QFileDialog.Options()

        dialog = QtWidgets.QFileDialog()
        dialog.setOptions(options)
        dialog.setFileMode(QtWidgets.QFileDialog.AnyFile)
        dialog.setAcceptMode(QtWidgets.QFileDialog.AcceptOpen)

        return self.exec_open_dialog(dialog)

    def open_folder(self):
        """Prompt user to select folder to map files from"""
        options = QtWidgets.QFileDialog.Options()

        dialog = QtWidgets.QFileDialog()
        dialog.setOptions(options)
        dialog.setFileMode(QtWidgets.QFileDialog.Directory)
        dialog.setAcceptMode(QtWidgets.QFileDialog.AcceptOpen)

        return self.exec_open_dialog(dialog)

def main(args=None):
    """Create PE Tree Qt standalone application"""
    application = QtWidgets.QApplication(sys.argv)
    window = PETreeWindow(application, ApplicationRuntime)
    window.showMaximized()
    sys.exit(application.exec_())

if __name__ == "__main__":
    main()
