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

"""PE Tree main window handling"""

import os

# Qt imports
from PyQt5 import QtCore, QtWidgets

# QDarkStyle
try:
    import qdarkstyle

    HAVE_DARKSTYLE = True
except:
    HAVE_DARKSTYLE = False

# PE Tree imports
import pe_tree.form
import pe_tree.scandir
import pe_tree.info

class PETreeWindow(QtWidgets.QMainWindow):
    """Main window for the PE Tree application"""

    def __init__(self, application, runtime, args, open_file=True):
        super(PETreeWindow, self).__init__()

        self.application = application

        # Create container widget, runtime and PE Tree form
        widget = QtWidgets.QWidget()
        self.runtime = runtime(widget, args)
        self.pe_tree_form = pe_tree.form.PETreeForm(widget, application, self.runtime)
        self.pe_tree_form.dispatcher = application.eventDispatcher()
        application.aboutToQuit.connect(self.pe_tree_form.wait_for_threads)
        self.runtime.pe_tree_form = self.pe_tree_form

        if HAVE_DARKSTYLE:
            application.setStyleSheet(qdarkstyle.load_stylesheet(qt_api="pyqt5"))

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

        self.showMaximized()

        # Process command line
        if open_file:
            if args.filenames:
                # Map all files/folders specified on the command line
                for filename in args.filenames:
                    if os.path.exists(filename):
                        self.pe_tree_form.threadpool.start(pe_tree.scandir.ScanDir(self.pe_tree_form, filename))
            else:
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
                self.pe_tree_form.threadpool.start(pe_tree.scandir.ScanDir(self.pe_tree_form, QtCore.QDir.toNativeSeparators(str(url.toLocalFile()))), priority=1)
        else:
            e.ignore()

    def exec_open_dialog(self, dialog):
        """Execute open dialog and map PE files"""
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            for filename in dialog.selectedFiles():
                self.pe_tree_form.threadpool.start(pe_tree.scandir.ScanDir(self.pe_tree_form, QtCore.QDir.toNativeSeparators(filename)))

            return True

        return False

    def open_file(self):
        """Prompt user to select file to map files from"""
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog

        dialog = QtWidgets.QFileDialog()
        dialog.setOptions(options)
        dialog.setFileMode(QtWidgets.QFileDialog.AnyFile)
        dialog.setAcceptMode(QtWidgets.QFileDialog.AcceptOpen)

        return self.exec_open_dialog(dialog)

    def open_folder(self):
        """Prompt user to select folder to map files from"""
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog

        dialog = QtWidgets.QFileDialog()
        dialog.setOptions(options)
        dialog.setFileMode(QtWidgets.QFileDialog.Directory)
        dialog.setAcceptMode(QtWidgets.QFileDialog.AcceptOpen)

        return self.exec_open_dialog(dialog)