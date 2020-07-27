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

"""Main form for PE Tree"""

# Standard imports
import os
import threading
import multiprocessing
import webbrowser

# Requests
import requests

# Qt imports
from PyQt5 import QtCore, QtGui, QtWidgets, Qt

# IDAPro imports
try:
    import idc

    have_ida = True
except ImportError:
    have_ida = False

# PE Tree imports
import pe_tree.tree
import pe_tree.map
import pe_tree.contextmenu
import pe_tree.qstandarditems
import pe_tree.utils

class PETreeForm():
    """PETree GUI and helper functions
    
    Args:
        widget (QWidget): Parent widget
        application (QApplication): Application widget, or None for IDA plugin
        runtime (pe_tree.runtime.Runtime): Runtime callbacks

    """

    def __init__(self, widget, application, runtime):
        # Get parent widget and application
        if not application:
            application = widget

        self.widget = widget
        self.application = application
        self.runtime = runtime

        # Load main font
        self.font = runtime.get_available_font()

        # Load compiler IDs
        self.load_compiler_ids()

        # Load icons
        resources_dir = os.path.join(runtime.get_script_dir(), "resources")

        self.vt_icon = self.load_icon(os.path.join(resources_dir, "virustotal.png"))
        self.cyberchef_icon = self.load_icon(os.path.join(resources_dir, "cyberchef.ico"))

        # Load window icon
        self.application.setWindowIcon(self.load_icon(os.path.join(resources_dir, "spear.png")))

        # Create tree view and model
        self.treeview = QtWidgets.QTreeView()
        self.model = QtGui.QStandardItemModel(self.treeview)
        self.model.setHorizontalHeaderLabels(["Item", "Value"])

        # Setup tree view
        self.treeview.setModel(self.model)
        self.treeview.doubleClicked.connect(self.row_double_clicked)
        self.treeview.clicked.connect(self.row_clicked)
        self.treeview.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.treeview.customContextMenuRequested.connect(self.context_menu)
        #self.treeview.setAlternatingRowColors(True)
        #self.treeview.setAutoScroll(True)
        self.treeview.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.treeview.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.treeview.setItemDelegate(pe_tree.tree.TreeViewDelegate(self))
        self.treeview.expanded.connect(self.expanded)
        self.treeview.collapsed.connect(self.collapsed)
        self.treeview.selectionModel().selectionChanged.connect(self.selection_changed)
        self.treeview.setVisible(False)
            
        if not have_ida:
            self.treeview.setStyleSheet("""
                QTreeView::item:selected {
                }

                QTreeView::item:hover {
                    color: #ffffff;
                    background-color: #69d03c;
                }

                QTreeView::item:hover:selected {
                }
            """)

        # Create stack of PE maps
        self.map_stack = QtWidgets.QStackedWidget()

        # Right hand pane
        right_pane = QtWidgets.QSplitter()

        right_pane.addWidget(self.treeview)

        if have_ida == False:
            self.output_stack = QtWidgets.QStackedWidget()

            right_pane.addWidget(self.output_stack)

            right_pane.setOrientation(QtCore.Qt.Vertical) 
            right_pane.setSizes([300, 100])

        # Create the splitter
        self.splitter = QtWidgets.QSplitter()
        self.splitter.addWidget(self.map_stack)
        self.splitter.addWidget(right_pane)

        self.splitter.setSizes([100, 300])

        # Create the status bar widgets
        self.status_widget = QtWidgets.QWidget()
        self.status_widget.setVisible(False)
        self.status_widget.setFixedHeight(25)

        status_layout = QtWidgets.QHBoxLayout()
        self.status_label = QtWidgets.QLabel(self.status_widget)

        self.cancel_button = QtWidgets.QPushButton("Cancel", self.status_widget)
        self.cancel_button.setFixedHeight(25)
        self.cancel_button.clicked.connect(self.cancel_clicked)

        status_layout.addWidget(self.cancel_button)
        status_layout.addWidget(self.status_label)

        self.status_widget.setLayout(status_layout)
        self.status_label.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)

        status_layout.setContentsMargins(0, 0, 0, 0)
        self.status_label.setContentsMargins(0, 0, 0, 0)

        # Create layout and add widgets
        self.layout = QtWidgets.QVBoxLayout()
        self.layout.addWidget(self.splitter)
        self.layout.addWidget(self.status_widget)

        # Populate form with layout
        self.widget.setLayout(self.layout)

        # Construct context menu actions
        self.context_menu_actions = pe_tree.contextmenu.CommonStandardItemContextMenu(self)

        # Array of all PETree() root items
        self.tree_roots = []

        self.expanding = False

        # Create thread pool, events and signals
        self.threadpool = QtCore.QThreadPool()
        self.threadpool.setMaxThreadCount(1)
        self.stop_event = threading.Event()
        self.signals = pe_tree.tree.PETreeSignals()
        self.signals.update_ui.connect(self.update_ui)
        self.signals.process_file.connect(self.process_file)
        self.dispatcher = None

        if not have_ida:
            # Use process pool for parsing PE files
            self.processpool = multiprocessing.Pool(1)
        else:
            # Process pool does bad things under IDA!
            self.processpool = None

        if have_ida:
            # For IDA we'll have to wait for threads on-close like this
            self.widget.destroyed.connect(self.wait_for_threads)

    def wait_for_threads(self):
        """Wait for worker threads/processes to terminate before we close"""
        # Signal to threads that the application is closing
        self.stop_event.set()

        # Remove any queued threads
        self.threadpool.clear()

        # Process application events whilst we wait for all threads to complete
        if self.dispatcher != None:
            while self.threadpool.waitForDone(10) == False:
                self.dispatcher.processEvents(Qt.QEventLoop.AllEvents)

        # Wait for processes to complete
        if self.processpool != None:
            self.processpool.close()
            self.processpool.join()

    def cancel_clicked(self):
        """Abort all map/scan dir threads"""
        # Wait for all threads/processes to complete
        self.wait_for_threads()
        
        # Hide the progress bar
        self.status_widget.setVisible(False)
        
        # Recreate the process pool (cannot use again after close)
        if self.processpool != None:
            self.processpool = multiprocessing.Pool(1)

        # Clear the stop event
        self.stop_event.clear()

    def load_compiler_ids(self):
        """Load and parse compiler IDs from https://github.com/dishather/richprint"""
        try:
            self.compiler_ids = None

            filepath = os.path.join(self.runtime.get_temp_dir(), "comp_id.txt")

            # Download compiler IDs 
            if not os.path.exists(filepath):
                r = requests.get("https://raw.githubusercontent.com/dishather/richprint/master/comp_id.txt", allow_redirects=True)
                with open(filepath, "wb") as compiler_ids_file:
                    compiler_ids_file.write(r.content)

            with open(filepath, "r") as compiler_ids_file:
                # Parse compiler IDs into dict
                self.compiler_ids = {}
        
                for line in compiler_ids_file.readlines():
                    if len(line) <= 2 or line[0] == "#":
                        continue
                    
                    ids = line.split(" ")

                    # Create description entry
                    self.compiler_ids[ids[0]] = " ".join(ids[1:]).strip()
        except:
            pass

    def load_icon(self, file_path):
        """Load icon from file
        
        Args:
            file_path (str): Path to icon file

        Returns:
            QIcon: Icon loaded with image from file, otherwise a blank QIcon on error
            
        """
        try:
            if os.path.exists(file_path):
                with open(file_path, "rb") as ficon:
                    return pe_tree.utils.QIcon_from_ICO_data(ficon.read())
        except:
            pass
            
        return QtGui.QIcon()

    def set_map_view(self, item):
        """Set the tree view's corresponding map view to active in the map stack
        
        Args:
            item (pe_tree.tree.PETree): Active tree view

        """
        if item.tree.form.map_stack.currentIndex() == item.tree.map_index:
            return

        item.tree.form.map_stack.setCurrentIndex(item.tree.map_index)

        if hasattr(item.tree.form, "output_stack"):
            item.tree.form.output_stack.setCurrentIndex(item.tree.output_view_index)

    def expanded(self, index):
        """Update map view if tree node expanded
        
         Args:
            index (QModelIndex): Item model index

        """
        self.set_map_view(self.model.itemFromIndex(index))

        # Did we trigger the expand? If so, ignore.
        if not self.expanding:
            # Resize the column width to fit the content
            self.treeview.resizeColumnToContents(0)
            self.treeview.resizeColumnToContents(1)

    def collapsed(self, index):
        """Update map view if tree node collapsed

        Args:
            index (QModelIndex): Item model index

        """
        self.set_map_view(self.model.itemFromIndex(index))

    def row_clicked(self, index):
        """Display URL associated with item

        Args:
            index (QModelIndex): Item model index

        """
        item = self.model.itemFromIndex(index.sibling(index.row(), index.column()))

        if item.url:
            webbrowser.open_new_tab(item.url)

    def row_double_clicked(self, index):
        """Navigate to item offset in IDA view

        Args:
            index (QModelIndex): Item model index

        """
        item = self.model.itemFromIndex(index.sibling(index.row(), 1))

        if item.offset == 0:
            return

        # Convert RVA to VA
        if item.offset < item.tree.image_base:
            offset = item.tree.image_base + item.offset
        else:
            offset = item.offset

        # Attempt to navigate to address in IDA view
        item.tree.form.runtime.jumpto(item, offset)

    def context_menu(self, point):
        """Tree view right-click context menu activated

        Args:
            point (QPoint): Mouse click co-ordinates

        """
        index = self.treeview.indexAt(point)

        # Find item that was right-clicked
        item = self.model.itemFromIndex(index)

        if item == None:
            item = pe_tree.qstandarditems.NoItem(pe_tree.tree.PETree(self, "", 0, None))

        # Display the item's context menu
        item.context_menu(self.context_menu_actions.new_menu(self, self.treeview.viewport().mapToGlobal(point), item, index))

    def selection_changed(self, selection):
        """Change PE map in map stack
        
        Args:
            selection (QItemSelectionModel): PE tree view selection

        """
        # Find selected item
        for index in selection.indexes():
            # Update map view
            item = self.model.itemFromIndex(index)
            form = item.tree.form

            item.tree.form.map_stack.setCurrentIndex(item.tree.map_index)

            if hasattr(form, "output_stack"):
                item.tree.form.output_stack.setCurrentIndex(item.tree.output_view_index)

            return

    def expand_items(self, index):
        """Expand all children in a tree view from given index (recursive)

        Args:
            index (QModelIndex): Item model index

        """
        # Ensure the index is valid
        if not index.isValid():
            return

        # Expand all children
        for i in range(self.model.rowCount(index)):
            self.expand_items(index.child(i, 0))

        # Expand current index
        self.treeview.setExpanded(index, True)

    def process_file(self, filename):
        """Signaled via worker thread to update status bar UI.
        
        Args:
            filename (str): The path of the current file being processed

        """
        self.status_widget.setVisible(True)
        self.status_label.setText("Processing {}".format(filename))

    def update_ui(self, tree):
        """Add treeview and map widgets to the main form. Signaled via worker thread.
        
        Args:
            tree (pe_tree.tree.PETree): New PETree to add to the form view

        """
        # Have we been signaled to stop?
        if self.stop_event.is_set():
            return

        # Ensure we have root items
        if not tree.root_item or not tree.root_value_item:
            return

        # Get the "invisible root" for the tree model
        invisible_root_item = self.model.invisibleRootItem()
        has_children = invisible_root_item.hasChildren()

        invisible_root_item.appendRow([tree.root_item, tree.root_value_item])

        # Create new output window (if needed)
        if hasattr(self, "output_stack"):
            tree.output_view = QtWidgets.QTextEdit()
            tree.output_view.setFont(self.font)

            tree.output_view_index = self.output_stack.addWidget(tree.output_view)

            if has_children == False:
                # Set the output widgets as active
                self.output_stack.setCurrentIndex(tree.output_view_index)

        # Create the PE map widget and scroll area and add to stack
        tree.map = pe_tree.map.PEMap(tree.size)
        tree.map.file_size = tree.size

        tree.map_scroll_area = QtWidgets.QScrollArea()
        tree.map_scroll_area.setWidgetResizable(True)
        tree.map_scroll_area.setAutoFillBackground(True)
        tree.map_scroll_area.setWidget(tree.map)

        tree.map_index = self.map_stack.addWidget(tree.map_scroll_area)

        # Add the file regions to the PE map widget
        tree.map.add_regions(tree.regions)

        # Append this PETree object to the list of roots
        self.tree_roots.append(tree)

        # Is this the first PE file?
        if has_children == False:
            # Set the map widget as active
            self.map_stack.setCurrentIndex(tree.map_index)

        self.treeview.setVisible(True)

        # Ensure the filename fits in the column
        self.treeview.resizeColumnToContents(0)

        # Hide the status bar if no more threads are running
        if self.threadpool.activeThreadCount() == 0:
            self.status_widget.setVisible(False)

    def map_pe(self, filename=None, image_base=0, data=None, priority=0):
        """Starts a new thread to map PE from file/memory/data
        
        Args:
            filename (str, optional): Path to PE file to map
            image_base (int, optional): Image base of PE file to map
            data (bytes, optional): PE File data to map
            priority (int, optional): QRunnable thread priority
        
        """
        self.threadpool.start(pe_tree.tree.PETree(self, filename, image_base, data), priority)

    def show(self):
        """Display the main form widget"""
        self.runtime.show_widget()
