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

"""PE Tree file region map"""

# Standard imports
import sys
import itertools

# Qt imports
from PyQt5 import QtCore, QtGui, QtWidgets

class FileRegion():
    """Holds information about a file region for the map view

    Args:
        name (str): Name of the region
        start (int, optional): File offset
        size (int, optional): Size in bytes
        rva (int, optional): In-memory offset
        item (pe_tree.tree.PETree, optional): PE Tree

    """
    def __init__(self, name, start=0, size=0, end=0, rva=0, item=None):
        if sys.version_info > (3,):
            self.name = name
        else:
            self.name = str(name)

        self.start = start
        self.size = size
        self.end = end
        self.rva = rva
        self.item = item
        self.rect = None
        self.colour = None
        self.hover = False

        if self.end == 0:
            self.end = self.start + self.size

        if self.size == 0:
            self.size = self.end - self.start

class PEMap(QtWidgets.QGroupBox):
    """PE map group box widget for holding region labels

    Args:
        file_size (int): Size of the PE file
        parent (QWidget, optional): Parent widget

    """
    def __init__(self, file_size, parent=None):
        super(PEMap, self).__init__(parent=parent)

        self.file_size = file_size
        self.colours = None
        self.rainbows = {}

        # Create group box layout for the PE map
        self.layout = QtWidgets.QVBoxLayout(self)

        # Remove space between widgets
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        # Set background to white (for alpha)
        self.setStyleSheet("background-color: white; margin-top: 0px; padding: 0px;")

    def add_regions(self, regions):
        """Add list of file regions to the PE map

        Args:
            regions ([pe_tree.map.FileRegions]: File regions

        """
        # Rainbow colours for the PE map
        colours = ["#b9413c", "#ea8c2c", "#ffbd20", "#559f7a", "#4c82a4", "#764a73", "#2f0128"]

        wanted = len(regions) + len(colours)

        if wanted in self.rainbows:
            # Use saved colours
            colours = self.rainbows[wanted]
        else:
            # Make a rainbow
            while True:
                gradients = polylinear_gradient(colours, wanted)

                if len(gradients["hex"]) >= len(regions):
                    break

                wanted += 1

            colours = []

            for colour in gradients["hex"]:
                colours.append(QtGui.QColor(int(colour[1:], 16)))

            # Save colours
            self.rainbows[len(colours)] = colours

        self.colours = itertools.cycle(colours)

        # Sort regions by start offset, create labels and add to the group box layout
        for region in sorted(regions, key=lambda region: (region.start)):
            self.layout.addWidget(PEMapLabel(region, next(self.colours), self.file_size, parent=self))

class PEMapLabel(QtWidgets.QWidget):
    """PE map label widget

    Args:
        region (pe_tree.map.FileRegion): PE file region
        colour (QColor): Region background colour
        file_size (int): Size of the PE file
        parent (QWidget, optional): Parent widget

    """
    def __init__(self, region, colour, file_size, parent=None):
        super(PEMapLabel, self).__init__(parent=parent)

        self.region = region
        self.colour = colour
        self.file_size = file_size

        # Initialise self
        self.setMouseTracking(True)
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.context_menu)
        self.setMinimumHeight(30)

        # Initialise font
        families = ["Consolas", "Monospace", "Courier"]

        for family in families:
            family = family.strip()
            if family in QtGui.QFontDatabase().families():
                self.setFont(QtGui.QFont(family))

    def paintEvent(self, event):
        """Draw the PE map label

        Args:
            event (QPaintEvent): Paint event

        """
        super(PEMapLabel, self).paintEvent(event)

        # Get size of the label rect
        r = event.region().boundingRect()

        w = self.width()
        h = self.height()
        y = r.y()
        x = r.x()

        # Get colour and region
        colour = self.colour
        region = self.region

        # Same colour but with alpha
        colour_alpha = QtGui.QColor(colour.red(), colour.green(), colour.blue(), alpha=100 if region.hover is True else 175)

        # Expand the font on mouse over
        font = self.font()
        font.setWeight(QtGui.QFont.Medium)

        if region.hover:
            font.setStretch(QtGui.QFont.Expanded)
        else:
            font.setStretch(QtGui.QFont.SemiExpanded)

        # Draw the main rect
        painter = QtGui.QPainter(self)

        region.rect = QtCore.QRect(x, y, w, h)
        painter.setPen(QtCore.Qt.NoPen)
        painter.setBrush(QtGui.QBrush(QtGui.QColor(colour), QtCore.Qt.SolidPattern))
        painter.drawRect(region.rect)

        # Determine width per byte of file size
        delta = float(w) / float(max(self.file_size, region.start + region.size))

        # Draw the ratio portion over a white background
        painter.setBrush(QtGui.QBrush(QtGui.QColor("white"), QtCore.Qt.SolidPattern))
        painter.drawRect(x + int(region.start * delta), y, max(int(region.size * delta), 2), h)

        painter.setBrush(QtGui.QBrush(QtGui.QColor(colour_alpha), QtCore.Qt.SolidPattern))
        painter.drawRect(x + int(region.start * delta), y, max(int(region.size * delta), 2), h)

        # Draw drop shadow text
        painter.setFont(font)
        painter.setPen(QtGui.QPen(QtGui.QColor(63, 63, 63, 100)))
        painter.drawText(QtCore.QRect(x + 1, y + 1, w, h), QtCore.Qt.AlignCenter, str(region.name))

        # Write the region name
        painter.setPen(QtGui.QPen(QtGui.QColor(244, 244, 250)))
        painter.drawText(QtCore.QRect(x, y, w, h), QtCore.Qt.AlignCenter, str(region.name))

        painter.end()

    def mouseMoveEvent(self, event):
        """Set region hover state and redraw the PE map label

        Args:
            event (QMouseEvent): Mouse move event

        """
        self.region.hover = True
        self.update()

    def leaveEvent(self, event):
        """Clear region hover state and redraw the PE map label

        Args:
            event (QMouseEvent): Mouse move event

        """
        self.region.hover = False
        self.update()

    def mousePressEvent(self, event):
        """Locate item related to PE map label in tree view

        Args:
            event (QMouseEvent): Mouse press event

        """
        if event.button() == QtCore.Qt.RightButton:
            return

        item = self.region.item
        form = item.tree.form
        index = form.model.indexFromItem(item)

        # Find/expand/scroll to the item in the PE tree
        form.treeview.setCurrentIndex(index)
        form.expanding = True
        form.expand_items(index)
        form.expanding = False
        form.treeview.resizeColumnToContents(0)
        form.treeview.resizeColumnToContents(1)
        form.treeview.scrollTo(index, QtWidgets.QAbstractItemView.PositionAtTop)

    def mouseDoubleClickEvent(self, event):
        """Locate item related to PE map label in external view

        Args:
            event (QMouseEvent): Mouse click event

        """
        self.region.hover = False

        self.region.item.tree.form.runtime.jumpto(self.region.item, self.region.rva)

    def context_menu(self, point):
        """Show PE map label right-click context menu

        Args:
            point (QPoint): Right-click location

        """
        item = self.region.item
        form = item.tree.form
        point = self.mapToGlobal(point)
        index = form.model.indexFromItem(item)

        item.context_menu(form.context_menu_actions.new_menu(form, point, item, index))

class PEMapScrollArea(QtWidgets.QScrollArea):
    """PE map scroll area widget"""
    def eventFilter(self, obj, event):
        if event.type() is QtCore.QEvent.MouseMove:
            # Force the map view to update when the mouse moves over the scrollbar
            self.widget().update()

        return super(PEMapScrollArea, self).eventFilter(obj, event)

#
# The following code is gratefully borrowed from:
# https://github.com/bsouthga/blog/blob/master/public/posts/color-gradients-with-python.md
# licensed as follows:
# Copyright 2017 Ben Southgate
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE
#

def hex_to_RGB(hex):
    ''' "#FFFFFF" -> [255,255,255] '''
    # Pass 16 to the integer function for change of base
    return [int(hex[i:i+2], 16) for i in range(1,6,2)]


def RGB_to_hex(RGB):
    ''' [255,255,255] -> "#FFFFFF" '''
    # Components need to be integers for hex to make sense
    RGB = [int(x) for x in RGB]
    return "#"+"".join(["0{0:x}".format(v) if v < 16 else "{0:x}".format(v) for v in RGB])

def color_dict(gradient):
    ''' Takes in a list of RGB sub-lists and returns dictionary of
    colors in RGB and hex form for use in a graphing function
    defined later on '''
    return {"hex":[RGB_to_hex(RGB) for RGB in gradient],
            "r":[RGB[0] for RGB in gradient],
            "g":[RGB[1] for RGB in gradient],
            "b":[RGB[2] for RGB in gradient]}

def linear_gradient(start_hex, finish_hex="#FFFFFF", n=10):
    ''' returns a gradient list of (n) colors between
    two hex colors. start_hex and finish_hex
    should be the full six-digit color string,
    inlcuding the number sign ("#FFFFFF") '''
    # Starting and ending colors in RGB form
    s = hex_to_RGB(start_hex)
    f = hex_to_RGB(finish_hex)
    # Initilize a list of the output colors with the starting color
    RGB_list = [s]
    # Calcuate a color at each evenly spaced value of t from 1 to n
    for t in range(1, n):
        # Interpolate RGB vector for color at the current value of t
        curr_vector = [
            int(s[j] + (float(t)/(n-1))*(f[j]-s[j]))
            for j in range(3)
        ]
        # Add it to our list of output colors
        RGB_list.append(curr_vector)

    return color_dict(RGB_list)

def polylinear_gradient(colors, n):
    ''' returns a list of colors forming linear gradients between
        all sequential pairs of colors. "n" specifies the total
        number of desired output colors '''
    # The number of colors per individual linear gradient
    n_out = int(float(n) / (len(colors) - 1))
    # returns dictionary defined by color_dict()
    gradient_dict = linear_gradient(colors[0], colors[1], n_out)

    if len(colors) > 1:
        for col in range(1, len(colors) - 1):
            next = linear_gradient(colors[col], colors[col+1], n_out)
            for k in ("hex", "r", "g", "b"):
                # Exclude first point to avoid duplicates
                gradient_dict[k] += next[k][1:]

        return gradient_dict
