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

"""PE Tree utility functions"""

# Standard imports
import os
import sys
import string
import struct
from io import BytesIO
import collections

# Qt imports
from PyQt5 import QtGui, Qt

def hexdump(buffer, base=0, width=16):
    """Hexdump a buffer

    Args:
        buffer (bytes): Data to hexdump
        base (int): Base address of data
        width (int): Number of bytes to show per line

    Returns:
        str: Hex dump of data

    """
    dump = ""
    offset = 0
    printable = "".join([c if ord(c) >= 0x20 and ord(c) < 0x7f else "" for c in string.printable])

    if sys.version_info > (3,):
        _hex = lambda line: " ".join(["{:02x}".format(c) for c in line])
        _ascii = lambda line: "".join([chr(c) if chr(c) in printable else "." for c in line])
    else:
        _hex = lambda line: " ".join(["{:02x}".format(ord(c)) for c in line])
        _ascii = lambda line: "".join([c if c in printable else "." for c in line])

    while buffer:
        line = buffer[:width]

        dump += "0x{:08x} {:{}} {}{}".format(base + offset, _hex(line), width * 3, _ascii(line), os.linesep)

        offset += width
        buffer = buffer[width:]

    return dump

def human_readable_filesize(size):
    """Convert file size in bytes to human readable format

    Args:
        size (int): Size in bytes

    Returns:
        str: Human readable file-size, i.e. 567.4 KB (580984 bytes)

    """
    if size < 1024:
        return "{} bytes".format(size)
    remain = float(size)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if remain < 1024.0:
            return "{:.1f} {} ({:d} bytes)".format(remain, unit, size)
        remain /= 1024.0

def qicon_from_ico_data(data):
    """Convert ICO/PNG data to QIcon

    Args:
        data (bytes): Data starting with either an ICONDIR or BITMAPINFOHEADER

    Returns:
        QIcon: Icon loaded from data if successful, otherwise an empty icon

    """
    # Ensure we have some data to work with
    if not data:
        return QtGui.QIcon()

    # Is this a PNG icon?
    if data[1:4].startswith(b"PNG"):
        # Load PNG image data
        return QtGui.QIcon(QtGui.QPixmap.fromImage(QtGui.QImage.fromData(data)))

    # Starts with BITMAPINFOHEADER?
    if data.startswith(b"\x28"):
        # Add dummy 16x16 ICONDIR header
        data = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x00\x00\x00\x00" + struct.pack("<I", len(data)) + b"\x16\x00\x00\x00" + data

    try:
        # Open ico "file"
        ico = BytesIO(data)

        # Parse the ICONDIR
        icondir = collections.namedtuple("ICONDIR", "reserved type images")._make(struct.Struct("<H H H").unpack(ico.read(6)))

        # Valid looking icon directory?
        if icondir.reserved != 0 or icondir.type != 1 or icondir.images == 0:
            return QtGui.QIcon()

        # Parse the ICONDIRENTRY array
        icons = []

        for i in range(icondir.images):
            icons.append(collections.namedtuple("ICONDIRENTRY", "width height colours reserved planes bpp image_size image_offset")._make(struct.Struct("<B B B B H H I I").unpack(ico.read(16))))

        # Find 32x32 icon, otherwise use the first
        icon = icons[0]

        for _icon in icons:
            if _icon.width == 32:
                icon = _icon

        # Read image data
        image = data[icon.image_offset:icon.image_size]

        # Is the image a PNG?
        if image.startswith(b"PNG"):
            # Create icon from PNG image data
            return QtGui.QIcon(QtGui.QPixmap.fromImage(QtGui.QImage.fromData(image)))

        # Open BMP/DIB image "file"
        bmp = BytesIO(image)

        # Parse the BITMAPINFOHEADER
        bitmap_info = collections.namedtuple("BITMAPINFOHEADER", "sizeof width height planes bpp compression image_size x_ppm y_ppm colours_used important_colours")._make(struct.Struct("<I I I H H I I I I I I").unpack(bmp.read(40)))

        # Ensure the image is supported
        if bitmap_info.sizeof != 40 or bitmap_info.compression != 0 or bitmap_info.bpp not in [1, 2, 4, 8, 16, 24, 32] or bitmap_info.width < 16 or bitmap_info.width % 8 != 0 or bitmap_info.width > 256:
            return QtGui.QIcon()

        # Contains a colour palette?
        if bitmap_info.colours_used != 0 or bitmap_info.bpp <= 8:
            # Determine the total number of colours in the palette
            colours = bitmap_info.colours_used if bitmap_info.colours_used > 0 else pow(2, bitmap_info.bpp)

            # Read RGBA palette colours
            palette_data = bmp.read(colours * 4)
            palette = []

            # Parse palette colours into RGBA
            for i in range(colours):
                b, g, r, a = struct.unpack("!BBBB", palette_data[i * 4 : i * 4 + 4])
                palette.append((r, g, b, 0xff))

        # Determine row stride
        stride = ((((bitmap_info.width * bitmap_info.bpp) + 31) & ~31) >> 3)

        # If height is greater than width then we have alpha channel data
        height = bitmap_info.width

        # Read pixels
        pixel_data = bmp.read(stride * height)

        if sys.version_info > (3,):
            _ord = int
        else:
            _ord = ord

        # Determine pixel format
        if bitmap_info.bpp == 32:
            # 32-bit RGBA
            format = QtGui.QImage.Format_RGBA8888
        elif bitmap_info.bpp == 24:
            # 24-bit RGB
            format = QtGui.QImage.Format_RGB888
        elif bitmap_info.bpp == 16:
            # 16-bit RGB
            format = QtGui.QImage.Format_RGB16
        elif bitmap_info.bpp == 8:
            # 8-bit indexed, convert to 32-bit RGBA
            format = QtGui.QImage.Format_RGBA8888
            pixels = b""
            for index in pixel_data:
                r, g, b, a = palette[_ord(index)]
                pixels += struct.pack("!BBBB", r, g, b, a)

            pixel_data = pixels
        elif bitmap_info.bpp == 4:
            # 4-bit indexed, convert to 32-bit RGBA
            format = QtGui.QImage.Format_RGBA8888
            pixels = b""
            for index in pixel_data:
                index = _ord(index)
                for i in range(2):
                    r, g, b, a = palette[(index & 0xf0) >> 4]
                    pixels += struct.pack("!BBBB", r, g, b, a)
                    index <<= 4

            pixel_data = pixels
        elif bitmap_info.bpp == 2:
            # 2-bit indexed, convert to 32-bit RGBA
            format = QtGui.QImage.Format_RGBA8888
            pixels = b""
            for index in pixel_data:
                index = _ord(index)
                for i in range(4):
                    r, g, b, a = palette[(index & 0xC0) >> 6]
                    pixels += struct.pack("!BBBB", r, g, b, a)
                    index <<= 2

            pixel_data = pixels
        elif bitmap_info.bpp == 1:
            # 1-bit indexed, convert to 32-bit RGBA
            format = QtGui.QImage.Format_RGBA8888
            pixels = b""
            for index in pixel_data:
                index = _ord(index)
                for i in range(8):
                    r, g, b, a = palette[(index & 0x80) >> 7]
                    pixels += struct.pack("!BBBB", r, g, b, a)
                    index <<= 1

            pixel_data = pixels

        # Create image from pixel data and mirror flip (as the bitmap is stored backwards)
        image = QtGui.QImage(pixel_data, bitmap_info.width, bitmap_info.width, format).mirrored(False, True)
        pixmap = QtGui.QPixmap.fromImage(image)

        # No alpha?
        if bitmap_info.bpp < 32:
            # Use pixel 0, 0 as the transparent background colour
            pixmap.setMask(pixmap.createMaskFromColor(image.pixelColor(0, 0), Qt.Qt.MaskInColor))

        # Create icon from pixmap
        return QtGui.QIcon(pixmap)
    except:
        return QtGui.QIcon()
