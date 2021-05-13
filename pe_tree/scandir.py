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

"""PE Tree directory scanning"""

# Standard imports
import os
import zipfile

# Scan dir
import scandir

# Qt imports
from PyQt5 import QtCore

class ScanDir(QtCore.QRunnable):
    """Scan directory thread. Responsible for traversing directories and archives.

    Args:
        pe_tree_form (pe_tree.form): PE Tree form
        filename (str): Path to file/folder/zip archive to scan for PE files

    """
    def __init__(self, pe_tree_form, filename):
        super(ScanDir, self).__init__()

        self.filename = filename
        self.pe_tree_form = pe_tree_form

    def unpack_and_map(self, filename):
        """Attempt to extract a zip archive and map PE files"""
        try:
            # Attempt to open as zip archive
            with zipfile.ZipFile(filename) as zip_archive:
                # Iterate over all filenames
                for zip_filename in zip_archive.namelist():
                    # Iterate over passwords from the config file
                    for password in self.pe_tree_form.runtime.get_config_option("config", "passwords", "").split(","):
                        if password != "":
                            # Set the password if specified
                            zip_archive.setpassword(password.encode("utf-8"))

                        # Attempt to extract the file
                        try:
                            with zip_archive.open(zip_filename, "r") as zipped_file:
                                # Read the zipped file
                                data = zipped_file.read()

                                # Ensure the file has an MZ header
                                if data[:2] == b"MZ":
                                    # Map the PE data
                                    self.pe_tree_form.map_pe(filename=os.path.join(filename, zip_filename), data=data, disable_dump=True)

                                break
                        except RuntimeError:
                            # Possibly a bad password?
                            pass

                # No point trying to map as a PE as well
                return
        except zipfile.BadZipFile:
            # Attempt to map as PE file
            self.pe_tree_form.map_pe(filename=filename)
        except OSError:
            pass

    def run(self):
        """Iterate over all files/folders and map PE files"""
        if os.path.isdir(self.filename):
            for root, dirs, files in scandir.walk(self.filename):
                for file in files:
                    # Have we been signaled to stop?
                    if self.pe_tree_form.stop_event.is_set():
                        return

                    # Map the PE file
                    self.pe_tree_form.map_pe(filename=os.path.join(root, file))
        else:
            # Unpack and map PE files
            self.unpack_and_map(filename=self.filename)