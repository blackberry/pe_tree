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

"""Hash all portions of a PE file, this may be run as a separate process"""

# Standard imports
import json
import hashlib

import pefile

def hash_data(data, entropy_H):
    """Calculate MD5/SHA1/SHA256 of given data
    
    Args:
        data (bytes): Data to calculate hashes/entropy
        entropy_H (pefile.SectionStructure.entropy_H): Callback function for calculating entropy

    Returns:
        dict: Dictionary of hashes/entropy

    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    md5.update(data)
    sha1.update(data)
    sha256.update(data)

    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest(), "entropy": entropy_H(data), "size": len(data)}

def hash_pe_file(filename, data=None, pe=None, json_dumps=True):
    """Calculate PE file hashes.

    Either call directly or invoke via processpool::

        processpool = multiprocessing.Pool(10)
        hashes = json.loads(processpool.apply_async(pe_tree.hash_pe.hash_pe_file, (filename,)).get())

    Args:
        filename (str): Path to file to hash (or specify via data)
        data (bytes, optional): PE file data
        pe (pefile.PE, optional): Parsed PE file
        json_dumps (bool, optional): Return data as JSON

    Returns:
        dict: PE file hashes if json_dumps == False
        str: JSON PE file hashes if json_dumps == True
    
    """
    if pe == None:
        pe = pefile.PE(filename)

    # Calculate entropy (use pefile implementation!)
    entropy_H = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__, pe=pe).entropy_H

    file_hashes = {"file": {"md5": "", "sha1": "", "sha256": "", "entropy": 0.0, "size": 0},
              "file_no_overlay": {"md5": "", "sha1": "", "sha256": "", "entropy": 0.0, "size": 0},
              "dos_stub": {"md5": "", "sha1": "", "sha256": "", "entropy": 0.0, "size": 0},
              "sections": [], 
              "resources": [],
              "security_directory": {"md5": "", "sha1": "", "sha256": "", "entropy": 0.0, "size": 0},
              "overlay": {"md5": "", "sha1": "", "sha256": "", "entropy": 0.0, "size": 0}}

    if not data:
        with open(filename, "rb") as f:
            data = f.read()

    # Hash entire file
    file_hashes["file"] = hash_data(data, entropy_H)

    # Hash DOS stub
    if pe.DOS_HEADER.e_lfanew > 64:
        file_hashes["dos_stub"] = hash_data(data[64:pe.DOS_HEADER.e_lfanew], entropy_H)

    # Hash sections
    for section in pe.sections:
        file_hashes["sections"].append({"md5": section.get_hash_md5(), "sha256": section.get_hash_sha256(), "entropy": section.get_entropy()})

    # Hash resources
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        mapped_data = pe.get_memory_mapped_image()

        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if not hasattr(resource_type, "directory"):
                continue

            for resource_id in resource_type.directory.entries:
                if not hasattr(resource_id, "directory"):
                    continue

                for resource_language in resource_id.directory.entries:
                    if not hasattr(resource_language, "data"):
                        continue

                    offset = resource_language.data.struct.OffsetToData
                    size = resource_language.data.struct.Size

                    try:
                        resource_data = mapped_data[offset:offset + size]
                    except:
                        resource_data = ""

                    file_hashes["resources"].append(hash_data(resource_data, entropy_H))

    overlay_offset = pe.get_overlay_data_start_offset()

    if overlay_offset:
        overlay_data = pe.get_overlay()

        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]

        if security.VirtualAddress != 0 and security.Size != 0:
            size = min(security.Size, len(overlay_data))

            # Hash security directory
            file_hashes["security_directory"] = hash_data(overlay_data[:size], entropy_H)

            overlay_data = overlay_data[size:]
            overlay_offset += size

        # Hash overlay
        file_hashes["overlay"] = hash_data(overlay_data, entropy_H)
        file_hashes["file_no_overlay"] = hash_data(data[overlay_offset:], entropy_H)

    # Return JSON
    if json_dumps:
        return json.dumps(file_hashes)
    
    # Return dict
    return file_hashes