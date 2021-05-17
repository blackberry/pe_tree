# Changelog

All notable changes to this project will be documented in this file.

## [1.0.30](/../../releases/tag/1.0.30) - 2021-04-08

### Added

- Plugin for [Ghidra](https://ghidra-sre.org/) using [Ghidra Bridge](https://github.com/justfoxing/ghidra_bridge)
- Plugin for [Volatility](https://github.com/volatilityfoundation/volatility3)
- Application for extracting PE images from Minidumps using [minidump](https://github.com/skelsec/minidump)
- Application for carving PE files from binary files
- Support for unpacking PE files from zip files (including password protected)
- Additional information in PE summary view
- Resource MIME type detection

### Changed
- Moved code for finding PE files in an IDB to the IDA runtime
- Switched to non-native file open dialogs as accept was slow on Windows
- Improved IDAPro in-memory PE handling
- Consolidated code in runtime
- Hide the output log view if it is empty

### Fixed

- Bug loading minidump files under IDA when no input file is present
- Added drop shadow to PE map labels to improve text readability
- Bug loading capstone disassembler
- Dumping without touching the IAT works properly now

## [1.0.29](/../../releases/tag/1.0.29) - 2020-10-05

### Fixed

- Fixed section MD5 VT search query

## [1.0.28](/../../releases/tag/1.0.28) - 2020-07-30

### Added

- [Rekall](http://www.rekall-forensic.com/) integration
- [.gitignore](.gitignore) file

### Changed

- Tidied runtime interface
- Renamed reconstructed imports section from .idata to .pe_tree

### Fixed

- Certificate parsing
- Improved PE dumping/import reconstruction
- pylint updates

## [1.0.27](/../../releases/tag/1.0.27) - 2020-05-20

### Added

- Added [LICENSE](LICENSE)

### Changed

- [setup.py](setup.py) now reads requirements from [requirements.txt](requirements.txt)
- Updated IDAPython installation documentation in [README.md](README.md)

### Fixed

- The PE no-overlay hash was not calculated correctly
- Ensure the correct tree item is removed from the view via right click -> remove

## [1.0.26](/../../releases/tag/1.0.26) - 2020-05-19

### Changed

- Removed *package_data* from [setup.py](setup.py)

### Added

- Added [MANIFEST.in](MANIFEST.in) to include package resources

## [1.0.25](/../../releases/tag/1.0.25) - 2020-05-19

### Changed

- Updated copyright
- Updated VirusTotal logo
- Updated about box information

## [1.0.24](/../../releases/tag/1.0.24) - 2020-05-19

### Added

- VirusTotal and CyberChef URLs moved to configuration file
- Improved developer documentation

### Changed

- Updated about box information

### Fixed

- Fixed fatal exception when starting pe_tree application with partial configuration
- Fixed several pylint warnings

## [1.0.23](/../../releases/tag/1.0.23) - 2020-05-15

### Changed

- Updated [setup.py](setup.py) to better support installing as either standalone application or IDA plugin

## [1.0.22](/../../releases/tag/1.0.22) - 2020-05-14

### Added

- Changelog markdown
- Contributing markdown

### Changed

- Updated [README.md](README.md)

### Fixed

- Fixed bug when loading as IDAPython plugin

## [1.0.21](/../../releases/tag/1.0.21) - 2020-05-12

### Added

- IAT reconstruction
