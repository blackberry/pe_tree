# Changelog

All notable changes to this project will be documented in this file.

## [1.0.28](/../tags/1.0.28) - 2020-10-02

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

## [1.0.27](/../tags/1.0.27) - 2020-05-20

### Added

- Added [LICENSE](LICENSE)

### Changed

- [setup.py](setup.py) now reads requirements from [requirements.txt](requirements.txt)
- Updated IDAPython installation documentation in [README.md](README.md)

### Fixed

- The PE no-overlay hash was not calculated correctly
- Ensure the correct tree item is removed from the view via right click -> remove

## [1.0.26](/../tags/1.0.26) - 2020-05-19

### Changed

- Removed `package_data` from [setup.py](setup.py)

### Added

- Added [MANIFEST.in](MANIFEST.in) to include package resources

## [1.0.25](/../tags/1.0.25) - 2020-05-19

### Changed

- Updated copyright
- Updated VirusTotal logo
- Updated about box information

## [1.0.24](/../tags/1.0.24) - 2020-05-19

### Added

- VirusTotal and CyberChef URLs moved to configuration file
- Improved developer documentation

### Changed

- Updated about box information

### Fixed

- Fixed fatal exception when starting pe_tree application with partial configuration
- Fixed several pylint warnings

## [1.0.23](/../tags/1.0.23) - 2020-05-15

### Changed

- Updated [setup.py](setup.py) to better support installing as either standalone application or IDA plugin

## [1.0.22](/../tags/1.0.22) - 2020-05-14

### Added

- Changelog markdown
- Contributing markdown

### Changed

- Updated [README.md](README.md)

### Fixed

- Fixed bug when loading as IDAPython plugin

## [1.0.21](/../tags/1.0.21) - 2020-05-12

### Added

- IAT reconstruction
