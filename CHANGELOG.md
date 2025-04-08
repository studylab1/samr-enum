# Changelog

This file documents all notable changes made to the SAMR enumeration tool samr-enum.py.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.2.0] - 2025-04-08
### Changed
  Simplified the usage of the `opnums` and `debug` parameters. These can now be specified as flags (e.g., `opnums` or `debug`) without requiring an explicit value such as `true`.

### Fixed
  Corrected the OpNum list output when using the `acl` parameter so that the proper operation numbers are displayed in the final output.

## [1.1.2] - 2025-04-08
### Fixed
  Errors in the output when using the acl parameter.
 
## [1.1.1] - 2025-04-08
### Added
- **ACL Support:**  
  - Added support for querying and displaying detailed ACL information when the "acl" flag is provided (only for `enumerate=account-details`).
  - For user accounts and local groups, the tool now outputs the security descriptor's owner and group SIDs (with friendly names when resolvable), control flags, and a parsed list of DACL ACEs.
  - ACEs now show the access mask both in hexadecimal and as a comma-separated list of permission names (e.g., "USR_READ_GEN, USR_READ_PREF, ...") based on the SAMR specification.

## [1.0.1] - 2025-03-12
### Changed
- Included version number.
- Changed Impacket reference.
- Adjusted the code for 'import' requirements according to PEP 8.

### Fixed
- Fixed issue with missing Domain SID in `enumerate=users`, `enumerate=display-info`, and `enumerate=summary` enumerations.

## [1.0.0] - 2025-03-08
### Added
- Initial release of the SAMR Enumeration Tool.
- Domain enumeration capabilities including users, computers, local groups, and domain groups.
- Support for both NTLM (default) and Kerberos authentication.
- Options to export results in TXT, CSV, and JSON formats.
- Debug logging with detailed SAMR operation numbers.
