# Changelog

All notable changes to PlexiChat will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [a.1.1-17] - 2025-01-15

### Fixed
- Fixed over 25 files with pyright and linter errors
- Resolved malformed import statements throughout the codebase
- Fixed type annotation issues (added Optional types for parameters with None defaults)
- Corrected syntax errors in multiple authentication modules
- Fixed import resolution issues with missing modules
- Added fallback implementations for missing dependencies
- Resolved dataclass field type annotation issues
- Fixed completely corrupted files (orchestrator_core.py, client_analytics.py)
- Added compatibility aliases for renamed classes (MFAManager = Advanced2FASystem)

### Changed
- Updated .gitignore to exclude development artifacts and junk files
- Improved error handling with try-catch blocks for missing imports
- Enhanced type safety across the codebase

### Removed
- Cleaned up junk files and development artifacts
- Removed temporary test files and debug scripts
- Removed backup directories and analysis reports

## [a.1.1-16] - Previous Release

### Added
- Initial alpha release with core functionality
- Authentication system
- Database abstraction layer
- Web interface
- CLI interface
- Plugin system
- Security features

### Known Issues
- Multiple pyright and linter errors (resolved in a.1.1-17)
- Import resolution issues (resolved in a.1.1-17)
- Type annotation inconsistencies (resolved in a.1.1-17)
