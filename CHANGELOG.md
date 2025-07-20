# PlexiChat Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [a.1.1-31] - 2025-07-20

### Fixed
- Fixed syntax errors in exceptions.py, unified_auth.py, audit_manager.py, biometric_manager.py, device_manager.py, and ai_features_routes.py
- Fixed function definition syntax errors (missing opening parentheses)
- Fixed HTTPException calls with proper parameter formatting
- Fixed FastAPI app initialization and CORS middleware setup
- Improved error handling and logging throughout the application

### Added
- Implemented colorized logging with ColoredFormatter for better log visibility
- Enhanced logging with color-coded levels: DEBUG (cyan), INFO (green), WARNING (yellow), ERROR (red), CRITICAL (red+bold)
- Added refresh command to update system for redownloading and verifying current version
- All CLI commands (gui, webui, api, test, clean, version, deps, system, wizard) now work properly

### Changed
- Improved logging system with better color coding and formatting
- Enhanced update system with file integrity checking
- Better error messages and user feedback

## [a.1.1-30] - Previous Release

### Fixed
- Removed duplicate y_testing/y_testing directory and resolved import shadowing
- Ensured only one codebase is present for clean startup

## [a.1.1-29] - Previous Release

### Fixed
- Rewritten features and interfaces modules to resolve hidden syntax errors
- Ensured clean startup for all components

## [a.1.1-28] - Previous Release

### Changed
- Moved file analysis/antivirus to advanced_antivirus plugin
- Updated imports and fixed enums
- Added advanced_antivirus to default plugins

## [a.1.1-27] - Previous Release

### Changed
- Migrated all core tests to test_plugin
- Added default plugin installation
- Exposed CPU command via plugin manager
- Removed references to old src/plexichat/tests directory

## [a.1.1-26] - Previous Release

### Fixed
- Fixed unmatched parenthesis in ConfigurationManager.get method in config.py
- Ensured all bootstraps and interactive setup work

## [a.1.1-25] - Previous Release

### Fixed
- Confirmed and fixed ALLOWED_FILE_TYPES IndentationError in config.py
- Ensured all bootstraps and interactive setup work
