# PlexiChat Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [a.1.1-34] - 2025-07-20

### Added
- **Splitscreen CLI**: Implemented functional splitscreen CLI with rich terminal interface
- **Unified Interface System**: Both GUI and WebUI now use the same CLI system (run_api_and_cli)
- **Real-time Monitoring**: Enhanced CLI with real-time logs, system metrics, operations tracking
- **Interface Options**: Multiple interface modes (gui, webui, api, cli) for different use cases
- **Admin Update Guide**: Comprehensive guide for administrators to manage updates and deployments

### Fixed
- Fixed all syntax errors in splitscreen CLI console_manager.py (missing opening parentheses)
- Fixed syntax errors in ai_abstraction_layer_simple.py, security_api.py, certificate_manager.py
- Fixed ConfigManager method calls (load_config instead of reload_configuration)
- Resolved all compilation errors - system now starts successfully
- Fixed GUI startup issues - GUI now runs properly with `python run.py gui`

### Changed
- Updated README.md with current version (a.1.1-34) and new interface commands
- Enhanced Getting Started guide with detailed interface options
- Improved error handling and logging throughout CLI components
- Both GUI and WebUI provide consistent CLI experience with splitscreen interface

### Documentation
- Updated README.md with splitscreen CLI information
- Added comprehensive Admin Update & Push Guide
- Enhanced Getting Started guide with interface options
- Updated version badges and feature highlights

## [a.1.1-33] - 2025-07-20

### Added
- Enhanced update system to use existing CLI from interfaces/cli instead of standalone system
- Added bootstrap mode detection for standalone operation when src directory unavailable
- Integrated unified plugin manager to auto-discover and load plugin commands
- Added plugin command execution directly from update system menu
- Enhanced update system menu to show available plugin commands dynamically

### Fixed
- Added fallback functionality when full CLI system is not available
- Improved error handling and user feedback for plugin command execution
- Update system now properly uses existing UpdateCLI from interfaces/cli/commands/updates

## [a.1.1-32] - 2025-07-20

### Added
- Added refresh command to update system for redownloading and verifying current version files
- Created version.json with comprehensive version information and feature tracking
- Added CHANGELOG.md for proper version history documentation
- Implemented file integrity checking with backup creation before refresh
- Enhanced update system with GitHub download capability and ZIP extraction

### Fixed
- Fixed syntax errors in versioning/__init__.py with proper import fallbacks
- Improved error handling and user feedback in refresh process
- All critical files are backed up before refresh operations

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
