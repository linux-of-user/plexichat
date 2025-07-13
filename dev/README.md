# PlexiChat Dev Tools

This directory contains all development tools, scripts, and utilities needed for coding, testing, and maintaining PlexiChat.

## Contents
- **format.sh / format.ps1**: Code formatting scripts (Black, isort, etc.)
- **lint.sh / lint.ps1**: Linting scripts (ruff, flake8, mypy, etc.)
- **test.sh / test.ps1**: Test runner scripts
- **fix_imports.py**: Script to auto-fix import errors
- **find_dead_code.py**: Script to find and optionally remove dead code
- **plugin_dev_tools/**: Tools for developing and testing plugins
- **requirements-dev.txt**: Dev dependencies (see below)

## Usage
- Run `format.sh` or `format.ps1` to auto-format code.
- Run `lint.sh` or `lint.ps1` to lint the codebase.
- Run `test.sh` or `test.ps1` to run all tests.
- Use the plugin tools to scaffold, test, and publish plugins.

## Dev Dependencies
See `requirements-dev.txt` for all dev dependencies (install with `pip install -r requirements-dev.txt`).

## Adding New Tools
Add any new scripts/utilities for development here and update this README. 