"""
PlexiChat Shared Constants

This module contains TRUE constants that should NOT be configurable,
such as plugin system constants, status enums, and fixed system values.
All configurable values should be loaded from config files.

Version information is loaded from version.json, not stored as constants.
"""

import json
from pathlib import Path

def get_version() -> str:
    """Get current version from version.json file."""
    try:
        # Look for version.json in the project root
        current_file = Path(__file__)
        version_file = current_file.parent.parent.parent.parent / "version.json"

        if version_file.exists():
            with open(version_file, 'r', encoding='utf-8') as f:
                version_data = json.load(f)
                return version_data.get('version', 'b.1.1-88')
        else:
            # Fallback version
            return 'b.1.1-88'
    except Exception:
        return 'b.1.1-88'

# For backward compatibility, provide PLEXICHAT_VERSION
PLEXICHAT_VERSION = get_version()

# Plugin Discovery Constants (these are fixed file names, not configurable)
PLUGIN_MANIFEST_FILES = [
    "plugin.json",
    "plugin.yaml", 
    "plugin.yml",
    "manifest.json"
]

PLUGIN_MAIN_FILES = [
    "main.py",
    "__init__.py"
]

# Plugin Status Constants (these are enum values, not configurable)
PLUGIN_STATUS_DISCOVERED = "discovered"
PLUGIN_STATUS_LOADING = "loading"
PLUGIN_STATUS_LOADED = "loaded"
PLUGIN_STATUS_ENABLED = "enabled"
PLUGIN_STATUS_DISABLED = "disabled"
PLUGIN_STATUS_FAILED = "failed"
PLUGIN_STATUS_UNLOADED = "unloaded"

# Plugin Security Levels (enum values)
SECURITY_LEVEL_TRUSTED = "trusted"
SECURITY_LEVEL_SANDBOXED = "sandboxed"
SECURITY_LEVEL_RESTRICTED = "restricted"

# Plugin Types (enum values)
PLUGIN_TYPE_CORE = "core"
PLUGIN_TYPE_FEATURE = "feature"
PLUGIN_TYPE_UTILITY = "utility"
PLUGIN_TYPE_INTEGRATION = "integration"
PLUGIN_TYPE_THEME = "theme"

# Fixed API Constants (these are protocol constants)
API_VERSION = "v1"

# Fixed File Extensions (security-related, should not be configurable)
ALLOWED_FILE_EXTENSIONS = [
    '.txt', '.json', '.yaml', '.yml', '.py', '.js', '.html', '.css',
    '.md', '.rst', '.log', '.csv', '.xml', '.ini', '.conf'
]

# Fixed Logging Format (standard format, not configurable)
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Fixed CLI Constants
CLI_PROMPT = "plexichat> "

# Fixed Error Messages (these are constants, not config)
ERROR_PLUGIN_NOT_FOUND = "Plugin not found"
ERROR_PLUGIN_LOAD_FAILED = "Failed to load plugin"
ERROR_PLUGIN_TIMEOUT = "Plugin operation timed out"
ERROR_INVALID_CONFIG = "Invalid configuration"
ERROR_PERMISSION_DENIED = "Permission denied"
ERROR_RESOURCE_NOT_FOUND = "Resource not found"
ERROR_INTERNAL_SERVER = "Internal server error"

# Fixed Success Messages
SUCCESS_PLUGIN_LOADED = "Plugin loaded successfully"
SUCCESS_PLUGIN_UNLOADED = "Plugin unloaded successfully"
SUCCESS_CONFIG_UPDATED = "Configuration updated successfully"
SUCCESS_OPERATION_COMPLETED = "Operation completed successfully"

# User validation constants (these are validation rules, not configurable)
MAX_USERNAME_LENGTH = 50
MIN_USERNAME_LENGTH = 3
MAX_EMAIL_LENGTH = 255
MAX_DISPLAY_NAME_LENGTH = 100
MIN_DISPLAY_NAME_LENGTH = 1

# Backup constants (these are system limits, not configurable)
BACKUP_RETENTION_DAYS = 30
BACKUP_COMPRESSION_ENABLED = True
SHARD_SIZE = 1024 * 1024  # 1MB shard size for backup files
MIN_BACKUP_SHARDS = 3  # Minimum number of backup shards
PARITY_SHARD_RATIO = 0.2  # 20% parity shards for redundancy


