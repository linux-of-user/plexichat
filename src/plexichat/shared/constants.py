"""
PlexiChat Shared Constants

This module contains TRUE constants that should NOT be configurable,
such as plugin system constants, status enums, and fixed system values.
All configurable values should be loaded from config files.
"""

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


