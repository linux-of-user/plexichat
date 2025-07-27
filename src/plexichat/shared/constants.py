"""
PlexiChat Shared Constants

This module contains shared constants used across the PlexiChat system,
particularly for plugin management and system configuration.
"""

# Plugin System Constants
PLUGIN_TIMEOUT = 30.0  # seconds
MAX_PLUGIN_MEMORY = 128 * 1024 * 1024  # 128MB in bytes
PLUGIN_SANDBOX_ENABLED = True

# Plugin Discovery Constants
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

# Plugin Status Constants
PLUGIN_STATUS_DISCOVERED = "discovered"
PLUGIN_STATUS_LOADING = "loading"
PLUGIN_STATUS_LOADED = "loaded"
PLUGIN_STATUS_ENABLED = "enabled"
PLUGIN_STATUS_DISABLED = "disabled"
PLUGIN_STATUS_FAILED = "failed"
PLUGIN_STATUS_UNLOADED = "unloaded"

# Plugin Security Levels
SECURITY_LEVEL_TRUSTED = "trusted"
SECURITY_LEVEL_SANDBOXED = "sandboxed"
SECURITY_LEVEL_RESTRICTED = "restricted"

# Plugin Types
PLUGIN_TYPE_CORE = "core"
PLUGIN_TYPE_FEATURE = "feature"
PLUGIN_TYPE_UTILITY = "utility"
PLUGIN_TYPE_INTEGRATION = "integration"
PLUGIN_TYPE_THEME = "theme"

# System Constants
DEFAULT_PLUGINS_DIR = "plugins"
DEFAULT_CONFIG_DIR = "config"
DEFAULT_DATA_DIR = "data"
DEFAULT_LOGS_DIR = "logs"

# API Constants
DEFAULT_API_HOST = "localhost"
DEFAULT_API_PORT = 8000
API_VERSION = "v1"

# Database Constants
DEFAULT_DATABASE_URL = "sqlite:///plexichat.db"
DATABASE_POOL_SIZE = 10
DATABASE_MAX_OVERFLOW = 20

# Cache Constants
DEFAULT_CACHE_TTL = 3600  # 1 hour in seconds
MAX_CACHE_SIZE = 1000

# Performance Constants
MAX_CONCURRENT_REQUESTS = 100
REQUEST_TIMEOUT = 30.0
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10MB

# Logging Constants
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
DEFAULT_LOG_LEVEL = "INFO"

# Testing Constants
TEST_TIMEOUT = 60.0  # seconds
MAX_TEST_RETRIES = 3
TEST_DATA_DIR = "test_data"

# User Constants
MAX_USERNAME_LENGTH = 50
MIN_USERNAME_LENGTH = 3
MAX_EMAIL_LENGTH = 255
MAX_DISPLAY_NAME_LENGTH = 100
MIN_DISPLAY_NAME_LENGTH = 1

# Backup Constants (additional)
BACKUP_RETENTION_DAYS = 30
BACKUP_COMPRESSION_ENABLED = True

# CLI Constants
CLI_PROMPT = "plexichat> "
CLI_HISTORY_SIZE = 1000

# Event System Constants
MAX_EVENT_LISTENERS = 100
EVENT_TIMEOUT = 5.0

# Backup Constants
DEFAULT_BACKUP_DIR = "backups"
MAX_BACKUP_FILES = 10
BACKUP_COMPRESSION = True

# Monitoring Constants
METRICS_COLLECTION_INTERVAL = 60  # seconds
MAX_METRICS_HISTORY = 1000
HEALTH_CHECK_INTERVAL = 30  # seconds

# Security Constants
DEFAULT_SESSION_TIMEOUT = 3600  # 1 hour
MAX_LOGIN_ATTEMPTS = 5
PASSWORD_MIN_LENGTH = 8
TOKEN_EXPIRY = 86400  # 24 hours

# AI System Constants
AI_REQUEST_TIMEOUT = 30  # seconds
MAX_AI_CONTEXT_LENGTH = 4000  # characters
AI_RATE_LIMIT = 10  # requests per minute

# File System Constants
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
ALLOWED_FILE_EXTENSIONS = [
    '.txt', '.json', '.yaml', '.yml', '.py', '.js', '.html', '.css',
    '.md', '.rst', '.log', '.csv', '.xml', '.ini', '.conf'
]

# Network Constants
MAX_CONNECTIONS = 1000
CONNECTION_TIMEOUT = 30.0
KEEP_ALIVE_TIMEOUT = 5.0

# Development Constants
DEBUG_MODE = False
DEVELOPMENT_MODE = False
TESTING_MODE = False

# Version Constants
PLEXICHAT_VERSION = "1.0.0"
API_VERSION_MAJOR = 1
API_VERSION_MINOR = 0
API_VERSION_PATCH = 0

# Feature Flags
ENABLE_PLUGIN_SYSTEM = True
ENABLE_API_DOCS = True
ENABLE_METRICS = True
ENABLE_CACHING = True
ENABLE_RATE_LIMITING = True
ENABLE_AUTHENTICATION = True
ENABLE_AUTHORIZATION = True
ENABLE_LOGGING = True
ENABLE_MONITORING = True
ENABLE_BACKUP = True

# Error Messages
ERROR_PLUGIN_NOT_FOUND = "Plugin not found"
ERROR_PLUGIN_LOAD_FAILED = "Failed to load plugin"
ERROR_PLUGIN_TIMEOUT = "Plugin operation timed out"
ERROR_INVALID_CONFIG = "Invalid configuration"
ERROR_PERMISSION_DENIED = "Permission denied"
ERROR_RESOURCE_NOT_FOUND = "Resource not found"
ERROR_INTERNAL_SERVER = "Internal server error"

# Success Messages
SUCCESS_PLUGIN_LOADED = "Plugin loaded successfully"
SUCCESS_PLUGIN_UNLOADED = "Plugin unloaded successfully"
SUCCESS_CONFIG_UPDATED = "Configuration updated successfully"
SUCCESS_OPERATION_COMPLETED = "Operation completed successfully"

# Default Configuration Values
DEFAULT_CONFIG = {
    "plugins": {
        "enabled": True,
        "auto_discover": True,
        "auto_load": True,
        "sandbox_enabled": PLUGIN_SANDBOX_ENABLED,
        "timeout": PLUGIN_TIMEOUT,
        "max_memory": MAX_PLUGIN_MEMORY,
        "plugins_dir": DEFAULT_PLUGINS_DIR
    },
    "api": {
        "host": DEFAULT_API_HOST,
        "port": DEFAULT_API_PORT,
        "version": API_VERSION,
        "timeout": REQUEST_TIMEOUT,
        "max_upload_size": MAX_UPLOAD_SIZE
    },
    "database": {
        "url": DEFAULT_DATABASE_URL,
        "pool_size": DATABASE_POOL_SIZE,
        "max_overflow": DATABASE_MAX_OVERFLOW
    },
    "logging": {
        "level": DEFAULT_LOG_LEVEL,
        "format": LOG_FORMAT,
        "date_format": LOG_DATE_FORMAT
    },
    "security": {
        "session_timeout": DEFAULT_SESSION_TIMEOUT,
        "max_login_attempts": MAX_LOGIN_ATTEMPTS,
        "password_min_length": PASSWORD_MIN_LENGTH,
        "token_expiry": TOKEN_EXPIRY
    },
    "performance": {
        "max_concurrent_requests": MAX_CONCURRENT_REQUESTS,
        "cache_ttl": DEFAULT_CACHE_TTL,
        "max_cache_size": MAX_CACHE_SIZE
    }
}
