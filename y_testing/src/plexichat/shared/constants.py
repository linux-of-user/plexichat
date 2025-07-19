# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Shared Constants

Application-wide constants used across all modules.
"""

import os
import secrets
from pathlib import Path

# Application Information
APP_NAME = "PlexiChat"
APP_VERSION = "3.0.0"
APP_DESCRIPTION = "Advanced Chat Platform with AI Integration"
APP_AUTHOR = "PlexiChat Team"

# Directory Paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
SRC_DIR = PROJECT_ROOT / "src"
DATA_DIR = PROJECT_ROOT / "data"
CONFIG_DIR = PROJECT_ROOT / "config"
LOGS_DIR = PROJECT_ROOT / "logs"
UPLOADS_DIR = PROJECT_ROOT / "uploads"
BACKUPS_DIR = PROJECT_ROOT / "backups"
CACHE_DIR = PROJECT_ROOT / "cache"
TEMP_DIR = PROJECT_ROOT / "temp"

# Configuration Files
DEFAULT_CONFIG_FILE = "plexichat.yaml"
ENV_CONFIG_FILE = ".env"
SECRETS_FILE = "secrets.yaml"

# Database Constants
DEFAULT_DATABASE_URL = "sqlite:///plexichat.db"
DATABASE_POOL_SIZE = 20
DATABASE_MAX_OVERFLOW = 30
DATABASE_TIMEOUT = 30

# Security Constants
DEFAULT_SECRET_KEY = "plexichat-default-secret-key-change-in-production"
TOKEN_EXPIRY_HOURS = 24
REFRESH_TOKEN_EXPIRY_DAYS = 30
PASSWORD_MIN_LENGTH = 8
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

# API Constants
API_VERSION = "v1"
API_PREFIX = f"/api/{API_VERSION}"
MAX_REQUEST_SIZE = 100 * 1024 * 1024  # 100MB
DEFAULT_PAGE_SIZE = 50

# Server Configuration
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8000
DEFAULT_WORKERS = 4
MAX_STARTUP_TIME = 60

# Process Management
PROCESS_LOCK_FILE = "plexichat.lock"
HEALTH_CHECK_INTERVAL = 30
SHUTDOWN_TIMEOUT = 30

# Logging Configuration
LOGS_DIR = "logs"
LOG_RETENTION_DAYS = 30
LOG_MAX_SIZE = "10MB"
LOG_BACKUP_COUNT = 5
MAX_PAGE_SIZE = 1000
RATE_LIMIT_REQUESTS = 1000
RATE_LIMIT_WINDOW = 3600  # 1 hour

# WebSocket Constants
WS_HEARTBEAT_INTERVAL = 30
WS_MAX_CONNECTIONS = 10000
WS_MESSAGE_MAX_SIZE = 1024 * 1024  # 1MB

# File Upload Constants
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
ALLOWED_FILE_TYPES = {
    'images': {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg'},
    'documents': {'.pdf', '.doc', '.docx', '.txt', '.md', '.rtf'},
    'archives': {'.zip', '.tar', '.gz', '.rar', '.7z'},
    'audio': {'.mp3', '.wav', '.ogg', '.m4a', '.flac'},
    'video': {'.mp4', '.avi', '.mkv', '.mov', '.wmv', '.webm'}
}

# Logging Constants
DEFAULT_LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_LOG_FILE_SIZE = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5

# Cache Constants
DEFAULT_CACHE_TTL = 3600  # 1 hour
CACHE_KEY_PREFIX = "plexichat:"
MAX_CACHE_SIZE = 1000

# Plugin Constants
PLUGIN_TIMEOUT = 30
MAX_PLUGIN_MEMORY = 100 * 1024 * 1024  # 100MB
PLUGIN_SANDBOX_ENABLED = True

# Monitoring Constants
METRICS_COLLECTION_INTERVAL = 60  # seconds
HEALTH_CHECK_INTERVAL = 30  # seconds
ALERT_COOLDOWN_PERIOD = 300  # 5 minutes

# Backup Constants
BACKUP_RETENTION_DAYS = 30
BACKUP_COMPRESSION_ENABLED = True
BACKUP_ENCRYPTION_ENABLED = True
SHARD_SIZE = 64 * 1024 * 1024  # 64MB
MIN_BACKUP_SHARDS = 3
PARITY_SHARD_RATIO = 0.3

# Performance Constants
CACHE_TTL_SECONDS = 30
SLOW_QUERY_THRESHOLD = 1.0  # seconds
HIGH_CPU_THRESHOLD = 80.0  # percent
HIGH_MEMORY_THRESHOLD = 85.0  # percent
HIGH_DISK_THRESHOLD = 90.0  # percent

# Message Constants
MAX_MESSAGE_LENGTH = 4000
MAX_ATTACHMENT_COUNT = 10
MESSAGE_HISTORY_LIMIT = 1000

# Channel Constants
MAX_CHANNEL_NAME_LENGTH = 100
MAX_CHANNEL_DESCRIPTION_LENGTH = 500
MAX_CHANNEL_MEMBERS = 10000

# User Constants
MAX_USERNAME_LENGTH = 50
MAX_DISPLAY_NAME_LENGTH = 100
MAX_EMAIL_LENGTH = 255

# AI Constants
AI_REQUEST_TIMEOUT = 60
MAX_AI_CONTEXT_LENGTH = 8000
AI_RATE_LIMIT = 100  # requests per hour

# Clustering Constants
CLUSTER_HEARTBEAT_INTERVAL = 10
CLUSTER_ELECTION_TIMEOUT = 5
MAX_CLUSTER_NODES = 100

# Error Codes
ERROR_CODES = {
    # Authentication errors
    'AUTH_INVALID_CREDENTIALS': 'AUTH001',
    'AUTH_TOKEN_EXPIRED': 'AUTH002',
    'AUTH_INSUFFICIENT_PERMISSIONS': 'AUTH003',
    'AUTH_ACCOUNT_LOCKED': 'AUTH004',

    # Validation errors
    'VALIDATION_REQUIRED_FIELD': 'VAL001',
    'VALIDATION_INVALID_FORMAT': 'VAL002',
    'VALIDATION_VALUE_TOO_LONG': 'VAL003',
    'VALIDATION_VALUE_TOO_SHORT': 'VAL004',

    # Resource errors
    'RESOURCE_NOT_FOUND': 'RES001',
    'RESOURCE_ALREADY_EXISTS': 'RES002',
    'RESOURCE_ACCESS_DENIED': 'RES003',
    'RESOURCE_QUOTA_EXCEEDED': 'RES004',

    # System errors
    'SYSTEM_DATABASE_ERROR': 'SYS001',
    'SYSTEM_NETWORK_ERROR': 'SYS002',
    'SYSTEM_TIMEOUT': 'SYS003',
    'SYSTEM_MAINTENANCE': 'SYS004',

    # Plugin errors
    'PLUGIN_NOT_FOUND': 'PLG001',
    'PLUGIN_LOAD_FAILED': 'PLG002',
    'PLUGIN_EXECUTION_ERROR': 'PLG003',
    'PLUGIN_PERMISSION_DENIED': 'PLG004',
}

# HTTP Status Codes
HTTP_STATUS = {
    'OK': 200,
    'CREATED': 201,
    'ACCEPTED': 202,
    'NO_CONTENT': 204,
    'BAD_REQUEST': 400,
    'UNAUTHORIZED': 401,
    'FORBIDDEN': 403,
    'NOT_FOUND': 404,
    'METHOD_NOT_ALLOWED': 405,
    'CONFLICT': 409,
    'UNPROCESSABLE_ENTITY': 422,
    'TOO_MANY_REQUESTS': 429,
    'INTERNAL_SERVER_ERROR': 500,
    'BAD_GATEWAY': 502,
    'SERVICE_UNAVAILABLE': 503,
    'GATEWAY_TIMEOUT': 504,
}

# Environment Variables
ENV_VARS = {
    'DEBUG': 'PLEXICHAT_DEBUG',
    'SECRET_KEY': 'PLEXICHAT_SECRET_KEY',
    'DATABASE_URL': 'PLEXICHAT_DATABASE_URL',
    'REDIS_URL': 'PLEXICHAT_REDIS_URL',
    'LOG_LEVEL': 'PLEXICHAT_LOG_LEVEL',
    'API_HOST': 'PLEXICHAT_API_HOST',
    'API_PORT': 'PLEXICHAT_API_PORT',
    'WEB_HOST': 'PLEXICHAT_WEB_HOST',
    'WEB_PORT': 'PLEXICHAT_WEB_PORT',
}

# Default Configuration
DEFAULT_CONFIG = {
    'debug': False,
    'secret_key': DEFAULT_SECRET_KEY,
    'database_url': DEFAULT_DATABASE_URL,
    'api': {
        'host': '0.0.0.0',
        'port': 8000,
        'workers': 4,
        'timeout': 30,
    },
    'web': {
        'host': '0.0.0.0',
        'port': 3000,
        'static_files': True,
    },
    'logging': {
        'level': DEFAULT_LOG_LEVEL,
        'format': LOG_FORMAT,
        'file_size': MAX_LOG_FILE_SIZE,
        'backup_count': LOG_BACKUP_COUNT,
    },
    'security': {
        'token_expiry_hours': TOKEN_EXPIRY_HOURS,
        'password_min_length': PASSWORD_MIN_LENGTH,
        'max_login_attempts': MAX_LOGIN_ATTEMPTS,
    },
    'features': {
        'ai_enabled': True,
        'plugins_enabled': True,
        'clustering_enabled': False,
        'backup_enabled': True,
        'monitoring_enabled': True,
    },
}

# Export all constants
__all__ = [
    # App info
    'APP_NAME',
    'APP_VERSION',
    'APP_DESCRIPTION',
    'APP_AUTHOR',

    # Paths
    'PROJECT_ROOT',
    'SRC_DIR',
    'DATA_DIR',
    'CONFIG_DIR',
    'LOGS_DIR',
    'UPLOADS_DIR',
    'BACKUPS_DIR',
    'CACHE_DIR',
    'TEMP_DIR',

    # Config files
    'DEFAULT_CONFIG_FILE',
    'ENV_CONFIG_FILE',
    'SECRETS_FILE',

    # Limits and thresholds
    'MAX_FILE_SIZE',
    '4096',
    'MAX_USERNAME_LENGTH',
    '30',
    'RATE_LIMIT_REQUESTS',

    # Collections
    '[".txt", ".pdf", ".doc", ".docx", ".jpg", ".png", ".gif"]',
    'ERROR_CODES',
    'HTTP_STATUS',
    'ENV_VARS',
    'DEFAULT_CONFIG',
]
