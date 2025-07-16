"""
PlexiChat Constants

Application-wide constants and configuration values.
"""

import os
from enum import Enum
from typing import Dict, List, Any

# Application Information
APP_NAME = "PlexiChat"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "Advanced Chat Application with AI Integration"
APP_AUTHOR = "PlexiChat Team"
APP_LICENSE = "MIT"
APP_URL = "https://github.com/plexichat/plexichat"

# Environment
DEFAULT_ENVIRONMENT = "development"
PRODUCTION_ENVIRONMENT = "production"
TESTING_ENVIRONMENT = "testing"
DEVELOPMENT_ENVIRONMENT = "development"

# Database Constants
DEFAULT_DATABASE_URL = "sqlite:///plexichat.db"
DEFAULT_DATABASE_POOL_SIZE = 10
DEFAULT_DATABASE_TIMEOUT = 30
MAX_DATABASE_CONNECTIONS = 100
DATABASE_RETRY_ATTEMPTS = 3
DATABASE_RETRY_DELAY = 1.0

# Server Constants
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8000
DEFAULT_WORKERS = 4
MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10MB
DEFAULT_TIMEOUT = 30
MAX_CONNECTIONS = 1000

# Security Constants
DEFAULT_SECRET_KEY = "your-secret-key-change-this"
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # 5 minutes
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW = 3600  # 1 hour

# File Upload Constants
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
ALLOWED_FILE_EXTENSIONS = [
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp',  # Images
    '.pdf', '.doc', '.docx', '.txt', '.rtf',  # Documents
    '.mp3', '.wav', '.ogg', '.m4a',  # Audio
    '.mp4', '.avi', '.mov', '.wmv', '.flv',  # Video
    '.zip', '.rar', '.7z', '.tar', '.gz'  # Archives
]
UPLOAD_DIRECTORY = "uploads"
TEMP_DIRECTORY = "temp"

# Message Constants
MAX_MESSAGE_LENGTH = 4000
MAX_MESSAGES_PER_REQUEST = 100
MESSAGE_HISTORY_LIMIT = 1000
TYPING_TIMEOUT = 5  # seconds

# User Constants
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 30
USERNAME_PATTERN = r'^[a-zA-Z0-9_]+$'
EMAIL_MAX_LENGTH = 254
DISPLAY_NAME_MAX_LENGTH = 100

# Room Constants
ROOM_NAME_MIN_LENGTH = 3
ROOM_NAME_MAX_LENGTH = 50
ROOM_DESCRIPTION_MAX_LENGTH = 500
MAX_ROOM_MEMBERS = 1000
MAX_ROOMS_PER_USER = 100

# Cache Constants
DEFAULT_CACHE_TTL = 3600  # 1 hour
CACHE_MAX_SIZE = 10000
CACHE_CLEANUP_INTERVAL = 300  # 5 minutes
SESSION_CACHE_TTL = 1800  # 30 minutes
USER_CACHE_TTL = 900  # 15 minutes

# Threading Constants
DEFAULT_THREAD_POOL_SIZE = 10
MAX_THREAD_POOL_SIZE = 50
THREAD_TIMEOUT = 30
QUEUE_MAX_SIZE = 1000

# WebSocket Constants
WEBSOCKET_PING_INTERVAL = 30
WEBSOCKET_PING_TIMEOUT = 10
WEBSOCKET_MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB
WEBSOCKET_COMPRESSION = True

# Logging Constants
DEFAULT_LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_LOG_FILE_SIZE = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5

# Performance Constants
PERFORMANCE_MONITORING_INTERVAL = 60  # seconds
METRICS_RETENTION_DAYS = 30
SLOW_QUERY_THRESHOLD = 1.0  # seconds
HIGH_CPU_THRESHOLD = 80.0  # percent
HIGH_MEMORY_THRESHOLD = 85.0  # percent

# AI Integration Constants
AI_REQUEST_TIMEOUT = 30
AI_MAX_TOKENS = 4000
AI_TEMPERATURE = 0.7
AI_MAX_RETRIES = 3
AI_RETRY_DELAY = 1.0

# Backup Constants
BACKUP_RETENTION_DAYS = 30
BACKUP_COMPRESSION = True
AUTO_BACKUP_INTERVAL = 86400  # 24 hours
BACKUP_DIRECTORY = "backups"

# Plugin Constants
PLUGINS_DIRECTORY = "plugins"
PLUGIN_TIMEOUT = 30
MAX_PLUGINS = 50

# Status Codes
class StatusCode(Enum):
    """HTTP status codes."""
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NO_CONTENT = 204
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    CONFLICT = 409
    UNPROCESSABLE_ENTITY = 422
    TOO_MANY_REQUESTS = 429
    INTERNAL_SERVER_ERROR = 500
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503

# Message Types
class MessageType(Enum):
    """Message types."""
    TEXT = "text"
    IMAGE = "image"
    FILE = "file"
    AUDIO = "audio"
    VIDEO = "video"
    SYSTEM = "system"
    COMMAND = "command"

# User Roles
class UserRole(Enum):
    """User roles."""
    ADMIN = "admin"
    MODERATOR = "moderator"
    USER = "user"
    GUEST = "guest"

# Room Types
class RoomType(Enum):
    """Room types."""
    PUBLIC = "public"
    PRIVATE = "private"
    DIRECT = "direct"
    GROUP = "group"

# Event Types
class EventType(Enum):
    """Event types."""
    USER_JOIN = "user_join"
    USER_LEAVE = "user_leave"
    MESSAGE_SENT = "message_sent"
    MESSAGE_EDITED = "message_edited"
    MESSAGE_DELETED = "message_deleted"
    ROOM_CREATED = "room_created"
    ROOM_UPDATED = "room_updated"
    ROOM_DELETED = "room_deleted"
    USER_TYPING = "user_typing"
    USER_ONLINE = "user_online"
    USER_OFFLINE = "user_offline"

# Priority Levels
class Priority(Enum):
    """Priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"

# Error Codes
class ErrorCode(Enum):
    """Application error codes."""
    VALIDATION_ERROR = "validation_error"
    AUTHENTICATION_ERROR = "authentication_error"
    AUTHORIZATION_ERROR = "authorization_error"
    NOT_FOUND_ERROR = "not_found_error"
    DUPLICATE_ERROR = "duplicate_error"
    RATE_LIMIT_ERROR = "rate_limit_error"
    INTERNAL_ERROR = "internal_error"
    EXTERNAL_SERVICE_ERROR = "external_service_error"

# Default Configuration
DEFAULT_CONFIG = {
    "app": {
        "name": APP_NAME,
        "version": APP_VERSION,
        "environment": DEFAULT_ENVIRONMENT,
        "debug": False
    },
    "server": {
        "host": DEFAULT_HOST,
        "port": DEFAULT_PORT,
        "workers": DEFAULT_WORKERS,
        "timeout": DEFAULT_TIMEOUT
    },
    "database": {
        "url": DEFAULT_DATABASE_URL,
        "pool_size": DEFAULT_DATABASE_POOL_SIZE,
        "timeout": DEFAULT_DATABASE_TIMEOUT
    },
    "security": {
        "secret_key": DEFAULT_SECRET_KEY,
        "jwt_expiry_hours": JWT_EXPIRY_HOURS,
        "password_min_length": PASSWORD_MIN_LENGTH,
        "max_login_attempts": MAX_LOGIN_ATTEMPTS
    },
    "cache": {
        "enabled": True,
        "max_size": CACHE_MAX_SIZE,
        "default_ttl": DEFAULT_CACHE_TTL
    },
    "logging": {
        "level": DEFAULT_LOG_LEVEL,
        "format": LOG_FORMAT,
        "file_path": None
    },
    "threading": {
        "max_workers": DEFAULT_THREAD_POOL_SIZE,
        "timeout": THREAD_TIMEOUT
    },
    "websocket": {
        "ping_interval": WEBSOCKET_PING_INTERVAL,
        "ping_timeout": WEBSOCKET_PING_TIMEOUT,
        "compression": WEBSOCKET_COMPRESSION
    }
}

# API Endpoints
API_PREFIX = "/api/v1"
API_ENDPOINTS = {
    "auth": {
        "login": f"{API_PREFIX}/auth/login",
        "logout": f"{API_PREFIX}/auth/logout",
        "register": f"{API_PREFIX}/auth/register",
        "refresh": f"{API_PREFIX}/auth/refresh"
    },
    "users": {
        "list": f"{API_PREFIX}/users",
        "get": f"{API_PREFIX}/users/{{user_id}}",
        "update": f"{API_PREFIX}/users/{{user_id}}",
        "delete": f"{API_PREFIX}/users/{{user_id}}"
    },
    "rooms": {
        "list": f"{API_PREFIX}/rooms",
        "create": f"{API_PREFIX}/rooms",
        "get": f"{API_PREFIX}/rooms/{{room_id}}",
        "update": f"{API_PREFIX}/rooms/{{room_id}}",
        "delete": f"{API_PREFIX}/rooms/{{room_id}}",
        "join": f"{API_PREFIX}/rooms/{{room_id}}/join",
        "leave": f"{API_PREFIX}/rooms/{{room_id}}/leave"
    },
    "messages": {
        "list": f"{API_PREFIX}/rooms/{{room_id}}/messages",
        "send": f"{API_PREFIX}/rooms/{{room_id}}/messages",
        "get": f"{API_PREFIX}/messages/{{message_id}}",
        "update": f"{API_PREFIX}/messages/{{message_id}}",
        "delete": f"{API_PREFIX}/messages/{{message_id}}"
    },
    "files": {
        "upload": f"{API_PREFIX}/files/upload",
        "download": f"{API_PREFIX}/files/{{file_id}}",
        "delete": f"{API_PREFIX}/files/{{file_id}}"
    }
}

# WebSocket Events
WEBSOCKET_EVENTS = {
    "connection": "connection",
    "disconnect": "disconnect",
    "join_room": "join_room",
    "leave_room": "leave_room",
    "send_message": "send_message",
    "typing_start": "typing_start",
    "typing_stop": "typing_stop",
    "user_status": "user_status"
}

# Regex Patterns
PATTERNS = {
    "username": USERNAME_PATTERN,
    "email": r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    "url": r'https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?',
    "mention": r'@([a-zA-Z0-9_]+)',
    "hashtag": r'#([a-zA-Z0-9_]+)',
    "uuid": r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
}

# MIME Types
MIME_TYPES = {
    # Images
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.bmp': 'image/bmp',
    '.webp': 'image/webp',
    
    # Documents
    '.pdf': 'application/pdf',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.txt': 'text/plain',
    '.rtf': 'application/rtf',
    
    # Audio
    '.mp3': 'audio/mpeg',
    '.wav': 'audio/wav',
    '.ogg': 'audio/ogg',
    '.m4a': 'audio/mp4',
    
    # Video
    '.mp4': 'video/mp4',
    '.avi': 'video/x-msvideo',
    '.mov': 'video/quicktime',
    '.wmv': 'video/x-ms-wmv',
    '.flv': 'video/x-flv',
    
    # Archives
    '.zip': 'application/zip',
    '.rar': 'application/x-rar-compressed',
    '.7z': 'application/x-7z-compressed',
    '.tar': 'application/x-tar',
    '.gz': 'application/gzip'
}

# Environment Variables
ENV_VARS = {
    "DATABASE_URL": "DATABASE_URL",
    "SECRET_KEY": "SECRET_KEY",
    "ENVIRONMENT": "ENVIRONMENT",
    "DEBUG": "DEBUG",
    "HOST": "HOST",
    "PORT": "PORT",
    "WORKERS": "WORKERS",
    "LOG_LEVEL": "LOG_LEVEL",
    "REDIS_URL": "REDIS_URL",
    "AI_API_KEY": "AI_API_KEY",
    "UPLOAD_PATH": "UPLOAD_PATH"
}

# Feature Flags
FEATURES = {
    "ai_integration": True,
    "file_uploads": True,
    "voice_messages": True,
    "video_calls": False,
    "screen_sharing": False,
    "plugins": True,
    "analytics": True,
    "monitoring": True,
    "backup": True,
    "rate_limiting": True,
    "caching": True,
    "compression": True,
    "encryption": True
}

# System Limits
LIMITS = {
    "max_users": 10000,
    "max_rooms": 1000,
    "max_messages_per_room": 100000,
    "max_file_size": MAX_FILE_SIZE,
    "max_message_length": MAX_MESSAGE_LENGTH,
    "max_room_members": MAX_ROOM_MEMBERS,
    "max_concurrent_connections": MAX_CONNECTIONS
}

# Default Permissions
DEFAULT_PERMISSIONS = {
    UserRole.ADMIN.value: [
        "create_room", "delete_room", "manage_users", "manage_settings",
        "send_message", "edit_message", "delete_message", "upload_file",
        "view_analytics", "manage_plugins", "backup_data"
    ],
    UserRole.MODERATOR.value: [
        "create_room", "manage_room", "send_message", "edit_message",
        "delete_message", "upload_file", "moderate_content"
    ],
    UserRole.USER.value: [
        "send_message", "edit_own_message", "delete_own_message",
        "upload_file", "create_private_room"
    ],
    UserRole.GUEST.value: [
        "send_message", "view_public_rooms"
    ]
}

# System Messages
SYSTEM_MESSAGES = {
    "user_joined": "{user} joined the room",
    "user_left": "{user} left the room",
    "room_created": "Room '{room}' was created",
    "room_deleted": "Room '{room}' was deleted",
    "user_promoted": "{user} was promoted to {role}",
    "user_demoted": "{user} was demoted to {role}",
    "message_deleted": "A message was deleted",
    "file_uploaded": "{user} uploaded a file: {filename}"
}

# Time Formats
TIME_FORMATS = {
    "iso": "%Y-%m-%dT%H:%M:%S.%fZ",
    "display": "%Y-%m-%d %H:%M:%S",
    "date_only": "%Y-%m-%d",
    "time_only": "%H:%M:%S",
    "filename": "%Y%m%d_%H%M%S"
}

# Utility Functions
def get_env_var(key: str, default: Any = None) -> Any:
    """Get environment variable with default."""
    return os.getenv(key, default)

def is_production() -> bool:
    """Check if running in production."""
    return get_env_var(ENV_VARS["ENVIRONMENT"], DEFAULT_ENVIRONMENT) == PRODUCTION_ENVIRONMENT

def is_development() -> bool:
    """Check if running in development."""
    return get_env_var(ENV_VARS["ENVIRONMENT"], DEFAULT_ENVIRONMENT) == DEVELOPMENT_ENVIRONMENT

def is_testing() -> bool:
    """Check if running in testing."""
    return get_env_var(ENV_VARS["ENVIRONMENT"], DEFAULT_ENVIRONMENT) == TESTING_ENVIRONMENT

def get_feature_flag(feature: str) -> bool:
    """Get feature flag value."""
    return FEATURES.get(feature, False)

def get_limit(limit_name: str) -> int:
    """Get system limit value."""
    return LIMITS.get(limit_name, 0)

def get_permission(role: str, permission: str) -> bool:
    """Check if role has permission."""
    role_permissions = DEFAULT_PERMISSIONS.get(role, [])
    return permission in role_permissions
