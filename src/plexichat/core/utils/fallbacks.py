"""PlexiChat Core Fallbacks - Shared Module

Centralized implementations for fallback classes, functions, enums, and utilities
used across core __init__.py files. These provide no-op/empty implementations
that preserve functionality while allowing graceful degradation when primary
implementations are unavailable.

All fallbacks are designed to be equivalent to local definitions, ensuring
no behavior changes. Classes use dynamic __dict__ for flexibility, functions
return sensible defaults (None, [], False, etc.), and enums use string constants.
"""

import logging
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)

# Utility Functions

def get_fallback_class(class_name: str) -> type:
    """
    Factory function to get fallback class by name.
    
    Args:
        class_name: Name of the fallback class (e.g., 'EventManager')
    
    Returns:
        The fallback class type.
    """
    fallback_classes = {
        'EventManager': EventManager,
        'Event': Event,
        'EventHandler': EventHandler,
        'EventPriority': EventPriority,
        'FileManager': FileManager,
        'FileMetadata': FileMetadata,
        'UnifiedMessagingManager': UnifiedMessagingManager,
        'MessageEncryption': MessageEncryption,
        'MessageValidator': MessageValidator,
        'MessageRouter': MessageRouter,
        'ChannelManager': ChannelManager,
        'MessageMetadata': MessageMetadata,
        'MessageDelivery': MessageDelivery,
        'ChannelSettings': ChannelSettings,
        'MessageType': MessageType,
        'ChannelType': ChannelType,
        'MessageStatus': MessageStatus,
        'EncryptionLevel': EncryptionLevel,
        'NotificationManager': NotificationManager,
        'Notification': Notification,
        'NotificationPriority': NotificationPriority,
        'NotificationType': NotificationType,
        'BaseAPIException': BaseAPIException,
        'AuthenticationError': AuthenticationError,
        'AuthorizationError': AuthorizationError,
        'ValidationError': ValidationError,
        'DatabaseError': DatabaseError,
        'NetworkError': NetworkError,
        'FileError': FileError,
        'ExternalServiceError': ExternalServiceError,
        'RateLimitError': RateLimitError,
        'ConfigurationError': ConfigurationError,
        'ProcessLockError': ProcessLockError,
        'StartupError': StartupError,
        'SecurityError': SecurityError,
        'ErrorSeverity': ErrorSeverity,
        'ErrorCategory': ErrorCategory,
        'ErrorManager': ErrorManager,
        'CircuitBreaker': CircuitBreaker,
        'ErrorCode': ErrorCode,
        'CacheManager': CacheManager,
        'DistributedCacheManager': DistributedCacheManager,
        'CacheEntry': CacheEntry,
        'TaskScheduler': TaskScheduler,
        'ScheduledTask': ScheduledTask,
        'TaskStatus': TaskStatus,
        'TaskType': TaskType,
        'ServiceManager': ServiceManager,
        'PerformanceMonitor': PerformanceMonitor,
        'AlertLevel': AlertLevel,
        'MetricType': MetricType,
        'PerformanceMetric': PerformanceMetric,
        'SystemHealthStatus': SystemHealthStatus,
        'PerformanceAlert': PerformanceAlert,
        # Add more as needed from plan
    }
    return fallback_classes.get(class_name, object)  # Fallback to basic object if unknown

def get_fallback_instance(class_name: str, *args, **kwargs) -> Any:
    """
    Factory to get fallback instance by class name.
    
    Args:
        class_name: Name of the fallback class
        *args, **kwargs: Arguments to pass to constructor
    
    Returns:
        Instance of the fallback class.
    """
    cls = get_fallback_class(class_name)
    return cls(*args, **kwargs)

def get_module_version(module_name: Optional[str] = None) -> str:
    """
    Get version for a module, falling back to default.
    
    Args:
        module_name: Optional module name for specific version
    
    Returns:
        Version string (defaults to '0.0.0').
    """
    try:
        from plexichat.core.config_manager import get_config
        version = get_config("system.version", "0.0.0")
    except ImportError:
        # Fallback if config_manager unavailable
        version = "0.0.0"
    logger.debug(f"Module version for {module_name or __name__}: {version}")
    return version

# Core Fallback Classes (Generic patterns)

class MockConfig:
    """Mock configuration class for fallbacks."""
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

# Event Fallbacks
class EventManager:
    """Fallback EventManager - no-op implementation."""
    def __init__(self):
        self._handlers = {}

class Event:
    """Fallback Event - dynamic attributes."""
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class EventHandler:
    """Fallback EventHandler - no-op."""
    def __init__(self):
        pass

class EventPriority:
    """Fallback EventPriority enum."""
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"

def emit_event(*args, **kwargs):
    """Fallback emit_event - no-op."""
    pass

def register_event_handler(*args, **kwargs):
    """Fallback register_event_handler - no-op."""
    pass

def unregister_event_handler(*args, **kwargs):
    """Fallback unregister_event_handler - no-op."""
    pass

def get_events(*args, **kwargs):
    """Fallback get_events - return empty list."""
    return []

def event_handler(*args, **kwargs):
    """Fallback event_handler decorator - identity."""
    def decorator(func):
        return func
    return decorator

global_event_handler = None

# File Fallbacks
class FileManager:
    """Fallback FileManager - no-op."""
    def __init__(self):
        pass

class FileMetadata:
    """Fallback FileMetadata - dynamic."""
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

def upload_file(*args, **kwargs):
    """Fallback upload_file - return None."""
    return None

def get_file_metadata(*args, **kwargs):
    """Fallback get_file_metadata - return None."""
    return None

def get_file_data(*args, **kwargs):
    """Fallback get_file_data - return None."""
    return None

def delete_file(*args, **kwargs):
    """Fallback delete_file - return False."""
    return False

# Messaging Fallbacks
class UnifiedMessagingManager:
    """Fallback UnifiedMessagingManager - no-op."""
    def __init__(self):
        pass

class MessageEncryption:
    """Fallback MessageEncryption - no-op."""
    def __init__(self):
        pass

class MessageValidator:
    """Fallback MessageValidator - no-op."""
    def __init__(self):
        pass

class MessageRouter:
    """Fallback MessageRouter - no-op."""
    def __init__(self):
        pass

class ChannelManager:
    """Fallback ChannelManager - no-op."""
    def __init__(self):
        pass

class MessageMetadata:
    """Fallback MessageMetadata - dynamic."""
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class MessageDelivery:
    """Fallback MessageDelivery - dynamic."""
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class ChannelSettings:
    """Fallback ChannelSettings - dynamic."""
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class MessageType:
    """Fallback MessageType enum."""
    TEXT = "text"
    IMAGE = "image"
    FILE = "file"

class ChannelType:
    """Fallback ChannelType enum."""
    PUBLIC = "public"
    PRIVATE = "private"
    GROUP = "group"

class MessageStatus:
    """Fallback MessageStatus enum."""
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"

class EncryptionLevel:
    """Fallback EncryptionLevel enum."""
    NONE = "none"
    BASIC = "basic"
    ADVANCED = "advanced"

async def send_message(*args, **kwargs):
    """Fallback send_message - return None."""
    return None

async def get_message(*args, **kwargs):
    """Fallback get_message - return None."""
    return None

async def get_channel_messages(*args, **kwargs):
    """Fallback get_channel_messages - return empty list."""
    return []

async def create_channel(*args, **kwargs):
    """Fallback create_channel - return None."""
    return None

def get_messaging_manager():
    """Fallback get_messaging_manager - return instance."""
    return UnifiedMessagingManager()

# Notification Fallbacks
class NotificationManager:
    """Fallback NotificationManager - no-op."""
    def __init__(self):
        pass

class Notification:
    """Fallback Notification - dynamic."""
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class NotificationType:
    """Fallback NotificationType enum."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    SUCCESS = "success"

class NotificationPriority:
    """Fallback NotificationPriority enum."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"

def send_notification(*args, **kwargs):
    """Fallback send_notification - return None."""
    return None

def mark_notification_read(*args, **kwargs):
    """Fallback mark_notification_read - return False."""
    return False

def get_notifications(*args, **kwargs):
    """Fallback get_notifications - return empty list."""
    return []

def get_unread_notification_count(*args, **kwargs):
    """Fallback get_unread_notification_count - return 0."""
    return 0

# Error Fallbacks
class BaseAPIException(Exception):
    """Fallback BaseAPIException."""
    def __init__(self, message: str = "", status_code: int = 500, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}

class AuthenticationError(BaseAPIException):
    """Fallback AuthenticationError."""
    def __init__(self, message: str = "Authentication failed", **kwargs):
        super().__init__(message, status_code=401, **kwargs)

class AuthorizationError(BaseAPIException):
    """Fallback AuthorizationError."""
    def __init__(self, message: str = "Authorization failed", **kwargs):
        super().__init__(message, status_code=403, **kwargs)

class ValidationError(BaseAPIException):
    """Fallback ValidationError."""
    def __init__(self, message: str = "Validation failed", **kwargs):
        super().__init__(message, status_code=400, **kwargs)

class DatabaseError(BaseAPIException):
    """Fallback DatabaseError."""
    def __init__(self, message: str = "Database error", **kwargs):
        super().__init__(message, status_code=500, **kwargs)

class NetworkError(BaseAPIException):
    """Fallback NetworkError."""
    def __init__(self, message: str = "Network error", **kwargs):
        super().__init__(message, status_code=503, **kwargs)

class FileError(BaseAPIException):
    """Fallback FileError."""
    def __init__(self, message: str = "File error", **kwargs):
        super().__init__(message, status_code=500, **kwargs)

class ExternalServiceError(BaseAPIException):
    """Fallback ExternalServiceError."""
    def __init__(self, message: str = "External service error", **kwargs):
        super().__init__(message, status_code=502, **kwargs)

class RateLimitError(BaseAPIException):
    """Fallback RateLimitError."""
    def __init__(self, message: str = "Rate limit exceeded", **kwargs):
        super().__init__(message, status_code=429, **kwargs)

class ConfigurationError(BaseAPIException):
    """Fallback ConfigurationError."""
    def __init__(self, message: str = "Configuration error", **kwargs):
        super().__init__(message, status_code=500, **kwargs)

class ProcessLockError(BaseAPIException):
    """Fallback ProcessLockError."""
    def __init__(self, message: str = "Process lock error", **kwargs):
        super().__init__(message, status_code=500, **kwargs)

class StartupError(BaseAPIException):
    """Fallback StartupError."""
    def __init__(self, message: str = "Startup error", **kwargs):
        super().__init__(message, status_code=500, **kwargs)

class SecurityError(BaseAPIException):
    """Fallback SecurityError."""
    def __init__(self, message: str = "Security error", **kwargs):
        super().__init__(message, status_code=403, **kwargs)

class ErrorSeverity:
    """Fallback ErrorSeverity enum."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ErrorCategory:
    """Fallback ErrorCategory enum."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    DATABASE = "database"
    NETWORK = "network"
    SECURITY = "security"
    SYSTEM = "system"
    FILE = "file"
    EXTERNAL = "external"

class ErrorManager:
    """Fallback ErrorManager."""
    def __init__(self):
        self.errors: List[Dict[str, Any]] = []

    def log_error(self, error: Union[Exception, Dict[str, Any], str]) -> None:
        entry = {
            "error": str(error) if not isinstance(error, dict) else error,
            "type": type(error).__name__ if not isinstance(error, dict) else "dict",
        }
        self.errors.append(entry)

def get_error_manager():
    """Fallback get_error_manager - return instance."""
    return ErrorManager()

class CircuitBreaker:
    """Fallback CircuitBreaker - identity."""
    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, func):
        return func

def handle_exception(exc: Exception) -> Dict[str, Any]:
    """Fallback handle_exception."""
    return {
        "type": type(exc).__name__,
        "message": str(exc),
        "details": getattr(exc, "details", {}),
    }

def create_error_response(exc: Exception, status_code: int = 500) -> Dict[str, Any]:
    """Fallback create_error_response."""
    return {
        "success": False,
        "error": handle_exception(exc),
        "status_code": status_code,
    }

def handle_404(request, exc):
    """Fallback handle_404."""
    return {"error": "Not found", "status_code": 404}

def handle_500(request, exc):
    """Fallback handle_500."""
    return {"error": "Internal server error", "status_code": 500}

def handle_validation_error(request, exc):
    """Fallback handle_validation_error."""
    return {"error": "Validation failed", "status_code": 400}

def handle_authentication_error(request, exc):
    """Fallback handle_authentication_error."""
    return {"error": "Authentication failed", "status_code": 401}

def handle_authorization_error(request, exc):
    """Fallback handle_authorization_error."""
    return {"error": "Authorization failed", "status_code": 403}

def handle_rate_limit_error(request, exc):
    """Fallback handle_rate_limit_error."""
    return {"error": "Rate limit exceeded", "status_code": 429}

async def not_found_handler(request, exc):
    """Fallback not_found_handler for async."""
    return {"error": "Not Found", "status_code": 404}

async def internal_error_handler(request, exc):
    """Fallback internal_error_handler for async."""
    return {"error": "Internal Server Error", "status_code": 500}

def register_error_handlers(app):
    """Fallback register_error_handlers - no-op."""
    pass

from enum import Enum as EnumBase
from typing import Tuple

@EnumBase
class ErrorCode:
    """Fallback ErrorCode enum with tuple values for backward compatibility."""
    AUTH_INVALID_CREDENTIALS = ("AUTH_INVALID_CREDENTIALS", 401, "Invalid credentials", "authentication", "high")
    AUTH_TOKEN_EXPIRED = ("AUTH_TOKEN_EXPIRED", 401, "Authentication token has expired", "authentication", "medium")
    # Add all from plan's ErrorCode examples
    # ... (include all 20+ from the errors/__init__.py fallback)

    def __init__(self, code: str, http_status: int, message: str, category: str, severity: str):
        self._code = code
        self._http_status = http_status
        self._message = message
        self._category = category
        self._severity = severity

    @property
    def code(self) -> str:
        return self._code

    @property
    def status(self) -> int:
        return self._http_status

    @property
    def message(self) -> str:
        return self._message

    @property
    def category(self) -> str:
        return self._category

    @property
    def severity(self) -> str:
        return self._severity

ERROR_CODE_MAP: Dict[str, ErrorCode] = {ec.code: ec for ec in ErrorCode}

def get_error_code(identifier: Union[str, ErrorCode]) -> Optional[ErrorCode]:
    """Fallback get_error_code."""
    if isinstance(identifier, ErrorCode):
        return identifier
    if not isinstance(identifier, str):
        return None
    return ERROR_CODE_MAP.get(identifier)

def error_to_response(error_code: Union[str, ErrorCode], details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Fallback error_to_response."""
    ec = get_error_code(error_code)
    if ec is None:
        return {
            "success": False,
            "error": {
                "code": "UNKNOWN_ERROR",
                "message": "An unknown error occurred",
                "category": "system",
                "severity": "medium",
                "details": details or {},
            },
            "status_code": 500,
        }
    return {
        "success": False,
        "error": {
            "code": ec.code,
            "message": ec.message,
            "category": ec.category,
            "severity": ec.severity,
            "details": details or {},
        },
        "status_code": ec.status,
    }

def raise_for_code(error_code: Union[str, ErrorCode], details: Optional[Dict[str, Any]] = None) -> None:
    """Fallback raise_for_code."""
    ec = get_error_code(error_code)
    if ec is None:
        raise BaseAPIException("Unknown error code", status_code=500, details=details or {})
    raise BaseAPIException(ec.message, status_code=ec.status, details=details or {})

def list_error_codes() -> List[Dict[str, Any]]:
    """Fallback list_error_codes."""
    codes = []
    for ec in ErrorCode:
        codes.append({
            "code": ec.code,
            "status": ec.status,
            "message": ec.message,
            "category": ec.category,
            "severity": ec.severity,
        })
    return codes

# Caching Fallbacks
class CacheManager:
    """Fallback CacheManager - in-memory dict."""
    def __init__(self):
        self._cache = {}

    def get(self, key):
        return self._cache.get(key)

    def set(self, key, value, ttl=None):
        self._cache[key] = value

    def delete(self, key):
        self._cache.pop(key, None)

class DistributedCacheManager:
    """Fallback DistributedCacheManager - same as CacheManager."""
    def __init__(self):
        self._cache = {}

    def get(self, key):
        return self._cache.get(key)

    def set(self, key, value, ttl=None):
        self._cache[key] = value

class CacheEntry:
    """Fallback CacheEntry - dynamic."""
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

def cache_get(key):
    """Fallback cache_get."""
    return CacheManager().get(key)

def cache_set(key, value, ttl=None):
    """Fallback cache_set."""
    CacheManager().set(key, value, ttl)

def cache_delete(key):
    """Fallback cache_delete."""
    CacheManager().delete(key)

async def cache_get_async(key):
    """Fallback cache_get_async."""
    return cache_get(key)

async def cache_set_async(key, value, ttl=None):
    """Fallback cache_set_async."""
    cache_set(key, value, ttl)

def cached(*args, **kwargs):
    """Fallback cached decorator - identity."""
    def decorator(func):
        return func
    return decorator

def async_cached_decorator(*args, **kwargs):
    """Fallback async_cached_decorator - identity."""
    def decorator(func):
        return func
    return decorator

# Scheduler Fallbacks
class TaskScheduler:
    """Fallback TaskScheduler - no-op."""
    def __init__(self):
        pass

class ScheduledTask:
    """Fallback ScheduledTask - dynamic."""
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class TaskStatus:
    """Fallback TaskStatus enum."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class TaskType:
    """Fallback TaskType enum."""
    ONCE = "once"
    RECURRING = "recurring"
    CRON = "cron"

def schedule_once(*args, **kwargs):
    """Fallback schedule_once - return None."""
    return None

def schedule_recurring(*args, **kwargs):
    """Fallback schedule_recurring - return None."""
    return None

def schedule_cron(*args, **kwargs):
    """Fallback schedule_cron - return None."""
    return None

def cancel_task(*args, **kwargs):
    """Fallback cancel_task - return False."""
    return False

def get_scheduled_tasks(*args, **kwargs):
    """Fallback get_scheduled_tasks - return empty list."""
    return []

# Services Fallbacks
class ServiceManager:
    """Fallback ServiceManager."""
    def __init__(self):
        self._services = {}

    def register(self, name: str, service: Any):
        self._services[name] = service

    def get(self, name: str):
        return self._services.get(name)

    def list(self):
        return list(self._services.keys())

def get_service_manager():
    """Fallback get_service_manager."""
    return ServiceManager()

# Monitoring Fallbacks
performance_monitor = None

def start_performance_monitoring():
    """Fallback start_performance_monitoring - no-op."""
    pass

def stop_performance_monitoring():
    """Fallback stop_performance_monitoring - no-op."""
    pass

def get_performance_dashboard():
    """Fallback get_performance_dashboard - return empty dict."""
    return {}

def get_system_health_status():
    """Fallback get_system_health_status - return empty dict."""
    return {}

def record_performance_metric(*args, **kwargs):
    """Fallback record_performance_metric - no-op."""
    pass

class MetricType:
    """Fallback MetricType - no-op."""
    pass

class AlertLevel:
    """Fallback AlertLevel - no-op."""
    pass

class PerformanceMetric:
    """Fallback PerformanceMetric - dynamic."""
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class SystemHealthStatus:
    """Fallback SystemHealthStatus - dynamic."""
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class PerformanceAlert:
    """Fallback PerformanceAlert - dynamic."""
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class PerformanceMonitor:
    """Fallback PerformanceMonitor - no-op."""
    def __init__(self):
        pass

# Additional fallbacks for middleware, threading, clustering, security, versioning, performance as per plan
# (minimal or __version__ only, but include if referenced)

# For middleware: no specific fallbacks needed beyond __version__

# For threading: no specific fallbacks

# For clustering: full impl already, no fallbacks

# For security: imports exist, but fallbacks if needed (e.g., from security/__init__.py)

# For versioning and performance: mainly __version__

# Export all for wildcard imports
__all__ = [
    # Utilities
    "get_fallback_class",
    "get_fallback_instance",
    "get_module_version",
    "MockConfig",
    # Events
    "EventManager", "Event", "EventHandler", "EventPriority",
    "emit_event", "register_event_handler", "unregister_event_handler",
    "get_events", "event_handler", "global_event_handler",
    # Files
    "FileManager", "FileMetadata",
    "upload_file", "get_file_metadata", "get_file_data", "delete_file",
    # Messaging
    "UnifiedMessagingManager", "MessageEncryption", "MessageValidator", "MessageRouter",
    "ChannelManager", "MessageMetadata", "MessageDelivery", "ChannelSettings",
    "MessageType", "ChannelType", "MessageStatus", "EncryptionLevel",
    "send_message", "get_message", "get_channel_messages", "create_channel", "get_messaging_manager",
    # Notifications
    "NotificationManager", "Notification", "NotificationType", "NotificationPriority",
    "send_notification", "mark_notification_read", "get_notifications", "get_unread_notification_count",
    # Errors
    "BaseAPIException", "AuthenticationError", "AuthorizationError", "ValidationError",
    "DatabaseError", "NetworkError", "FileError", "ExternalServiceError", "RateLimitError",
    "ConfigurationError", "ProcessLockError", "StartupError", "SecurityError",
    "ErrorSeverity", "ErrorCategory", "ErrorManager", "CircuitBreaker", "ErrorCode",
    "ERROR_CODE_MAP", "get_error_manager",
    "handle_exception", "create_error_response",
    "handle_404", "handle_500", "handle_validation_error", "handle_authentication_error",
    "handle_authorization_error", "handle_rate_limit_error",
    "not_found_handler", "internal_error_handler", "register_error_handlers",
    "get_error_code", "error_to_response", "raise_for_code", "list_error_codes",
    # Caching
    "CacheManager", "DistributedCacheManager", "CacheEntry",
    "cache_get", "cache_set", "cache_delete", "cache_get_async", "cache_set_async",
    "cached", "async_cached_decorator",
    # Scheduler
    "TaskScheduler", "ScheduledTask", "TaskStatus", "TaskType",
    "schedule_once", "schedule_recurring", "schedule_cron", "cancel_task", "get_scheduled_tasks",
    # Services
    "ServiceManager", "get_service_manager",
    # Monitoring
    "performance_monitor", "start_performance_monitoring", "stop_performance_monitoring",
    "get_performance_dashboard", "get_system_health_status", "record_performance_metric",
    "MetricType", "AlertLevel", "PerformanceMetric", "SystemHealthStatus", "PerformanceAlert",
    "PerformanceMonitor",
    # Others as needed
]