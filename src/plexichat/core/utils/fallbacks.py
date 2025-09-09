"""Shared fallback implementations for PlexiChat core modules."""
__all__ = [
    # Managers
    "EventManager", "FileManager", "UnifiedMessagingManager", "MiddlewareBase", "PerformanceMonitor",
    "NotificationManager", "ErrorManager", "CacheManager", "DistributedCacheManager", "TaskScheduler",
    "ServiceManager", "ThreadingManager", "ClusterManager", "SecurityManager", "VersionManager",
    # Data classes
    "Event", "FileMetadata", "Notification", "CacheEntry", "ScheduledTask",
    # Enums
    "EventPriority", "MessageType", "ChannelType", "NotificationType", "NotificationPriority",
    "ErrorSeverity", "ErrorCategory", "TaskStatus", "TaskType", "MetricType",
    # Exceptions
    "BaseAPIException", "AuthenticationError", "ValidationError", "DatabaseError",
    # Functions
    "emit_event", "register_event_handler", "upload_file", "get_file_metadata", "send_message",
    "start_performance_monitoring", "stop_performance_monitoring", "send_notification", "get_notifications",
    "cache_get", "schedule_once", "schedule_recurring", "get_service_manager", "authenticate_user",
    "validate_token", "measure_performance", "create_error_response", "handle_exception", "log_error",
    # Decorators
    "cached",
    # Factories and helpers
    "get_fallback_class", "get_fallback_instance", "get_module_version",
]

# Fallback Managers (all empty classes)
class EventManager:
    def __init__(self):
        pass

class FileManager:
    def __init__(self):
        pass

class UnifiedMessagingManager:
    def __init__(self):
        pass

class MiddlewareBase:
    def __init__(self):
        pass

class PerformanceMonitor:
    def __init__(self):
        pass

class NotificationManager:
    def __init__(self):
        pass

class ErrorManager:
    def __init__(self):
        pass

class CacheManager:
    def __init__(self):
        pass

class DistributedCacheManager:
    def __init__(self):
        pass

class TaskScheduler:
    def __init__(self):
        pass

class ServiceManager:
    def __init__(self):
        pass

class ThreadingManager:
    def __init__(self):
        pass

class ClusterManager:
    def __init__(self):
        pass

class SecurityManager:
    def __init__(self):
        pass

class VersionManager:
    def __init__(self):
        pass

# Data classes (simple dict-like)
class Event:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class FileMetadata:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class Notification:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class CacheEntry:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class ScheduledTask:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

# Enums (as classes with constants)
class EventPriority:
    LOW = 1
    MEDIUM = 2
    HIGH = 3

class MessageType:
    TEXT = 1
    IMAGE = 2
    FILE = 3

class ChannelType:
    DIRECT = 1
    GROUP = 2

class NotificationType:
    EMAIL = 1
    SMS = 2
    PUSH = 3

class NotificationPriority:
    LOW = 1
    MEDIUM = 2
    HIGH = 3

class ErrorSeverity:
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4

class ErrorCategory:
    AUTH = 1
    VALIDATION = 2
    DATABASE = 3
    SYSTEM = 4

class TaskStatus:
    PENDING = 1
    RUNNING = 2
    COMPLETED = 3

class TaskType:
    ONE_TIME = 1
    RECURRING = 2

class MetricType:
    CPU = 1
    MEMORY = 2
    DISK = 3

# Exceptions
class BaseAPIException(Exception):
    def __init__(self, message=""):
        super().__init__(message)

class AuthenticationError(BaseAPIException):
    def __init__(self):
        super().__init__("Authentication failed")

class ValidationError(BaseAPIException):
    def __init__(self):
        super().__init__("Validation failed")

class DatabaseError(BaseAPIException):
    def __init__(self):
        super().__init__("Database error")

# No-op functions
def emit_event(*args, **kwargs):
    pass

def register_event_handler(*args, **kwargs):
    pass

def upload_file(*args, **kwargs):
    pass

def get_file_metadata(*args, **kwargs):
    pass

async def send_message(*args, **kwargs):
    pass

def start_performance_monitoring(*args, **kwargs):
    pass

def stop_performance_monitoring(*args, **kwargs):
    pass

def send_notification(*args, **kwargs):
    pass

def get_notifications(*args, **kwargs):
    pass

def cache_get(*args, **kwargs):
    pass

def schedule_once(*args, **kwargs):
    pass

def schedule_recurring(*args, **kwargs):
    pass

def get_service_manager(*args, **kwargs):
    pass

def authenticate_user(*args, **kwargs):
    pass

def validate_token(*args, **kwargs):
    pass

def measure_performance(*args, **kwargs):
    pass

def create_error_response(*args, **kwargs):
    pass

def handle_exception(*args, **kwargs):
    pass

def log_error(*args, **kwargs):
    pass

# Decorator
def cached(func):
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper

# Factory functions
def get_fallback_class(class_name):
    """Factory to get fallback class by name."""
    fallback_classes = {
        'EventManager': EventManager,
        'FileManager': FileManager,
        'UnifiedMessagingManager': UnifiedMessagingManager,
        'MiddlewareBase': MiddlewareBase,
        'PerformanceMonitor': PerformanceMonitor,
        'NotificationManager': NotificationManager,
        'ErrorManager': ErrorManager,
        'CacheManager': CacheManager,
        'DistributedCacheManager': DistributedCacheManager,
        'TaskScheduler': TaskScheduler,
        'ServiceManager': ServiceManager,
        'ThreadingManager': ThreadingManager,
        'ClusterManager': ClusterManager,
        'SecurityManager': SecurityManager,
        'VersionManager': VersionManager,
        # Add more mappings as needed
    }
    return fallback_classes.get(class_name, object)  # Default to object if not found

def get_fallback_instance(class_name):
    """Get fallback instance or None for global managers."""
    cls = get_fallback_class(class_name)
    return None  # For global instances like event_manager = None

def get_module_version():
    """Shared version getter for modules."""
    return "0.0.0"