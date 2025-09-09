"""Shared fallback implementations for PlexiChat core modules."""
import os
from typing import Any, Callable, Dict, List, Optional, Type, Union
from enum import Enum

# Assume get_config exists in core; fallback to "0.0.0" if not
try:
    from plexichat.core import get_config
except ImportError:
    def get_config(key: str, default: str = "0.0.0") -> str:
        return default

def get_module_version() -> str:
    """Get the module version from config or default."""
    return get_config("system.version", "0.0.0")

def get_fallback_class(class_name: str) -> Type[Any]:
    """Factory to get fallback class by name."""
    fallback_classes = {
        "EventManager": EventManager,
        "Event": Event,
        "EventHandler": EventHandler,
        "FileManager": FileManager,
        "FileMetadata": FileMetadata,
        "UnifiedMessagingManager": UnifiedMessagingManager,
        "MessageEncryption": MessageEncryption,
        "MessageValidator": MessageValidator,
        "MiddlewareBase": MiddlewareBase,
        "PerformanceMonitor": PerformanceMonitor,
        "MetricType": MetricType,
        "NotificationManager": NotificationManager,
        "Notification": Notification,
        "BaseAPIException": BaseAPIException,
        "AuthenticationError": AuthenticationError,
        "ValidationError": ValidationError,
        "DatabaseError": DatabaseError,
        "CacheManager": CacheManager,
        "DistributedCacheManager": DistributedCacheManager,
        "CacheEntry": CacheEntry,
        "TaskScheduler": TaskScheduler,
        "ScheduledTask": ScheduledTask,
        "ServiceManager": ServiceManager,
        "ThreadingManager": ThreadingManager,
        "ClusterManager": ClusterManager,
        "SecurityManager": SecurityManager,
        "VersionManager": VersionManager,
    }
    return fallback_classes.get(class_name, object)

def get_fallback_instance(class_name: str) -> Any:
    """Factory to get fallback instance by name."""
    cls = get_fallback_class(class_name)
    return cls()

# Fallback classes (empty/no-op implementations)
class EventManager:
    def __init__(self):
        pass

    def emit(self, event: Any, *args, **kwargs):
        pass

class Event:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class EventHandler:
    def __init__(self):
        pass

    def handle(self, event: Any):
        pass

class EventPriority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3

def emit_event(*args, **kwargs):
    pass

def register_event_handler(handler: Callable, priority: EventPriority = EventPriority.NORMAL):
    pass

class FileManager:
    def __init__(self):
        pass

    def upload(self, file_path: str):
        pass

class FileMetadata:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

def upload_file(file_path: str):
    return None

def get_file_metadata(file_id: str):
    return FileMetadata()

class UnifiedMessagingManager:
    def __init__(self):
        pass

    def send(self, message: str, channel: str):
        pass

class MessageEncryption:
    def __init__(self):
        pass

    def encrypt(self, message: str):
        return message

class MessageValidator:
    def __init__(self):
        pass

    def validate(self, message: str):
        return True

class MessageType(Enum):
    TEXT = "text"
    IMAGE = "image"
    FILE = "file"

class ChannelType(Enum):
    DIRECT = "direct"
    GROUP = "group"
    CHANNEL = "channel"

def send_message(message: str, recipient: str, channel_type: ChannelType = ChannelType.DIRECT):
    pass

class MiddlewareBase:
    def __init__(self):
        pass

    def process_request(self, request: Any):
        pass

    def process_response(self, response: Any):
        pass

class PerformanceMonitor:
    def __init__(self):
        pass

    def start(self):
        pass

    def stop(self):
        pass

class MetricType(Enum):
    CPU = "cpu"
    MEMORY = "memory"
    LATENCY = "latency"

def start_performance_monitoring():
    pass

def stop_performance_monitoring():
    pass

performance_monitor = PerformanceMonitor()

class NotificationManager:
    def __init__(self):
        pass

    def send(self, notification: Notification):
        pass

class Notification:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class NotificationType(Enum):
    EMAIL = "email"
    PUSH = "push"
    SMS = "sms"

class NotificationPriority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3

def send_notification(title: str, message: str, priority: NotificationPriority = NotificationPriority.NORMAL):
    pass

def get_notifications():
    return []

class ErrorManager:
    def __init__(self):
        pass

    def handle(self, error: Exception):
        pass

class ErrorSeverity(Enum):
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4

class ErrorCategory(Enum):
    VALIDATION = "validation"
    AUTH = "auth"
    DATABASE = "database"
    API = "api"

class BaseAPIException(Exception):
    def __init__(self, message: str, code: str = "BASE_ERROR"):
        self.message = message
        self.code = code
        super().__init__(message)

class AuthenticationError(BaseAPIException):
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, "AUTH_ERROR")

class ValidationError(BaseAPIException):
    def __init__(self, message: str = "Validation failed"):
        super().__init__(message, "VALIDATION_ERROR")

class DatabaseError(BaseAPIException):
    def __init__(self, message: str = "Database error"):
        super().__init__(message, "DB_ERROR")

def create_error_response(exception: Exception) -> Dict[str, Any]:
    return {"error": str(exception), "code": "UNKNOWN"}

def handle_exception(exception: Exception):
    pass

def log_error(error: Exception):
    pass

def get_error_manager():
    return ErrorManager()

class CacheManager:
    def __init__(self):
        pass

    def get(self, key: str):
        return None

    def set(self, key: str, value: Any):
        pass

class DistributedCacheManager(CacheManager):
    def __init__(self):
        super().__init__()

class CacheEntry:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

def cache_get(key: str):
    return None

def cached(func: Callable) -> Callable:
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper

cache_manager = CacheManager()

class TaskScheduler:
    def __init__(self):
        pass

    def schedule(self, task: Callable, delay: int):
        pass

class ScheduledTask:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class TaskType(Enum):
    ONCE = "once"
    RECURRING = "recurring"

def schedule_once(task: Callable, delay: int):
    pass

def schedule_recurring(task: Callable, interval: int):
    pass

task_scheduler = TaskScheduler()

class ServiceManager:
    def __init__(self):
        pass

    def register(self, name: str, service: Any):
        pass

def get_service_manager():
    return ServiceManager()

class ThreadingManager:
    def __init__(self):
        pass

    def start_thread(self, target: Callable):
        pass

class ClusterManager:
    def __init__(self):
        pass

    def join_cluster(self):
        pass

class SecurityManager:
    def __init__(self):
        pass

    def authenticate(self, credentials: Dict[str, Any]):
        return True

def authenticate_user(username: str, password: str):
    return True

def validate_token(token: str):
    return True

security_manager = SecurityManager()

class VersionManager:
    def __init__(self):
        pass

    def get_version(self):
        return get_module_version()

def measure_performance(metric: str):
    pass

performance_monitor = PerformanceMonitor()