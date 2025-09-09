"""Shared fallback implementations for PlexiChat core modules."""
from __future__ import annotations

from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type, Union, Tuple

def get_config(key: str, default: str = "0.0.0") -> str:
    """Fallback get_config function."""
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
        "ErrorManager": ErrorManager,
        "ErrorSeverity": ErrorSeverity,
        "ErrorCategory": ErrorCategory,
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
    def __init__(self) -> None:
        pass

    def emit(self, event: Any, *args: Any, **kwargs: Any) -> None:
        pass

class Event:
    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)

class EventHandler:
    def __init__(self) -> None:
        pass

    def handle(self, event: Any) -> None:
        pass

class EventPriority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3

def emit_event(*args: Any, **kwargs: Any) -> None:
    pass

def register_event_handler(handler: Callable[[Any], None], priority: EventPriority = EventPriority.NORMAL) -> None:
    pass

class FileManager:
    def __init__(self) -> None:
        pass

    def upload(self, file_path: str) -> None:
        pass

class FileMetadata:
    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)

def upload_file(file_path: str) -> Optional[Dict[str, Any]]:
    return None

def get_file_metadata(file_id: str) -> FileMetadata:
    return FileMetadata()

class UnifiedMessagingManager:
    def __init__(self) -> None:
        pass

    def send(self, message: str, channel: str) -> None:
        pass

class MessageEncryption:
    def __init__(self) -> None:
        pass

    def encrypt(self, message: str) -> str:
        return message

class MessageValidator:
    def __init__(self) -> None:
        pass

    def validate(self, message: str) -> bool:
        return True

class MessageType(Enum):
    TEXT = "text"
    IMAGE = "image"
    FILE = "file"

class ChannelType(Enum):
    DIRECT = "direct"
    GROUP = "group"
    CHANNEL = "channel"

def send_message(message: str, recipient: str, channel_type: ChannelType = ChannelType.DIRECT) -> None:
    pass

class MiddlewareBase:
    def __init__(self) -> None:
        pass

    def process_request(self, request: Any) -> Any:
        return request

    def process_response(self, response: Any) -> Any:
        return response

class PerformanceMonitor:
    def __init__(self) -> None:
        pass

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

class MetricType(Enum):
    CPU = "cpu"
    MEMORY = "memory"
    LATENCY = "latency"

def start_performance_monitoring() -> None:
    pass

def stop_performance_monitoring() -> None:
    pass

class NotificationManager:
    def __init__(self) -> None:
        pass

    def send(self, notification: Notification) -> None:
        pass

class Notification:
    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)

class NotificationType(Enum):
    EMAIL = "email"
    PUSH = "push"
    SMS = "sms"

class NotificationPriority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3

def send_notification(title: str, message: str, priority: NotificationPriority = NotificationPriority.NORMAL) -> None:
    pass

def get_notifications() -> List[Notification]:
    return []

class ErrorManager:
    def __init__(self) -> None:
        pass

    def handle(self, error: Exception) -> None:
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
    def __init__(self, message: str, code: str = "BASE_ERROR") -> None:
        self.message = message
        self.code = code
        super().__init__(message)

class AuthenticationError(BaseAPIException):
    def __init__(self, message: str = "Authentication failed") -> None:
        super().__init__(message, "AUTH_ERROR")

class ValidationError(BaseAPIException):
    def __init__(self, message: str = "Validation failed") -> None:
        super().__init__(message, "VALIDATION_ERROR")

class DatabaseError(BaseAPIException):
    def __init__(self, message: str = "Database error") -> None:
        super().__init__(message, "DB_ERROR")

def create_error_response(exception: Exception) -> Dict[str, Any]:
    return {"error": str(exception), "code": "UNKNOWN"}

def handle_exception(exception: Exception) -> None:
    pass

def log_error(error: Exception) -> None:
    pass

def get_error_manager() -> ErrorManager:
    return ErrorManager()

class CacheManager:
    def __init__(self) -> None:
        pass

    def get(self, key: str) -> Optional[Any]:
        return None

    def set(self, key: str, value: Any) -> None:
        pass

class DistributedCacheManager(CacheManager):
    def __init__(self) -> None:
        super().__init__()

class CacheEntry:
    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)

def cache_get(key: str) -> Optional[Any]:
    return None

def cached(func: Callable[..., Any]) -> Callable[..., Any]:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return func(*args, **kwargs)
    return wrapper

cache_manager: CacheManager = CacheManager()

class TaskScheduler:
    def __init__(self) -> None:
        pass

    def schedule(self, task: Callable[..., None], delay: int) -> None:
        pass

class ScheduledTask:
    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class TaskType(Enum):
    ONCE = "once"
    RECURRING = "recurring"

def schedule_once(task: Callable[..., None], delay: int) -> None:
    pass

def schedule_recurring(task: Callable[..., None], interval: int) -> None:
    pass

task_scheduler: TaskScheduler = TaskScheduler()

class ServiceManager:
    def __init__(self) -> None:
        pass

    def register(self, name: str, service: Any) -> None:
        pass

def get_service_manager() -> ServiceManager:
    return ServiceManager()

class ThreadingManager:
    def __init__(self) -> None:
        pass

    def start_thread(self, target: Callable[..., None]) -> None:
        pass

class ClusterManager:
    def __init__(self) -> None:
        pass

    def join_cluster(self) -> None:
        pass

class SecurityManager:
    def __init__(self) -> None:
        pass

    def authenticate(self, credentials: Dict[str, Any]) -> bool:
        return True

def authenticate_user(username: str, password: str) -> bool:
    return True

def validate_token(token: str) -> bool:
    return True

security_manager: SecurityManager = SecurityManager()

class VersionManager:
    def __init__(self) -> None:
        pass

    def get_version(self) -> str:
        return get_module_version()

def measure_performance(metric: str) -> Dict[str, Any]:
    return {}

performance_monitor: PerformanceMonitor = PerformanceMonitor()