# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Shared Types

Common type definitions and type aliases used across the application.
"""

from typing import (
    Any, Dict, List, Optional, Union, Callable, Awaitable,
    TypeVar, Generic, Protocol, runtime_checkable
)
from datetime import datetime
from pathlib import Path

# Basic type aliases
JSON = Dict[str, Any]
JSONList = List[Dict[str, Any]]
Headers = Dict[str, str]
QueryParams = Dict[str, Union[str, int, float, bool]]
PathParams = Dict[str, str]

# File and path types
FilePath = Union[str, Path]
FileContent = Union[str, bytes]

# ID types
UserId = str
MessageId = str
ChannelId = str
PluginId = str
SessionId = str
TaskId = str
EventId = str

# Callback types
EventCallback = Callable[[Dict[str, Any]], None]
AsyncEventCallback = Callable[[Dict[str, Any]], Awaitable[None]]
ErrorCallback = Callable[[Exception], None]
AsyncErrorCallback = Callable[[Exception], Awaitable[None]]

# Handler types
RequestHandler = Callable[[Dict[str, Any]], Dict[str, Any]]
AsyncRequestHandler = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]
MessageHandler = Callable[[str, Dict[str, Any]], None]
AsyncMessageHandler = Callable[[str, Dict[str, Any]], Awaitable[None]]

# Configuration types
ConfigValue = Union[str, int, float, bool, List[Any], Dict[str, Any]]
ConfigDict = Dict[str, ConfigValue]

# Database types
DatabaseRow = Dict[str, Any]
DatabaseRows = List[DatabaseRow]
QueryResult = Union[DatabaseRow, DatabaseRows, None]

# Plugin types
PluginConfig = Dict[str, Any]
PluginMetadata = Dict[str, Any]
PluginResult = Dict[str, Any]

# API types
ApiRequest = Dict[str, Any]
ApiResponse = Dict[str, Any]
ApiHeaders = Dict[str, str]

# WebSocket types
WebSocketMessage = Dict[str, Any]
WebSocketHandler = Callable[[WebSocketMessage], None]
AsyncWebSocketHandler = Callable[[WebSocketMessage], Awaitable[None]]

# Monitoring types
MetricValue = Union[int, float]
MetricTags = Dict[str, str]
AlertCondition = Callable[[MetricValue], bool]

# Security types
Token = str
HashedPassword = str
Salt = str
Permissions = List[str]
SecurityContext = Dict[str, Any]

# Generic types
T = TypeVar('T')
K = TypeVar('K')
V = TypeVar('V')

# Protocol definitions
@runtime_checkable
class Serializable(Protocol):
    """Protocol for objects that can be serialized."""

    def to_dict(self) -> Dict[str, Any]:
        """Convert object to dictionary."""
        ...

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Serializable':
        """Create object from dictionary."""
        ...


@runtime_checkable
class Configurable(Protocol):
    """Protocol for configurable objects."""

    def configure(self, config: ConfigDict) -> None:
        """Configure the object with given configuration."""
        ...

    def get_config(self) -> ConfigDict:
        """Get current configuration."""
        ...


@runtime_checkable
class Lifecycle(Protocol):
    """Protocol for objects with lifecycle management."""

    async def initialize(self) -> bool:
        """Initialize the object."""
        ...

    async def start(self) -> None:
        """Start the object."""
        ...

    async def stop(self) -> None:
        """Stop the object."""
        ...

    async def shutdown(self) -> None:
        """Shutdown the object."""
        ...


@runtime_checkable
class Healthcheck(Protocol):
    """Protocol for objects that can report health status."""

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check and return status."""
        ...


@runtime_checkable
class Cacheable(Protocol):
    """Protocol for cacheable objects."""

    def cache_key(self) -> str:
        """Get cache key for this object."""
        ...

    def cache_ttl(self) -> int:
        """Get cache TTL in seconds."""
        ...


@runtime_checkable
class Validatable(Protocol):
    """Protocol for validatable objects."""

    def validate(self) -> List[str]:
        """Validate object and return list of errors."""
        ...

    def is_valid(self) -> bool:
        """Check if object is valid."""
        ...


@runtime_checkable
class Auditable(Protocol):
    """Protocol for auditable objects."""

    def audit_info(self) -> Dict[str, Any]:
        """Get audit information."""
        ...


# Generic container types
class Result(Generic[T]):
    """Result container that can hold success value or error."""

    def __init__(self, value: Optional[T] = None, error: Optional[Exception] = None):
        self._value = value
        self._error = error

    @property
    def is_success(self) -> bool:
        """Check if result is successful."""
        return self._error is None

    @property
    def is_error(self) -> bool:
        """Check if result is an error."""
        return self._error is not None

    @property
    def value(self) -> T:
        """Get the success value."""
        if self._error:
            raise self._error
        return self._value

    @property
    def error(self) -> Optional[Exception]:
        """Get the error."""
        return self._error

    @classmethod
    def success(cls, value: T) -> 'Result[T]':
        """Create successful result."""
        return cls(value=value)

    @classmethod
    def failure(cls, error: Exception) -> 'Result[T]':
        """Create error result."""
        return cls(error=error)


class Optional(Generic[T]):
    """Optional container that can hold a value or be empty."""

    def __init__(self, value: Optional[T] = None):
        self._value = value

    @property
    def is_present(self) -> bool:
        """Check if value is present."""
        return self._value is not None

    @property
    def is_empty(self) -> bool:
        """Check if value is empty."""
        return self._value is None

    @property
    def value(self) -> T:
        """Get the value."""
        if self._value is None:
            raise ValueError("Optional value is empty")
        return self._value

    def get_or_default(self, default: T) -> T:
        """Get value or return default."""
        return self._value if self._value is not None else default

    @classmethod
    def of(cls, value: T) -> 'Optional[T]':
        """Create optional with value."""
        return cls(value)

    @classmethod
    def empty(cls) -> 'Optional[T]':
        """Create empty optional."""
        return cls()


# Export all types
__all__ = [
    # Basic types
    'JSON',
    'JSONList',
    'Headers',
    'QueryParams',
    'PathParams',
    'FilePath',
    'FileContent',

    # ID types
    'UserId',
    'MessageId',
    'ChannelId',
    'PluginId',
    'SessionId',
    'TaskId',
    'EventId',

    # Callback types
    'EventCallback',
    'AsyncEventCallback',
    'ErrorCallback',
    'AsyncErrorCallback',

    # Handler types
    'RequestHandler',
    'AsyncRequestHandler',
    'MessageHandler',
    'AsyncMessageHandler',
    'WebSocketHandler',
    'AsyncWebSocketHandler',

    # Configuration types
    'ConfigValue',
    'ConfigDict',

    # Database types
    'DatabaseRow',
    'DatabaseRows',
    'QueryResult',

    # Plugin types
    'PluginConfig',
    'PluginMetadata',
    'PluginResult',

    # API types
    'ApiRequest',
    'ApiResponse',
    'ApiHeaders',
    'WebSocketMessage',

    # Monitoring types
    'MetricValue',
    'MetricTags',
    'AlertCondition',

    # Security types
    'Token',
    'HashedPassword',
    'Salt',
    'Permissions',
    'SecurityContext',

    # Generic types
    'T',
    'K',
    'V',

    # Protocols
    'Serializable',
    'Configurable',
    'Lifecycle',
    'Healthcheck',
    'Cacheable',
    'Validatable',
    'Auditable',

    # Containers
    'Result',
    'Optional',
]
