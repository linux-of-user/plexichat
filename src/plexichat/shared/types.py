"""
PlexiChat Enhanced Shared Types

Comprehensive type definitions with advanced features:
- Advanced type safety with generic protocols
- Database integration types
- Security and encryption types
- Plugin and extension types
- Performance monitoring types
- Compliance and audit types
- Edge computing and distributed system types
"""

from typing import (
    Any, Dict, List, Optional, Union, Callable, TypeVar, Generic,
    Protocol, runtime_checkable, TypedDict, Awaitable
)
from enum import Enum, IntEnum, IntFlag
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# Basic type aliases
JSON = Union[Dict[str, Any], List[Any], str, int, float, bool, None]
JSONObject = Dict[str, Any]
JSONArray = List[Any]
ConfigDict = Dict[str, Any]

# ID types
UserId = str
MessageId = str
ChannelId = str
NodeId = str
EventId = str

# Type variables
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


# Enhanced Protocol Definitions for Advanced Features

@runtime_checkable
class Encryptable(Protocol):
    """Protocol for objects that can be encrypted."""

    def encrypt(self, key: bytes) -> bytes: ...
    def decrypt(self, encrypted_data: bytes, key: bytes) -> 'Encryptable': ...

@runtime_checkable
class DatabaseEntity(Protocol):
    """Protocol for database entities."""

    def to_db_dict(self) -> Dict[str, Any]: ...
    @classmethod
    def from_db_dict(cls, data: Dict[str, Any]) -> 'DatabaseEntity': ...
    def primary_key(self) -> str: ...

@runtime_checkable
class PluginInterface(Protocol):
    """Enhanced protocol for plugin interfaces."""

    def initialize(self, config: JSONObject) -> Awaitable[bool]: ...
    def execute(self, command: str, args: JSONObject) -> Awaitable[JSONObject]: ...
    def cleanup(self) -> Awaitable[None]: ...
    def health_check(self) -> Awaitable[bool]: ...

@runtime_checkable
class AIModelInterface(Protocol):
    """Protocol for AI model interfaces."""

    def predict(self, input_data: Any) -> Awaitable[Dict[str, Any]]: ...
    def train(self, training_data: List[Dict[str, Any]]) -> Awaitable[bool]: ...
    def evaluate(self, test_data: List[Dict[str, Any]]) -> Awaitable[Dict[str, float]]: ...

@runtime_checkable
class SecurityProvider(Protocol):
    """Protocol for security providers."""

    def authenticate(self, credentials: JSONObject) -> Awaitable[Optional[UserId]]: ...
    def authorize(self, user_id: UserId, resource: str, action: str) -> Awaitable[bool]: ...
    def encrypt_data(self, data: bytes, context: JSONObject) -> Awaitable[bytes]: ...
    def decrypt_data(self, encrypted_data: bytes, context: JSONObject) -> Awaitable[bytes]: ...

# Enhanced Enum Definitions

class SecurityLevel(Enum):
    """Enhanced security levels with quantum readiness."""
    BASIC = "basic"
    STANDARD = "standard"
    HIGH = "high"
    MAXIMUM = "maximum"
    QUANTUM = "quantum"
    ZERO_TRUST = "zero_trust"

class NodeStatus(Enum):
    """Comprehensive node status enumeration."""
    INITIALIZING = "initializing"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"
    MAINTENANCE = "maintenance"
    OFFLINE = "offline"
    DECOMMISSIONED = "decommissioned"

class TaskPriority(IntEnum):
    """Task priority levels with numeric values."""
    LOWEST = 1
    LOW = 2
    NORMAL = 3
    HIGH = 4
    HIGHEST = 5
    CRITICAL = 6
    EMERGENCY = 7

class EventSeverity(Enum):
    """Event severity levels for monitoring and alerting."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    FATAL = "fatal"

class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms."""
    AES_256_GCM = "aes_256_gcm"
    CHACHA20_POLY1305 = "chacha20_poly1305"
    RSA_4096 = "rsa_4096"
    ECDSA_P384 = "ecdsa_p384"
    QUANTUM_RESISTANT = "quantum_resistant"
    POST_QUANTUM = "post_quantum"

class DatabaseEngine(Enum):
    """Supported database engines."""
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    SQLITE = "sqlite"
    MONGODB = "mongodb"
    REDIS = "redis"
    CASSANDRA = "cassandra"
    ELASTICSEARCH = "elasticsearch"

class MessageType(Enum):
    """Enhanced message types for communication."""
    TEXT = "text"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    FILE = "file"
    SYSTEM = "system"
    ENCRYPTED = "encrypted"
    EPHEMERAL = "ephemeral"
    AI_GENERATED = "ai_generated"
    BLOCKCHAIN_VERIFIED = "blockchain_verified"

class PermissionLevel(IntFlag):
    """Permission levels using flags for combination."""
    NONE = 0
    READ = 1
    WRITE = 2
    EXECUTE = 4
    DELETE = 8
    ADMIN = 16
    OWNER = 32
    FULL = READ | WRITE | EXECUTE | DELETE | ADMIN | OWNER

# Advanced TypedDict definitions for structured data

class UserProfileData(TypedDict):
    """Typed dictionary for user profile data."""
    user_id: UserId
    username: str
    email: str
    display_name: Optional[str]
    avatar_url: Optional[str]
    created_at: datetime
    last_active: datetime
    status: str
    role: str
    permissions: List[str]
    preferences: JSONObject
    security_settings: JSONObject
    verification_status: Dict[str, bool]

class MessageData(TypedDict):
    """Typed dictionary for message data."""
    message_id: MessageId
    channel_id: ChannelId
    user_id: UserId
    content: str
    message_type: str
    timestamp: datetime
    edited_at: Optional[datetime]
    attachments: List[str]
    mentions: List[UserId]
    metadata: JSONObject
    encryption_info: Optional[JSONObject]

# Export all types
__all__ = [
    # Basic types
    'JSON',
    'JSONObject',
    'JSONArray',
    'ConfigDict',
    # ID types
    'UserId',
    'MessageId',
    'ChannelId',
    'NodeId',
    'EventId',
    # Protocols
    'Serializable',
    'Configurable',
    'Lifecycle',
    'Healthcheck',
    'Cacheable',
    'Validatable',
    'Auditable',
    'Encryptable',
    'DatabaseEntity',
    'PluginInterface',
    'AIModelInterface',
    'SecurityProvider',
    # Enums
    'SecurityLevel',
    'NodeStatus',
    'TaskPriority',
    'EventSeverity',
    'EncryptionAlgorithm',
    'DatabaseEngine',
    'MessageType',
    'PermissionLevel',
    # TypedDicts
    'UserProfileData',
    'MessageData',
]
