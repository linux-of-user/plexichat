# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Shared Models

Common data models and schemas used across the application.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

# Import Pydantic BaseModel for compatibility
try:
    from pydantic import BaseModel
except ImportError:
    # Fallback if pydantic is not available
    class BaseModel:
        pass


class Priority(Enum):
    """Priority levels."""

    LOW = 1
    NORMAL = 5
    HIGH = 10
    CRITICAL = 20


class Status(Enum):
    """Generic status enumeration."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


class LogLevel(Enum):
    """Log level enumeration."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class BaseDataModel:
    """Base data model with common fields."""

    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)

    def update_timestamp(self):
        """Update the updated_at timestamp."""
        self.updated_at = datetime.now(UTC)


@dataclass
class User(BaseDataModel):
    """User model."""

    username: str = ""
    email: str = ""
    display_name: str = ""
    is_active: bool = True
    is_admin: bool = False
    last_login: datetime | None = None
    preferences: dict[str, Any] = field(default_factory=dict)
    # Profile enhancement fields
    bio: str | None = None
    avatar_url: str | None = None
    status: str = "online"
    timezone: str | None = None
    language: str = "en"
    theme: str = "dark"


@dataclass
class Message(BaseDataModel):
    """Message model."""

    content: str = ""
    user_id: str = ""
    channel_id: str = ""
    message_type: str = "text"
    attachments: list[str] = field(default_factory=list)
    reactions: dict[str, list[str]] = field(default_factory=dict)
    thread_id: str | None = None
    reply_to: str | None = None
    edited_at: datetime | None = None
    deleted_at: datetime | None = None


@dataclass
class Channel(BaseDataModel):
    """Channel model."""

    name: str = ""
    description: str = ""
    channel_type: str = "public"
    owner_id: str = ""
    members: list[str] = field(default_factory=list)
    settings: dict[str, Any] = field(default_factory=dict)
    is_archived: bool = False


@dataclass
class Plugin(BaseDataModel):
    """Plugin model."""

    name: str = ""
    version: str = "1.0.0"
    description: str = ""
    author: str = ""
    status: Status = Status.PENDING
    priority: Priority = Priority.NORMAL
    config: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)


@dataclass
class Event(BaseDataModel):
    """Event model."""

    event_type: str = ""
    source: str = ""
    target: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    priority: Priority = Priority.NORMAL
    processed: bool = False
    processed_at: datetime | None = None


@dataclass
class Task(BaseDataModel):
    """Task model."""

    name: str = ""
    description: str = ""
    task_type: str = "generic"
    status: Status = Status.PENDING
    priority: Priority = Priority.NORMAL
    scheduled_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    result: Any | None = None
    error_message: str | None = None
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class Metric(BaseDataModel):
    """Metric model."""

    name: str = ""
    value: int | float = 0
    metric_type: str = "gauge"
    tags: dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class Alert(BaseDataModel):
    """Alert model."""

    name: str = ""
    message: str = ""
    severity: str = "info"
    source: str = ""
    resolved: bool = False
    resolved_at: datetime | None = None
    acknowledged: bool = False
    acknowledged_by: str | None = None
    acknowledged_at: datetime | None = None


@dataclass
class Configuration(BaseDataModel):
    """Configuration model."""

    key: str = ""
    value: Any = None
    config_type: str = "string"
    description: str = ""
    is_secret: bool = False
    is_readonly: bool = False
    validation_rules: dict[str, Any] = field(default_factory=dict)


@dataclass
class Session(BaseDataModel):
    """Session model."""

    user_id: str = ""
    session_token: str = ""
    expires_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    ip_address: str = ""
    user_agent: str = ""
    is_active: bool = True
    last_activity: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class Permission(BaseDataModel):
    """Permission model."""

    name: str = ""
    description: str = ""
    resource: str = ""
    action: str = ""
    conditions: dict[str, Any] = field(default_factory=dict)


@dataclass
class Role(BaseDataModel):
    """Role model."""

    name: str = ""
    description: str = ""
    permissions: list[str] = field(default_factory=list)
    is_system_role: bool = False


@dataclass
class ApiResponse:
    """Standard API response model."""

    success: bool = True
    message: str = "Success"
    data: Any | None = None
    error_code: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result: dict[str, Any] = {
            "success": self.success,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
        }

        if self.data is not None:
            result["data"] = self.data

        if self.error_code:
            result["error_code"] = self.error_code

        return result


# Export all models
__all__ = [
    # Enums
    "Priority",
    "Status",
    "LogLevel",
    # Base models
    "BaseModel",
    "ApiResponse",
    # Core models
    "User",
    "Message",
    "Channel",
    "Plugin",
    "Event",
    "Task",
    "Metric",
    "Alert",
    "Configuration",
    "Session",
    "Permission",
    "Role",
]
