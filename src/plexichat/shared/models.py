"""
import time
PlexiChat Shared Models

Common data models and schemas used across the application.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4


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
class BaseModel:
    """Base model with common fields."""
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def update_timestamp(self):
        """Update the updated_at timestamp."""
        self.updated_at = datetime.now(timezone.utc)


@dataclass
class User(BaseModel):
    """User model."""
    username: str = ""
    email: str = ""
    display_name: str = ""
    is_active: bool = True
    is_admin: bool = False
    last_login: Optional[datetime] = None
    preferences: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Message(BaseModel):
    """Message model."""
    content: str = ""
    user_id: str = ""
    channel_id: str = ""
    message_type: str = "text"
    attachments: List[str] = field(default_factory=list)
    reactions: Dict[str, List[str]] = field(default_factory=dict)
    thread_id: Optional[str] = None
    reply_to: Optional[str] = None
    edited_at: Optional[datetime] = None
    deleted_at: Optional[datetime] = None


@dataclass
class Channel(BaseModel):
    """Channel model."""
    name: str = ""
    description: str = ""
    channel_type: str = "public"
    owner_id: str = ""
    members: List[str] = field(default_factory=list)
    settings: Dict[str, Any] = field(default_factory=dict)
    is_archived: bool = False


@dataclass
class Plugin(BaseModel):
    """Plugin model."""
    name: str = ""
    version: str = "1.0.0"
    description: str = ""
    author: str = ""
    status: Status = Status.PENDING
    priority: Priority = Priority.NORMAL
    config: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)


@dataclass
class Event(BaseModel):
    """Event model."""
    event_type: str = ""
    source: str = ""
    target: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    priority: Priority = Priority.NORMAL
    processed: bool = False
    processed_at: Optional[datetime] = None


@dataclass
class Task(BaseModel):
    """Task model."""
    name: str = ""
    description: str = ""
    task_type: str = "generic"
    status: Status = Status.PENDING
    priority: Priority = Priority.NORMAL
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Any] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class Metric(BaseModel):
    """Metric model."""
    name: str = ""
    value: Union[int, float] = 0
    metric_type: str = "gauge"
    tags: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Alert(BaseModel):
    """Alert model."""
    name: str = ""
    message: str = ""
    severity: str = "info"
    source: str = ""
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None


@dataclass
class Configuration(BaseModel):
    """Configuration model."""
    key: str = ""
    value: Any = None
    config_type: str = "string"
    description: str = ""
    is_secret: bool = False
    is_readonly: bool = False
    validation_rules: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Session(BaseModel):
    """Session model."""
    user_id: str = ""
    session_token: str = ""
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ip_address: str = ""
    user_agent: str = ""
    is_active: bool = True
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Permission(BaseModel):
    """Permission model."""
    name: str = ""
    description: str = ""
    resource: str = ""
    action: str = ""
    conditions: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Role(BaseModel):
    """Role model."""
    name: str = ""
    description: str = ""
    permissions: List[str] = field(default_factory=list)
    is_system_role: bool = False


@dataclass
class ApiResponse:
    """Standard API response model."""
    success: bool = True
    message: str = "Success"
    data: Optional[Any] = None
    error_code: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "success": self.success,
            "message": self.message,
            "timestamp": self.timestamp.isoformat()
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
