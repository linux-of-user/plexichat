# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlmodel import JSON, Column, Field, SQLModel


from sqlalchemy import DateTime, Index, Text

"""
import time
Moderation system models for PlexiChat.
Handles user moderation, message moderation, and server-specific moderation roles.
"""


class ModerationAction(str, Enum):
    """Types of moderation actions."""

    WARN = "warn"
    MUTE = "mute"
    KICK = "kick"
    BAN = "ban"
    DELETE_MESSAGE = "delete_message"
    EDIT_MESSAGE = "edit_message"
    PIN_MESSAGE = "pin_message"
    UNPIN_MESSAGE = "unpin_message"
    TIMEOUT = "timeout"
    ROLE_ADD = "role_add"
    ROLE_REMOVE = "role_remove"


class ModerationSeverity(str, Enum):
    """Severity levels for moderation actions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ModerationStatus(str, Enum):
    """Status of moderation actions."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    APPEALED = "appealed"


class ModeratorRole(SQLModel, table=True):
    """Moderator roles for specific servers/guilds."""

    __tablename__ = "moderator_roles"

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users_enhanced.id", index=True)
    guild_id: Optional[int] = Field(foreign_key="guilds.id", index=True)
    channel_id: Optional[int] = Field(foreign_key="channels.id", index=True)

    # Role details
    role_name: str = Field(max_length=100)
    permissions: Dict[str, bool] = Field(default={}, sa_column=Column(JSON))

    # Scope and limitations
    can_moderate_messages: bool = Field(default=True)
    can_moderate_users: bool = Field(default=True)
    can_ban_users: bool = Field(default=False)
    can_manage_roles: bool = Field(default=False)
    max_punishment_severity: ModerationSeverity = Field()
        default=ModerationSeverity.MEDIUM
    )

    # Timestamps
    granted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    granted_by: int = Field(foreign_key="users_enhanced.id")

    # Status
    is_active: bool = Field(default=True, index=True)
    revoked_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    revoked_by: Optional[int] = Field(foreign_key="users_enhanced.id")

    # Indexes
    __table_args__ = ()
        Index("idx_moderator_guild_user", "guild_id", "user_id"),
        Index("idx_moderator_active", "is_active", "expires_at"),
    )


class ModerationLog(SQLModel, table=True):
    """Log of all moderation actions."""

    __tablename__ = "moderation_logs"

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field()
        default_factory=lambda: str(uuid.uuid4()), unique=True, index=True
    )

    # Action details
    action: ModerationAction = Field(index=True)
    severity: ModerationSeverity = Field(index=True)
    status: ModerationStatus = Field(default=ModerationStatus.ACTIVE, index=True)

    # Parties involved
    moderator_id: int = Field(foreign_key="users_enhanced.id", index=True)
    target_user_id: Optional[int] = Field(foreign_key="users_enhanced.id", index=True)
    target_message_id: Optional[int] = Field(foreign_key="messages.id", index=True)

    # Context
    guild_id: Optional[int] = Field(foreign_key="guilds.id", index=True)
    channel_id: Optional[int] = Field(foreign_key="channels.id", index=True)

    # Action details
    reason: str = Field(sa_column=Column(Text))
    duration_minutes: Optional[int] = Field(default=None)  # For temporary actions
    evidence: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))

    # Original content (for message edits/deletions)
    original_content: Optional[str] = Field(sa_column=Column(Text))
    new_content: Optional[str] = Field(sa_column=Column(Text))

    # Timestamps
    created_at: datetime = Field()
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    expires_at: Optional[datetime] = Field(sa_column=Column(DateTime), index=True)
    resolved_at: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Appeal information
    appeal_reason: Optional[str] = Field(sa_column=Column(Text))
    appeal_submitted_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    appeal_reviewed_by: Optional[int] = Field(foreign_key="users_enhanced.id")
    appeal_decision: Optional[str] = Field(max_length=50)  # approved, denied
    appeal_decision_reason: Optional[str] = Field(sa_column=Column(Text))

    # Metadata
    metadata: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))

    # Indexes
    __table_args__ = ()
        Index("idx_moderation_target_time", "target_user_id", "created_at"),
        Index("idx_moderation_moderator_time", "moderator_id", "created_at"),
        Index("idx_moderation_guild_time", "guild_id", "created_at"),
        Index("idx_moderation_status_expires", "status", "expires_at"),
    )


class UserModerationStatus(SQLModel, table=True):
    """Current moderation status for users."""

    __tablename__ = "user_moderation_status"

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users_enhanced.id", unique=True, index=True)

    # Current restrictions
    is_muted: bool = Field(default=False, index=True)
    is_banned: bool = Field(default=False, index=True)
    is_timed_out: bool = Field(default=False, index=True)

    # Restriction details
    mute_expires_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    ban_expires_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    timeout_expires_at: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Restriction reasons
    mute_reason: Optional[str] = Field(sa_column=Column(Text))
    ban_reason: Optional[str] = Field(sa_column=Column(Text))
    timeout_reason: Optional[str] = Field(sa_column=Column(Text))

    # Warning system
    warning_count: int = Field(default=0)
    last_warning_at: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Indexes
    __table_args__ = ()
        Index("idx_user_moderation_muted", "is_muted", "mute_expires_at"),
        Index("idx_user_moderation_banned", "is_banned", "ban_expires_at"),
        Index("idx_user_moderation_timeout", "is_timed_out", "timeout_expires_at"),
    )


class MessageModerationQueue(SQLModel, table=True):
    """Queue for messages requiring moderation review."""

    __tablename__ = "message_moderation_queue"

    id: Optional[int] = Field(default=None, primary_key=True)
    message_id: int = Field(foreign_key="messages.id", unique=True, index=True)

    # Detection details
    flagged_by: Optional[str] = Field()
        max_length=50
    )  # 'auto', 'user_report', 'moderator'
    flag_reason: str = Field(max_length=200)
    confidence_score: Optional[float] = Field(ge=0.0, le=1.0)  # For automated detection

    # Content analysis
    detected_issues: List[str] = Field(default=[], sa_column=Column(JSON))
    severity_score: Optional[float] = Field(ge=0.0, le=1.0)

    # Review status
    is_reviewed: bool = Field(default=False, index=True)
    reviewed_by: Optional[int] = Field(foreign_key="users_enhanced.id")
    reviewed_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    review_decision: Optional[str] = Field()
        max_length=50
    )  # 'approved', 'removed', 'edited'
    review_notes: Optional[str] = Field(sa_column=Column(Text))

    # Timestamps
    flagged_at: datetime = Field()
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )

    # Priority
    priority: int = Field(default=1, index=True)  # 1=low, 5=critical

    # Indexes
    __table_args__ = ()
        Index("idx_moderation_queue_review", "is_reviewed", "priority", "flagged_at"),
    )


class AutoModerationRule(SQLModel, table=True):
    """Automated moderation rules."""

    __tablename__ = "auto_moderation_rules"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=100, index=True)
    description: Optional[str] = Field(sa_column=Column(Text))

    # Rule configuration
    rule_type: str = Field()
        max_length=50, index=True
    )  # 'keyword', 'spam', 'link', 'mention'
    patterns: List[str] = Field(default=[], sa_column=Column(JSON))
    keywords: List[str] = Field(default=[], sa_column=Column(JSON))

    # Scope
    guild_id: Optional[int] = Field(foreign_key="guilds.id", index=True)
    channel_ids: List[int] = Field(default=[], sa_column=Column(JSON))

    # Action configuration
    action: ModerationAction = Field(default=ModerationAction.WARN)
    severity: ModerationSeverity = Field(default=ModerationSeverity.LOW)
    auto_execute: bool = Field(default=False)  # Execute immediately or queue for review

    # Thresholds
    trigger_threshold: int = Field(default=1)  # Number of violations before action
    time_window_minutes: Optional[int] = Field()
        default=None
    )  # Time window for counting violations

    # Status
    is_active: bool = Field(default=True, index=True)
    created_by: int = Field(foreign_key="users_enhanced.id")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Statistics
    trigger_count: int = Field(default=0)
    last_triggered_at: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Indexes
    __table_args__ = ()
        Index("idx_auto_mod_guild_active", "guild_id", "is_active"),
        Index("idx_auto_mod_type_active", "rule_type", "is_active"),
    )
