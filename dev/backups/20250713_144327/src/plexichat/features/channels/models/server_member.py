from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlmodel import JSON, Column, Field, SQLModel

from ....infrastructure.utils.snowflake import SnowflakeGenerator

from datetime import datetime
from datetime import datetime
from datetime import datetime


from datetime import datetime
from datetime import datetime
from datetime import datetime

from sqlalchemy import DateTime, Index

"""
PlexiChat Server Member Model

Server membership model tracking user participation in servers.
"""

# Initialize snowflake generator for server members
member_snowflake = SnowflakeGenerator(datacenter_id=1, worker_id=7)


class ServerMember(SQLModel, table=True):
    """
    Server member model tracking user membership in servers.

    Manages roles, nicknames, and membership status for users in servers.
    """
    __tablename__ = "server_members"

    # Primary identification
    member_id: str = Field(
        default_factory=lambda: str(member_snowflake.generate_id()),
        primary_key=True,
        index=True,
        description="Unique snowflake ID for the server membership"
    )

    # Server and user relationships
    server_id: str = Field(
        foreign_key="servers.server_id",
        index=True,
        description="Server the user is a member of"
    )

    user_id: str = Field(
        foreign_key="users.id",
        index=True,
        description="User who is a member"
    )

    # Member customization
    nickname: Optional[str] = Field(
        default=None,
        max_length=32,
        description="Server-specific nickname"
    )

    # Role assignments
    roles: List[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description="List of role IDs assigned to this member"
    )

    # Membership timestamps
    joined_at: datetime = Field(
        default_factory=datetime.utcnow,
        sa_column=Column(DateTime),
        index=True,
        description="When the user joined the server"
    )

    premium_since: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime),
        description="When the user started boosting the server"
    )

    # Membership status
    pending: bool = Field(
        default=False,
        index=True,
        description="Whether member is pending verification"
    )

    # Moderation
    muted: bool = Field(
        default=False,
        index=True,
        description="Whether member is server muted"
    )

    deafened: bool = Field(
        default=False,
        description="Whether member is server deafened"
    )

    # Timeout/discipline
    timeout_until: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime),
        index=True,
        description="When member timeout expires"
    )

    # Member flags
    flags: int = Field(
        default=0,
        description="Member flags bitfield"
    )

    # Avatar override
    avatar_url: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Server-specific avatar URL"
    )

    # Communication disabled
    communication_disabled_until: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime),
        description="When communication restriction expires"
    )

    # Relationships (will be defined when other models are created)
    # server: Optional["Server"] = Relationship(back_populates="members")
    # user: Optional["User"] = Relationship()

    class Config:
        """SQLModel configuration."""
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }

    def __repr__(self) -> str:
        return f"<ServerMember(member_id='{self.member_id}', server_id='{self.server_id}', user_id='{self.user_id}')>"

    def has_role(self, role_id: str) -> bool:
        """Check if member has a specific role."""
        return role_id in self.roles

    def add_role(self, role_id: str) -> None:
        """Add a role to the member."""
        if role_id not in self.roles:
            self.roles.append(role_id)

    def remove_role(self, role_id: str) -> None:
        """Remove a role from the member."""
        if role_id in self.roles:
            self.roles.remove(role_id)

    def is_premium_subscriber(self) -> bool:
        """Check if member is a premium subscriber (booster)."""
        return self.premium_since is not None

    def is_timed_out(self) -> bool:
        """Check if member is currently timed out."""
        if self.timeout_until is None:
            return False
        return from datetime import datetime
datetime.utcnow() < self.timeout_until

    def is_communication_disabled(self) -> bool:
        """Check if member's communication is disabled."""
        if self.communication_disabled_until is None:
            return False
        return from datetime import datetime
datetime.utcnow() < self.communication_disabled_until

    def get_display_name(self, fallback_username: str = None) -> str:
        """Get the display name for this member."""
        return self.nickname or fallback_username or "Unknown User"

    def days_since_joined(self) -> int:
        """Get number of days since member joined."""
        return (from datetime import datetime
datetime.utcnow() - self.joined_at).days

    def to_dict(self) -> Dict[str, Any]:
        """Convert server member to dictionary."""
        return {
            "member_id": self.member_id,
            "server_id": self.server_id,
            "user_id": self.user_id,
            "nickname": self.nickname,
            "roles": self.roles,
            "joined_at": self.joined_at.isoformat() if self.joined_at else None,
            "premium_since": self.premium_since.isoformat() if self.premium_since else None,
            "pending": self.pending,
            "muted": self.muted,
            "deafened": self.deafened,
            "timeout_until": self.timeout_until.isoformat() if self.timeout_until else None,
            "communication_disabled_until": self.communication_disabled_until.isoformat() if self.communication_disabled_until else None,
            "avatar_url": self.avatar_url,
            "flags": self.flags,
        }


# Database indexes for performance
__table_args__ = (
    Index('idx_member_server_user', 'server_id', 'user_id', unique=True),
    Index('idx_member_server_joined', 'server_id', 'joined_at'),
    Index('idx_member_user_joined', 'user_id', 'joined_at'),
    Index('idx_member_pending_server', 'pending', 'server_id'),
    Index('idx_member_premium_server', 'premium_since', 'server_id'),
    Index('idx_member_timeout', 'timeout_until'),
    Index('idx_member_communication_disabled', 'communication_disabled_until'),
)
