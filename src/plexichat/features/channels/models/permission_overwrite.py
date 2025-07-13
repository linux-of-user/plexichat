from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, Index
from sqlmodel import Column, Field, SQLModel

from ....infrastructure.utils.snowflake import SnowflakeGenerator
from .role import Permissions

"""
PlexiChat Permission Overwrite Model

Channel-specific permission overrides for roles and users.
"""

# Initialize snowflake generator for permission overwrites
overwrite_snowflake = SnowflakeGenerator(datacenter_id=1, worker_id=4)


class OverwriteType(str, Enum):
    """Permission overwrite target types."""
    ROLE = "role"
    MEMBER = "member"


class PermissionOverwrite(SQLModel, table=True):
    """
    Permission overwrite model for channel-specific permissions.
    
    Allows fine-grained control over permissions for specific roles or users in channels.
    """
    __tablename__ = "permission_overwrites"
    
    # Primary identification
    overwrite_id: str = Field(
        default_factory=lambda: str(overwrite_snowflake.generate_id()),
        primary_key=True,
        index=True,
        description="Unique snowflake ID for the permission overwrite"
    )
    
    # Channel relationship
    channel_id: str = Field(
        foreign_key="channels.channel_id",
        index=True,
        description="Channel this overwrite applies to"
    )
    
    # Target (role or user)
    target_id: str = Field(
        index=True,
        description="ID of the role or user this overwrite applies to"
    )
    
    target_type: OverwriteType = Field(
        index=True,
        description="Whether this overwrite targets a role or member"
    )
    
    # Permission overrides
    allow: int = Field(
        default=0,
        description="Permissions explicitly allowed (bitfield)"
    )
    
    deny: int = Field(
        default=0,
        description="Permissions explicitly denied (bitfield)"
    )
    
    # Timestamps
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        sa_column=Column(DateTime),
        index=True,
        description="Overwrite creation timestamp"
    )
    
    updated_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime),
        description="Last update timestamp"
    )
    
    # Relationships (will be defined when other models are created)
    # channel: Optional["Channel"] = Relationship(back_populates="permission_overwrites")
    
    class Config:
        """SQLModel configuration."""
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
    
    def __repr__(self) -> str:
        return f"<PermissionOverwrite(overwrite_id='{self.overwrite_id}', target_type='{self.target_type}', target_id='{self.target_id}')>"
    
    def has_permission_allowed(self, permission: Permissions) -> bool:
        """Check if a permission is explicitly allowed."""
        return bool(self.allow & permission)
    
    def has_permission_denied(self, permission: Permissions) -> bool:
        """Check if a permission is explicitly denied."""
        return bool(self.deny & permission)
    
    def allow_permission(self, permission: Permissions) -> None:
        """Explicitly allow a permission."""
        self.allow |= permission
        self.deny &= ~permission  # Remove from deny if present
    
    def deny_permission(self, permission: Permissions) -> None:
        """Explicitly deny a permission."""
        self.deny |= permission
        self.allow &= ~permission  # Remove from allow if present
    
    def clear_permission(self, permission: Permissions) -> None:
        """Clear a permission (neither allow nor deny)."""
        self.allow &= ~permission
        self.deny &= ~permission
    
    def get_effective_permission(self, permission: Permissions) -> Optional[bool]:
        """
        Get the effective permission state.
        
        Returns:
            True if explicitly allowed
            False if explicitly denied
            None if not overridden (inherit from role/default)
        """
        if self.has_permission_denied(permission):
            return False
        elif self.has_permission_allowed(permission):
            return True
        else:
            return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert permission overwrite to dictionary."""
        return {
            "overwrite_id": self.overwrite_id,
            "channel_id": self.channel_id,
            "target_id": self.target_id,
            "target_type": self.target_type,
            "allow": str(self.allow),
            "deny": str(self.deny),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# Database indexes for performance
__table_args__ = (
    Index('idx_overwrite_channel_target', 'channel_id', 'target_id', 'target_type'),
    Index('idx_overwrite_target_type', 'target_type', 'target_id'),
    Index('idx_overwrite_permissions', 'allow', 'deny'),
    Index('idx_overwrite_created_channel', 'created_at', 'channel_id'),
)
