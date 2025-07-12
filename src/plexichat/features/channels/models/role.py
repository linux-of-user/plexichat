"""
PlexiChat Role Model

Discord-like role model with comprehensive permission system.
"""

from datetime import datetime
from typing import Optional, Dict, Any
from enum import IntFlag
from sqlmodel import SQLModel, Field, Column
from sqlalchemy import DateTime, Index
import uuid

from ....infrastructure.utils.snowflake import SnowflakeGenerator

# Initialize snowflake generator for roles
role_snowflake = SnowflakeGenerator(datacenter_id=1, worker_id=3)


class Permissions(IntFlag):
    """Permission flags for roles and channels."""
    # General permissions
    CREATE_INSTANT_INVITE = 1 << 0
    KICK_MEMBERS = 1 << 1
    BAN_MEMBERS = 1 << 2
    ADMINISTRATOR = 1 << 3
    MANAGE_CHANNELS = 1 << 4
    MANAGE_GUILD = 1 << 5
    ADD_REACTIONS = 1 << 6
    VIEW_AUDIT_LOG = 1 << 7
    PRIORITY_SPEAKER = 1 << 8
    STREAM = 1 << 9
    VIEW_CHANNEL = 1 << 10
    SEND_MESSAGES = 1 << 11
    SEND_TTS_MESSAGES = 1 << 12
    MANAGE_MESSAGES = 1 << 13
    EMBED_LINKS = 1 << 14
    ATTACH_FILES = 1 << 15
    READ_MESSAGE_HISTORY = 1 << 16
    MENTION_EVERYONE = 1 << 17
    USE_EXTERNAL_EMOJIS = 1 << 18
    VIEW_GUILD_INSIGHTS = 1 << 19
    CONNECT = 1 << 20
    SPEAK = 1 << 21
    MUTE_MEMBERS = 1 << 22
    DEAFEN_MEMBERS = 1 << 23
    MOVE_MEMBERS = 1 << 24
    USE_VAD = 1 << 25
    CHANGE_NICKNAME = 1 << 26
    MANAGE_NICKNAMES = 1 << 27
    MANAGE_ROLES = 1 << 28
    MANAGE_WEBHOOKS = 1 << 29
    MANAGE_EMOJIS_AND_STICKERS = 1 << 30
    USE_APPLICATION_COMMANDS = 1 << 31
    REQUEST_TO_SPEAK = 1 << 32
    MANAGE_EVENTS = 1 << 33
    MANAGE_THREADS = 1 << 34
    CREATE_PUBLIC_THREADS = 1 << 35
    CREATE_PRIVATE_THREADS = 1 << 36
    USE_EXTERNAL_STICKERS = 1 << 37
    SEND_MESSAGES_IN_THREADS = 1 << 38
    USE_EMBEDDED_ACTIVITIES = 1 << 39
    MODERATE_MEMBERS = 1 << 40


class Role(SQLModel, table=True):
    """
    Role model with Discord-like permission system.
    
    Represents a role within a server with specific permissions and appearance.
    """
    __tablename__ = "roles"
    
    # Primary identification
    role_id: str = Field(
        default_factory=lambda: str(role_snowflake.generate_id()),
        primary_key=True,
        index=True,
        description="Unique snowflake ID for the role"
    )
    
    # Server relationship
    server_id: str = Field(
        foreign_key="servers.server_id",
        index=True,
        description="Server this role belongs to"
    )
    
    # Basic role information
    name: str = Field(
        max_length=100,
        index=True,
        description="Role name (1-100 characters)"
    )
    
    # Permission system
    permissions: int = Field(
        default=0,
        description="Permission bitfield for this role"
    )
    
    # Visual appearance
    color: int = Field(
        default=0,
        ge=0,
        le=16777215,  # 0xFFFFFF
        description="Role color as RGB integer (0-16777215)"
    )
    
    # Role behavior
    hoist: bool = Field(
        default=False,
        description="Whether role is displayed separately in member list"
    )
    
    mentionable: bool = Field(
        default=False,
        description="Whether role can be mentioned by everyone"
    )
    
    # Role hierarchy
    position: int = Field(
        default=0,
        index=True,
        description="Position in role hierarchy (higher = more permissions)"
    )
    
    # Role management
    managed: bool = Field(
        default=False,
        description="Whether role is managed by an integration"
    )
    
    # Role icon (premium feature)
    icon_url: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Role icon URL (premium servers only)"
    )
    
    unicode_emoji: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Unicode emoji for the role"
    )
    
    # Role tags (for special roles)
    bot_id: Optional[str] = Field(
        default=None,
        foreign_key="users.id",
        description="Bot ID if this is a bot role"
    )
    
    integration_id: Optional[str] = Field(
        default=None,
        description="Integration ID if this is an integration role"
    )
    
    premium_subscriber: bool = Field(
        default=False,
        description="Whether this is the premium subscriber role"
    )
    
    # Timestamps
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        sa_column=Column(DateTime),
        index=True,
        description="Role creation timestamp"
    )
    
    updated_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime),
        description="Last update timestamp"
    )
    
    # Relationships (will be defined when other models are created)
    # server: Optional["Server"] = Relationship(back_populates="roles")
    # members: List["ServerMember"] = Relationship(back_populates="roles")
    # permission_overwrites: List["PermissionOverwrite"] = Relationship(back_populates="role")
    
    class Config:
        """SQLModel configuration."""
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
    
    def __repr__(self) -> str:
        return f"<Role(role_id='{self.role_id}', name='{self.name}', position={self.position})>"
    
    def has_permission(self, permission: Permissions) -> bool:
        """Check if role has a specific permission."""
        if self.permissions & Permissions.ADMINISTRATOR:
            return True
        return bool(self.permissions & permission)
    
    def add_permission(self, permission: Permissions) -> None:
        """Add a permission to this role."""
        self.permissions |= permission
    
    def remove_permission(self, permission: Permissions) -> None:
        """Remove a permission from this role."""
        self.permissions &= ~permission
    
    def get_color_hex(self) -> str:
        """Get role color as hex string."""
        return f"#{self.color:06x}"
    
    def set_color_hex(self, hex_color: str) -> None:
        """Set role color from hex string."""
        if hex_color.startswith('#'):
            hex_color = hex_color[1:]
        self.color = int(hex_color, 16)
    
    def is_default_role(self) -> bool:
        """Check if this is the @everyone role."""
        return self.name == "@everyone"
    
    def is_higher_than(self, other_role: "Role") -> bool:
        """Check if this role is higher in hierarchy than another role."""
        return self.position > other_role.position
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert role to dictionary."""
        return {
            "role_id": self.role_id,
            "server_id": self.server_id,
            "name": self.name,
            "permissions": str(self.permissions),
            "color": self.color,
            "hoist": self.hoist,
            "mentionable": self.mentionable,
            "position": self.position,
            "managed": self.managed,
            "icon_url": self.icon_url,
            "unicode_emoji": self.unicode_emoji,
            "premium_subscriber": self.premium_subscriber,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# Database indexes for performance
__table_args__ = (
    Index('idx_role_server_position', 'server_id', 'position'),
    Index('idx_role_server_name', 'server_id', 'name'),
    Index('idx_role_permissions', 'permissions'),
    Index('idx_role_managed_bot', 'managed', 'bot_id'),
    Index('idx_role_created_server', 'created_at', 'server_id'),
)
