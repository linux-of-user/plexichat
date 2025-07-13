from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlmodel import JSON, Column, Field, Relationship, SQLModel



from sqlalchemy import DateTime, Index, Text

"""
Guild (Server) models for Discord-like functionality.
Includes servers, channels, roles, and permissions.
"""

class GuildFeature(str, Enum):
    """Guild feature flags."""
    ANIMATED_ICON = "ANIMATED_ICON"
    BANNER = "BANNER"
    COMMERCE = "COMMERCE"
    COMMUNITY = "COMMUNITY"
    DISCOVERABLE = "DISCOVERABLE"
    FEATURABLE = "FEATURABLE"
    INVITE_SPLASH = "INVITE_SPLASH"
    MEMBER_VERIFICATION_GATE = "MEMBER_VERIFICATION_GATE"
    NEWS = "NEWS"
    PARTNERED = "PARTNERED"
    PREVIEW_ENABLED = "PREVIEW_ENABLED"
    VANITY_URL = "VANITY_URL"
    VERIFIED = "VERIFIED"
    VIP_REGIONS = "VIP_REGIONS"
    WELCOME_SCREEN_ENABLED = "WELCOME_SCREEN_ENABLED"

class VerificationLevel(int, Enum):
    """Guild verification levels."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERY_HIGH = 4

class ExplicitContentFilter(int, Enum):
    """Explicit content filter levels."""
    DISABLED = 0
    MEMBERS_WITHOUT_ROLES = 1
    ALL_MEMBERS = 2

class MFALevel(int, Enum):
    """Multi-factor authentication levels."""
    NONE = 0
    ELEVATED = 1

class NSFWLevel(int, Enum):
    """NSFW content levels."""
    DEFAULT = 0
    EXPLICIT = 1
    SAFE = 2
    AGE_RESTRICTED = 3

class Guild(SQLModel, table=True):
    """Guild (Server) model with comprehensive Discord-like features."""
    __tablename__ = "guilds"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=100, index=True)
    description: Optional[str] = Field(sa_column=Column(Text))
    icon: Optional[str] = Field(max_length=255)  # Icon URL/hash
    icon_hash: Optional[str] = Field(max_length=64)
    splash: Optional[str] = Field(max_length=255)  # Splash image
    discovery_splash: Optional[str] = Field(max_length=255)
    banner: Optional[str] = Field(max_length=255)  # Banner image
    
    # Owner and permissions
    owner_id: int = Field(foreign_key="users.id", index=True)
    permissions: Optional[str] = Field(max_length=20)  # Bitfield as string
    
    # Guild settings
    region: str = Field(default="us-west", max_length=50)
    afk_channel_id: Optional[int] = Field(foreign_key="channels.id")
    afk_timeout: int = Field(default=300)  # Seconds
    widget_enabled: bool = Field(default=False)
    widget_channel_id: Optional[int] = Field(foreign_key="channels.id")
    verification_level: VerificationLevel = Field(default=VerificationLevel.NONE)
    default_message_notifications: int = Field(default=0)  # 0=all, 1=mentions
    explicit_content_filter: ExplicitContentFilter = Field(default=ExplicitContentFilter.DISABLED)
    mfa_level: MFALevel = Field(default=MFALevel.NONE)
    nsfw_level: NSFWLevel = Field(default=NSFWLevel.DEFAULT)
    
    # Features and limits
    features: List[str] = Field(default=[], sa_column=Column(JSON))
    max_presences: Optional[int] = Field(default=25000)
    max_members: Optional[int] = Field(default=250000)
    max_video_channel_users: Optional[int] = Field(default=25)
    
    # Vanity URL
    vanity_url_code: Optional[str] = Field(max_length=50, unique=True)
    vanity_url_uses: int = Field(default=0)
    
    # Discovery and community
    preferred_locale: str = Field(default="en-US", max_length=10)
    public_updates_channel_id: Optional[int] = Field(foreign_key="channels.id")
    rules_channel_id: Optional[int] = Field(foreign_key="channels.id")
    system_channel_id: Optional[int] = Field(foreign_key="channels.id")
    system_channel_flags: int = Field(default=0)
    
    # Premium features
    premium_tier: int = Field(default=0)  # 0, 1, 2, 3
    premium_subscription_count: int = Field(default=0)
    premium_progress_bar_enabled: bool = Field(default=False)
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime))
    updated_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    
    # Status
    is_active: bool = Field(default=True, index=True)
    is_large: bool = Field(default=False)  # >250 members
    is_unavailable: bool = Field(default=False)
    
    # Relationships
    channels: List["Channel"] = Relationship(back_populates="guild")
    roles: List["Role"] = Relationship(back_populates="guild")
    members: List["GuildMember"] = Relationship(back_populates="guild")
    emojis: List["Emoji"] = Relationship(back_populates="guild")
    invites: List["Invite"] = Relationship(back_populates="guild")
    webhooks: List["Webhook"] = Relationship(back_populates="guild")
    
    # Indexes
    __table_args__ = (
        Index('idx_guild_owner', 'owner_id'),
        Index('idx_guild_name', 'name'),
        Index('idx_guild_created', 'created_at'),
    )

class GuildMember(SQLModel, table=True):
    """Guild membership with roles and permissions."""
    __tablename__ = "guild_members"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    guild_id: int = Field(foreign_key="guilds.id", index=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    
    # Member info
    nick: Optional[str] = Field(max_length=32)  # Nickname in guild
    avatar: Optional[str] = Field(max_length=255)  # Guild-specific avatar
    
    # Timestamps
    joined_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime))
    premium_since: Optional[datetime] = Field(sa_column=Column(DateTime))  # Nitro boost
    communication_disabled_until: Optional[datetime] = Field(sa_column=Column(DateTime))  # Timeout
    
    # Status
    is_pending: bool = Field(default=False)  # Pending membership screening
    is_deaf: bool = Field(default=False)
    is_mute: bool = Field(default=False)
    
    # Relationships
    guild: Optional[Guild] = Relationship(back_populates="members")
    user: Optional["User"] = Relationship()
    roles: List["Role"] = Relationship(link_table="member_roles")
    
    # Indexes
    __table_args__ = (
        Index('idx_guild_member_unique', 'guild_id', 'user_id', unique=True),
        Index('idx_guild_member_joined', 'joined_at'),
    )

class Role(SQLModel, table=True):
    """Role model with permissions and hierarchy."""
    __tablename__ = "roles"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    guild_id: int = Field(foreign_key="guilds.id", index=True)
    name: str = Field(max_length=100)
    color: int = Field(default=0)  # RGB color as integer
    hoist: bool = Field(default=False)  # Display separately in member list
    icon: Optional[str] = Field(max_length=255)  # Role icon
    unicode_emoji: Optional[str] = Field(max_length=100)  # Unicode emoji
    position: int = Field(default=0, index=True)  # Role hierarchy position
    permissions: str = Field(max_length=20)  # Bitfield as string
    managed: bool = Field(default=False)  # Managed by integration
    mentionable: bool = Field(default=False)
    
    # Premium features
    premium_subscriber: bool = Field(default=False)
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime))
    updated_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    
    # Relationships
    guild: Optional[Guild] = Relationship(back_populates="roles")
    members: List[GuildMember] = Relationship(link_table="member_roles")
    
    # Indexes
    __table_args__ = (
        Index('idx_role_guild_position', 'guild_id', 'position'),
        Index('idx_role_name', 'name'),
    )

# Association table for member roles
class MemberRole(SQLModel, table=True):
    """Association table for member roles."""
    __tablename__ = "member_roles"
    
    member_id: int = Field(foreign_key="guild_members.id", primary_key=True)
    role_id: int = Field(foreign_key="roles.id", primary_key=True)
    assigned_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime))
    assigned_by: Optional[int] = Field(foreign_key="users.id")

class Emoji(SQLModel, table=True):
    """Custom emoji model."""
    __tablename__ = "emojis"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    guild_id: Optional[int] = Field(foreign_key="guilds.id", index=True)
    name: str = Field(max_length=32, index=True)
    image: str = Field(max_length=255)  # Image URL/hash
    
    # Properties
    require_colons: bool = Field(default=True)
    managed: bool = Field(default=False)
    animated: bool = Field(default=False)
    available: bool = Field(default=True)
    
    # Creator info
    user_id: Optional[int] = Field(foreign_key="users.id")
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime))
    
    # Relationships
    guild: Optional[Guild] = Relationship(back_populates="emojis")
    creator: Optional["User"] = Relationship()

class Invite(SQLModel, table=True):
    """Guild invite model."""
    __tablename__ = "invites"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    code: str = Field(max_length=10, unique=True, index=True)
    guild_id: int = Field(foreign_key="guilds.id", index=True)
    channel_id: int = Field(foreign_key="channels.id", index=True)
    inviter_id: Optional[int] = Field(foreign_key="users.id")
    target_user_id: Optional[int] = Field(foreign_key="users.id")
    target_type: Optional[int] = Field(default=None)  # 1=stream, 2=embedded_application
    
    # Invite settings
    max_age: int = Field(default=86400)  # Seconds, 0 = never expire
    max_uses: int = Field(default=0)  # 0 = unlimited
    temporary: bool = Field(default=False)
    unique: bool = Field(default=False)
    
    # Usage tracking
    uses: int = Field(default=0)
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime))
    expires_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    
    # Relationships
    guild: Optional[Guild] = Relationship(back_populates="invites")
    channel: Optional["Channel"] = Relationship()
    inviter: Optional["User"] = Relationship(foreign_keys=[inviter_id])
    target_user: Optional["User"] = Relationship(foreign_keys=[target_user_id])

class GuildSettings(SQLModel, table=True):
    """Extended guild settings and preferences."""
    __tablename__ = "guild_settings"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    guild_id: int = Field(foreign_key="guilds.id", unique=True, index=True)
    
    # Welcome screen
    welcome_screen_enabled: bool = Field(default=False)
    welcome_channels: List[Dict[str, Any]] = Field(default=[], sa_column=Column(JSON))
    description: Optional[str] = Field(sa_column=Column(Text))
    
    # Auto moderation
    auto_mod_enabled: bool = Field(default=False)
    auto_mod_rules: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    
    # Logging
    audit_log_channel_id: Optional[int] = Field(foreign_key="channels.id")
    mod_log_channel_id: Optional[int] = Field(foreign_key="channels.id")
    
    # Custom settings
    custom_settings: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime))
    updated_at: Optional[datetime] = Field(sa_column=Column(DateTime))

class GuildAuditLog(SQLModel, table=True):
    """Guild audit log for tracking changes."""
    __tablename__ = "guild_audit_logs"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    guild_id: int = Field(foreign_key="guilds.id", index=True)
    user_id: Optional[int] = Field(foreign_key="users.id", index=True)
    target_id: Optional[str] = Field(max_length=50)  # ID of affected entity
    
    # Action info
    action_type: int = Field(index=True)  # Action type enum
    changes: List[Dict[str, Any]] = Field(default=[], sa_column=Column(JSON))
    options: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    reason: Optional[str] = Field(sa_column=Column(Text))
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime), index=True)
    
    # Indexes
    __table_args__ = (
        Index('idx_audit_guild_action', 'guild_id', 'action_type'),
        Index('idx_audit_user_action', 'user_id', 'action_type'),
        Index('idx_audit_created', 'created_at'),
    )
