"""
PlexiChat Server Model

Discord-like server (guild) model with comprehensive features.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import IntEnum
from sqlmodel import SQLModel, Field, Relationship, JSON, Column
from sqlalchemy import Text, DateTime, Index
import uuid

from ....infrastructure.utils.snowflake import SnowflakeGenerator

# Initialize snowflake generator for servers
server_snowflake = SnowflakeGenerator(datacenter_id=1, worker_id=1)


class VerificationLevel(IntEnum):
    """Server verification levels."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERY_HIGH = 4


class DefaultMessageNotifications(IntEnum):
    """Default message notification settings."""
    ALL_MESSAGES = 0
    ONLY_MENTIONS = 1


class ExplicitContentFilter(IntEnum):
    """Explicit content filter levels."""
    DISABLED = 0
    MEMBERS_WITHOUT_ROLES = 1
    ALL_MEMBERS = 2


class Server(SQLModel, table=True):
    """
    Server (Guild) model with Discord-like features.
    
    Represents a PlexiChat server with channels, roles, and members.
    """
    __tablename__ = "servers"
    
    # Primary identification
    server_id: str = Field(
        default_factory=lambda: str(server_snowflake.generate_id()),
        primary_key=True,
        index=True,
        description="Unique snowflake ID for the server"
    )
    
    # Basic server information
    name: str = Field(
        max_length=100,
        index=True,
        description="Server name (2-100 characters)"
    )
    
    owner_id: str = Field(
        foreign_key="users.id",
        index=True,
        description="User ID of the server owner"
    )
    
    # Visual customization
    icon_url: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Server icon URL"
    )
    
    banner_url: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Server banner URL"
    )
    
    # Server settings
    region: Optional[str] = Field(
        default="us-east",
        max_length=50,
        index=True,
        description="Server voice region"
    )
    
    verification_level: VerificationLevel = Field(
        default=VerificationLevel.NONE,
        index=True,
        description="Verification level required for members"
    )
    
    default_message_notifications: DefaultMessageNotifications = Field(
        default=DefaultMessageNotifications.ALL_MESSAGES,
        description="Default notification setting for new members"
    )
    
    explicit_content_filter: ExplicitContentFilter = Field(
        default=ExplicitContentFilter.DISABLED,
        description="Explicit content filter level"
    )
    
    # Additional server features
    description: Optional[str] = Field(
        default=None,
        sa_column=Column(Text),
        description="Server description"
    )
    
    splash_url: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Server invite splash image URL"
    )
    
    discovery_splash_url: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Server discovery splash image URL"
    )
    
    # Server features and limits
    max_members: int = Field(
        default=100000,
        ge=1,
        description="Maximum number of members"
    )
    
    max_presences: Optional[int] = Field(
        default=None,
        ge=1,
        description="Maximum number of online members"
    )
    
    max_video_channel_users: Optional[int] = Field(
        default=25,
        ge=1,
        description="Maximum users in video channels"
    )
    
    # Server status
    unavailable: bool = Field(
        default=False,
        index=True,
        description="Whether server is unavailable due to outage"
    )
    
    widget_enabled: bool = Field(
        default=False,
        description="Whether server widget is enabled"
    )
    
    widget_channel_id: Optional[str] = Field(
        default=None,
        foreign_key="channels.channel_id",
        description="Channel ID for server widget"
    )
    
    # Moderation settings
    mfa_level: int = Field(
        default=0,
        ge=0,
        le=1,
        description="MFA level required for moderation actions"
    )
    
    # Premium features
    premium_tier: int = Field(
        default=0,
        ge=0,
        le=3,
        description="Server boost level"
    )
    
    premium_subscription_count: int = Field(
        default=0,
        ge=0,
        description="Number of premium subscriptions"
    )
    
    # Vanity URL
    vanity_url_code: Optional[str] = Field(
        default=None,
        max_length=50,
        unique=True,
        index=True,
        description="Custom vanity URL code"
    )
    
    # System channels
    system_channel_id: Optional[str] = Field(
        default=None,
        foreign_key="channels.channel_id",
        description="System messages channel"
    )
    
    rules_channel_id: Optional[str] = Field(
        default=None,
        foreign_key="channels.channel_id",
        description="Rules channel for community servers"
    )
    
    public_updates_channel_id: Optional[str] = Field(
        default=None,
        foreign_key="channels.channel_id",
        description="Public updates channel"
    )
    
    # AFK settings
    afk_channel_id: Optional[str] = Field(
        default=None,
        foreign_key="channels.channel_id",
        description="AFK voice channel"
    )
    
    afk_timeout: int = Field(
        default=300,
        ge=60,
        le=3600,
        description="AFK timeout in seconds"
    )
    
    # Timestamps
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        sa_column=Column(DateTime),
        index=True,
        description="Server creation timestamp"
    )
    
    updated_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime),
        description="Last update timestamp"
    )
    
    # Metadata
    features: List[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description="Server features list"
    )
    
    preferred_locale: str = Field(
        default="en-US",
        max_length=10,
        description="Preferred locale for the server"
    )
    
    # Relationships (will be defined when other models are created)
    # channels: List["Channel"] = Relationship(back_populates="server")
    # roles: List["Role"] = Relationship(back_populates="server")
    # members: List["ServerMember"] = Relationship(back_populates="server")
    
    class Config:
        """SQLModel configuration."""
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
    
    def __repr__(self) -> str:
        return f"<Server(server_id='{self.server_id}', name='{self.name}')>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert server to dictionary."""
        return {
            "server_id": self.server_id,
            "name": self.name,
            "owner_id": self.owner_id,
            "icon_url": self.icon_url,
            "banner_url": self.banner_url,
            "region": self.region,
            "verification_level": self.verification_level,
            "default_message_notifications": self.default_message_notifications,
            "explicit_content_filter": self.explicit_content_filter,
            "description": self.description,
            "max_members": self.max_members,
            "unavailable": self.unavailable,
            "widget_enabled": self.widget_enabled,
            "mfa_level": self.mfa_level,
            "premium_tier": self.premium_tier,
            "vanity_url_code": self.vanity_url_code,
            "features": self.features,
            "preferred_locale": self.preferred_locale,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# Database indexes for performance
__table_args__ = (
    Index('idx_server_owner_created', 'owner_id', 'created_at'),
    Index('idx_server_region_verification', 'region', 'verification_level'),
    Index('idx_server_premium_tier', 'premium_tier'),
    Index('idx_server_features', 'features'),
)
