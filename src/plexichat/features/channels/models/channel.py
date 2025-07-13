"""
PlexiChat Channel Model

Discord-like channel model with comprehensive features for text, voice, and special channels.
"""

from datetime import datetime
from enum import IntEnum
from typing import Any, Dict, List, Optional

from sqlalchemy import DateTime, Index, Text
from sqlmodel import JSON, Column, Field, SQLModel

from ....infrastructure.utils.snowflake import SnowflakeGenerator

# Initialize snowflake generator for channels
channel_snowflake = SnowflakeGenerator(datacenter_id=1, worker_id=2)


class ChannelType(IntEnum):
    """Channel types matching Discord API."""
    GUILD_TEXT = 0
    DM = 1
    GUILD_VOICE = 2
    GROUP_DM = 3
    GUILD_CATEGORY = 4
    GUILD_ANNOUNCEMENT = 5
    ANNOUNCEMENT_THREAD = 10
    PUBLIC_THREAD = 11
    PRIVATE_THREAD = 12
    GUILD_STAGE_VOICE = 13
    GUILD_DIRECTORY = 14
    GUILD_FORUM = 15


class VideoQualityMode(IntEnum):
    """Video quality modes for voice channels."""
    AUTO = 1
    FULL = 2


class SortOrderType(IntEnum):
    """Sort order for forum channels."""
    LATEST_ACTIVITY = 0
    CREATION_DATE = 1


class Channel(SQLModel, table=True):
    """
    Channel model with Discord-like features.
    
    Supports text channels, voice channels, categories, threads, and forums.
    """
    __tablename__ = "channels"
    
    # Primary identification
    channel_id: str = Field(
        default_factory=lambda: str(channel_snowflake.generate_id()),
        primary_key=True,
        index=True,
        description="Unique snowflake ID for the channel"
    )
    
    # Server relationship
    server_id: str = Field(
        foreign_key="servers.server_id",
        index=True,
        description="Server this channel belongs to"
    )
    
    # Basic channel information
    name: str = Field(
        max_length=100,
        index=True,
        description="Channel name (1-100 characters)"
    )
    
    type: ChannelType = Field(
        default=ChannelType.GUILD_TEXT,
        index=True,
        description="Type of channel"
    )
    
    topic: Optional[str] = Field(
        default=None,
        sa_column=Column(Text),
        description="Channel topic/description"
    )
    
    # Channel organization
    position: int = Field(
        default=0,
        index=True,
        description="Sorting position of the channel"
    )
    
    parent_id: Optional[str] = Field(
        default=None,
        foreign_key="channels.channel_id",
        index=True,
        description="Parent category channel ID"
    )
    
    # Voice channel specific settings
    user_limit: Optional[int] = Field(
        default=0,
        ge=0,
        le=99,
        description="User limit for voice channels (0 = unlimited)"
    )
    
    bitrate: Optional[int] = Field(
        default=64000,
        ge=8000,
        le=384000,
        description="Voice channel bitrate in bits per second"
    )
    
    video_quality_mode: Optional[VideoQualityMode] = Field(
        default=VideoQualityMode.AUTO,
        description="Video quality mode for voice channels"
    )
    
    rtc_region: Optional[str] = Field(
        default=None,
        max_length=50,
        description="Voice region override"
    )
    
    # Channel moderation
    nsfw: bool = Field(
        default=False,
        index=True,
        description="Whether channel is marked as NSFW"
    )
    
    rate_limit_per_user: int = Field(
        default=0,
        ge=0,
        le=21600,
        description="Rate limit per user in seconds (slowmode)"
    )
    
    # Thread specific settings
    owner_id: Optional[str] = Field(
        default=None,
        foreign_key="users.id",
        description="Thread owner (for thread channels)"
    )
    
    message_count: Optional[int] = Field(
        default=0,
        ge=0,
        description="Approximate message count (for threads)"
    )
    
    member_count: Optional[int] = Field(
        default=0,
        ge=0,
        description="Approximate member count (for threads)"
    )
    
    # Thread metadata
    thread_metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        sa_column=Column(JSON),
        description="Thread-specific metadata"
    )
    
    # Forum channel settings
    default_auto_archive_duration: Optional[int] = Field(
        default=1440,
        description="Default auto archive duration in minutes"
    )
    
    default_thread_rate_limit_per_user: Optional[int] = Field(
        default=0,
        ge=0,
        le=21600,
        description="Default rate limit for threads in forum"
    )
    
    default_sort_order: Optional[SortOrderType] = Field(
        default=SortOrderType.LATEST_ACTIVITY,
        description="Default sort order for forum posts"
    )
    
    # Channel permissions and features
    permissions_synced: bool = Field(
        default=True,
        description="Whether permissions are synced with parent category"
    )
    
    # System channels
    system_channel_flags: int = Field(
        default=0,
        description="System channel flags bitfield"
    )
    
    # Channel status
    archived: bool = Field(
        default=False,
        index=True,
        description="Whether channel is archived"
    )
    
    locked: bool = Field(
        default=False,
        description="Whether channel is locked"
    )
    
    invitable: bool = Field(
        default=True,
        description="Whether non-moderators can add users to thread"
    )
    
    # Timestamps
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        sa_column=Column(DateTime),
        index=True,
        description="Channel creation timestamp"
    )
    
    updated_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime),
        description="Last update timestamp"
    )
    
    last_message_id: Optional[str] = Field(
        default=None,
        foreign_key="messages.message_id",
        description="ID of the last message sent"
    )
    
    last_pin_timestamp: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime),
        description="When the last pinned message was pinned"
    )
    
    # Auto-archive settings
    auto_archive_duration: Optional[int] = Field(
        default=1440,
        description="Auto archive duration in minutes"
    )
    
    archive_timestamp: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime),
        description="When the thread was archived"
    )
    
    # Forum channel tags
    available_tags: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        sa_column=Column(JSON),
        description="Available tags for forum posts"
    )
    
    # Applied tags (for forum posts)
    applied_tags: Optional[List[str]] = Field(
        default=None,
        sa_column=Column(JSON),
        description="Applied tag IDs (for forum posts)"
    )
    
    # Relationships (will be defined when other models are created)
    # server: Optional["Server"] = Relationship(back_populates="channels")
    # messages: List["Message"] = Relationship(back_populates="channel")
    # permission_overwrites: List["PermissionOverwrite"] = Relationship(back_populates="channel")
    # parent: Optional["Channel"] = Relationship(back_populates="children")
    # children: List["Channel"] = Relationship(back_populates="parent")
    
    class Config:
        """SQLModel configuration."""
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
    
    def __repr__(self) -> str:
        return f"<Channel(channel_id='{self.channel_id}', name='{self.name}', type={self.type})>"
    
    def is_text_channel(self) -> bool:
        """Check if this is a text-based channel."""
        return self.type in [
            ChannelType.GUILD_TEXT,
            ChannelType.GUILD_ANNOUNCEMENT,
            ChannelType.ANNOUNCEMENT_THREAD,
            ChannelType.PUBLIC_THREAD,
            ChannelType.PRIVATE_THREAD,
            ChannelType.GUILD_FORUM
        ]
    
    def is_voice_channel(self) -> bool:
        """Check if this is a voice-based channel."""
        return self.type in [
            ChannelType.GUILD_VOICE,
            ChannelType.GUILD_STAGE_VOICE
        ]
    
    def is_thread(self) -> bool:
        """Check if this is a thread channel."""
        return self.type in [
            ChannelType.ANNOUNCEMENT_THREAD,
            ChannelType.PUBLIC_THREAD,
            ChannelType.PRIVATE_THREAD
        ]
    
    def is_category(self) -> bool:
        """Check if this is a category channel."""
        return self.type == ChannelType.GUILD_CATEGORY
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert channel to dictionary."""
        return {
            "channel_id": self.channel_id,
            "server_id": self.server_id,
            "name": self.name,
            "type": self.type,
            "topic": self.topic,
            "position": self.position,
            "parent_id": self.parent_id,
            "user_limit": self.user_limit,
            "bitrate": self.bitrate,
            "nsfw": self.nsfw,
            "rate_limit_per_user": self.rate_limit_per_user,
            "permissions_synced": self.permissions_synced,
            "archived": self.archived,
            "locked": self.locked,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# Database indexes for performance
__table_args__ = (
    Index('idx_channel_server_type', 'server_id', 'type'),
    Index('idx_channel_server_position', 'server_id', 'position'),
    Index('idx_channel_parent_position', 'parent_id', 'position'),
    Index('idx_channel_type_archived', 'type', 'archived'),
    Index('idx_channel_created_server', 'created_at', 'server_id'),
)
