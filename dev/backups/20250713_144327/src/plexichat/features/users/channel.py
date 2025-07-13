from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlmodel import JSON, Column, Field, Relationship, SQLModel


from sqlalchemy import DateTime, Index, Text

"""
Channel models for Discord-like functionality.
Includes text channels, voice channels, categories, threads, and permissions.
"""


class ChannelType(int, Enum):
    """Channel types matching Discord API."""

    GUILD_TEXT = 0
    DM = 1
    GUILD_VOICE = 2
    GROUP_DM = 3
    GUILD_CATEGORY = 4
    GUILD_NEWS = 5
    GUILD_STORE = 6
    GUILD_NEWS_THREAD = 10
    GUILD_PUBLIC_THREAD = 11
    GUILD_PRIVATE_THREAD = 12
    GUILD_STAGE_VOICE = 13
    GUILD_DIRECTORY = 14
    GUILD_FORUM = 15


class VideoQualityMode(int, Enum):
    """Video quality modes for voice channels."""

    AUTO = 1
    FULL = 2


class SortOrderType(int, Enum):
    """Sort order for forum channels."""

    LATEST_ACTIVITY = 0
    CREATION_DATE = 1


class Channel(SQLModel, table=True):
    """Channel model with comprehensive Discord-like features."""

    __tablename__ = "channels"

    id: Optional[int] = Field(default=None, primary_key=True)
    type: ChannelType = Field(index=True)
    guild_id: Optional[int] = Field(foreign_key="guilds.id", index=True)
    position: Optional[int] = Field(index=True)
    name: Optional[str] = Field(max_length=100, index=True)
    topic: Optional[str] = Field(sa_column=Column(Text))
    nsfw: bool = Field(default=False)

    # Rate limiting
    rate_limit_per_user: int = Field(default=0)  # Slowmode in seconds

    # Voice channel specific
    bitrate: Optional[int] = Field(default=64000)  # Voice bitrate
    user_limit: Optional[int] = Field(default=0)  # 0 = unlimited
    video_quality_mode: Optional[VideoQualityMode] = Field(
        default=VideoQualityMode.AUTO
    )
    rtc_region: Optional[str] = Field(max_length=50)

    # Thread specific
    parent_id: Optional[int] = Field(foreign_key="channels.id", index=True)
    owner_id: Optional[int] = Field(foreign_key="users.id")
    thread_metadata: Optional[Dict[str, Any]] = Field(sa_column=Column(JSON))
    member_count: Optional[int] = Field(default=0)
    message_count: Optional[int] = Field(default=0)

    # Forum channel specific
    available_tags: List[Dict[str, Any]] = Field(default=[], sa_column=Column(JSON))
    applied_tags: List[int] = Field(default=[], sa_column=Column(JSON))
    default_reaction_emoji: Optional[Dict[str, Any]] = Field(sa_column=Column(JSON))
    default_thread_rate_limit_per_user: int = Field(default=0)
    default_sort_order: Optional[SortOrderType] = Field(
        default=SortOrderType.LATEST_ACTIVITY
    )

    # Permissions
    permission_overwrites: List[Dict[str, Any]] = Field(
        default=[], sa_column=Column(JSON)
    )

    # Timestamps
    last_message_id: Optional[int] = Field(foreign_key="messages.id")
    last_pin_timestamp: Optional[datetime] = Field(sa_column=Column(DateTime))
    created_at: datetime = Field(
        default_factory=datetime.utcnow, sa_column=Column(DateTime)
    )
    updated_at: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Status
    is_active: bool = Field(default=True, index=True)

    # Relationships
    guild: Optional["Guild"] = Relationship(back_populates="channels")
    parent: Optional["Channel"] = Relationship(
        sa_relationship_kwargs={"remote_side": "Channel.id"}
    )
    children: List["Channel"] = Relationship(
        sa_relationship_kwargs={"remote_side": "Channel.parent_id"}
    )
    messages: List["Message"] = Relationship(back_populates="channel")
    webhooks: List["Webhook"] = Relationship(back_populates="channel")

    # Indexes
    __table_args__ = (
        Index("idx_channel_guild_type", "guild_id", "type"),
        Index("idx_channel_parent", "parent_id"),
        Index("idx_channel_position", "position"),
    )


class ChannelPermissionOverwrite(SQLModel, table=True):
    """Channel permission overwrites for roles and users."""

    __tablename__ = "channel_permission_overwrites"

    id: Optional[int] = Field(default=None, primary_key=True)
    channel_id: int = Field(foreign_key="channels.id", index=True)
    target_id: int = Field(index=True)  # Role or User ID
    target_type: int = Field()  # 0 = role, 1 = member
    allow: str = Field(max_length=20)  # Allowed permissions bitfield
    deny: str = Field(max_length=20)  # Denied permissions bitfield

    # Timestamps
    created_at: datetime = Field(
        default_factory=datetime.utcnow, sa_column=Column(DateTime)
    )
    updated_at: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Indexes
    __table_args__ = (
        Index(
            "idx_permission_channel_target",
            "channel_id",
            "target_id",
            "target_type",
            unique=True,
        ),
    )


class ThreadMember(SQLModel, table=True):
    """Thread membership tracking."""

    __tablename__ = "thread_members"

    id: Optional[int] = Field(default=None, primary_key=True)
    thread_id: int = Field(foreign_key="channels.id", index=True)
    user_id: int = Field(foreign_key="users.id", index=True)

    # Thread-specific data
    join_timestamp: datetime = Field(
        default_factory=datetime.utcnow, sa_column=Column(DateTime)
    )
    flags: int = Field(default=0)  # Thread member flags

    # Relationships
    thread: Optional[Channel] = Relationship()
    user: Optional["User"] = Relationship()

    # Indexes
    __table_args__ = (
        Index("idx_thread_member_unique", "thread_id", "user_id", unique=True),
    )


class ChannelFollower(SQLModel, table=True):
    """Channel following for news channels."""

    __tablename__ = "channel_followers"

    id: Optional[int] = Field(default=None, primary_key=True)
    channel_id: int = Field(foreign_key="channels.id", index=True)  # Source channel
    webhook_id: int = Field(foreign_key="webhooks.id", index=True)  # Target webhook

    # Timestamps
    created_at: datetime = Field(
        default_factory=datetime.utcnow, sa_column=Column(DateTime)
    )


class VoiceState(SQLModel, table=True):
    """Voice channel state tracking."""

    __tablename__ = "voice_states"

    id: Optional[int] = Field(default=None, primary_key=True)
    guild_id: Optional[int] = Field(foreign_key="guilds.id", index=True)
    channel_id: Optional[int] = Field(foreign_key="channels.id", index=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    session_id: str = Field(max_length=32)

    # Voice state flags
    deaf: bool = Field(default=False)
    mute: bool = Field(default=False)
    self_deaf: bool = Field(default=False)
    self_mute: bool = Field(default=False)
    self_stream: bool = Field(default=False)
    self_video: bool = Field(default=False)
    suppress: bool = Field(default=False)

    # Request to speak (Stage channels)
    request_to_speak_timestamp: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Timestamps
    joined_at: datetime = Field(
        default_factory=datetime.utcnow, sa_column=Column(DateTime)
    )
    updated_at: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Relationships
    guild: Optional["Guild"] = Relationship()
    channel: Optional[Channel] = Relationship()
    user: Optional["User"] = Relationship()

    # Indexes
    __table_args__ = (
        Index("idx_voice_state_user", "user_id", unique=True),
        Index("idx_voice_state_channel", "channel_id"),
    )


class StageInstance(SQLModel, table=True):
    """Stage channel instances."""

    __tablename__ = "stage_instances"

    id: Optional[int] = Field(default=None, primary_key=True)
    guild_id: int = Field(foreign_key="guilds.id", index=True)
    channel_id: int = Field(foreign_key="channels.id", unique=True, index=True)
    topic: str = Field(max_length=120)
    privacy_level: int = Field(default=1)  # 1 = public, 2 = guild_only
    discoverable_disabled: bool = Field(default=False)

    # Timestamps
    created_at: datetime = Field(
        default_factory=datetime.utcnow, sa_column=Column(DateTime)
    )
    updated_at: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Relationships
    guild: Optional["Guild"] = Relationship()
    channel: Optional[Channel] = Relationship()


class ForumTag(SQLModel, table=True):
    """Forum channel tags."""

    __tablename__ = "forum_tags"

    id: Optional[int] = Field(default=None, primary_key=True)
    channel_id: int = Field(foreign_key="channels.id", index=True)
    name: str = Field(max_length=20)
    moderated: bool = Field(default=False)
    emoji_id: Optional[int] = Field(foreign_key="emojis.id")
    emoji_name: Optional[str] = Field(max_length=32)

    # Timestamps
    created_at: datetime = Field(
        default_factory=datetime.utcnow, sa_column=Column(DateTime)
    )

    # Relationships
    channel: Optional[Channel] = Relationship()
    emoji: Optional["Emoji"] = Relationship()


class ChannelSettings(SQLModel, table=True):
    """Extended channel settings and preferences."""

    __tablename__ = "channel_settings"

    id: Optional[int] = Field(default=None, primary_key=True)
    channel_id: int = Field(foreign_key="channels.id", unique=True, index=True)

    # Auto-moderation
    auto_mod_enabled: bool = Field(default=False)
    auto_mod_rules: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))

    # Welcome message
    welcome_message_enabled: bool = Field(default=False)
    welcome_message: Optional[str] = Field(sa_column=Column(Text))

    # Pinned messages
    pinned_message_ids: List[int] = Field(default=[], sa_column=Column(JSON))

    # Custom settings
    custom_settings: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))

    # Timestamps
    created_at: datetime = Field(
        default_factory=datetime.utcnow, sa_column=Column(DateTime)
    )
    updated_at: Optional[datetime] = Field(sa_column=Column(DateTime))


class ChannelInvite(SQLModel, table=True):
    """Channel-specific invite tracking."""

    __tablename__ = "channel_invites"

    id: Optional[int] = Field(default=None, primary_key=True)
    channel_id: int = Field(foreign_key="channels.id", index=True)
    invite_id: int = Field(foreign_key="invites.id", index=True)

    # Usage tracking
    uses_from_this_channel: int = Field(default=0)

    # Timestamps
    created_at: datetime = Field(
        default_factory=datetime.utcnow, sa_column=Column(DateTime)
    )

    # Indexes
    __table_args__ = (
        Index("idx_channel_invite_unique", "channel_id", "invite_id", unique=True),
    )
