"""
Enhanced message models with Discord-like features.
Includes reactions, embeds, attachments, threads, and rich content.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlalchemy import DateTime, Index, Text
from sqlmodel import JSON, Column, Field, SQLModel


class MessageType(int, Enum):
    """Message types matching Discord API."""
    DEFAULT = 0
    RECIPIENT_ADD = 1
    RECIPIENT_REMOVE = 2
    CALL = 3
    CHANNEL_NAME_CHANGE = 4
    CHANNEL_ICON_CHANGE = 5
    CHANNEL_PINNED_MESSAGE = 6
    GUILD_MEMBER_JOIN = 7
    USER_PREMIUM_GUILD_SUBSCRIPTION = 8
    USER_PREMIUM_GUILD_SUBSCRIPTION_TIER_1 = 9
    USER_PREMIUM_GUILD_SUBSCRIPTION_TIER_2 = 10
    USER_PREMIUM_GUILD_SUBSCRIPTION_TIER_3 = 11
    CHANNEL_FOLLOW_ADD = 12
    GUILD_DISCOVERY_DISQUALIFIED = 14
    GUILD_DISCOVERY_REQUALIFIED = 15
    GUILD_DISCOVERY_GRACE_PERIOD_INITIAL_WARNING = 16
    GUILD_DISCOVERY_GRACE_PERIOD_FINAL_WARNING = 17
    THREAD_CREATED = 18
    REPLY = 19
    CHAT_INPUT_COMMAND = 20
    THREAD_STARTER_MESSAGE = 21
    GUILD_INVITE_REMINDER = 22
    CONTEXT_MENU_COMMAND = 23
    AUTO_MODERATION_ACTION = 24

class MessageFlags(int, Enum):
    """Message flags bitfield."""
    CROSSPOSTED = 1 << 0
    IS_CROSSPOST = 1 << 1
    SUPPRESS_EMBEDS = 1 << 2
    SOURCE_MESSAGE_DELETED = 1 << 3
    URGENT = 1 << 4
    HAS_THREAD = 1 << 5
    EPHEMERAL = 1 << 6
    LOADING = 1 << 7
    FAILED_TO_MENTION_SOME_ROLES_IN_THREAD = 1 << 8
    SUPPRESS_NOTIFICATIONS = 1 << 12

class Message(SQLModel, table=True):
    """Enhanced message model with Discord-like features."""
    __tablename__ = "messages"

    id: Optional[int] = Field(default=None, primary_key=True)
    channel_id: Optional[int] = Field(foreign_key="channels.id", index=True)
    guild_id: Optional[int] = Field(foreign_key="guilds.id", index=True)
    author_id: Optional[int] = Field(foreign_key="users.id", index=True)

    # Legacy fields for backward compatibility
    sender_id: Optional[int] = Field(foreign_key="users.id", index=True)
    recipient_id: Optional[int] = Field(foreign_key="users.id", index=True)

    # Message content
    content: Optional[str] = Field(sa_column=Column(Text))
    type: MessageType = Field(default=MessageType.DEFAULT, index=True)
    flags: int = Field(default=0)  # MessageFlags bitfield

    # Message references (replies, forwards)
    message_reference: Optional[Dict[str, Any]] = Field(sa_column=Column(JSON))
    referenced_message_id: Optional[int] = Field(foreign_key="messages.id", index=True)

    # Thread information
    thread_id: Optional[int] = Field(foreign_key="channels.id", index=True)

    # Timestamps
    timestamp: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime), index=True)
    edited_timestamp: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Webhook info
    webhook_id: Optional[int] = Field(foreign_key="webhooks.id")

    # Application info (for bot commands)
    application_id: Optional[int] = Field()
    interaction_id: Optional[int] = Field()

    # Mentions
    mention_everyone: bool = Field(default=False)
    mention_roles: List[int] = Field(default=[], sa_column=Column(JSON))
    mention_users: List[int] = Field(default=[], sa_column=Column(JSON))
    mention_channels: List[int] = Field(default=[], sa_column=Column(JSON))

    # File attachments (stored as file IDs)
    attached_files: List[int] = Field(default=[], sa_column=Column(JSON))
    embedded_files: List[Dict[str, Any]] = Field(default=[], sa_column=Column(JSON))  # File embed metadata

    # Advanced message features
    expires_at: Optional[datetime] = Field(sa_column=Column(DateTime))  # Disappearing messages
    auto_delete_after: Optional[int] = Field(default=None)  # Auto-delete after N seconds

    # Status
    is_pinned: bool = Field(default=False, index=True)
    is_tts: bool = Field(default=False)  # Text-to-speech
    is_deleted: bool = Field(default=False, index=True)
    is_system: bool = Field(default=False, index=True)  # System-generated message

    # Legacy fields
    is_edited: bool = Field(default=False)
    is_system: bool = Field(default=False)
    created_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    updated_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    edited_at: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Legacy JSON fields
    attachments: List[Dict[str, Any]] = Field(default=[], sa_column=Column(JSON))
    embeds: List[Dict[str, Any]] = Field(default=[], sa_column=Column(JSON))
    reactions: List[Dict[str, Any]] = Field(default=[], sa_column=Column(JSON))
    mentions: List[int] = Field(default=[], sa_column=Column(JSON))

    # Indexes
    __table_args__ = (
        Index('idx_message_channel_timestamp', 'channel_id', 'timestamp'),
        Index('idx_message_author_timestamp', 'author_id', 'timestamp'),
        Index('idx_message_guild_timestamp', 'guild_id', 'timestamp'),
        Index('idx_message_thread', 'thread_id'),
        Index('idx_message_legacy', 'sender_id', 'recipient_id', 'timestamp'),
    )

class MessageEmbed(SQLModel, table=True):
    """Message embed model for rich content."""
    __tablename__ = "message_embeds"

    id: Optional[int] = Field(default=None, primary_key=True)
    message_id: int = Field(foreign_key="messages.id", index=True)

    # Embed content
    title: Optional[str] = Field(max_length=256)
    description: Optional[str] = Field(sa_column=Column(Text))
    url: Optional[str] = Field(max_length=2048)
    timestamp: Optional[datetime] = Field(sa_column=Column(DateTime))
    color: Optional[int] = Field()  # RGB color as integer

    # Footer
    footer_text: Optional[str] = Field(max_length=2048)
    footer_icon_url: Optional[str] = Field(max_length=2048)

    # Image
    image_url: Optional[str] = Field(max_length=2048)
    image_proxy_url: Optional[str] = Field(max_length=2048)
    image_height: Optional[int] = Field()
    image_width: Optional[int] = Field()

    # Thumbnail
    thumbnail_url: Optional[str] = Field(max_length=2048)
    thumbnail_proxy_url: Optional[str] = Field(max_length=2048)
    thumbnail_height: Optional[int] = Field()
    thumbnail_width: Optional[int] = Field()

    # Video
    video_url: Optional[str] = Field(max_length=2048)
    video_proxy_url: Optional[str] = Field(max_length=2048)
    video_height: Optional[int] = Field()
    video_width: Optional[int] = Field()

    # Provider
    provider_name: Optional[str] = Field(max_length=256)
    provider_url: Optional[str] = Field(max_length=2048)

    # Author
    author_name: Optional[str] = Field(max_length=256)
    author_url: Optional[str] = Field(max_length=2048)
    author_icon_url: Optional[str] = Field(max_length=2048)
    author_proxy_icon_url: Optional[str] = Field(max_length=2048)

class MessageEmbedField(SQLModel, table=True):
    """Message embed field model."""
    __tablename__ = "message_embed_fields"

    id: Optional[int] = Field(default=None, primary_key=True)
    embed_id: int = Field(foreign_key="message_embeds.id", index=True)
    name: str = Field(max_length=256)
    value: str = Field(max_length=1024)
    inline: bool = Field(default=False)
    position: int = Field(default=0)  # Field order

class MessageAttachment(SQLModel, table=True):
    """Message attachment model."""
    __tablename__ = "message_attachments"

    id: Optional[int] = Field(default=None, primary_key=True)
    message_id: int = Field(foreign_key="messages.id", index=True)
    filename: str = Field(max_length=256)
    description: Optional[str] = Field(max_length=1024)
    content_type: Optional[str] = Field(max_length=128)
    size: int = Field()
    url: str = Field(max_length=2048)
    proxy_url: str = Field(max_length=2048)

    # Image/video specific
    height: Optional[int] = Field()
    width: Optional[int] = Field()
    ephemeral: bool = Field(default=False)

    # Timestamps
    uploaded_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime))

class MessageReaction(SQLModel, table=True):
    """Message reaction model."""
    __tablename__ = "message_reactions"

    id: Optional[int] = Field(default=None, primary_key=True)
    message_id: int = Field(foreign_key="messages.id", index=True)
    user_id: int = Field(foreign_key="users.id", index=True)

    # Emoji info
    emoji_id: Optional[int] = Field(foreign_key="emojis.id")  # Custom emoji
    emoji_name: Optional[str] = Field(max_length=32)  # Unicode emoji name
    emoji_animated: bool = Field(default=False)

    # Legacy fields
    emoji: Optional[str] = Field(max_length=100)  # For backward compatibility

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime))

    # Indexes
    __table_args__ = (
        Index('idx_reaction_unique', 'message_id', 'user_id', 'emoji_id', 'emoji_name', unique=True),
        Index('idx_reaction_message_emoji', 'message_id', 'emoji_id', 'emoji_name'),
    )

class MessageComponent(SQLModel, table=True):
    """Message component model for interactive elements."""
    __tablename__ = "message_components"

    id: Optional[int] = Field(default=None, primary_key=True)
    message_id: int = Field(foreign_key="messages.id", index=True)
    type: int = Field()  # Component type (1=ActionRow, 2=Button, 3=SelectMenu, etc.)
    style: Optional[int] = Field()  # Component style
    label: Optional[str] = Field(max_length=80)
    emoji: Optional[Dict[str, Any]] = Field(sa_column=Column(JSON))
    custom_id: Optional[str] = Field(max_length=100)
    url: Optional[str] = Field(max_length=512)
    disabled: bool = Field(default=False)

    # Select menu specific
    options: List[Dict[str, Any]] = Field(default=[], sa_column=Column(JSON))
    placeholder: Optional[str] = Field(max_length=150)
    min_values: Optional[int] = Field(default=1)
    max_values: Optional[int] = Field(default=1)

    # Position in component tree
    row: int = Field(default=0)
    position: int = Field(default=0)

class MessageEdit(SQLModel, table=True):
    """Message edit history."""
    __tablename__ = "message_edits"

    id: Optional[int] = Field(default=None, primary_key=True)
    message_id: int = Field(foreign_key="messages.id", index=True)
    editor_id: int = Field(foreign_key="users.id", index=True)

    # Edit content
    old_content: Optional[str] = Field(sa_column=Column(Text))
    new_content: Optional[str] = Field(sa_column=Column(Text))
    edit_reason: Optional[str] = Field(max_length=512)

    # Timestamps
    edited_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime), index=True)
