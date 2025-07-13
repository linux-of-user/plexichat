from datetime import datetime
from enum import IntFlag
from typing import Any, Dict, List, Optional

from sqlmodel import JSON, Column, Field, SQLModel

from ....infrastructure.utils.snowflake import SnowflakeGenerator


from sqlalchemy import DateTime, Index, Text

"""
PlexiChat Message Model

Enhanced message model with Discord-like features including embeds, attachments, and replies.
"""

# Initialize snowflake generator for messages
message_snowflake = SnowflakeGenerator(datacenter_id=1, worker_id=5)


class MessageFlags(IntFlag):
    """Message flags for special message types."""
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


class MessageType(int):
    """Message types."""
    DEFAULT = 0
    RECIPIENT_ADD = 1
    RECIPIENT_REMOVE = 2
    CALL = 3
    CHANNEL_NAME_CHANGE = 4
    CHANNEL_ICON_CHANGE = 5
    CHANNEL_PINNED_MESSAGE = 6
    USER_JOIN = 7
    GUILD_BOOST = 8
    GUILD_BOOST_TIER_1 = 9
    GUILD_BOOST_TIER_2 = 10
    GUILD_BOOST_TIER_3 = 11
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


class Message(SQLModel, table=True):
    """
    Enhanced message model with Discord-like features.
    
    Supports rich content, embeds, attachments, replies, and reactions.
    """
    __tablename__ = "messages"
    
    # Primary identification
    message_id: str = Field(
        default_factory=lambda: str(message_snowflake.generate_id()),
        primary_key=True,
        index=True,
        description="Unique snowflake ID for the message"
    )
    
    # Channel and author relationships
    channel_id: str = Field(
        foreign_key="channels.channel_id",
        index=True,
        description="Channel this message was sent in"
    )
    
    author_id: str = Field(
        foreign_key="users.id",
        index=True,
        description="User who sent this message"
    )
    
    # Message content
    content: str = Field(
        sa_column=Column(Text),
        description="Message content (up to 2000 characters)"
    )
    
    # Rich content
    embeds: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        sa_column=Column(JSON),
        description="Rich embeds attached to the message"
    )
    
    attachments: Optional[List[str]] = Field(
        default=None,
        sa_column=Column(JSON),
        description="File attachment IDs"
    )
    
    sticker_ids: Optional[List[str]] = Field(
        default=None,
        sa_column=Column(JSON),
        description="Sticker IDs used in the message"
    )
    
    # Message threading and replies
    reply_to_message_id: Optional[str] = Field(
        default=None,
        foreign_key="messages.message_id",
        index=True,
        description="Message this is replying to"
    )
    
    thread_id: Optional[str] = Field(
        default=None,
        foreign_key="channels.channel_id",
        description="Thread channel created from this message"
    )
    
    # Message metadata
    type: int = Field(
        default=MessageType.DEFAULT,
        index=True,
        description="Type of message"
    )
    
    flags: int = Field(
        default=0,
        description="Message flags bitfield"
    )
    
    tts: bool = Field(
        default=False,
        description="Whether message is text-to-speech"
    )
    
    pinned: bool = Field(
        default=False,
        index=True,
        description="Whether message is pinned in channel"
    )
    
    # Timestamps
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        sa_column=Column(DateTime),
        index=True,
        description="Message creation timestamp"
    )
    
    edited_timestamp: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime),
        description="Last edit timestamp"
    )
    
    # Webhook and bot messages
    webhook_id: Optional[str] = Field(
        default=None,
        description="Webhook ID if sent by webhook"
    )
    
    application_id: Optional[str] = Field(
        default=None,
        description="Application ID if sent by bot"
    )
    
    # Message interaction data
    interaction_id: Optional[str] = Field(
        default=None,
        description="Interaction ID for slash commands"
    )
    
    # Nonce for message deduplication
    nonce: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Nonce for message deduplication"
    )
    
    # Message activity (for rich presence)
    activity: Optional[Dict[str, Any]] = Field(
        default=None,
        sa_column=Column(JSON),
        description="Message activity data"
    )
    
    # Message components (buttons, select menus)
    components: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        sa_column=Column(JSON),
        description="Interactive message components"
    )
    
    # Relationships (will be defined when other models are created)
    # channel: Optional["Channel"] = Relationship(back_populates="messages")
    # author: Optional["User"] = Relationship()
    # reactions: List["Reaction"] = Relationship(back_populates="message")
    # reply_to: Optional["Message"] = Relationship()
    
    class Config:
        """SQLModel configuration."""
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
    
    def __repr__(self) -> str:
        content_preview = self.content[:50] + "..." if len(self.content) > 50 else self.content
        return f"<Message(message_id='{self.message_id}', author_id='{self.author_id}', content='{content_preview}')>"
    
    def has_flag(self, flag: MessageFlags) -> bool:
        """Check if message has a specific flag."""
        return bool(self.flags & flag)
    
    def add_flag(self, flag: MessageFlags) -> None:
        """Add a flag to the message."""
        self.flags |= flag
    
    def remove_flag(self, flag: MessageFlags) -> None:
        """Remove a flag from the message."""
        self.flags &= ~flag
    
    def is_reply(self) -> bool:
        """Check if this message is a reply."""
        return self.reply_to_message_id is not None
    
    def is_system_message(self) -> bool:
        """Check if this is a system message."""
        return self.type != MessageType.DEFAULT
    
    def is_edited(self) -> bool:
        """Check if this message has been edited."""
        return self.edited_timestamp is not None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary."""
        return {
            "message_id": self.message_id,
            "channel_id": self.channel_id,
            "author_id": self.author_id,
            "content": self.content,
            "embeds": self.embeds,
            "attachments": self.attachments,
            "sticker_ids": self.sticker_ids,
            "reply_to_message_id": self.reply_to_message_id,
            "type": self.type,
            "flags": self.flags,
            "tts": self.tts,
            "pinned": self.pinned,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "edited_timestamp": self.edited_timestamp.isoformat() if self.edited_timestamp else None,
        }


# Database indexes for performance
__table_args__ = (
    Index('idx_message_channel_timestamp', 'channel_id', 'timestamp'),
    Index('idx_message_author_timestamp', 'author_id', 'timestamp'),
    Index('idx_message_reply_chain', 'reply_to_message_id'),
    Index('idx_message_type_channel', 'type', 'channel_id'),
    Index('idx_message_pinned_channel', 'pinned', 'channel_id'),
    Index('idx_message_edited', 'edited_timestamp'),
)
