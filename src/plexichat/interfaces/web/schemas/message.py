
"""
Message schemas for PlexiChat API.
Enhanced with comprehensive validation and security.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class MessageType(str, Enum):
    """Message type enumeration."""
    TEXT = "text"
    IMAGE = "image"
    FILE = "file"
    SYSTEM = "system"
    NOTIFICATION = "notification"


class MessagePriority(str, Enum):
    """Message priority enumeration."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class MessageBase(BaseModel):
    """Base message schema."""
    content: str = Field(..., min_length=1, max_length=2000, description="Message content")
    message_type: MessageType = Field(default=MessageType.TEXT, description="Message type")
    priority: MessagePriority = Field(default=MessagePriority.NORMAL, description="Message priority")

    @field_validator('content')
    @classmethod
    def validate_content(cls, v):
        if not v.strip():
            raise ValueError('Message content cannot be empty')
        return v.strip()


class MessageCreate(MessageBase):
    """Message creation schema."""
    recipient_id: int = Field(..., description="Recipient user ID")
    parent_id: int | None = Field(None, description="Parent message ID for threading")
    metadata: dict[str, Any] | None = Field(None, description="Additional message metadata")


class MessageUpdate(BaseModel):
    """Message update schema."""
    content: str | None = Field(None, min_length=1, max_length=2000, description="Updated content")
    priority: MessagePriority | None = Field(None, description="Updated priority")
    metadata: dict[str, Any] | None = Field(None, description="Updated metadata")

    @field_validator('content')
    @classmethod
    def validate_content(cls, v):
        if v is not None and not v.strip():
            raise ValueError('Message content cannot be empty')
        return v.strip() if v else v


class MessageResponse(MessageBase):
    """Message response schema."""
    id: int = Field(..., description="Message ID")
    sender_id: int = Field(..., description="Sender user ID")
    recipient_id: int = Field(..., description="Recipient user ID")
    parent_id: int | None = Field(None, description="Parent message ID")
    timestamp: datetime = Field(..., description="Message timestamp")
    updated_at: datetime | None = Field(None, description="Last update timestamp")
    is_read: bool = Field(default=False, description="Read status")
    is_edited: bool = Field(default=False, description="Edit status")
    metadata: dict[str, Any] | None = Field(None, description="Message metadata")

    class Config:
        from_attributes = True


class MessageListResponse(BaseModel):
    """Message list response schema."""
    messages: list[MessageResponse] = Field(..., description="List of messages")
    total_count: int = Field(..., description="Total number of messages")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Items per page")
    has_next: bool = Field(..., description="Whether there are more pages")
    has_prev: bool = Field(..., description="Whether there are previous pages")


class MessageThread(BaseModel):
    """Message thread schema."""
    parent_message: MessageResponse = Field(..., description="Parent message")
    replies: list[MessageResponse] = Field(..., description="Reply messages")
    reply_count: int = Field(..., description="Total number of replies")


class MessageReaction(BaseModel):
    """Message reaction schema."""
    id: int = Field(..., description="Reaction ID")
    message_id: int = Field(..., description="Message ID")
    user_id: int = Field(..., description="User ID who reacted")
    emoji: str = Field(..., min_length=1, max_length=10, description="Reaction emoji")
    timestamp: datetime = Field(..., description="Reaction timestamp")


class MessageWithReactions(MessageResponse):
    """Message with reactions schema."""
    reactions: list[MessageReaction] = Field(default=[], description="Message reactions")
    reaction_counts: dict[str, int] = Field(default={}, description="Reaction counts by emoji")


class MessageSearch(BaseModel):
    """Message search schema."""
    query: str = Field(..., min_length=1, max_length=100, description="Search query")
    sender_id: int | None = Field(None, description="Filter by sender ID")
    recipient_id: int | None = Field(None, description="Filter by recipient ID")
    message_type: MessageType | None = Field(None, description="Filter by message type")
    start_date: datetime | None = Field(None, description="Start date filter")
    end_date: datetime | None = Field(None, description="End date filter")

    @field_validator('query')
    @classmethod
    def validate_query(cls, v):
        if not v.strip():
            raise ValueError('Search query cannot be empty')
        return v.strip()


class MessageStats(BaseModel):
    """Message statistics schema."""
    total_messages: int = Field(default=0, description="Total message count")
    messages_today: int = Field(default=0, description="Messages sent today")
    messages_this_week: int = Field(default=0, description="Messages sent this week")
    messages_this_month: int = Field(default=0, description="Messages sent this month")
    average_per_day: float = Field(default=0.0, description="Average messages per day")
    most_active_hour: int | None = Field(None, description="Most active hour of day")
    message_types: dict[str, int] = Field(default={}, description="Message count by type")
