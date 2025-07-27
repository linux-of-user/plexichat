# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Message Model

Enhanced message model with comprehensive functionality and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum
from sqlalchemy import Column, JSON

# SQLModel imports
try:
    from sqlmodel import SQLModel, Field, Relationship
except ImportError:
    SQLModel = object
    Field = lambda *args, **kwargs: None
    Relationship = lambda *args, **kwargs: None

# Pydantic imports
try:
    from pydantic import BaseModel, field_validator
except ImportError:
    BaseModel = object
    validator = lambda *args, **kwargs: lambda f: f

# Use EXISTING database abstraction layer
try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger, timer
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None
    timer = None

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

class MessageType(str, Enum):
    """Message type enumeration."""
    TEXT = "text"
    IMAGE = "image"
    FILE = "file"
    SYSTEM = "system"
    NOTIFICATION = "notification"
    VOICE = "voice"
    VIDEO = "video"

class MessageStatus(str, Enum):
    """Message status enumeration."""
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"
    FAILED = "failed"
    DELETED = "deleted"

class Message(SQLModel, table=True):
    """Enhanced message model with comprehensive functionality."""

    # Primary fields
    id: Optional[int] = Field(default=None, primary_key=True, description="Message ID")
    content: str = Field(..., max_length=2000, description="Message content")
    message_type: MessageType = Field(default=MessageType.TEXT, description="Message type")

    # User relationships
    sender_id: int = Field(..., foreign_key="user.id", description="Sender user ID")
    recipient_id: Optional[int] = Field(None, foreign_key="user.id", description="Recipient user ID")
    channel_id: Optional[int] = Field(None, description="Channel ID for group messages")

    # Threading
    parent_id: Optional[int] = Field(None, foreign_key="message.id", description="Parent message ID for threading")
    thread_count: int = Field(default=0, description="Number of replies in thread")

    # Status and metadata
    status: MessageStatus = Field(default=MessageStatus.SENT, description="Message status")
    is_edited: bool = Field(default=False, description="Whether message was edited")
    is_pinned: bool = Field(default=False, description="Whether message is pinned")
    is_system: bool = Field(default=False, description="Whether this is a system message")

    # Timestamps
    timestamp: datetime = Field(default_factory=datetime.now, description="Message timestamp")
    edited_at: Optional[datetime] = Field(None, description="Last edit timestamp")
    read_at: Optional[datetime] = Field(None, description="Read timestamp")

    # Rich content
    attachments: Optional[str] = Field(None, description="JSON string of attachments")
    mentions: Optional[str] = Field(None, description="JSON string of user mentions")
    reactions: Optional[str] = Field(None, description="JSON string of reactions")
    extra_metadata: Optional[str] = Field(None, description="Additional metadata as JSON")
    custom_fields: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))  # Dynamic custom fields (persisted as JSON)

    # Search and indexing
    search_vector: Optional[str] = Field(None, description="Search vector for full-text search")

    # Relationships (would be defined with actual relationships in full implementation)
    # sender: Optional["User"] = Relationship(back_populates="sent_messages")
    # recipient: Optional["User"] = Relationship(back_populates="received_messages")
    # parent: Optional["Message"] = Relationship(back_populates="replies")
    # replies: List["Message"] = Relationship(back_populates="parent")

class MessageCreate(BaseModel):
    """Message creation model."""
    content: str = Field(..., min_length=1, max_length=2000, description="Message content")
    message_type: MessageType = Field(default=MessageType.TEXT, description="Message type")
    recipient_id: Optional[int] = Field(None, description="Recipient user ID")
    channel_id: Optional[int] = Field(None, description="Channel ID")
    parent_id: Optional[int] = Field(None, description="Parent message ID")
    attachments: Optional[List[Dict[str, Any]]] = Field(None, description="Message attachments")
    mentions: Optional[List[int]] = Field(None, description="User mentions")

    @field_validator('content')
    @classmethod
    def validate_content(cls, v):
        if not v.strip():
            raise ValueError('Message content cannot be empty')
        return v.strip()

class MessageUpdate(BaseModel):
    """Message update model."""
    content: Optional[str] = Field(None, min_length=1, max_length=2000, description="Updated content")
    is_pinned: Optional[bool] = Field(None, description="Pin status")

    @field_validator('content')
    @classmethod
    def validate_content(cls, v):
        if v is not None and not v.strip():
            raise ValueError('Message content cannot be empty')
        return v.strip() if v else v

class MessageResponse(BaseModel):
    """Message response model."""
    id: int = Field(..., description="Message ID")
    content: str = Field(..., description="Message content")
    message_type: MessageType = Field(..., description="Message type")
    sender_id: int = Field(..., description="Sender user ID")
    recipient_id: Optional[int] = Field(None, description="Recipient user ID")
    channel_id: Optional[int] = Field(None, description="Channel ID")
    parent_id: Optional[int] = Field(None, description="Parent message ID")
    thread_count: int = Field(..., description="Thread reply count")
    status: MessageStatus = Field(..., description="Message status")
    is_edited: bool = Field(..., description="Edit status")
    is_pinned: bool = Field(..., description="Pin status")
    timestamp: datetime = Field(..., description="Message timestamp")
    edited_at: Optional[datetime] = Field(None, description="Edit timestamp")
    attachments: Optional[List[Dict[str, Any]]] = Field(None, description="Attachments")
    mentions: Optional[List[int]] = Field(None, description="User mentions")
    reactions: Optional[Dict[str, int]] = Field(None, description="Reaction counts")

    class Config:
        from_attributes = True

class MessageService:
    """Enhanced message service using EXISTING database abstraction."""

    def __init__(self):
        try:
            from plexichat.core.database.manager import database_manager
            self.db_manager = database_manager
        except ImportError:
            self.db_manager = None

    async def get_message_by_id(self, message_id: int):
        if self.db_manager:
            result = await self.db_manager.get_message_by_id(message_id)
            return result
        return None

    async def update_message(self, message):
        if self.db_manager:
            await self.db_manager.update_message(message)

    @async_track_performance("message_creation") if async_track_performance else lambda f: f
    async def create_message(self, sender_id: int, message_data: MessageCreate) -> Optional[Message]:
        """Create new message using EXISTING database abstraction."""
        if self.db_manager:
            try:
                import json

                # Prepare data
                create_query = """
                    INSERT INTO messages ()
                        content, message_type, sender_id, recipient_id, channel_id,
                        parent_id, timestamp, attachments, mentions, extra_metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    RETURNING *
                """
                create_params = {
                    "content": message_data.content,
                    "message_type": message_data.message_type.value,
                    "sender_id": sender_id,
                    "recipient_id": message_data.recipient_id,
                    "channel_id": message_data.channel_id,
                    "parent_id": message_data.parent_id,
                    "timestamp": datetime.now(),
                    "attachments": json.dumps(message_data.attachments) if message_data.attachments else None,
                    "mentions": json.dumps(message_data.mentions) if message_data.mentions else None,
                    "extra_metadata": json.dumps({"created_by": "api"})
                }

                if self.performance_logger and timer:
                    with timer("message_creation_query"):
                        result = await self.db_manager.execute_query(create_query, create_params)
                else:
                    result = await self.db_manager.execute_query(create_query, create_params)

                if result:
                    # Update thread count if this is a reply
                    if message_data.parent_id:
                        await self._update_thread_count(message_data.parent_id)

                    # Update user message count
                    await self._update_user_message_count(sender_id)

                    # Convert result to Message object
                    row = result[0]
                    message = Message(
                        id=row[0],
                        content=row[1],
                        message_type=MessageType(row[2]),
                        sender_id=row[3],
                        recipient_id=row[4],
                        # ... map other fields
                        timestamp=row[7]
                    )

                    # Performance tracking
                    if self.performance_logger:
                        self.performance_logger.record_metric("messages_created", 1, "count")

                    return message

            except Exception as e:
                logger.error(f"Error creating message: {e}")
                return None

        return None

    @async_track_performance("message_update") if async_track_performance else lambda f: f
    async def update_message(self, message_id: int, sender_id: int, message_data: MessageUpdate) -> Optional[Message]:
        """Update message using EXISTING database abstraction."""
        if self.db_manager:
            try:
                # Check if user owns the message
                check_query = "SELECT sender_id FROM messages WHERE id = ?"
                check_params = {"id": message_id}

                result = await self.db_manager.execute_query(check_query, check_params)
                if not result or result[0][0] != sender_id:
                    return None  # Not authorized

                # Build update query
                update_fields = []
                params = {"id": message_id, "edited_at": datetime.now()}

                for field, value in message_data.dict(exclude_unset=True).items():
                    if value is not None:
                        update_fields.append(f"{field} = ?")
                        params[field] = value

                if not update_fields:
                    return None

                # Mark as edited
                update_fields.append("is_edited = ?")
                params["is_edited"] = True

                update_query = f"""
                    UPDATE messages
                    SET {', '.join(update_fields)}, edited_at = ?
                    WHERE id = ?
                    RETURNING *
                """

                if self.performance_logger and timer:
                    with timer("message_update_query"):
                        result = await self.db_manager.execute_query(update_query, params)
                else:
                    result = await self.db_manager.execute_query(update_query, params)

                if result:
                    # Performance tracking
                    if self.performance_logger:
                        self.performance_logger.record_metric("messages_updated", 1, "count")

                    # Convert result to Message object
                    row = result[0]
                    return Message(
                        id=row[0],
                        content=row[1],
                        # ... map other fields
                    )

            except Exception as e:
                logger.error(f"Error updating message: {e}")
                return None

        return None

    async def _update_thread_count(self, parent_id: int):
        """Update thread count for parent message."""
        if self.db_manager:
            try:
                query = """
                    UPDATE messages
                    SET thread_count = ()
                        SELECT COUNT(*) FROM messages WHERE parent_id = ?
                    )
                    WHERE id = ?
                """
                params = {"parent_id": parent_id, "id": parent_id}
                await self.db_manager.execute_query(query, params)
            except Exception as e:
                logger.error(f"Error updating thread count: {e}")

    async def _update_user_message_count(self, user_id: int):
        """Update user's message count."""
        if self.db_manager:
            try:
                query = "UPDATE users SET message_count = message_count + 1 WHERE id = ?"
                params = {"id": user_id}
                await self.db_manager.execute_query(query, params)
            except Exception as e:
                logger.error(f"Error updating user message count: {e}")

    @async_track_performance("message_search") if async_track_performance else lambda f: f
    async def search_messages(self, query: str, user_id: int, limit: int = 50) -> List[Message]:
        """Search messages using EXISTING database abstraction."""
        if self.db_manager:
            try:
                search_query = """
                    SELECT * FROM messages
                    WHERE (sender_id = ? OR recipient_id = ?)
                    AND content LIKE ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """
                search_params = {
                    "sender_id": user_id,
                    "recipient_id": user_id,
                    "query": f"%{query}%",
                    "limit": limit
                }

                if self.performance_logger and timer:
                    with timer("message_search_query"):
                        result = await self.db_manager.execute_query(search_query, search_params)
                else:
                    result = await self.db_manager.execute_query(search_query, search_params)

                messages = []
                if result:
                    for row in result:
                        messages.append(Message(
                            id=row[0],
                            content=row[1],
                            # ... map other fields
                        ))

                # Performance tracking
                if self.performance_logger:
                    self.performance_logger.record_metric("message_searches", 1, "count")

                return messages

            except Exception as e:
                logger.error(f"Error searching messages: {e}")
                return []

        return []

# Global message service instance
message_service = MessageService()
