from datetime import datetime
from typing import Any, Dict, Optional

from sqlmodel import Column, Field, SQLModel

from ....infrastructure.utils.snowflake import SnowflakeGenerator


from sqlalchemy import DateTime, Index

"""
PlexiChat Reaction Model

Message reaction model for emoji responses to messages.
"""

# Initialize snowflake generator for reactions
reaction_snowflake = SnowflakeGenerator(datacenter_id=1, worker_id=6)


class Reaction(SQLModel, table=True):
    """
    Reaction model for message emoji responses.

    Tracks user reactions to messages with emoji support.
    """

    __tablename__ = "reactions"

    # Primary identification
    reaction_id: str = Field(
        default_factory=lambda: str(reaction_snowflake.generate_id()),
        primary_key=True,
        index=True,
        description="Unique snowflake ID for the reaction",
    )

    # Message and user relationships
    message_id: str = Field(
        foreign_key="messages.message_id",
        index=True,
        description="Message this reaction is on",
    )

    user_id: str = Field(
        foreign_key="users.id", index=True, description="User who added this reaction"
    )

    # Emoji information
    emoji: str = Field(
        max_length=200,
        index=True,
        description="Unicode emoji or custom emoji identifier",
    )

    # Custom emoji details (if applicable)
    emoji_id: Optional[str] = Field(
        default=None, description="Custom emoji ID (if custom emoji)"
    )

    emoji_name: Optional[str] = Field(
        default=None, max_length=100, description="Custom emoji name (if custom emoji)"
    )

    emoji_animated: bool = Field(
        default=False, description="Whether custom emoji is animated"
    )

    # Timestamp
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        sa_column=Column(DateTime),
        index=True,
        description="Reaction creation timestamp",
    )

    # Relationships (will be defined when other models are created)
    # message: Optional["Message"] = Relationship(back_populates="reactions")
    # user: Optional["User"] = Relationship()

    class Config:
        """SQLModel configuration."""

        arbitrary_types_allowed = True
        json_encoders = {datetime: lambda v: v.isoformat() if v else None}

    def __repr__(self) -> str:
        return f"<Reaction(reaction_id='{self.reaction_id}', emoji='{self.emoji}', user_id='{self.user_id}')>"

    def is_custom_emoji(self) -> bool:
        """Check if this reaction uses a custom emoji."""
        return self.emoji_id is not None

    def is_unicode_emoji(self) -> bool:
        """Check if this reaction uses a Unicode emoji."""
        return self.emoji_id is None

    def get_emoji_identifier(self) -> str:
        """Get the emoji identifier for API responses."""
        if self.is_custom_emoji():
            return f"{self.emoji_name}:{self.emoji_id}"
        else:
            return self.emoji

    def to_dict(self) -> Dict[str, Any]:
        """Convert reaction to dictionary."""
        return {
            "reaction_id": self.reaction_id,
            "message_id": self.message_id,
            "user_id": self.user_id,
            "emoji": self.emoji,
            "emoji_id": self.emoji_id,
            "emoji_name": self.emoji_name,
            "emoji_animated": self.emoji_animated,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


# Database indexes for performance
__table_args__ = (
    Index("idx_reaction_message_emoji", "message_id", "emoji"),
    Index("idx_reaction_message_user", "message_id", "user_id"),
    Index("idx_reaction_user_timestamp", "user_id", "timestamp"),
    Index("idx_reaction_emoji_custom", "emoji_id", "emoji_name"),
    # Unique constraint to prevent duplicate reactions
    Index("idx_reaction_unique", "message_id", "user_id", "emoji", unique=True),
)
