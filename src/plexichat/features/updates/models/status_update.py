from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, Index, Text
from sqlmodel import Column, Field, SQLModel

from ....infrastructure.utils.snowflake import SnowflakeGenerator

"""
PlexiChat Status Update Model

WhatsApp-like status update model with 24-hour expiry.
"""

# Initialize snowflake generator for status updates
status_snowflake = SnowflakeGenerator(datacenter_id=3, worker_id=1)


class StatusType(str, Enum):
    """Status update content types."""
    TEXT = "text"
    IMAGE = "image"
    VIDEO = "video"


class StatusVisibility(str, Enum):
    """Status visibility levels."""
    PUBLIC = "public"
    FRIENDS = "friends"
    PRIVATE = "private"


class StatusUpdate(SQLModel, table=True):
    """
    Status update model for WhatsApp-like stories.
    
    Supports text, image, and video content with 24-hour expiry.
    """
    __tablename__ = "status_updates"
    
    # Primary identification
    status_id: str = Field(
        default_factory=lambda: str(status_snowflake.generate_id()),
        primary_key=True,
        index=True,
        description="Unique snowflake ID for the status update"
    )
    
    # User relationship
    user_id: str = Field(
        foreign_key="users.id",
        index=True,
        description="User who created this status update"
    )
    
    # Status content
    type: StatusType = Field(
        default=StatusType.TEXT,
        index=True,
        description="Type of status content"
    )
    
    content: Optional[str] = Field(
        default=None,
        sa_column=Column(Text),
        description="Text content for text status"
    )
    
    media_url: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Media URL for image/video status"
    )
    
    # Visual customization (for text status)
    background_color: Optional[str] = Field(
        default=None,
        max_length=7,
        description="Background color (hex) for text status"
    )
    
    font_style: Optional[str] = Field(
        default=None,
        max_length=50,
        description="Font style for text status"
    )
    
    # Privacy settings
    visibility: StatusVisibility = Field(
        default=StatusVisibility.FRIENDS,
        index=True,
        description="Who can view this status"
    )
    
    # Engagement tracking
    view_count: int = Field(
        default=0,
        description="Number of views"
    )
    
    # Timestamps
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        sa_column=Column(DateTime),
        index=True,
        description="Status creation timestamp"
    )
    
    expires_at: datetime = Field(
        default_factory=lambda: from datetime import datetime
datetime.utcnow() + timedelta(hours=24),
        sa_column=Column(DateTime),
        index=True,
        description="Status expiry timestamp (24 hours)"
    )
    
    # Relationships (will be defined when other models are created)
    # user: Optional["User"] = Relationship()
    # views: List["StatusView"] = Relationship(back_populates="status_update")
    
    class Config:
        """SQLModel configuration."""
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
    
    def __repr__(self) -> str:
        return f"<StatusUpdate(status_id='{self.status_id}', type='{self.type}', user_id='{self.user_id}')>"
    
    def is_expired(self) -> bool:
        """Check if status update has expired."""
        return from datetime import datetime
datetime.utcnow() > self.expires_at
    
    def is_text_status(self) -> bool:
        """Check if this is a text status."""
        return self.type == StatusType.TEXT
    
    def is_media_status(self) -> bool:
        """Check if this is a media status."""
        return self.type in [StatusType.IMAGE, StatusType.VIDEO]
    
    def time_remaining(self) -> timedelta:
        """Get time remaining before expiry."""
        if self.is_expired():
            return timedelta(0)
        return self.expires_at - from datetime import datetime
datetime.utcnow()
    
    def hours_remaining(self) -> float:
        """Get hours remaining before expiry."""
        remaining = self.time_remaining()
        return remaining.total_seconds() / 3600
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert status update to dictionary."""
        return {
            "status_id": self.status_id,
            "user_id": self.user_id,
            "type": self.type,
            "content": self.content,
            "media_url": self.media_url,
            "background_color": self.background_color,
            "font_style": self.font_style,
            "visibility": self.visibility,
            "view_count": self.view_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_expired": self.is_expired(),
            "hours_remaining": self.hours_remaining(),
        }


# Database indexes for performance
__table_args__ = (
    Index('idx_status_user_created', 'user_id', 'created_at'),
    Index('idx_status_expires_at', 'expires_at'),
    Index('idx_status_visibility_created', 'visibility', 'created_at'),
    Index('idx_status_type_user', 'type', 'user_id'),
    Index('idx_status_active', 'expires_at', 'created_at'),  # For active status queries
)
