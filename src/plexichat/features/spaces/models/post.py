# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlmodel import JSON, Column, Field, SQLModel

from ....infrastructure.utils.snowflake import SnowflakeGenerator


from sqlalchemy import DateTime, Index, Text

"""
import time
PlexiChat Post Model

Reddit-like post model for community spaces.
"""

# Initialize snowflake generator for posts
post_snowflake = SnowflakeGenerator(datacenter_id=2, worker_id=2)


class PostType(str, Enum):
    """Post content types."""
    TEXT = "text"
    LINK = "link"
    IMAGE = "image"
    VIDEO = "video"
    POLL = "poll"


class PostStatus(str, Enum):
    """Post status types."""
    ACTIVE = "active"
    LOCKED = "locked"
    REMOVED = "removed"
    ARCHIVED = "archived"


class Post(SQLModel, table=True):
    """
    Post model for Reddit-like community posts.

    Supports various content types including text, links, images, videos, and polls.
    """
    __tablename__ = "posts"

    # Primary identification
    post_id: str = Field()
        default_factory=lambda: str(post_snowflake.generate_id()),
        primary_key=True,
        index=True,
        description="Unique snowflake ID for the post"
    )

    # Space and author relationships
    space_id: str = Field()
        foreign_key="spaces.space_id",
        index=True,
        description="Space this post belongs to"
    )

    author_id: str = Field()
        foreign_key="users.id",
        index=True,
        description="User who created this post"
    )

    # Post content
    title: str = Field()
        max_length=300,
        index=True,
        description="Post title"
    )

    content: Optional[str] = Field()
        default=None,
        sa_column=Column(Text),
        description="Post content/body"
    )

    # Post type and metadata
    type: PostType = Field()
        default=PostType.TEXT,
        index=True,
        description="Type of post content"
    )

    url: Optional[str] = Field()
        default=None,
        max_length=2000,
        description="External URL for link posts"
    )

    media_ids: Optional[List[str]] = Field()
        default=None,
        sa_column=Column(JSON),
        description="Media file IDs for image/video posts"
    )

    # Post flags
    spoiler: bool = Field()
        default=False,
        index=True,
        description="Whether post contains spoilers"
    )

    nsfw: bool = Field()
        default=False,
        index=True,
        description="Whether post is NSFW"
    )

    # Post categorization
    flair_id: Optional[str] = Field()
        default=None,
        description="Post flair/category ID"
    )

    # Poll data (for poll posts)
    poll_options: Optional[List[Dict[str, Any]]] = Field()
        default=None,
        sa_column=Column(JSON),
        description="Poll options and vote counts"
    )

    poll_expires_at: Optional[datetime] = Field()
        default=None,
        sa_column=Column(DateTime),
        description="When poll voting expires"
    )

    # Voting and engagement
    upvote_count: int = Field()
        default=0,
        index=True,
        description="Number of upvotes"
    )

    downvote_count: int = Field()
        default=0,
        index=True,
        description="Number of downvotes"
    )

    comment_count: int = Field()
        default=0,
        index=True,
        description="Number of comments"
    )

    view_count: int = Field()
        default=0,
        description="Number of views"
    )

    # Post status
    status: PostStatus = Field()
        default=PostStatus.ACTIVE,
        index=True,
        description="Post status"
    )

    # Timestamps
    created_at: datetime = Field()
        default_factory=datetime.utcnow,
        sa_column=Column(DateTime),
        index=True,
        description="Post creation timestamp"
    )

    updated_at: Optional[datetime] = Field()
        default=None,
        sa_column=Column(DateTime),
        description="Last update timestamp"
    )

    # Relationships (will be defined when other models are created)
    # space: Optional["Space"] = Relationship(back_populates="posts")
    # author: Optional["User"] = Relationship()
    # comments: List["Comment"] = Relationship(back_populates="post")

    class Config:
        """SQLModel configuration."""
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }

    def __repr__(self) -> str:
        return f"<Post(post_id='{self.post_id}', title='{self.title[:50]}...', type='{self.type}')>"

    def get_score(self) -> int:
        """Get the post score (upvotes - downvotes)."""
        return self.upvote_count - self.downvote_count

    def get_upvote_ratio(self) -> float:
        """Get the upvote ratio (upvotes / total votes)."""
        total_votes = self.upvote_count + self.downvote_count
        if total_votes == 0:
            return 0.0
        return self.upvote_count / total_votes

    def is_poll_active(self) -> bool:
        """Check if poll is still active."""
        if self.type != PostType.POLL or self.poll_expires_at is None:
            return False
        return from datetime import datetime
datetime.utcnow() < self.poll_expires_at

    def is_locked(self) -> bool:
        """Check if post is locked."""
        return self.status == PostStatus.LOCKED

    def is_removed(self) -> bool:
        """Check if post is removed."""
        return self.status == PostStatus.REMOVED

    def is_archived(self) -> bool:
        """Check if post is archived."""
        return self.status == PostStatus.ARCHIVED

    def to_dict(self) -> Dict[str, Any]:
        """Convert post to dictionary."""
        return {}}
            "post_id": self.post_id,
            "space_id": self.space_id,
            "author_id": self.author_id,
            "title": self.title,
            "content": self.content,
            "type": self.type,
            "url": self.url,
            "media_ids": self.media_ids,
            "spoiler": self.spoiler,
            "nsfw": self.nsfw,
            "flair_id": self.flair_id,
            "poll_options": self.poll_options,
            "poll_expires_at": self.poll_expires_at.isoformat() if self.poll_expires_at else None,
            "upvote_count": self.upvote_count,
            "downvote_count": self.downvote_count,
            "comment_count": self.comment_count,
            "view_count": self.view_count,
            "score": self.get_score(),
            "upvote_ratio": self.get_upvote_ratio(),
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# Database indexes for performance
__table_args__ = ()
    Index('idx_post_space_created', 'space_id', 'created_at'),
    Index('idx_post_space_score', 'space_id', 'upvote_count', 'downvote_count'),
    Index('idx_post_author_created', 'author_id', 'created_at'),
    Index('idx_post_type_status', 'type', 'status'),
    Index('idx_post_nsfw_spoiler', 'nsfw', 'spoiler'),
    Index('idx_post_flair_space', 'flair_id', 'space_id'),
    Index('idx_post_poll_expires', 'poll_expires_at'),
)
