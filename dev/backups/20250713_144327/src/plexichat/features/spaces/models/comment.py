from datetime import datetime
from typing import Any, Dict, Optional

from sqlmodel import Column, Field, SQLModel

from ....infrastructure.utils.snowflake import SnowflakeGenerator


from sqlalchemy import DateTime, Index, Text

"""
PlexiChat Comment Model

Reddit-like comment model for posts with threading support.
"""

# Initialize snowflake generator for comments
comment_snowflake = SnowflakeGenerator(datacenter_id=2, worker_id=3)


class Comment(SQLModel, table=True):
    """
    Comment model for Reddit-like post comments.

    Supports threaded comments with voting and moderation.
    """

    __tablename__ = "comments"

    # Primary identification
    comment_id: str = Field(
        default_factory=lambda: str(comment_snowflake.generate_id()),
        primary_key=True,
        index=True,
        description="Unique snowflake ID for the comment",
    )

    # Post and author relationships
    post_id: str = Field(
        foreign_key="posts.post_id",
        index=True,
        description="Post this comment belongs to",
    )

    author_id: str = Field(
        foreign_key="users.id", index=True, description="User who created this comment"
    )

    # Comment content
    content: str = Field(sa_column=Column(Text), description="Comment content")

    # Threading support
    parent_comment_id: Optional[str] = Field(
        default=None,
        foreign_key="comments.comment_id",
        index=True,
        description="Parent comment ID for threaded replies",
    )

    # Comment hierarchy
    depth: int = Field(
        default=0,
        ge=0,
        index=True,
        description="Comment depth in thread (0 = top level)",
    )

    # Voting and engagement
    upvote_count: int = Field(default=0, index=True, description="Number of upvotes")

    downvote_count: int = Field(
        default=0, index=True, description="Number of downvotes"
    )

    reply_count: int = Field(default=0, description="Number of direct replies")

    # Comment status
    deleted: bool = Field(
        default=False, index=True, description="Whether comment is deleted"
    )

    removed: bool = Field(
        default=False, index=True, description="Whether comment is removed by moderator"
    )

    # Timestamps
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        sa_column=Column(DateTime),
        index=True,
        description="Comment creation timestamp",
    )

    updated_at: Optional[datetime] = Field(
        default=None, sa_column=Column(DateTime), description="Last update timestamp"
    )

    # Relationships (will be defined when other models are created)
    # post: Optional["Post"] = Relationship(back_populates="comments")
    # author: Optional["User"] = Relationship()
    # parent: Optional["Comment"] = Relationship(back_populates="replies")
    # replies: List["Comment"] = Relationship(back_populates="parent")

    class Config:
        """SQLModel configuration."""

        arbitrary_types_allowed = True
        json_encoders = {datetime: lambda v: v.isoformat() if v else None}

    def __repr__(self) -> str:
        content_preview = (
            self.content[:50] + "..." if len(self.content) > 50 else self.content
        )
        return f"<Comment(comment_id='{self.comment_id}', content='{content_preview}', depth={self.depth})>"

    def get_score(self) -> int:
        """Get the comment score (upvotes - downvotes)."""
        return self.upvote_count - self.downvote_count

    def get_upvote_ratio(self) -> float:
        """Get the upvote ratio (upvotes / total votes)."""
        total_votes = self.upvote_count + self.downvote_count
        if total_votes == 0:
            return 0.0
        return self.upvote_count / total_votes

    def is_top_level(self) -> bool:
        """Check if this is a top-level comment."""
        return self.parent_comment_id is None

    def is_reply(self) -> bool:
        """Check if this is a reply to another comment."""
        return self.parent_comment_id is not None

    def is_deleted(self) -> bool:
        """Check if comment is deleted."""
        return self.deleted

    def is_removed(self) -> bool:
        """Check if comment is removed."""
        return self.removed

    def is_visible(self) -> bool:
        """Check if comment is visible (not deleted or removed)."""
        return not (self.deleted or self.removed)

    def to_dict(self) -> Dict[str, Any]:
        """Convert comment to dictionary."""
        return {
            "comment_id": self.comment_id,
            "post_id": self.post_id,
            "author_id": self.author_id,
            "content": (
                self.content
                if self.is_visible()
                else "[deleted]" if self.deleted else "[removed]"
            ),
            "parent_comment_id": self.parent_comment_id,
            "depth": self.depth,
            "upvote_count": self.upvote_count,
            "downvote_count": self.downvote_count,
            "reply_count": self.reply_count,
            "score": self.get_score(),
            "upvote_ratio": self.get_upvote_ratio(),
            "deleted": self.deleted,
            "removed": self.removed,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# Database indexes for performance
__table_args__ = (
    Index("idx_comment_post_created", "post_id", "created_at"),
    Index("idx_comment_post_score", "post_id", "upvote_count", "downvote_count"),
    Index("idx_comment_author_created", "author_id", "created_at"),
    Index("idx_comment_parent_created", "parent_comment_id", "created_at"),
    Index("idx_comment_depth_post", "depth", "post_id"),
    Index("idx_comment_status", "deleted", "removed"),
)
