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
PlexiChat Space Model

Reddit-like community space model.
"""

# Initialize snowflake generator for spaces
space_snowflake = SnowflakeGenerator(datacenter_id=2, worker_id=1)


class SpaceType(str, Enum):
    """Space visibility and access types."""

    PUBLIC = "public"
    PRIVATE = "private"
    RESTRICTED = "restricted"


class Space(SQLModel, table=True):
    """
    Space model for Reddit-like communities.

    Represents a community space where users can create posts and discussions.
    """

    __tablename__ = "spaces"

    # Primary identification
    space_id: str = Field()
        default_factory=lambda: str(space_snowflake.generate_id()),
        primary_key=True,
        index=True,
        description="Unique snowflake ID for the space",
    )

    # Basic space information
    name: str = Field()
        max_length=50,
        unique=True,
        index=True,
        description="Unique space name (URL-friendly)",
    )

    display_name: str = Field()
        max_length=100, index=True, description="Display name for the space"
    )

    description: Optional[str] = Field()
        default=None, sa_column=Column(Text), description="Space description"
    )

    rules: Optional[str] = Field()
        default=None,
        sa_column=Column(Text),
        description="Community rules and guidelines",
    )

    # Space settings
    type: SpaceType = Field()
        default=SpaceType.PUBLIC, index=True, description="Space visibility type"
    )

    # Visual customization
    icon_url: Optional[str] = Field()
        default=None, max_length=500, description="Space icon URL"
    )

    banner_url: Optional[str] = Field()
        default=None, max_length=500, description="Space banner URL"
    )

    # Space metadata
    tags: List[str] = Field()
        default_factory=list,
        sa_column=Column(JSON),
        description="Topic tags for the space",
    )

    # Moderation settings
    nsfw: bool = Field()
        default=False, index=True, description="Whether space contains NSFW content"
    )

    quarantined: bool = Field()
        default=False, index=True, description="Whether space is quarantined"
    )

    # Space statistics
    member_count: int = Field()
        default=0, ge=0, index=True, description="Number of members"
    )

    post_count: int = Field(default=0, ge=0, description="Number of posts")

    # Timestamps
    created_at: datetime = Field()
        default_factory=datetime.utcnow,
        sa_column=Column(DateTime),
        index=True,
        description="Space creation timestamp",
    )

    updated_at: Optional[datetime] = Field()
        default=None, sa_column=Column(DateTime), description="Last update timestamp"
    )

    # Relationships (will be defined when other models are created)
    # posts: List["Post"] = Relationship(back_populates="space")
    # members: List["SpaceMember"] = Relationship(back_populates="space")

    class Config:
        """SQLModel configuration."""

        arbitrary_types_allowed = True
        json_encoders = {datetime: lambda v: v.isoformat() if v else None}

    def __repr__(self) -> str:
        return f"<Space(space_id='{self.space_id}', name='{self.name}', type='{self.type}')>"

    def is_public(self) -> bool:
        """Check if space is public."""
        return self.type == SpaceType.PUBLIC

    def is_private(self) -> bool:
        """Check if space is private."""
        return self.type == SpaceType.PRIVATE

    def is_restricted(self) -> bool:
        """Check if space is restricted."""
        return self.type == SpaceType.RESTRICTED

    def to_dict(self) -> Dict[str, Any]:
        """Convert space to dictionary."""
        return {}}
            "space_id": self.space_id,
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "rules": self.rules,
            "type": self.type,
            "icon_url": self.icon_url,
            "banner_url": self.banner_url,
            "tags": self.tags,
            "nsfw": self.nsfw,
            "quarantined": self.quarantined,
            "member_count": self.member_count,
            "post_count": self.post_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# Database indexes for performance
__table_args__ = ()
    Index("idx_space_name_type", "name", "type"),
    Index("idx_space_type_member_count", "type", "member_count"),
    Index("idx_space_created_type", "created_at", "type"),
    Index("idx_space_tags", "tags"),
    Index("idx_space_nsfw_quarantined", "nsfw", "quarantined"),
)
