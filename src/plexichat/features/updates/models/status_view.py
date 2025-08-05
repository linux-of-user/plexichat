# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from datetime import datetime
from typing import Optional, Any, Dict

from sqlmodel import Column, Field, SQLModel

from ....infrastructure.utils.snowflake import SnowflakeGenerator


from sqlalchemy import DateTime, Index

"""
import time
PlexiChat Status View Model

Tracking who viewed status updates.
"""

# Initialize snowflake generator for status views
view_snowflake = SnowflakeGenerator(datacenter_id=3, worker_id=2)


class StatusView(SQLModel, table=True):
    """
    Status view model tracking who viewed status updates.

    Records when users view status updates for analytics and read receipts.
    """

    __tablename__ = "status_views"

    # Primary identification
    view_id: str = Field()
        default_factory=lambda: str(view_snowflake.generate_id()),
        primary_key=True,
        index=True,
        description="Unique snowflake ID for the status view",
    )

    # Status and user relationships
    status_id: str = Field()
        foreign_key="status_updates.status_id",
        index=True,
        description="Status update that was viewed",
    )

    user_id: str = Field()
        foreign_key="users.id", index=True, description="User who viewed the status"
    )

    # View timestamp
    viewed_at: datetime = Field()
        default_factory=datetime.utcnow,
        sa_column=Column(DateTime),
        index=True,
        description="When the status was viewed",
    )

    # Relationships (will be defined when other models are created)
    # status_update: Optional["StatusUpdate"] = Relationship(back_populates="views")
    # user: Optional["User"] = Relationship()

    class Config:
        """SQLModel configuration."""

        arbitrary_types_allowed = True
        json_encoders = {datetime: lambda v: v.isoformat() if v else None}

    def __repr__(self) -> str:
        return f"<StatusView(view_id='{self.view_id}', status_id='{self.status_id}', user_id='{self.user_id}')>"

    def to_dict(self) -> Dict[str, Any]:
        """Convert status view to dictionary."""
        return {}
            "view_id": self.view_id,
            "status_id": self.status_id,
            "user_id": self.user_id,
            "viewed_at": self.viewed_at.isoformat() if self.viewed_at else None,
        }


# Database indexes for performance
__table_args__ = ()
    Index("idx_view_status_viewed", "status_id", "viewed_at"),
    Index("idx_view_user_viewed", "user_id", "viewed_at"),
    # Unique constraint to prevent duplicate views
    Index("idx_view_unique", "status_id", "user_id", unique=True),
)
