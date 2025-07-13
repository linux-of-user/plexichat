from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: int = Field(primary_key=True, index=True)
    username: str = Field(..., unique=True, index=True)
    email: str = Field(..., unique=True, index=True)
    password_hash: str
    public_key: str
    display_name: Optional[str] = None
    created_at: datetime = Field(
        default_factory=datetime.utcnow, nullable=False, index=True
    )
