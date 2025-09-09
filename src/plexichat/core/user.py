from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class User(BaseModel):
    id: int
    username: str
    is_admin: bool
    status: Optional[str] = "offline"  # online, away, busy, offline
    status_updated_at: Optional[datetime] = None
    custom_status: Optional[str] = None
