from datetime import datetime

from pydantic import BaseModel


class User(BaseModel):
    id: int
    username: str
    is_admin: bool
    status: str | None = "offline"  # online, away, busy, offline
    status_updated_at: datetime | None = None
    custom_status: str | None = None
