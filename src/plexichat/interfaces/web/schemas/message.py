from datetime import datetime


from pydantic import BaseModel, Field
from typing import Optional


class MessageBase(BaseModel):
    recipient_id: int = Field(..., description="User ID of the recipient")
    content: str = Field(..., min_length=1)


class MessageCreate(MessageBase):
    pass


class MessageRead(MessageBase):
    id: int = Field(...)
    sender_id: int = Field(...)
    timestamp: datetime
