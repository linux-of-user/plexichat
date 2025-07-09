from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional
import re

class UserBase(BaseModel):
    username: str = Field(..., min_length=1)
    email: str = Field(..., pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    public_key: str = Field(...)
    display_name: Optional[str] = Field(None, max_length=32)

class UserCreate(UserBase):
    password: str = Field(..., min_length=12)
    @field_validator('password')
    def validate_password(cls, v):
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$', v):
            raise ValueError('Password must include uppercase, lowercase, numbers, and symbols')
        return v

class UserRead(UserBase):
    id: int = Field(...)
    created_at: datetime

class UserUpdate(BaseModel):
    email: Optional[str] = Field(None, pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    public_key: Optional[str] = None
    display_name: Optional[str] = Field(None, max_length=32)
