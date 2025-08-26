from typing import Optional, List
from pydantic import BaseModel, EmailStr
from enum import Enum

class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"
    MODERATOR = "moderator"

class UserStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    BANNED = "banned"

class UserCreate(BaseModel):
    """Schema for creating a user."""
    username: str
    email: EmailStr
    password: str
    role: UserRole = UserRole.USER

class UserUpdate(BaseModel):
    """Schema for updating a user."""
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[UserRole] = None
    status: Optional[UserStatus] = None

class UserResponse(BaseModel):
    """Schema for user API responses."""
    id: str
    username: str
    email: EmailStr
    role: UserRole
    status: UserStatus
    created_at: str
    last_login: Optional[str] = None

class UserProfileUpdate(BaseModel):
    """Schema for updating user profile."""
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    timezone: Optional[str] = None
    language: Optional[str] = None
    theme: Optional[str] = None

class Config:
    orm_mode = True
