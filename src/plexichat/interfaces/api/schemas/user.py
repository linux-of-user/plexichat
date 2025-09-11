from enum import Enum

from pydantic import BaseModel, EmailStr


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
    username: str | None = None
    email: EmailStr | None = None
    role: UserRole | None = None
    status: UserStatus | None = None

class UserResponse(BaseModel):
    """Schema for user API responses."""
    id: str
    username: str
    email: EmailStr
    role: UserRole
    status: UserStatus
    created_at: str
    last_login: str | None = None
    display_name: str | None = None
    bio: str | None = None
    avatar_url: str | None = None
    user_status: str | None = None
    timezone: str | None = None
    language: str | None = None
    theme: str | None = None

class UserProfileUpdate(BaseModel):
    """Schema for updating user profile."""
    display_name: str | None = None
    bio: str | None = Field(None, max_length=500, description="User biography")
    avatar_url: str | None = Field(None, description="Avatar image URL")
    status: str | None = Field(None, description="User status (online, away, busy, offline)")
    timezone: str | None = Field(None, description="User timezone")
    language: str | None = Field(None, description="Preferred language")
    theme: str | None = Field(None, description="UI theme preference")

class Config:
    orm_mode = True
