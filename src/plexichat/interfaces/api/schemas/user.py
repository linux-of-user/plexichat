# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from typing import Optional


try:
    from .models import UserRole, UserStatus
except ImportError:
    from enum import Enum

class UserRole(Enum):
        USER = "user"
ADMIN = "admin"
MODERATOR = "moderator"

class UserStatus(Enum):
        ACTIVE = "active"
INACTIVE = "inactive"
BANNED = "banned"


from pydantic import BaseModel, EmailStr

"""User API schemas."""


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
