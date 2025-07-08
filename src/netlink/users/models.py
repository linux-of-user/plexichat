"""User data models."""
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, EmailStr
from enum import Enum

class UserRole(Enum):
    """User roles."""
    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"

class UserStatus(Enum):
    """User status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    BANNED = "banned"

class User(BaseModel):
    """User model."""
    id: str
    username: str
    email: EmailStr
    role: UserRole = UserRole.USER
    status: UserStatus = UserStatus.ACTIVE
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    metadata: Dict[str, Any] = {}

class UserProfile(BaseModel):
    """User profile model."""
    user_id: str
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    timezone: str = "UTC"
    language: str = "en"
    theme: str = "default"

class UserPreferences(BaseModel):
    """User preferences model."""
    user_id: str
    notifications_enabled: bool = True
    email_notifications: bool = True
    backup_enabled: bool = True
    privacy_level: str = "standard"
    preferences: Dict[str, Any] = {}
