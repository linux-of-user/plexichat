"""
PlexiChat User Data Models

Consolidated user models from models.py and enhanced_models.py.
Includes both Pydantic models for API validation and SQLModel for database operations.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.sql import func
from sqlmodel import JSON, Column
from sqlmodel import Field as SQLField
from sqlmodel import Index, SQLModel


# Enums
class UserRole(str, Enum):
    """User roles."""
    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


class UserStatus(str, Enum):
    """User account status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"
    BANNED = "banned"
    DELETED = "deleted"


class AccountType(str, Enum):
    """Account type enumeration."""
    USER = "user"
    ORGANIZATION = "organization"
    SERVICE = "service"
    BOT = "bot"


# Pydantic Models (for API validation)
class UserBase(BaseModel):
    """Base user model for API validation."""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    role: UserRole = UserRole.USER
    status: UserStatus = UserStatus.ACTIVE
    account_type: AccountType = AccountType.USER
    display_name: Optional[str] = Field(None, max_length=100)
    bio: Optional[str] = Field(None, max_length=500)
    avatar_url: Optional[str] = None
    timezone: Optional[str] = "UTC"
    language: Optional[str] = "en"
    metadata: Optional[Dict[str, Any]] = None


class UserCreate(UserBase):
    """User creation model."""
    password: str = Field(..., min_length=8)


class UserUpdate(BaseModel):
    """User update model."""
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    display_name: Optional[str] = Field(None, max_length=100)
    bio: Optional[str] = Field(None, max_length=500)
    avatar_url: Optional[str] = None
    timezone: Optional[str] = None
    language: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class User(UserBase):
    """Complete user model for API responses."""
    id: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    login_count: int = 0
    is_verified: bool = False
    is_online: bool = False
    last_seen: Optional[datetime] = None


# SQLModel Database Models
class UserTable(SQLModel, table=True):
    """Enhanced user database model with full feature set."""
    __tablename__ = "users"

    # Primary fields
    id: Optional[str] = SQLField(
        default_factory=lambda: str(uuid.uuid4()),
        primary_key=True,
        index=True
    )
    username: str = SQLField(
        index=True,
        unique=True,
        max_length=50,
        description="Unique username"
    )
    email: str = SQLField(
        index=True,
        unique=True,
        max_length=255,
        description="User email address"
    )

    # Authentication
    password_hash: str = SQLField(max_length=255)
    salt: Optional[str] = SQLField(max_length=255)

    # Profile information
    display_name: Optional[str] = SQLField(max_length=100)
    bio: Optional[str] = SQLField(max_length=500)
    avatar_url: Optional[str] = SQLField(max_length=500)

    # Status and role
    role: UserRole = SQLField(default=UserRole.USER, index=True)
    status: UserStatus = SQLField(default=UserStatus.ACTIVE, index=True)
    account_type: AccountType = SQLField(default=AccountType.USER)

    # Preferences
    timezone: str = SQLField(default="UTC", max_length=50)
    language: str = SQLField(default="en", max_length=10)
    theme: Optional[str] = SQLField(default="light", max_length=20)

    # Activity tracking
    created_at: datetime = SQLField(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True
    )
    updated_at: Optional[datetime] = SQLField(
        default=None,
        sa_column_kwargs={"onupdate": func.now()}
    )
    last_login: Optional[datetime] = SQLField(default=None, index=True)
    last_seen: Optional[datetime] = SQLField(default=None)
    login_count: int = SQLField(default=0)

    # Verification and security
    is_verified: bool = SQLField(default=False, index=True)
    email_verified_at: Optional[datetime] = SQLField(default=None)
    phone_verified_at: Optional[datetime] = SQLField(default=None)
    two_factor_enabled: bool = SQLField(default=False)

    # Online status
    is_online: bool = SQLField(default=False, index=True)

    # JSON metadata for extensibility
    metadata: Optional[Dict[str, Any]] = SQLField(
        default=None,
        sa_column=Column(JSON)
    )

    # Privacy settings
    privacy_settings: Optional[Dict[str, Any]] = SQLField(
        default=None,
        sa_column=Column(JSON)
    )

    # Notification preferences
    notification_settings: Optional[Dict[str, Any]] = SQLField(
        default=None,
        sa_column=Column(JSON)
    )

    # Indexes for performance
    __table_args__ = (
        Index('idx_users_email_status', 'email', 'status'),
        Index('idx_users_username_status', 'username', 'status'),
        Index('idx_users_role_status', 'role', 'status'),
        Index('idx_users_created_at', 'created_at'),
        Index('idx_users_last_login', 'last_login'),
    )
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
