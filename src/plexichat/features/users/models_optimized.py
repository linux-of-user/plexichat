# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
import time
PlexiChat User Models

Consolidated user models with comprehensive functionality and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum
from dataclasses import dataclass, field

# REMOVE SQLModel, BaseModel, and Field usage. Use only dataclasses or simple classes for models here.
@dataclass
class UserProfile:
    id: int
    user_id: int
    display_name: str = ""
    bio: str = ""
    location: str = ""
    website: str = ""
    avatar_url: str = ""
    banner_url: str = ""
    twitter_handle: str = ""
    github_username: str = ""
    linkedin_url: str = ""
    theme: str = "light"
    language: str = "en"
    timezone: str = ""
    show_email: bool = False
    show_online_status: bool = True
    allow_direct_messages: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = None

# User Settings Model
@dataclass
class UserSettings:
    """User settings and preferences."""

    id: int
    user_id: int

    # Notification settings
    email_notifications: bool = True
    push_notifications: bool = True
    desktop_notifications: bool = True

    # Message settings
    message_preview: bool = True
    read_receipts: bool = True
    typing_indicators: bool = True

    # Privacy settings
    two_factor_enabled: bool = False
    session_timeout: int = 3600

    # Content settings
    auto_play_media: bool = True
    show_nsfw_content: bool = False

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None

# User Activity Model
@dataclass
class UserActivity:
    """User activity tracking."""

    id: int
    user_id: int

    # Activity details
    activity_type: str
    description: str = ""
    metadata: str = ""

    # Context
    ip_address: str = ""
    user_agent: str = ""

    # Timestamp
    timestamp: datetime = field(default_factory=datetime.now)

# User Session Model
@dataclass
class UserSession:
    """User session tracking."""

    id: int
    user_id: int
    session_token: str
    ip_address: str = ""
    user_agent: str = ""
    device_info: str = ""
    is_active: bool = True
    online_status: str = "offline"
    created_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    expires_at: datetime = None

# Remove all remaining Pydantic BaseModel and Field usage from API models.
class UserProfileCreate:
    """User profile creation model."""
    def __init__(self, display_name: Optional[str] = None, bio: Optional[str] = None, location: Optional[str] = None, website: Optional[str] = None, theme: str = "light", language: str = "en", timezone: Optional[str] = None):
        self.display_name = display_name
        self.bio = bio
        self.location = location
        self.website = website
        self.theme = theme
        self.language = language
        self.timezone = timezone

class UserProfileUpdate:
    """User profile update model."""
    def __init__(self, display_name: Optional[str] = None, bio: Optional[str] = None, location: Optional[str] = None, website: Optional[str] = None, avatar_url: Optional[str] = None, banner_url: Optional[str] = None, theme: Optional[str] = None, language: Optional[str] = None, timezone: Optional[str] = None):
        self.display_name = display_name
        self.bio = bio
        self.location = location
        self.website = website
        self.avatar_url = avatar_url
        self.banner_url = banner_url
        self.theme = theme
        self.language = language
        self.timezone = timezone

class UserSettingsUpdate:
    """User settings update model."""
    def __init__(self, email_notifications: Optional[bool] = None, push_notifications: Optional[bool] = None, desktop_notifications: Optional[bool] = None, message_preview: Optional[bool] = None, read_receipts: Optional[bool] = None, typing_indicators: Optional[bool] = None, auto_play_media: Optional[bool] = None, show_nsfw_content: Optional[bool] = None):
        self.email_notifications = email_notifications
        self.push_notifications = push_notifications
        self.desktop_notifications = desktop_notifications
        self.message_preview = message_preview
        self.read_receipts = read_receipts
        self.typing_indicators = typing_indicators
        self.auto_play_media = auto_play_media
        self.show_nsfw_content = show_nsfw_content

class UserProfileResponse:
    """User profile response model."""
    def __init__(self, id: int, user_id: int, display_name: Optional[str] = None, bio: Optional[str] = None, location: Optional[str] = None, website: Optional[str] = None, avatar_url: Optional[str] = None, banner_url: Optional[str] = None, theme: str = "light", language: str = "en", timezone: Optional[str] = None, created_at: datetime = datetime.now()):
        self.id = id
        self.user_id = user_id
        self.display_name = display_name
        self.bio = bio
        self.location = location
        self.website = website
        self.avatar_url = avatar_url
        self.banner_url = banner_url
        self.theme = theme
        self.language = language
        self.timezone = timezone
        self.created_at = created_at

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "display_name": self.display_name,
            "bio": self.bio,
            "location": self.location,
            "website": self.website,
            "avatar_url": self.avatar_url,
            "banner_url": self.banner_url,
            "theme": self.theme,
            "language": self.language,
            "timezone": self.timezone,
            "created_at": self.created_at
        }

class UserSettingsResponse:
    """User settings response model."""
    def __init__(self, id: int, user_id: int, email_notifications: bool, push_notifications: bool, desktop_notifications: bool, message_preview: bool, read_receipts: bool, typing_indicators: bool, two_factor_enabled: bool, auto_play_media: bool, show_nsfw_content: bool, created_at: datetime = datetime.now()):
        self.id = id
        self.user_id = user_id
        self.email_notifications = email_notifications
        self.push_notifications = push_notifications
        self.desktop_notifications = desktop_notifications
        self.message_preview = message_preview
        self.read_receipts = read_receipts
        self.typing_indicators = typing_indicators
        self.two_factor_enabled = two_factor_enabled
        self.auto_play_media = auto_play_media
        self.show_nsfw_content = show_nsfw_content
        self.created_at = created_at

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "email_notifications": self.email_notifications,
            "push_notifications": self.push_notifications,
            "desktop_notifications": self.desktop_notifications,
            "message_preview": self.message_preview,
            "read_receipts": self.read_receipts,
            "typing_indicators": self.typing_indicators,
            "two_factor_enabled": self.two_factor_enabled,
            "auto_play_media": self.auto_play_media,
            "show_nsfw_content": self.show_nsfw_content,
            "created_at": self.created_at
        }

class UserActivityResponse:
    """User activity response model."""
    def __init__(self, id: int, activity_type: str, description: Optional[str] = None, timestamp: datetime = datetime.now()):
        self.id = id
        self.activity_type = activity_type
        self.description = description
        self.timestamp = timestamp

    def to_dict(self):
        return {
            "id": self.id,
            "activity_type": self.activity_type,
            "description": self.description,
            "timestamp": self.timestamp
        }

class UserSessionResponse:
    """User session response model."""
    def __init__(self, id: int, device_info: Optional[str] = None, ip_address: Optional[str] = None, online_status: str = "offline", created_at: datetime = datetime.now(), last_activity: datetime = datetime.now()):
        self.id = id
        self.device_info = device_info
        self.ip_address = ip_address
        self.online_status = online_status
        self.created_at = created_at
        self.last_activity = last_activity

    def to_dict(self):
        return {
            "id": self.id,
            "device_info": self.device_info,
            "ip_address": self.ip_address,
            "online_status": self.online_status,
            "created_at": self.created_at,
            "last_activity": self.last_activity
        }

# Service classes would be defined here for managing these models
class UserModelService:
    """Service for managing user models using EXISTING database abstraction."""

    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger

    @async_track_performance("user_profile_creation") if async_track_performance else lambda f: f
    async def create_user_profile(self, user_id: int, profile_data: UserProfileCreate) -> Optional[UserProfile]:
        """Create user profile using EXISTING database abstraction."""
        if self.db_manager:
            try:
                create_query = """
                    INSERT INTO user_profiles ()
                        user_id, display_name, bio, location, website,
                        theme, language, timezone, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    RETURNING *
                """
                create_params = {
                    "user_id": user_id,
                    "display_name": profile_data.display_name,
                    "bio": profile_data.bio,
                    "location": profile_data.location,
                    "website": profile_data.website,
                    "theme": profile_data.theme,
                    "language": profile_data.language,
                    "timezone": profile_data.timezone,
                    "created_at": datetime.now()
                }

                result = await self.db_manager.execute_query(create_query, create_params)

                if result:
                    # Performance tracking
                    if self.performance_logger:
                        self.performance_logger.record_metric("user_profiles_created", 1, "count")

                    # Convert result to UserProfile object
                    row = result[0]
                    return UserProfile()
                        id=row[0],
                        user_id=row[1],
                        display_name=row[2],
                        # ... map other fields
                        created_at=row[-1]
                    )

            except Exception as e:
                logger.error(f"Error creating user profile: {e}")
                return None

        return None

# Global service instance
user_model_service = UserModelService()
