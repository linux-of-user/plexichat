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

# REMOVE SQLModel, Field, Relationship usage. Use only Pydantic or dataclasses for models here.
from pydantic import BaseModel, Field as PydanticField
from dataclasses import dataclass, field

# Pydantic imports
try:
    from pydantic import validator, EmailStr
except ImportError:
    BaseModel = object
    validator = lambda *args, **kwargs: lambda f: f
    EmailStr = str

# Use EXISTING database abstraction layer
try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

class UserRole(str, Enum):
    """User role enumeration."""
    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"

class UserStatus(str, Enum):
    """User status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    BANNED = "banned"
    PENDING = "pending"

class OnlineStatus(str, Enum):
    """Online status enumeration."""
    ONLINE = "online"
    AWAY = "away"
    BUSY = "busy"
    INVISIBLE = "invisible"
    OFFLINE = "offline"

# User Model
@dataclass
class User:
    """Core user model. All persistent storage and API models must use the database abstraction layer or pure dataclasses, not Pydantic/SQLModel directly."""
    id: int
    username: str
    email: str
    hashed_password: str
    role: UserRole = UserRole.USER
    status: UserStatus = UserStatus.PENDING
    is_verified: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = None
    last_login: datetime = None
    custom_fields: Dict[str, Any] = field(default_factory=dict)  # Dynamic custom fields (persisted as JSON)

# User Profile Model
@dataclass
class UserProfile:
    """User profile model with extended information. Persistent storage must use the database abstraction layer."""
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
    """User settings and preferences. Persistent storage must use the database abstraction layer."""
    id: int
    user_id: int
    email_notifications: bool = True
    push_notifications: bool = True
    desktop_notifications: bool = True
    message_preview: bool = True
    read_receipts: bool = True
    typing_indicators: bool = True
    two_factor_enabled: bool = False
    session_timeout: int = 3600
    auto_play_media: bool = True
    show_nsfw_content: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = None

# User Activity Model
@dataclass
class UserActivity:
    """User activity tracking. Persistent storage must use the database abstraction layer."""
    id: int
    user_id: int
    activity_type: str
    description: str = ""
    metadata: str = ""
    ip_address: str = ""
    user_agent: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

# User Session Model
@dataclass
class UserSession:
    """User session tracking. Persistent storage must use the database abstraction layer."""
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

# Remove all remaining Pydantic Field usage and BaseModel inheritance from API models.
# All persistent storage and API models must use the database abstraction layer or pure dataclasses, not Pydantic/SQLModel directly.

@dataclass
class UserProfileCreate:
    display_name: str = ""
    bio: str = ""
    location: str = ""
    website: str = ""

# Remove UserSettingsResponse and any remaining Pydantic Field usage.

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
                    INSERT INTO user_profiles (
                        user_id, display_name, bio, location, website,
                        theme, language, timezone, created_at
                    ) VALUES (:user_id, :display_name, :bio, :location, :website, :theme, :language, :timezone, :created_at)
                    RETURNING *
                """
                create_params = {
                    "user_id": user_id,
                    "display_name": profile_data.display_name,
                    "bio": profile_data.bio,
                    "location": profile_data.location,
                    "website": profile_data.website,
                    "theme": "light",  # Default value
                    "language": "en",  # Default value
                    "timezone": "",  # Default value
                    "created_at": datetime.now()
                }

                result = await self.db_manager.execute_query(create_query, create_params)

                if result:
                    # Performance tracking
                    if self.performance_logger:
                        self.performance_logger.record_metric("user_profiles_created", 1, "count")

                    # Convert result to UserProfile object
                    row = result[0]
                    return UserProfile(
                        id=row[0],
                        user_id=row[1],
                        display_name=row[2],
                        bio=row[3],
                        location=row[4],
                        website=row[5],
                        avatar_url=row[6],
                        banner_url=row[7],
                        twitter_handle=row[8],
                        github_username=row[9],
                        linkedin_url=row[10],
                        theme=row[11],
                        language=row[12],
                        timezone=row[13],
                        show_email=row[14],
                        show_online_status=row[15],
                        allow_direct_messages=row[16],
                        created_at=row[17],
                        updated_at=row[18]
                    )

            except Exception as e:
                logger.error(f"Error creating user profile: {e}")
                return None

        return None

    async def get_user_by_id(self, user_id: int):
        # Use DAO/abstraction layer to fetch user by ID
        # Reference: improvements.txt
        if self.db_manager:
            result = await self.db_manager.get_user_by_id(user_id)
            return result
        return None

    async def update_user(self, user):
        # Use DAO/abstraction layer to update user
        # Reference: improvements.txt
        if self.db_manager:
            await self.db_manager.update_user(user)

# Global service instance
user_model_service = UserModelService()
