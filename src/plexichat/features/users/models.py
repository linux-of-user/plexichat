# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat User Models

Consolidated user models with comprehensive functionality and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum

# SQLModel imports
try:
    from sqlmodel import SQLModel, Field, Relationship
except ImportError:
    SQLModel = object
    Field = lambda *args, **kwargs: None
    Relationship = lambda *args, **kwargs: None

# Pydantic imports
try:
    from pydantic import BaseModel, validator, EmailStr
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

# User Profile Model
class UserProfile(SQLModel, table=True):
    """User profile model with extended information."""
    
    id: Optional[int] = Field(default=None, primary_key=True, description="Profile ID")
    user_id: int = Field(..., foreign_key="user.id", unique=True, description="User ID")
    
    # Personal information
    display_name: Optional[str] = Field(None, max_length=100, description="Display name")
    bio: Optional[str] = Field(None, max_length=1000, description="User biography")
    location: Optional[str] = Field(None, max_length=100, description="User location")
    website: Optional[str] = Field(None, max_length=200, description="Personal website")
    
    # Avatar and media
    avatar_url: Optional[str] = Field(None, description="Avatar image URL")
    banner_url: Optional[str] = Field(None, description="Profile banner URL")
    
    # Social links
    twitter_handle: Optional[str] = Field(None, max_length=50, description="Twitter handle")
    github_username: Optional[str] = Field(None, max_length=50, description="GitHub username")
    linkedin_url: Optional[str] = Field(None, max_length=200, description="LinkedIn URL")
    
    # Preferences
    theme: str = Field(default="light", description="UI theme preference")
    language: str = Field(default="en", description="Language preference")
    timezone: Optional[str] = Field(None, description="Timezone")
    
    # Privacy settings
    show_email: bool = Field(default=False, description="Show email publicly")
    show_online_status: bool = Field(default=True, description="Show online status")
    allow_direct_messages: bool = Field(default=True, description="Allow direct messages")
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.now, description="Profile creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")

# User Settings Model
class UserSettings(SQLModel, table=True):
    """User settings and preferences."""
    
    id: Optional[int] = Field(default=None, primary_key=True, description="Settings ID")
    user_id: int = Field(..., foreign_key="user.id", unique=True, description="User ID")
    
    # Notification settings
    email_notifications: bool = Field(default=True, description="Email notifications enabled")
    push_notifications: bool = Field(default=True, description="Push notifications enabled")
    desktop_notifications: bool = Field(default=True, description="Desktop notifications enabled")
    
    # Message settings
    message_preview: bool = Field(default=True, description="Show message previews")
    read_receipts: bool = Field(default=True, description="Send read receipts")
    typing_indicators: bool = Field(default=True, description="Show typing indicators")
    
    # Privacy settings
    two_factor_enabled: bool = Field(default=False, description="Two-factor authentication enabled")
    session_timeout: int = Field(default=3600, description="Session timeout in seconds")
    
    # Content settings
    auto_play_media: bool = Field(default=True, description="Auto-play media content")
    show_nsfw_content: bool = Field(default=False, description="Show NSFW content")
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.now, description="Settings creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")

# User Activity Model
class UserActivity(SQLModel, table=True):
    """User activity tracking."""
    
    id: Optional[int] = Field(default=None, primary_key=True, description="Activity ID")
    user_id: int = Field(..., foreign_key="user.id", description="User ID")
    
    # Activity details
    activity_type: str = Field(..., description="Type of activity")
    description: Optional[str] = Field(None, description="Activity description")
    metadata: Optional[str] = Field(None, description="Activity metadata as JSON")
    
    # Context
    ip_address: Optional[str] = Field(None, description="IP address")
    user_agent: Optional[str] = Field(None, description="User agent string")
    
    # Timestamp
    timestamp: datetime = Field(default_factory=datetime.now, description="Activity timestamp")

# User Session Model
class UserSession(SQLModel, table=True):
    """User session tracking."""
    
    id: Optional[int] = Field(default=None, primary_key=True, description="Session ID")
    user_id: int = Field(..., foreign_key="user.id", description="User ID")
    session_token: str = Field(..., unique=True, description="Session token")
    
    # Session details
    ip_address: Optional[str] = Field(None, description="IP address")
    user_agent: Optional[str] = Field(None, description="User agent string")
    device_info: Optional[str] = Field(None, description="Device information")
    
    # Status
    is_active: bool = Field(default=True, description="Session active status")
    online_status: OnlineStatus = Field(default=OnlineStatus.ONLINE, description="Online status")
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.now, description="Session creation timestamp")
    last_activity: datetime = Field(default_factory=datetime.now, description="Last activity timestamp")
    expires_at: Optional[datetime] = Field(None, description="Session expiration timestamp")

# Pydantic models for API
class UserProfileCreate(BaseModel):
    """User profile creation model."""
    display_name: Optional[str] = Field(None, max_length=100, description="Display name")
    bio: Optional[str] = Field(None, max_length=1000, description="Biography")
    location: Optional[str] = Field(None, max_length=100, description="Location")
    website: Optional[str] = Field(None, max_length=200, description="Website")
    theme: str = Field(default="light", description="Theme")
    language: str = Field(default="en", description="Language")
    timezone: Optional[str] = Field(None, description="Timezone")

class UserProfileUpdate(BaseModel):
    """User profile update model."""
    display_name: Optional[str] = Field(None, max_length=100, description="Display name")
    bio: Optional[str] = Field(None, max_length=1000, description="Biography")
    location: Optional[str] = Field(None, max_length=100, description="Location")
    website: Optional[str] = Field(None, max_length=200, description="Website")
    avatar_url: Optional[str] = Field(None, description="Avatar URL")
    banner_url: Optional[str] = Field(None, description="Banner URL")
    theme: Optional[str] = Field(None, description="Theme")
    language: Optional[str] = Field(None, description="Language")
    timezone: Optional[str] = Field(None, description="Timezone")

class UserSettingsUpdate(BaseModel):
    """User settings update model."""
    email_notifications: Optional[bool] = Field(None, description="Email notifications")
    push_notifications: Optional[bool] = Field(None, description="Push notifications")
    desktop_notifications: Optional[bool] = Field(None, description="Desktop notifications")
    message_preview: Optional[bool] = Field(None, description="Message preview")
    read_receipts: Optional[bool] = Field(None, description="Read receipts")
    typing_indicators: Optional[bool] = Field(None, description="Typing indicators")
    auto_play_media: Optional[bool] = Field(None, description="Auto-play media")
    show_nsfw_content: Optional[bool] = Field(None, description="Show NSFW content")

class UserProfileResponse(BaseModel):
    """User profile response model."""
    id: int = Field(..., description="Profile ID")
    user_id: int = Field(..., description="User ID")
    display_name: Optional[str] = Field(None, description="Display name")
    bio: Optional[str] = Field(None, description="Biography")
    location: Optional[str] = Field(None, description="Location")
    website: Optional[str] = Field(None, description="Website")
    avatar_url: Optional[str] = Field(None, description="Avatar URL")
    banner_url: Optional[str] = Field(None, description="Banner URL")
    theme: str = Field(..., description="Theme")
    language: str = Field(..., description="Language")
    timezone: Optional[str] = Field(None, description="Timezone")
    created_at: datetime = Field(..., description="Creation timestamp")
    
    class Config:
        from_attributes = True

class UserSettingsResponse(BaseModel):
    """User settings response model."""
    id: int = Field(..., description="Settings ID")
    user_id: int = Field(..., description="User ID")
    email_notifications: bool = Field(..., description="Email notifications")
    push_notifications: bool = Field(..., description="Push notifications")
    desktop_notifications: bool = Field(..., description="Desktop notifications")
    message_preview: bool = Field(..., description="Message preview")
    read_receipts: bool = Field(..., description="Read receipts")
    typing_indicators: bool = Field(..., description="Typing indicators")
    two_factor_enabled: bool = Field(..., description="Two-factor authentication")
    auto_play_media: bool = Field(..., description="Auto-play media")
    show_nsfw_content: bool = Field(..., description="Show NSFW content")
    
    class Config:
        from_attributes = True

class UserActivityResponse(BaseModel):
    """User activity response model."""
    id: int = Field(..., description="Activity ID")
    activity_type: str = Field(..., description="Activity type")
    description: Optional[str] = Field(None, description="Description")
    timestamp: datetime = Field(..., description="Timestamp")
    
    class Config:
        from_attributes = True

class UserSessionResponse(BaseModel):
    """User session response model."""
    id: int = Field(..., description="Session ID")
    device_info: Optional[str] = Field(None, description="Device information")
    ip_address: Optional[str] = Field(None, description="IP address")
    online_status: OnlineStatus = Field(..., description="Online status")
    created_at: datetime = Field(..., description="Creation timestamp")
    last_activity: datetime = Field(..., description="Last activity")
    
    class Config:
        from_attributes = True

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
                    return UserProfile(
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
