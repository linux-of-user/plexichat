"""
PlexiChat User Settings Models
=============================

Comprehensive user settings system with extensive privacy and customization options.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, validator
from sqlalchemy import Column, String, Boolean, Integer, DateTime, Text, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class PrivacyLevel(str, Enum):
    """Privacy levels for various settings."""
    PUBLIC = "public"
    FRIENDS_ONLY = "friends_only"
    PRIVATE = "private"
    CUSTOM = "custom"

class MessagePermission(str, Enum):
    """Who can send messages to the user."""
    EVERYONE = "everyone"
    FRIENDS_ONLY = "friends_only"
    VERIFIED_ONLY = "verified_only"
    CONTACTS_ONLY = "contacts_only"
    NOBODY = "nobody"

class OnlineStatus(str, Enum):
    """Online status visibility options."""
    VISIBLE = "visible"
    FRIENDS_ONLY = "friends_only"
    INVISIBLE = "invisible"

class NotificationFrequency(str, Enum):
    """Notification frequency options."""
    INSTANT = "instant"
    EVERY_5_MIN = "every_5_min"
    EVERY_15_MIN = "every_15_min"
    HOURLY = "hourly"
    DAILY = "daily"
    NEVER = "never"

class Theme(str, Enum):
    """UI theme options."""
    LIGHT = "light"
    DARK = "dark"
    AUTO = "auto"
    HIGH_CONTRAST = "high_contrast"
    CUSTOM = "custom"

class Language(str, Enum):
    """Supported languages."""
    ENGLISH = "en"
    SPANISH = "es"
    FRENCH = "fr"
    GERMAN = "de"
    ITALIAN = "it"
    PORTUGUESE = "pt"
    RUSSIAN = "ru"
    CHINESE = "zh"
    JAPANESE = "ja"
    KOREAN = "ko"

# Database Model
class UserSettings(Base):
    """Comprehensive user settings database model."""
    __tablename__ = "user_settings"
    
    # Primary key
    user_id = Column(String(36), ForeignKey("users.id"), primary_key=True)
    
    # Privacy Settings
    profile_visibility = Column(String(20), default=PrivacyLevel.FRIENDS_ONLY.value)
    message_permissions = Column(String(20), default=MessagePermission.FRIENDS_ONLY.value)
    online_status_visibility = Column(String(20), default=OnlineStatus.FRIENDS_ONLY.value)
    last_seen_visibility = Column(String(20), default=PrivacyLevel.FRIENDS_ONLY.value)
    email_visibility = Column(String(20), default=PrivacyLevel.PRIVATE.value)
    phone_visibility = Column(String(20), default=PrivacyLevel.PRIVATE.value)
    
    # Communication Settings
    allow_friend_requests = Column(Boolean, default=True)
    allow_group_invites = Column(Boolean, default=True)
    allow_voice_calls = Column(Boolean, default=True)
    allow_video_calls = Column(Boolean, default=True)
    allow_screen_sharing = Column(Boolean, default=True)
    allow_file_sharing = Column(Boolean, default=True)
    
    # Notification Settings
    email_notifications = Column(Boolean, default=True)
    push_notifications = Column(Boolean, default=True)
    desktop_notifications = Column(Boolean, default=True)
    sound_notifications = Column(Boolean, default=True)
    vibration_notifications = Column(Boolean, default=True)
    notification_frequency = Column(String(20), default=NotificationFrequency.INSTANT.value)
    
    # Message Settings
    read_receipts = Column(Boolean, default=True)
    typing_indicators = Column(Boolean, default=True)
    message_preview = Column(Boolean, default=True)
    auto_download_media = Column(Boolean, default=True)
    auto_download_limit_mb = Column(Integer, default=10)
    message_encryption = Column(Boolean, default=True)
    
    # UI/UX Settings
    theme = Column(String(20), default=Theme.AUTO.value)
    language = Column(String(5), default=Language.ENGLISH.value)
    font_size = Column(Integer, default=14)
    compact_mode = Column(Boolean, default=False)
    animations_enabled = Column(Boolean, default=True)
    auto_emoji = Column(Boolean, default=True)
    
    # Security Settings
    two_factor_enabled = Column(Boolean, default=False)
    login_notifications = Column(Boolean, default=True)
    session_timeout_minutes = Column(Integer, default=60)
    require_password_for_settings = Column(Boolean, default=False)
    
    # Advanced Settings
    data_usage_optimization = Column(Boolean, default=False)
    backup_enabled = Column(Boolean, default=True)
    backup_frequency_days = Column(Integer, default=7)
    analytics_enabled = Column(Boolean, default=True)
    crash_reports_enabled = Column(Boolean, default=True)
    
    # Custom Settings (JSON field for extensibility)
    custom_settings = Column(JSON, default=dict)
    
    # Blocked Users and Keywords
    blocked_users = Column(JSON, default=list)  # List of user IDs
    blocked_keywords = Column(JSON, default=list)  # List of keywords to filter
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    # user = relationship("User", back_populates="settings")

# Pydantic Models for API
class UserSettingsBase(BaseModel):
    """Base user settings model."""
    # Privacy Settings
    profile_visibility: PrivacyLevel = PrivacyLevel.FRIENDS_ONLY
    message_permissions: MessagePermission = MessagePermission.FRIENDS_ONLY
    online_status_visibility: OnlineStatus = OnlineStatus.FRIENDS_ONLY
    last_seen_visibility: PrivacyLevel = PrivacyLevel.FRIENDS_ONLY
    email_visibility: PrivacyLevel = PrivacyLevel.PRIVATE
    phone_visibility: PrivacyLevel = PrivacyLevel.PRIVATE
    
    # Communication Settings
    allow_friend_requests: bool = True
    allow_group_invites: bool = True
    allow_voice_calls: bool = True
    allow_video_calls: bool = True
    allow_screen_sharing: bool = True
    allow_file_sharing: bool = True
    
    # Notification Settings
    email_notifications: bool = True
    push_notifications: bool = True
    desktop_notifications: bool = True
    sound_notifications: bool = True
    vibration_notifications: bool = True
    notification_frequency: NotificationFrequency = NotificationFrequency.INSTANT
    
    # Message Settings
    read_receipts: bool = True
    typing_indicators: bool = True
    message_preview: bool = True
    auto_download_media: bool = True
    auto_download_limit_mb: int = Field(default=10, ge=1, le=100)
    message_encryption: bool = True
    
    # UI/UX Settings
    theme: Theme = Theme.AUTO
    language: Language = Language.ENGLISH
    font_size: int = Field(default=14, ge=8, le=24)
    compact_mode: bool = False
    animations_enabled: bool = True
    auto_emoji: bool = True
    
    # Security Settings
    two_factor_enabled: bool = False
    login_notifications: bool = True
    session_timeout_minutes: int = Field(default=60, ge=5, le=1440)
    require_password_for_settings: bool = False
    
    # Advanced Settings
    data_usage_optimization: bool = False
    backup_enabled: bool = True
    backup_frequency_days: int = Field(default=7, ge=1, le=30)
    analytics_enabled: bool = True
    crash_reports_enabled: bool = True
    
    # Custom Settings
    custom_settings: Dict[str, Any] = Field(default_factory=dict)
    
    # Blocked Users and Keywords
    blocked_users: List[str] = Field(default_factory=list)
    blocked_keywords: List[str] = Field(default_factory=list)

class UserSettingsCreate(UserSettingsBase):
    """Model for creating user settings."""
    pass

class UserSettingsUpdate(BaseModel):
    """Model for updating user settings (all fields optional)."""
    # Privacy Settings
    profile_visibility: Optional[PrivacyLevel] = None
    message_permissions: Optional[MessagePermission] = None
    online_status_visibility: Optional[OnlineStatus] = None
    last_seen_visibility: Optional[PrivacyLevel] = None
    email_visibility: Optional[PrivacyLevel] = None
    phone_visibility: Optional[PrivacyLevel] = None
    
    # Communication Settings
    allow_friend_requests: Optional[bool] = None
    allow_group_invites: Optional[bool] = None
    allow_voice_calls: Optional[bool] = None
    allow_video_calls: Optional[bool] = None
    allow_screen_sharing: Optional[bool] = None
    allow_file_sharing: Optional[bool] = None
    
    # Notification Settings
    email_notifications: Optional[bool] = None
    push_notifications: Optional[bool] = None
    desktop_notifications: Optional[bool] = None
    sound_notifications: Optional[bool] = None
    vibration_notifications: Optional[bool] = None
    notification_frequency: Optional[NotificationFrequency] = None
    
    # Message Settings
    read_receipts: Optional[bool] = None
    typing_indicators: Optional[bool] = None
    message_preview: Optional[bool] = None
    auto_download_media: Optional[bool] = None
    auto_download_limit_mb: Optional[int] = Field(None, ge=1, le=100)
    message_encryption: Optional[bool] = None
    
    # UI/UX Settings
    theme: Optional[Theme] = None
    language: Optional[Language] = None
    font_size: Optional[int] = Field(None, ge=8, le=24)
    compact_mode: Optional[bool] = None
    animations_enabled: Optional[bool] = None
    auto_emoji: Optional[bool] = None
    
    # Security Settings
    two_factor_enabled: Optional[bool] = None
    login_notifications: Optional[bool] = None
    session_timeout_minutes: Optional[int] = Field(None, ge=5, le=1440)
    require_password_for_settings: Optional[bool] = None
    
    # Advanced Settings
    data_usage_optimization: Optional[bool] = None
    backup_enabled: Optional[bool] = None
    backup_frequency_days: Optional[int] = Field(None, ge=1, le=30)
    analytics_enabled: Optional[bool] = None
    crash_reports_enabled: Optional[bool] = None
    
    # Custom Settings
    custom_settings: Optional[Dict[str, Any]] = None
    
    # Blocked Users and Keywords
    blocked_users: Optional[List[str]] = None
    blocked_keywords: Optional[List[str]] = None

class UserSettingsResponse(UserSettingsBase):
    """Model for user settings response."""
    user_id: str
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True
