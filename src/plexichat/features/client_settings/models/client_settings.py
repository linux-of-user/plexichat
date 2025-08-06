"""
PlexiChat Client Settings Database Models
========================================

Database models for flexible client settings with key-value storage and image support.


from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Column, String, Text, Integer, DateTime, Float, Boolean, ForeignKey, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class SettingType(str, Enum):
    """Types of client settings."""
        TEXT = "text"
    JSON = "json"
    NUMBER = "number"
    BOOLEAN = "boolean"
    IMAGE_REFERENCE = "image_reference"
    FILE_REFERENCE = "file_reference"

class ImageStatus(str, Enum):
    """Status of uploaded images."""
    UPLOADING = "uploading"
    ACTIVE = "active"
    DELETED = "deleted"
    FAILED = "failed"

# Database Models
class ClientSetting(Base):
    """Client settings key-value storage."""
        __tablename__ = "client_settings"
    
    # Composite primary key
    user_id = Column(String(36), primary_key=True)
    setting_key = Column(String(255), primary_key=True)
    
    # Setting data
    setting_value = Column(Text)  # Configurable length via application logic
    setting_type = Column(String(50), default=SettingType.TEXT.value)
    
    # Metadata
    description = Column(String(500))  # Optional description
    is_encrypted = Column(Boolean, default=False)
    is_public = Column(Boolean, default=False)  # Can other users see this setting
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_client_settings_user_id', 'user_id'),
        Index('idx_client_settings_type', 'setting_type'),
        Index('idx_client_settings_public', 'is_public'),
    )

class ClientSettingImage(Base):
    """Client setting images storage."""
    __tablename__ = "client_setting_images"
    
    # Primary key
    id = Column(String(36), primary_key=True)  # UUID
    
    # Foreign keys
    user_id = Column(String(36), nullable=False)
    setting_key = Column(String(255))  # Optional link to specific setting
    
    # Image metadata
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False)  # UUID-based filename
    file_path = Column(String(500), nullable=False)
    mime_type = Column(String(100), nullable=False)
    file_size = Column(Integer, nullable=False)  # Size in bytes
    
    # Image properties
    width = Column(Integer)
    height = Column(Integer)
    
    # Status and metadata
    status = Column(String(20), default=ImageStatus.ACTIVE.value)
    description = Column(String(500))
    alt_text = Column(String(255))  # For accessibility
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Indexes
    __table_args__ = (
        Index('idx_client_images_user_id', 'user_id'),
        Index('idx_client_images_setting_key', 'setting_key'),
        Index('idx_client_images_status', 'status'),
    )

# Pydantic Models for API
class ClientSettingBase(BaseModel):
    """Base client setting model.
        setting_key: str = Field(..., max_length=255)
    setting_value: str = Field(..., max_length=10000)  # Will be validated by config
    setting_type: SettingType = SettingType.TEXT
    description: Optional[str] = Field(None, max_length=500)
    is_public: bool = False

    @field_validator('setting_key')
    @classmethod
    def validate_setting_key_field(cls, v: str) -> str:
        """Validate setting key."""
        return validate_setting_key(v)

    @field_validator('setting_value')
    @classmethod
    def validate_setting_value_field(cls, v: str) -> str:
        Validate setting value."""
        return validate_setting_value(v)

class ClientSettingCreate(ClientSettingBase):
    """Model for creating client settings.
        pass

class ClientSettingUpdate(BaseModel):
    """Model for updating client settings."""
    setting_value: Optional[str] = Field(None, max_length=10000)
    setting_type: Optional[SettingType] = None
    description: Optional[str] = Field(None, max_length=500)
    is_public: Optional[bool] = None

class ClientSettingResponse(ClientSettingBase):
    Model for client setting responses."""
        user_id: str
    is_encrypted: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class ClientSettingImageBase(BaseModel):
    """Base client setting image model.
        setting_key: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None, max_length=500)
    alt_text: Optional[str] = Field(None, max_length=255)

class ClientSettingImageCreate(ClientSettingImageBase):
    """Model for creating client setting images."""
        pass

class ClientSettingImageUpdate(BaseModel):
    Model for updating client setting images."""
    setting_key: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None, max_length=500)
    alt_text: Optional[str] = Field(None, max_length=255)

class ClientSettingImageResponse(ClientSettingImageBase):
    """Model for client setting image responses.
        id: str
    user_id: str
    original_filename: str
    stored_filename: str
    file_path: str
    mime_type: str
    file_size: int
    width: Optional[int]
    height: Optional[int]
    status: ImageStatus
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class ClientSettingsBulkUpdate(BaseModel):
    """Model for bulk updating client settings."""
        settings: Dict[str, Union[str, Dict[str, Any]]] = Field(..., max_items=20)  # Configurable limit

class ClientSettingsBulkResponse(BaseModel):
    Response for bulk operations."""
        success: bool
    updated_count: int
    failed_count: int
    errors: List[Dict[str, str]] = []
    updated_keys: List[str] = []

class ClientSettingsStatsResponse(BaseModel):
    """Response for client settings statistics.
        total_settings: int
    total_images: int
    total_storage_used_bytes: int
    total_storage_used_mb: float
    settings_by_type: Dict[str, int]
    limits: Dict[str, Any]

class ClientSettingsExportResponse(BaseModel):
    """Response for exporting client settings."""
        user_id: str
    export_timestamp: datetime
    settings: Dict[str, Any]
    images: List[Dict[str, Any]]
    total_settings: int
    total_images: int

# Validation functions
def validate_setting_key(key: str) -> str:
    Validate and normalize setting key."""
    if not key:
        raise ValueError("Setting key cannot be empty")
    
    # Import here to avoid circular imports
    try:
        from plexichat.core.config.client_settings_config import validate_setting_key
        is_valid, error_msg = validate_setting_key(key)
        if not is_valid:
            raise ValueError(error_msg)
    except ImportError:
        # Fallback validation
        if len(key) > 255:
            raise ValueError("Setting key too long")
    
    return key.strip()

def validate_setting_value(value: str) -> str:
    """Validate setting value."""
    if value is None:
        return ""
    
    # Import here to avoid circular imports
    try:
        from plexichat.core.config.client_settings_config import validate_setting_value
        is_valid, error_msg = validate_setting_value(value)
        if not is_valid:
            raise ValueError(error_msg)
    except ImportError:
        # Fallback validation
        if len(value) > 10000:
            raise ValueError("Setting value too long")
    
    return value

# Validators are now defined directly in the ClientSettingBase class using @field_validator
