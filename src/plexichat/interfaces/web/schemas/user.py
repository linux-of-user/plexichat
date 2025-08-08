
"""
User schemas for PlexiChat API.
Enhanced with comprehensive validation and security.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator, EmailStr


class UserBase(BaseModel):
    """Base user schema."""
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    email: EmailStr = Field(..., description="Email address")

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if not v.strip():
            raise ValueError('Username cannot be empty')
        # Check for valid characters
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')
        return v.strip()


class UserCreate(UserBase):
    """User creation schema."""
    password: str = Field(..., min_length=6, max_length=100, description="Password")
    is_admin: bool = Field(default=False, description="Admin status")

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        # Basic password validation
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        return v


class UserUpdate(BaseModel):
    """User update schema."""
    username: Optional[str] = Field(None, min_length=3, max_length=50, description="Username")
    email: Optional[EmailStr] = Field(None, description="Email address")
    is_active: Optional[bool] = Field(None, description="Active status")
    is_admin: Optional[bool] = Field(None, description="Admin status")

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if v is not None:
            if not v.strip():
                raise ValueError('Username cannot be empty')
            import re
            if not re.match(r'^[a-zA-Z0-9_-]+$', v):
                raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')
            return v.strip()
        return v


class UserResponse(UserBase):
    """User response schema."""
    id: int = Field(..., description="User ID")
    is_active: bool = Field(..., description="Active status")
    is_admin: bool = Field(..., description="Admin status")
    created_at: datetime = Field(..., description="Creation timestamp")
    last_login: Optional[datetime] = Field(None, description="Last login timestamp")

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    """User list response schema."""
    users: List[UserResponse] = Field(..., description="List of users")
    total_count: int = Field(..., description="Total number of users")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Items per page")
    has_next: bool = Field(..., description="Whether there are more pages")
    has_prev: bool = Field(..., description="Whether there are previous pages")


class UserProfile(UserResponse):
    """Extended user profile schema."""
    bio: Optional[str] = Field(None, max_length=500, description="User biography")
    avatar_url: Optional[str] = Field(None, description="Avatar image URL")
    timezone: Optional[str] = Field(None, description="User timezone")
    language: Optional[str] = Field(None, description="Preferred language")


class UserStats(BaseModel):
    """User statistics schema."""
    user_id: int = Field(..., description="User ID")
    message_count: int = Field(default=0, description="Total messages sent")
    file_count: int = Field(default=0, description="Total files uploaded")
    login_count: int = Field(default=0, description="Total login count")
    last_activity: Optional[datetime] = Field(None, description="Last activity timestamp")
    account_age_days: int = Field(default=0, description="Account age in days")
