"""
User schemas for PlexiChat API.
Enhanced with comprehensive validation and security.
"""

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator


class UserBase(BaseModel):
    """Base user schema."""

    username: str = Field(..., min_length=3, max_length=50, description="Username")
    email: EmailStr = Field(..., description="Email address")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if not v.strip():
            raise ValueError("Username cannot be empty")
        # Check for valid characters
        import re

        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            raise ValueError(
                "Username can only contain letters, numbers, underscores, and hyphens"
            )
        return v.strip()


class UserCreate(UserBase):
    """User creation schema."""

    password: str = Field(..., min_length=6, max_length=100, description="Password")
    is_admin: bool = Field(default=False, description="Admin status")

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        # Basic password validation
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters long")
        return v


class UserUpdate(BaseModel):
    """User update schema."""

    username: str | None = Field(
        None, min_length=3, max_length=50, description="Username"
    )
    email: EmailStr | None = Field(None, description="Email address")
    is_active: bool | None = Field(None, description="Active status")
    is_admin: bool | None = Field(None, description="Admin status")
    display_name: str | None = Field(None, description="Display name")
    bio: str | None = Field(None, max_length=500, description="User biography")
    avatar_url: str | None = Field(None, description="Avatar image URL")
    user_status: str | None = Field(None, description="User status")
    timezone: str | None = Field(None, description="User timezone")
    language: str | None = Field(None, description="Preferred language")
    theme: str | None = Field(None, description="UI theme preference")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if v is not None:
            if not v.strip():
                raise ValueError("Username cannot be empty")
            import re

            if not re.match(r"^[a-zA-Z0-9_-]+$", v):
                raise ValueError(
                    "Username can only contain letters, numbers, underscores, and hyphens"
                )
            return v.strip()
        return v


class UserResponse(UserBase):
    """User response schema."""

    id: int = Field(..., description="User ID")
    is_active: bool = Field(..., description="Active status")
    is_admin: bool = Field(..., description="Admin status")
    created_at: datetime = Field(..., description="Creation timestamp")
    last_login: datetime | None = Field(None, description="Last login timestamp")
    display_name: str | None = Field(None, description="Display name")
    bio: str | None = Field(None, max_length=500, description="User biography")
    avatar_url: str | None = Field(None, description="Avatar image URL")
    user_status: str | None = Field(None, description="User status")
    timezone: str | None = Field(None, description="User timezone")
    language: str | None = Field(None, description="Preferred language")
    theme: str | None = Field(None, description="UI theme preference")

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    """User list response schema."""

    users: list[UserResponse] = Field(..., description="List of users")
    total_count: int = Field(..., description="Total number of users")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Items per page")
    has_next: bool = Field(..., description="Whether there are more pages")
    has_prev: bool = Field(..., description="Whether there are previous pages")


class UserProfile(UserResponse):
    """Extended user profile schema."""

    bio: str | None = Field(None, max_length=500, description="User biography")
    avatar_url: str | None = Field(None, description="Avatar image URL")
    user_status: str | None = Field(
        None, description="User status (online, away, busy, offline)"
    )
    timezone: str | None = Field(None, description="User timezone")
    language: str | None = Field(None, description="Preferred language")
    theme: str | None = Field(None, description="UI theme preference")


class UserStats(BaseModel):
    """User statistics schema."""

    user_id: int = Field(..., description="User ID")
    message_count: int = Field(default=0, description="Total messages sent")
    file_count: int = Field(default=0, description="Total files uploaded")
    login_count: int = Field(default=0, description="Total login count")
    last_activity: datetime | None = Field(None, description="Last activity timestamp")
    account_age_days: int = Field(default=0, description="Account age in days")
