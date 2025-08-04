# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
import time
Authentication schemas for PlexiChat API.
Enhanced with comprehensive validation and security.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class LoginRequest(BaseModel):
    """Login request schema."""
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    password: str = Field(..., min_length=6, max_length=100, description="Password")

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if not v.strip():
            raise ValueError('Username cannot be empty')
        return v.strip()


class TokenResponse(BaseModel):
    """Token response schema."""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    refresh_token: Optional[str] = Field(None, description="Refresh token")


class UserInfo(BaseModel):
    """User information schema."""
    id: int = Field(..., description="User ID")
    username: str = Field(..., description="Username")
    email: str = Field(..., description="Email address")
    is_active: bool = Field(..., description="User active status")
    is_admin: bool = Field(default=False, description="Admin status")
    created_at: datetime = Field(..., description="Account creation timestamp")
    last_login: Optional[datetime] = Field(None, description="Last login timestamp")


class RefreshTokenRequest(BaseModel):
    """Refresh token request schema."""
    refresh_token: str = Field(..., description="Refresh token")


class PasswordChangeRequest(BaseModel):
    """Password change request schema."""
    current_password: str = Field(..., min_length=6, description="Current password")
    new_password: str = Field(..., min_length=6, max_length=100, description="New password")
    confirm_password: str = Field(..., description="Password confirmation")

    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, v, info):
        if 'new_password' in info.data and v != info.data['new_password']:
            raise ValueError('Passwords do not match')
        return v


class LogoutResponse(BaseModel):
    """Logout response schema."""
    message: str = Field(default="Successfully logged out", description="Logout message")
    timestamp: datetime = Field(default_factory=datetime.now, description="Logout timestamp")
