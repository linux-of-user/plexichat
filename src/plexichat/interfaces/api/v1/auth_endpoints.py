# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import logging
from datetime import datetime
from typing import Dict, Optional, List

from ....core_system.auth.auth_manager import AuthManager
from ....features.security.api_security_decorators import (
    enhanced_security, SecurityLevel, require_permission,
    require_role, audit_log, ValidationLevel
)
from ....features.security.enhanced_input_validation import get_input_validator
from ....features.security.enhanced_auth_system import get_auth_system

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field, validator

"""
PlexiChat Authentication API Endpoints

Consolidated authentication API endpoints including:
- User login/logout
- Registration
- Password management
- Two-factor authentication
- Token management
- Session management

Merged from:
- auth/auth_2fa.py
- auth/auth_advanced.py
- core/auth.py
"""

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/auth", tags=["Authentication"])

# Security scheme
security = HTTPBearer()

# API Models with Enhanced Validation
class LoginRequest(BaseModel):
    """Enhanced login request model with security validation."""
    username: str = Field(..., min_length=3, max_length=50, regex="^[a-zA-Z0-9_.-]+$")
    password: str = Field(..., min_length=1, max_length=128)
    remember_me: bool = False
    mfa_code: Optional[str] = Field(None, min_length=6, max_length=8, regex="^[0-9]+$")
    device_fingerprint: Optional[str] = Field(None, max_length=64)

    @validator('username')
    def validate_username(cls, v):
        """Validate username for security."""
        validator = get_input_validator()
        result = validator.validate_input(v, ValidationLevel.STRICT)
        if not result.is_valid:
            raise ValueError(f"Invalid username: {', '.join(result.warnings)}")
        return result.sanitized_value

    @validator('password')
    def validate_password(cls, v):
        """Validate password for security."""
        if len(v) > 128:  # Prevent DoS
            raise ValueError("Password too long")
        return v

class RegisterRequest(BaseModel):
    """Enhanced registration request model with security validation."""
    username: str = Field(..., min_length=3, max_length=50, regex="^[a-zA-Z0-9_.-]+$")
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=128)
    confirm_password: str = Field(..., min_length=12, max_length=128)
    display_name: Optional[str] = Field(None, max_length=100)
    terms_accepted: bool = Field(..., description="Must accept terms and conditions")

    @validator('username')
    def validate_username(cls, v):
        """Validate username for security."""
        validator = get_input_validator()
        result = validator.validate_input(v, ValidationLevel.STRICT)
        if not result.is_valid:
            raise ValueError(f"Invalid username: {', '.join(result.warnings)}")

        # Check for reserved usernames
        reserved = ['admin', 'root', 'system', 'api', 'www', 'mail', 'ftp']
        if v.lower() in reserved:
            raise ValueError("Username is reserved")

        return result.sanitized_value

    @validator('display_name')
    def validate_display_name(cls, v):
        """Validate display name for security."""
        if v is None:
            return v
        validator = get_input_validator()
        result = validator.validate_input(v, ValidationLevel.STANDARD)
        if not result.is_valid:
            raise ValueError(f"Invalid display name: {', '.join(result.warnings)}")
        return result.sanitized_value

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        """Ensure passwords match."""
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

    @validator('terms_accepted')
    def terms_must_be_accepted(cls, v):
        """Ensure terms are accepted."""
        if not v:
            raise ValueError('Terms and conditions must be accepted')
        return v

class PasswordResetRequest(BaseModel):
    """Password reset request model."""
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    """Password reset confirmation model."""
    token: str
    new_password: str = Field(..., min_length=8)
    confirm_password: str = Field(..., min_length=8)

class ChangePasswordRequest(BaseModel):
    """Change password request model."""
    current_password: str
    new_password: str = Field(..., min_length=8)
    confirm_password: str = Field(..., min_length=8)

class MFASetupRequest(BaseModel):
    """MFA setup request model."""
    method: str = Field(..., regex="^(totp|sms|email)$")
    phone_number: Optional[str] = None

class MFAVerifyRequest(BaseModel):
    """MFA verification request model."""
    code: str = Field(..., min_length=6, max_length=6)

class TokenResponse(BaseModel):
    """Token response model."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    username: str
    role: str

class UserInfo(BaseModel):
    """User information model."""
    id: str
    username: str
    email: str
    display_name: Optional[str]
    role: str
    is_verified: bool
    mfa_enabled: bool
    created_at: datetime
    last_login: Optional[datetime]

# Authentication Endpoints
@router.post("/login", response_model=TokenResponse)
@enhanced_security(
    level=SecurityLevel.PUBLIC,
    rate_limit={"requests": 5, "window": 300},  # 5 attempts per 5 minutes
    require_csrf=False,  # API endpoint
    validate_input=True,
    validation_level=ValidationLevel.STRICT,
    log_requests=True,
    max_request_size=1024  # 1KB max for login
)
@audit_log("user_login", "authentication")
async def enhanced_login(http_request: Request, request: LoginRequest, response: Response):
    """Enhanced user authentication with comprehensive security."""
    try:
        # Get client information for security logging
        client_ip = http_request.client.host
        user_agent = http_request.headers.get("user-agent", "")

        # Get enhanced auth system
        auth_system = get_auth_system()

        # Validate credentials
        auth_result = await auth_manager.authenticate(
            username=request.username,
            password=request.password,
            mfa_code=request.mfa_code
        )

        if not auth_result.get("success", False):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=auth_result.get("message", "Invalid credentials")
            )

        user = auth_result["user"]

        # Generate tokens
        tokens = await auth_manager.generate_tokens(
            user_id=user["id"],
            remember_me=request.remember_me
        )

        # Set secure cookie for refresh token
        response.set_cookie(
            key="refresh_token",
            value=tokens["refresh_token"],
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=tokens.get("refresh_expires_in", 604800)  # 7 days default
        )

        # Update last login
        await auth_manager.update_last_login(user["id"])

        return TokenResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            expires_in=tokens["expires_in"],
            user_id=user["id"],
            username=user["username"],
            role=user["role"]
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error"
        )

@router.post("/register", response_model=Dict[str, str])
async def register(request: RegisterRequest):
    """Register a new user."""
    try:
        # Validate password confirmation
        if request.password != request.confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Passwords do not match"
            )

        auth_manager = AuthManager()

        # Register user
        result = await auth_manager.register_user(
            username=request.username,
            email=request.email,
            password=request.password,
            display_name=request.display_name
        )

        if not result.get("success", False):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("message", "Registration failed")
            )

        return {
            "message": "Registration successful",
            "user_id": result["user_id"]
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration service error"
        )

@router.post("/logout")
async def logout(
    response: Response,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Logout user and invalidate tokens."""
    try:
        auth_manager = AuthManager()

        # Invalidate access token
        await auth_manager.invalidate_token(credentials.credentials)

        # Clear refresh token cookie
        response.delete_cookie(
            key="refresh_token",
            httponly=True,
            secure=True,
            samesite="strict"
        )

        return {"message": "Logout successful"}

    except Exception as e:
        logger.error(f"Logout failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout service error"
        )

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: Request):
    """Refresh access token using refresh token."""
    try:
        # Get refresh token from cookie
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found"
            )

        auth_manager = AuthManager()

        # Refresh tokens
        result = await auth_manager.refresh_tokens(refresh_token)

        if not result.get("success", False):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )

        tokens = result["tokens"]
        user = result["user"]

        return TokenResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            expires_in=tokens["expires_in"],
            user_id=user["id"],
            username=user["username"],
            role=user["role"]
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh service error"
        )

@router.get("/me", response_model=UserInfo)
async def get_current_user from plexichat.infrastructure.utils.auth import get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get current user information."""
    try:
        auth_manager = AuthManager()

        # Validate token and get user
        user = await auth_manager.get_user_from_token(credentials.credentials)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

        return UserInfo(
            id=user["id"],
            username=user["username"],
            email=user["email"],
            display_name=user.get("display_name"),
            role=user["role"],
            is_verified=user.get("is_verified", False),
            mfa_enabled=user.get("mfa_enabled", False),
            created_at=user["created_at"],
            last_login=user.get("last_login")
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get current user failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User service error"
        )

# Password Management Endpoints
@router.post("/password/reset")
async def request_password_reset(request: PasswordResetRequest):
    """Request password reset."""
    try:
        auth_manager = AuthManager()

        # Send password reset email
        await auth_manager.request_password_reset(request.email)

        # Always return success to prevent email enumeration
        return {"message": "If the email exists, a password reset link has been sent"}

    except Exception as e:
        logger.error(f"Password reset request failed: {e}")
        # Still return success to prevent information disclosure
        return {"message": "If the email exists, a password reset link has been sent"}

@router.post("/password/reset/confirm")
async def confirm_password_reset(request: PasswordResetConfirm):
    """Confirm password reset with token."""
    try:
        # Validate password confirmation
        if request.new_password != request.confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Passwords do not match"
            )

        auth_manager = AuthManager()

        # Reset password
        result = await auth_manager.reset_password(
            token=request.token,
            new_password=request.new_password
        )

        if not result.get("success", False):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("message", "Invalid or expired token")
            )

        return {"message": "Password reset successful"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password reset confirmation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset service error"
        )

@router.post("/password/change")
async def change_password(
    request: ChangePasswordRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Change user password."""
    try:
        # Validate password confirmation
        if request.new_password != request.confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Passwords do not match"
            )

        auth_manager = AuthManager()

        # Get current user
        user = await auth_manager.get_user_from_token(credentials.credentials)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

        # Change password
        result = await auth_manager.change_password(
            user_id=user["id"],
            current_password=request.current_password,
            new_password=request.new_password
        )

        if not result.get("success", False):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("message", "Password change failed")
            )

        return {"message": "Password changed successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change service error"
        )

# Export router
__all__ = ["router"]
