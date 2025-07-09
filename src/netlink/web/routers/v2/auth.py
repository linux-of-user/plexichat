# app/routers/v2/auth.py
"""
Enhanced Authentication API v2 with improved security, performance, and features.
Includes rate limiting, advanced validation, and comprehensive error handling.
"""

import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, HTTPException, Depends, Request, Response, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlmodel import Session, select
from pydantic import BaseModel, EmailStr, Field, validator
import bcrypt
from jose import JWTError, jwt

from netlink.core.database import get_session
from netlink.users.user import User
import logging import settings, logger
from netlink.utils.monitoring import error_handler, monitor_performance
from netlink.utils.security import SecurityManager, InputSanitizer
from netlink.utils.rate_limiting import RateLimiter

router = APIRouter(prefix="/v2/auth", tags=["auth-v2"])
security = HTTPBearer()
security_manager = SecurityManager()
input_sanitizer = InputSanitizer()
rate_limiter = RateLimiter()


class LoginRequest(BaseModel):
    """Enhanced login request with validation."""
    username: str = Field(..., min_length=3, max_length=50, description="Username or email")
    password: str = Field(..., min_length=8, max_length=128, description="User password")
    remember_me: bool = Field(default=False, description="Extended session duration")
    device_info: Optional[Dict[str, str]] = Field(default=None, description="Device information")
    
    @validator('username')
    def validate_username(cls, v):
        return InputSanitizer.sanitize_username(v)
    
    @validator('password')
    def validate_password(cls, v):
        return InputSanitizer.sanitize_password(v)


class LoginResponse(BaseModel):
    """Enhanced login response with additional metadata."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    user_info: Dict[str, Any]
    session_id: str
    permissions: List[str] = []


class RefreshTokenRequest(BaseModel):
    """Refresh token request."""
    refresh_token: str = Field(..., description="Valid refresh token")


class PasswordChangeRequest(BaseModel):
    """Password change request with enhanced validation."""
    current_password: str = Field(..., min_length=8, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str = Field(..., min_length=8, max_length=128)
    
    @validator('new_password')
    def validate_new_password(cls, v):
        return SecurityManager.validate_password_strength(v)
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v


class TwoFactorSetupRequest(BaseModel):
    """Two-factor authentication setup request."""
    method: str = Field(..., regex="^(totp|sms|email)$", description="2FA method")
    phone_number: Optional[str] = Field(None, description="Phone number for SMS 2FA")


@router.post("/login", response_model=LoginResponse)
@monitor_performance
async def enhanced_login(
    request: LoginRequest,
    http_request: Request,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session)
):
    """
    Enhanced login with comprehensive security features.
    
    Features:
    - Rate limiting per IP and user
    - Device fingerprinting
    - Session management
    - Audit logging
    - Brute force protection
    """
    client_ip = security_manager.get_client_ip(http_request)
    
    # Rate limiting
    if not rate_limiter.check_rate_limit(f"login:{client_ip}", max_attempts=5, window_minutes=15):
        logger.warning("Login rate limit exceeded for IP: %s", client_ip)
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Please try again later."
        )
    
    try:
        # Find user by username or email
        user = session.exec(
            select(User).where(
                (User.username == request.username) | (User.email == request.username)
            )
        ).first()
        
        if not user:
            # Log failed attempt without revealing user existence
            logger.warning("Login attempt for non-existent user: %s from IP: %s", 
                         request.username, client_ip)
            rate_limiter.record_attempt(f"login:{client_ip}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Verify password
        if not security_manager.verify_password(request.password, user.password_hash):
            logger.warning("Failed login attempt for user: %s from IP: %s", 
                         user.username, client_ip)
            rate_limiter.record_attempt(f"login:{client_ip}")
            rate_limiter.record_attempt(f"user_login:{user.id}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Check if user account is locked
        if security_manager.is_account_locked(user.id):
            logger.warning("Login attempt for locked account: %s from IP: %s", 
                         user.username, client_ip)
            raise HTTPException(status_code=423, detail="Account is temporarily locked")
        
        # Generate session
        session_id = secrets.token_urlsafe(32)
        device_fingerprint = security_manager.generate_device_fingerprint(
            http_request, request.device_info
        )
        
        # Create tokens
        token_expiry = timedelta(
            hours=24 if request.remember_me else 1
        )
        
        access_token = security_manager.create_access_token(
            data={
                "sub": str(user.id),
                "username": user.username,
                "session_id": session_id,
                "device_fingerprint": device_fingerprint
            },
            expires_delta=token_expiry
        )
        
        refresh_token = security_manager.create_refresh_token(
            user_id=user.id,
            session_id=session_id
        ) if request.remember_me else None
        
        # Log successful login
        logger.info("Successful login for user: %s from IP: %s", user.username, client_ip)
        
        # Background tasks
        background_tasks.add_task(
            security_manager.log_login_event,
            user.id, client_ip, device_fingerprint, session_id
        )
        
        # Reset rate limiting on successful login
        rate_limiter.reset_attempts(f"login:{client_ip}")
        rate_limiter.reset_attempts(f"user_login:{user.id}")
        
        return LoginResponse(
            access_token=access_token,
            expires_in=int(token_expiry.total_seconds()),
            refresh_token=refresh_token,
            user_info={
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "display_name": user.display_name,
                "last_login": datetime.now(timezone.utc).isoformat()
            },
            session_id=session_id,
            permissions=security_manager.get_user_permissions(user.id)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        error_handler.handle_error(
            e, 
            context={
                "endpoint": "login",
                "username": request.username,
                "client_ip": client_ip
            },
            severity="HIGH"
        )
        raise HTTPException(status_code=500, detail="Authentication service error")


@router.post("/refresh", response_model=LoginResponse)
@monitor_performance
async def refresh_token(
    request: RefreshTokenRequest,
    http_request: Request,
    session: Session = Depends(get_session)
):
    """Refresh access token using refresh token."""
    client_ip = security_manager.get_client_ip(http_request)
    
    try:
        # Validate refresh token
        token_data = security_manager.validate_refresh_token(request.refresh_token)
        
        # Get user
        user = session.get(User, token_data["user_id"])
        if not user:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        # Generate new access token
        new_session_id = secrets.token_urlsafe(32)
        access_token = security_manager.create_access_token(
            data={
                "sub": str(user.id),
                "username": user.username,
                "session_id": new_session_id
            }
        )
        
        logger.info("Token refreshed for user: %s from IP: %s", user.username, client_ip)
        
        return LoginResponse(
            access_token=access_token,
            expires_in=3600,  # 1 hour
            refresh_token=request.refresh_token,  # Keep same refresh token
            user_info={
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "display_name": user.display_name
            },
            session_id=new_session_id,
            permissions=security_manager.get_user_permissions(user.id)
        )
        
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    except Exception as e:
        error_handler.handle_error(e, context={"endpoint": "refresh", "client_ip": client_ip})
        raise HTTPException(status_code=500, detail="Token refresh failed")


@router.post("/logout")
@monitor_performance
async def logout(
    http_request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    session: Session = Depends(get_session)
):
    """Enhanced logout with session invalidation."""
    try:
        # Validate token and get user info
        token_data = security_manager.validate_access_token(credentials.credentials)
        user_id = token_data["sub"]
        session_id = token_data.get("session_id")
        
        # Invalidate session
        if session_id:
            security_manager.invalidate_session(session_id)
        
        # Add token to blacklist
        security_manager.blacklist_token(credentials.credentials)
        
        client_ip = security_manager.get_client_ip(http_request)
        logger.info("User %s logged out from IP: %s", user_id, client_ip)
        
        return {"message": "Successfully logged out"}
        
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        error_handler.handle_error(e, context={"endpoint": "logout"})
        raise HTTPException(status_code=500, detail="Logout failed")


@router.post("/change-password")
@monitor_performance
async def change_password(
    request: PasswordChangeRequest,
    http_request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    session: Session = Depends(get_session)
):
    """Enhanced password change with security validation."""
    try:
        # Validate token
        token_data = security_manager.validate_access_token(credentials.credentials)
        user_id = int(token_data["sub"])
        
        # Get user
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Verify current password
        if not security_manager.verify_password(request.current_password, user.password_hash):
            client_ip = security_manager.get_client_ip(http_request)
            logger.warning("Failed password change attempt for user: %s from IP: %s", 
                         user.username, client_ip)
            raise HTTPException(status_code=401, detail="Current password is incorrect")
        
        # Check password history (prevent reuse)
        if security_manager.is_password_recently_used(user_id, request.new_password):
            raise HTTPException(
                status_code=400, 
                detail="Cannot reuse recent passwords"
            )
        
        # Hash new password
        new_password_hash = security_manager.hash_password(request.new_password)
        
        # Update password
        user.password_hash = new_password_hash
        session.add(user)
        session.commit()
        
        # Log password change
        client_ip = security_manager.get_client_ip(http_request)
        logger.info("Password changed for user: %s from IP: %s", user.username, client_ip)
        
        # Invalidate all existing sessions for this user
        security_manager.invalidate_all_user_sessions(user_id)
        
        return {"message": "Password changed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        error_handler.handle_error(e, context={"endpoint": "change_password"})
        raise HTTPException(status_code=500, detail="Password change failed")


@router.get("/me")
@monitor_performance
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    session: Session = Depends(get_session)
):
    """Get current user information with enhanced details."""
    try:
        # Validate token
        token_data = security_manager.validate_access_token(credentials.credentials)
        user_id = int(token_data["sub"])
        
        # Get user
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Get additional user metadata
        user_metadata = security_manager.get_user_metadata(user_id)
        
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "display_name": user.display_name,
            "created_at": user.created_at.isoformat(),
            "permissions": security_manager.get_user_permissions(user_id),
            "metadata": user_metadata,
            "session_info": {
                "session_id": token_data.get("session_id"),
                "expires_at": token_data.get("exp"),
                "device_fingerprint": token_data.get("device_fingerprint")
            }
        }
        
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        error_handler.handle_error(e, context={"endpoint": "get_current_user"})
        raise HTTPException(status_code=500, detail="Failed to get user information")


@router.post("/setup-2fa")
@monitor_performance
async def setup_two_factor_auth(
    request: TwoFactorSetupRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    session: Session = Depends(get_session)
):
    """Setup two-factor authentication."""
    try:
        # Validate token
        token_data = security_manager.validate_access_token(credentials.credentials)
        user_id = int(token_data["sub"])
        
        # Setup 2FA
        setup_result = security_manager.setup_2fa(
            user_id, request.method, request.phone_number
        )
        
        logger.info("2FA setup initiated for user: %s, method: %s", user_id, request.method)
        
        return setup_result
        
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        error_handler.handle_error(e, context={"endpoint": "setup_2fa"})
        raise HTTPException(status_code=500, detail="2FA setup failed")


@router.get("/sessions")
@monitor_performance
async def get_active_sessions(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get all active sessions for the current user."""
    try:
        # Validate token
        token_data = security_manager.validate_access_token(credentials.credentials)
        user_id = int(token_data["sub"])
        
        # Get active sessions
        sessions = security_manager.get_user_sessions(user_id)
        
        return {"sessions": sessions}
        
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        error_handler.handle_error(e, context={"endpoint": "get_sessions"})
        raise HTTPException(status_code=500, detail="Failed to get sessions")


@router.delete("/sessions/{session_id}")
@monitor_performance
async def revoke_session(
    session_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Revoke a specific session."""
    try:
        # Validate token
        token_data = security_manager.validate_access_token(credentials.credentials)
        user_id = int(token_data["sub"])
        
        # Revoke session
        success = security_manager.revoke_user_session(user_id, session_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Session not found")
        
        logger.info("Session %s revoked for user: %s", session_id, user_id)
        
        return {"message": "Session revoked successfully"}
        
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        error_handler.handle_error(e, context={"endpoint": "revoke_session"})
        raise HTTPException(status_code=500, detail="Failed to revoke session")
