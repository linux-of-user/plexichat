"""
Authentication and authorization endpoints.
Handles login, logout, token management, and user authentication.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import logging

from ....core.auth.jwt_manager import jwt_manager
from ....core.auth.dependencies import get_current_user, get_current_admin_user
from ....core.security.rate_limiting import rate_limiter
from ....core.security.integrated_security import integrated_security
from ....core.logging import get_logger

logger = get_logger(__name__)
security = HTTPBearer()

router = APIRouter(tags=["Authentication"])


class LoginRequest(BaseModel):
    """Login request model."""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    remember_me: bool = Field(default=False)
    device_info: Optional[Dict[str, Any]] = Field(default=None)


class LoginResponse(BaseModel):
    """Login response model."""
    success: bool
    message: str
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]
    session_id: str


class TokenRefreshRequest(BaseModel):
    """Token refresh request model."""
    refresh_token: str


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="User login",
    description="Authenticate user and return access token"
)
async def login(
    request: Request,
    login_data: LoginRequest
):
    """Authenticate user and return JWT token."""
    try:
        # Integrated security check
        client_ip = request.client.host
        security_result = await integrated_security.process_security_middleware({
            "client_ip": client_ip,
            "endpoint": "/auth/login",
            "method": "POST",
            "user_agent": request.headers.get("user-agent", ""),
            "body": login_data.dict()
        })

        if not security_result["allowed"]:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=security_result["message"]
            )
        
        # Authenticate user (placeholder - integrate with actual auth system)
        if login_data.username == "admin" and login_data.password == "admin123":
            user_data = {
                "id": 1,
                "username": "admin",
                "email": "admin@netlink.local",
                "is_admin": True,
                "is_active": True,
                "created_at": datetime.utcnow().isoformat()
            }
            
            # Generate tokens
            access_token = jwt_manager.create_access_token(
                data={"sub": str(user_data["id"]), "username": user_data["username"]},
                expires_delta=timedelta(hours=24 if login_data.remember_me else 1)
            )
            
            session_id = f"session_{user_data['id']}_{datetime.utcnow().timestamp()}"
            
            logger.info(f"User {login_data.username} logged in successfully from {client_ip}")
            
            return LoginResponse(
                success=True,
                message="Login successful",
                access_token=access_token,
                expires_in=86400 if login_data.remember_me else 3600,
                user=user_data,
                session_id=session_id
            )
        else:
            # Record failed attempt
            await rate_limiter.record_request(f"login:{client_ip}")
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error"
        )


@router.post(
    "/logout",
    summary="User logout",
    description="Logout user and invalidate token"
)
async def logout(
    request: Request,
    current_user=Depends(get_current_user)
):
    """Logout user and invalidate token."""
    try:
        # In a real implementation, you'd add the token to a blacklist
        logger.info(f"User {current_user.username} logged out")
        
        return {
            "success": True,
            "message": "Logged out successfully"
        }
    
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout service error"
        )


@router.get(
    "/me",
    summary="Get current user",
    description="Get information about the currently authenticated user"
)
async def get_current_user_info(
    current_user=Depends(get_current_user)
):
    """Get current user information."""
    return {
        "user": {
            "id": current_user.id,
            "username": current_user.username,
            "email": getattr(current_user, 'email', None),
            "is_admin": getattr(current_user, 'is_admin', False),
            "is_active": getattr(current_user, 'is_active', True),
            "last_login": getattr(current_user, 'last_login', None)
        }
    }


@router.post(
    "/refresh",
    summary="Refresh token",
    description="Refresh access token using refresh token"
)
async def refresh_token(
    request: Request,
    refresh_data: TokenRefreshRequest
):
    """Refresh access token."""
    try:
        # Verify refresh token and generate new access token
        # This is a placeholder implementation
        
        new_access_token = jwt_manager.create_access_token(
            data={"sub": "1", "username": "admin"},
            expires_delta=timedelta(hours=1)
        )
        
        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": 3600
        }
    
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


@router.get(
    "/sessions",
    summary="Get active sessions",
    description="Get list of active sessions for the current user"
)
async def get_active_sessions(
    current_user=Depends(get_current_user)
):
    """Get active sessions for the current user."""
    # Placeholder implementation
    return {
        "sessions": [
            {
                "session_id": "session_1_123456789",
                "device": "Web Browser",
                "ip_address": "127.0.0.1",
                "last_activity": datetime.utcnow().isoformat(),
                "is_current": True
            }
        ],
        "total": 1
    }


@router.delete(
    "/sessions/{session_id}",
    summary="Revoke session",
    description="Revoke a specific session"
)
async def revoke_session(
    session_id: str,
    current_user=Depends(get_current_user)
):
    """Revoke a specific session."""
    # Placeholder implementation
    logger.info(f"Session {session_id} revoked by user {current_user.username}")
    
    return {
        "success": True,
        "message": f"Session {session_id} revoked successfully"
    }
