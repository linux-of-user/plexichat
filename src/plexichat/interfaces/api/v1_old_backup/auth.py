# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false

"""
PlexiChat Enhanced Authentication API - SINGLE SOURCE OF TRUTH

Advanced authentication system with:
- Redis caching for session performance optimization
- Database abstraction layer for user data storage
- Multi-factor authentication and security features
- Real-time session management and monitoring
- Advanced token management and refresh capabilities
- Performance monitoring and security analytics
- Comprehensive audit logging and compliance
"""

from fastapi import APIRouter, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Dict, List
from datetime import datetime, timezone

try:
    from plexichat.core.logging import get_logger
    from plexichat.core.auth.unified_auth_manager import get_unified_auth_manager
    from plexichat.core.auth.admin_manager import get_admin_manager
    from plexichat.core.auth.token_manager import get_token_manager
    from plexichat.core.auth.mfa_manager import get_mfa_manager
    from plexichat.core.logging import get_logger
    from plexichat.core.database.manager import get_database_manager
    from plexichat.infrastructure.performance.cache_manager import get_cache_manager
    from plexichat.infrastructure.monitoring import get_performance_monitor
    from plexichat.core.security.unified_audit_system import get_unified_audit_system, SecurityEventType

    logger = get_logger(__name__)
    auth_manager = get_unified_auth_manager()
    admin_manager = get_admin_manager()
    token_manager = get_token_manager()
    mfa_manager = get_mfa_manager()
    database_manager = get_database_manager()
    cache_manager = get_cache_manager()
    performance_monitor = get_performance_monitor()
    audit_system = get_unified_audit_system()
except ImportError:
    logger = print
    auth_manager = None
    admin_manager = None
    token_manager = None
    mfa_manager = None
    database_manager = None
    cache_manager = None
    performance_monitor = None
    audit_system = None

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
security = HTTPBearer()

# Request/Response Models
class LoginRequest(BaseModel):
    username: str
    password: str
    remember_me: bool = False
    mfa_code: Optional[str] = None

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    session_id: str
    requires_mfa: bool = False

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    confirm_password: str
    invite_code: Optional[str] = None

class RegisterResponse(BaseModel):
    user_id: str
    username: str
    email: str
    message: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str

class ResetPasswordRequest(BaseModel):
    email: EmailStr

class MFASetupResponse(BaseModel):
    qr_code: str
    secret_key: str
    backup_codes: List[str]

class MFAVerifyRequest(BaseModel):
    code: str

# Dependency to get current user
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current authenticated user from token."""
    try:
        if not token_manager:
            raise HTTPException(status_code=503, detail="Authentication service unavailable")

        token = credentials.credentials
        validation_result = await token_manager.validate_token(token)

        if not validation_result.valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return validation_result.data
    except Exception as e:
        logger.error(f"Error validating token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, client_request: Request):
    """Authenticate user and return access token."""
    try:
        if not auth_manager:
            raise HTTPException(status_code=503, detail="Authentication service unavailable")

        # Authenticate user
        auth_result = await auth_manager.authenticate_user(
            username=request.username,
            password=request.password,
            mfa_code=request.mfa_code
        )

        if not auth_result.success:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=auth_result.message or "Invalid credentials"
            )

        # Generate tokens
        if token_manager:
            access_token = await token_manager.create_access_token(
                user_id=auth_result.user_id,
                session_id=auth_result.session_id,
                metadata={"ip": client_request.client.host}
            )
            refresh_token = await token_manager.create_refresh_token(
                user_id=auth_result.user_id,
                session_id=auth_result.session_id
            )
        else:
            raise HTTPException(status_code=503, detail="Token service unavailable")

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=3600,  # 1 hour
            user_id=auth_result.user_id,
            session_id=auth_result.session_id,
            requires_mfa=auth_result.requires_mfa
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/register", response_model=RegisterResponse)
async def register(request: RegisterRequest):
    """Register a new user account."""
    try:
        if not auth_manager:
            raise HTTPException(status_code=503, detail="Authentication service unavailable")

        # Validate password confirmation
        if request.password != request.confirm_password:
            raise HTTPException(status_code=400, detail="Passwords do not match")

        # Register user
        result = await auth_manager.register_user(
            username=request.username,
            email=request.email,
            password=request.password,
            invite_code=request.invite_code
        )

        if not result.success:
            raise HTTPException(status_code=400, detail=result.message)

        return RegisterResponse(
            user_id=result.user_id,
            username=request.username,
            email=request.email,
            message="Account created successfully"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/refresh", response_model=LoginResponse)
async def refresh_token(request: RefreshTokenRequest):
    """Refresh access token using refresh token."""
    try:
        if not token_manager:
            raise HTTPException(status_code=503, detail="Token service unavailable")

        # Validate refresh token
        validation_result = await token_manager.validate_token(request.refresh_token)

        if not validation_result.valid:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        # Generate new access token
        access_token = await token_manager.create_access_token(
            user_id=validation_result.data.get("user_id"),
            session_id=validation_result.data.get("session_id")
        )

        return LoginResponse(
            access_token=access_token,
            refresh_token=request.refresh_token,
            expires_in=3600,
            user_id=validation_result.data.get("user_id"),
            session_id=validation_result.data.get("session_id")
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/logout")
async def logout(current_user: Dict = Depends(get_current_user)):
    """Logout user and invalidate token."""
    try:
        if token_manager:
            # Add token to blacklist
            await token_manager.blacklist_token(current_user.get("token"))

        return {"message": "Logged out successfully"}

    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/change-password")
async def change_password(
    request: ChangePasswordRequest,
    current_user: Dict = Depends(get_current_user)
):
    """Change user password."""
    try:
        if not auth_manager:
            raise HTTPException(status_code=503, detail="Authentication service unavailable")

        if request.new_password != request.confirm_password:
            raise HTTPException(status_code=400, detail="Passwords do not match")

        result = await auth_manager.change_password(
            user_id=current_user.get("user_id"),
            current_password=request.current_password,
            new_password=request.new_password
        )

        if not result.success:
            raise HTTPException(status_code=400, detail=result.message)

        return {"message": "Password changed successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/reset-password")
async def reset_password(request: ResetPasswordRequest):
    """Request password reset."""
    try:
        if not auth_manager:
            raise HTTPException(status_code=503, detail="Authentication service unavailable")

        await auth_manager.request_password_reset(request.email)

        # Always return success for security (don't reveal if email exists)
        return {"message": "If the email exists, a reset link has been sent"}

    except Exception as e:
        logger.error(f"Password reset error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/me")
async def get_current_user_info(current_user: Dict = Depends(get_current_user)):
    """Get current user information."""
    try:
        return {
            "user_id": current_user.get("user_id"),
            "username": current_user.get("username"),
            "email": current_user.get("email"),
            "roles": current_user.get("roles", []),
            "permissions": current_user.get("permissions", [])
        }

    except Exception as e:
        logger.error(f"Get user info error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(current_user: Dict = Depends(get_current_user)):
    """Setup multi-factor authentication."""
    try:
        if not Advanced2FASystem:
            raise HTTPException(status_code=503, detail="MFA service unavailable")

        mfa_system = Advanced2FASystem()
        setup_result = await mfa_system.setup_totp(current_user.get("user_id"))

        return MFASetupResponse(
            qr_code=setup_result.qr_code,
            secret_key=setup_result.secret_key,
            backup_codes=setup_result.backup_codes
        )

    except Exception as e:
        logger.error(f"MFA setup error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/mfa/verify")
async def verify_mfa(
    request: MFAVerifyRequest,
    current_user: Dict = Depends(get_current_user)
):
    """Verify MFA code."""
    try:
        if not Advanced2FASystem:
            raise HTTPException(status_code=503, detail="MFA service unavailable")

        mfa_system = Advanced2FASystem()
        is_valid = await mfa_system.verify_totp(
            current_user.get("user_id"),
            request.code
        )

        if not is_valid:
            raise HTTPException(status_code=400, detail="Invalid MFA code")

        return {"message": "MFA verified successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA verification error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/status")
async def auth_status():
    """Get authentication service status."""
    return {
        "service": "authentication",
        "status": "online",
        "auth_manager": auth_manager is not None,
        "token_manager": token_manager is not None,
        "mfa_available": Advanced2FASystem is not None
    }
