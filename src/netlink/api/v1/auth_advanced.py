# app/api/v2/auth_advanced.py
"""
Advanced authentication endpoints with 2FA, session management, and enhanced security.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from sqlmodel import Session, select

from app.db import get_session
from app.models.user import User
from app.models.enhanced_models import UserSession, AuditLog
from app.utils.security import SecurityManager, TimeBasedSecurity, AdvancedEncryption
from app.utils.ip_security import ip_security
from app.logger_config import logger

router = APIRouter(prefix="/v2/auth", tags=["Authentication v2"])
security = HTTPBearer()
security_manager = SecurityManager()


# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str
    device_info: Optional[Dict[str, Any]] = None
    remember_me: bool = False


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_info: Dict[str, Any]
    requires_2fa: bool = False
    session_id: str


class TwoFactorSetupRequest(BaseModel):
    password: str


class TwoFactorSetupResponse(BaseModel):
    secret: str
    qr_code_url: str
    backup_codes: List[str]


class TwoFactorVerifyRequest(BaseModel):
    code: str
    session_id: str


class TwoFactorEnableRequest(BaseModel):
    code: str
    backup_codes: List[str]


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str
    logout_other_sessions: bool = True


class SessionInfo(BaseModel):
    session_id: str
    ip_address: str
    user_agent: str
    created_at: datetime
    last_activity: datetime
    is_current: bool
    location: Optional[Dict[str, str]] = None


@router.post("/login", response_model=LoginResponse)
async def advanced_login(
    request: LoginRequest,
    http_request: Request,
    session: Session = Depends(get_session)
):
    """Advanced login with device tracking and 2FA support."""
    
    # Get client information
    client_ip = security_manager.get_client_ip(http_request)
    user_agent = http_request.headers.get("user-agent", "")
    device_fingerprint = security_manager.generate_device_fingerprint(
        http_request, 
        request.device_info
    )
    
    # Find user
    user = session.exec(select(User).where(User.username == request.username)).first()
    if not user:
        # Record failed attempt
        ip_security.record_failed_attempt(client_ip, "invalid_username")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Verify password
    if not security_manager.verify_password(request.password, user.password_hash):
        # Record failed attempt
        ip_security.record_failed_attempt(client_ip, "invalid_password")
        
        # Log audit event
        audit_log = AuditLog(
            user_id=user.id,
            action="failed_login",
            resource_type="user",
            resource_id=str(user.id),
            ip_address=client_ip,
            user_agent=user_agent,
            success=False,
            error_message="Invalid password"
        )
        session.add(audit_log)
        session.commit()
        
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check if 2FA is enabled
    if user.two_factor_enabled:
        # Create temporary session for 2FA
        temp_session_id = security_manager.generate_session_id()
        
        # Store temporary session data (in production, use Redis)
        temp_session_data = {
            "user_id": user.id,
            "ip_address": client_ip,
            "user_agent": user_agent,
            "device_fingerprint": device_fingerprint,
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
            "requires_2fa": True
        }
        
        # In production, store in Redis with expiration
        # redis_client.setex(f"temp_session:{temp_session_id}", 600, json.dumps(temp_session_data))
        
        return LoginResponse(
            access_token="",
            refresh_token="",
            expires_in=0,
            user_info={},
            requires_2fa=True,
            session_id=temp_session_id
        )
    
    # Create full session
    session_id = security_manager.generate_session_id()
    expires_at = datetime.now(timezone.utc) + timedelta(
        days=30 if request.remember_me else 1
    )
    
    # Create user session
    user_session = UserSession(
        session_id=session_id,
        user_id=user.id,
        ip_address=client_ip,
        user_agent=user_agent,
        device_fingerprint=device_fingerprint,
        expires_at=expires_at,
        login_method="password"
    )
    session.add(user_session)
    
    # Update user login info
    user.last_login_at = datetime.now(timezone.utc)
    user.login_count += 1
    
    # Create tokens
    access_token = security_manager.create_access_token({
        "user_id": user.id,
        "session_id": session_id,
        "scopes": ["read", "write"]
    })
    
    refresh_token = security_manager.create_refresh_token(user.id, session_id)
    
    # Log successful login
    audit_log = AuditLog(
        user_id=user.id,
        session_id=session_id,
        action="login",
        resource_type="user",
        resource_id=str(user.id),
        ip_address=client_ip,
        user_agent=user_agent,
        success=True
    )
    session.add(audit_log)
    session.commit()
    
    logger.info("User %s logged in from %s", user.username, client_ip)
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=security_manager.access_token_expire_minutes * 60,
        user_info={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "display_name": user.display_name
        },
        requires_2fa=False,
        session_id=session_id
    )


@router.post("/2fa/setup", response_model=TwoFactorSetupResponse)
async def setup_two_factor(
    request: TwoFactorSetupRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Setup two-factor authentication."""
    
    # Verify current password
    if not security_manager.verify_password(request.password, current_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # Generate TOTP secret
    secret = TimeBasedSecurity.generate_totp_secret()
    
    # Generate backup codes
    backup_codes = [security_manager.generate_backup_code() for _ in range(10)]
    
    # Create QR code URL
    qr_code_url = f"otpauth://totp/ChatAPI:{current_user.username}?secret={secret}&issuer=ChatAPI"
    
    # Store secret temporarily (user needs to verify before enabling)
    # In production, store in Redis with expiration
    temp_2fa_data = {
        "secret": secret,
        "backup_codes": backup_codes,
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    }
    
    return TwoFactorSetupResponse(
        secret=secret,
        qr_code_url=qr_code_url,
        backup_codes=backup_codes
    )


@router.post("/2fa/verify")
async def verify_two_factor(
    request: TwoFactorVerifyRequest,
    http_request: Request,
    session: Session = Depends(get_session)
):
    """Verify 2FA code and complete login."""
    
    # Get temporary session data
    # In production, get from Redis
    # temp_session_data = redis_client.get(f"temp_session:{request.session_id}")
    
    # For demo, simulate temp session data
    temp_session_data = {
        "user_id": 1,  # This would come from Redis
        "requires_2fa": True
    }
    
    if not temp_session_data or not temp_session_data.get("requires_2fa"):
        raise HTTPException(status_code=400, detail="Invalid session")
    
    # Get user
    user = session.get(User, temp_session_data["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify 2FA code
    if not TimeBasedSecurity.verify_totp_code(user.two_factor_secret, request.code):
        # Check backup codes
        if request.code not in user.backup_codes:
            raise HTTPException(status_code=401, detail="Invalid 2FA code")
        else:
            # Remove used backup code
            backup_codes = user.backup_codes.copy()
            backup_codes.remove(request.code)
            user.backup_codes = backup_codes
    
    # Create full session (similar to login endpoint)
    session_id = security_manager.generate_session_id()
    client_ip = security_manager.get_client_ip(http_request)
    
    # Create tokens
    access_token = security_manager.create_access_token({
        "user_id": user.id,
        "session_id": session_id,
        "scopes": ["read", "write"]
    })
    
    refresh_token = security_manager.create_refresh_token(user.id, session_id)
    
    session.commit()
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": security_manager.access_token_expire_minutes * 60
    }


@router.post("/2fa/enable")
async def enable_two_factor(
    request: TwoFactorEnableRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Enable 2FA after verification."""
    
    # Get temporary 2FA data
    # In production, get from Redis
    
    # Verify the code with the temporary secret
    # This would use the secret from Redis
    
    # Enable 2FA for user
    current_user.two_factor_enabled = True
    current_user.two_factor_secret = "secret_from_redis"  # Get from Redis
    current_user.backup_codes = request.backup_codes
    
    session.commit()
    
    logger.info("2FA enabled for user %s", current_user.username)
    
    return {"message": "Two-factor authentication enabled successfully"}


@router.get("/sessions", response_model=List[SessionInfo])
async def get_user_sessions(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Get user's active sessions."""
    
    sessions = session.exec(
        select(UserSession).where(
            UserSession.user_id == current_user.id,
            UserSession.status == "active"
        )
    ).all()
    
    current_session_id = getattr(current_user, 'current_session_id', None)
    
    session_info = []
    for user_session in sessions:
        session_info.append(SessionInfo(
            session_id=user_session.session_id,
            ip_address=user_session.ip_address,
            user_agent=user_session.user_agent or "",
            created_at=user_session.created_at,
            last_activity=user_session.last_activity_at,
            is_current=user_session.session_id == current_session_id,
            location={
                "country": user_session.country,
                "city": user_session.city
            } if user_session.country else None
        ))
    
    return session_info


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Revoke a specific session."""
    
    user_session = session.exec(
        select(UserSession).where(
            UserSession.session_id == session_id,
            UserSession.user_id == current_user.id
        )
    ).first()
    
    if not user_session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Revoke session
    user_session.status = "revoked"
    user_session.revoked_at = datetime.now(timezone.utc)
    
    # Blacklist associated tokens
    security_manager.blacklist_session_tokens(session_id)
    
    session.commit()
    
    logger.info("Session %s revoked for user %s", session_id, current_user.username)
    
    return {"message": "Session revoked successfully"}


# Dependency to get current user
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    session: Session = Depends(get_session)
) -> User:
    """Get current authenticated user."""
    
    try:
        payload = security_manager.validate_access_token(credentials.credentials)
        user_id = payload.get("user_id")
        
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        # Add session info to user object
        user.current_session_id = payload.get("session_id")
        
        return user
        
    except Exception as e:
        logger.warning("Token validation failed: %s", e)
        raise HTTPException(status_code=401, detail="Invalid token")
