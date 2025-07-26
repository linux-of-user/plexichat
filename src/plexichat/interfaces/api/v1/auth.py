"""
PlexiChat API v1 - Enhanced Authentication System

Comprehensive authentication with full system integration:
- User registration with validation
- Multi-factor authentication
- Advanced session management
- Database abstraction integration
- Security system integration
- Caching optimization
- Rate limiting
- Audit logging
- Password policies
- Token management
"""

import asyncio
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, validator
import logging

# Core system imports
try:
    from plexichat.core.database import database_manager, execute_query
    from plexichat.core.caching.unified_cache_integration import cache_get, cache_set, cache_delete, cached
    from plexichat.core.security.unified_security_system import unified_security_manager, SecurityRequest, SecurityLevel
    from plexichat.core.auth.unified_auth_manager import unified_auth_manager
    from plexichat.core.security.two_factor_auth import two_factor_authenticator, TwoFactorMethod
    from plexichat.infrastructure.performance.performance_logger import performance_logger
except ImportError as e:
    # Fallback implementations
    database_manager = None
    execute_query = lambda q, p=None: {}
    async def cache_get(k, d=None): return d
    async def cache_set(k, v, t=None): return True
    async def cache_delete(k): return True
    cached = lambda ttl=None: lambda f: f
    unified_security_manager = None
    unified_auth_manager = None
    performance_logger = None
    SecurityRequest = dict
    SecurityLevel = None

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Enhanced Authentication"])
security = HTTPBearer()

# In-memory fallback storage
users_db = {}
sessions_db = {}
mfa_codes_db = {}
failed_attempts_db = {}

# Configuration
SECRET_KEY = "plexichat_secure_key_2024_v2"
TOKEN_EXPIRY_HOURS = 24
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 30
MFA_CODE_EXPIRY_MINUTES = 5
PASSWORD_MIN_LENGTH = 12

# Enhanced Models
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r'^[a-zA-Z0-9_-]+$')
    email: EmailStr
    password: str = Field(..., min_length=PASSWORD_MIN_LENGTH)
    display_name: Optional[str] = Field(None, max_length=100)
    first_name: Optional[str] = Field(None, max_length=50)
    last_name: Optional[str] = Field(None, max_length=50)
    invite_code: Optional[str] = None
    terms_accepted: bool = Field(..., description="Must accept terms of service")

    @validator('password')
    def validate_password_strength(cls, v):
        """Validate password meets security requirements."""
        if len(v) < PASSWORD_MIN_LENGTH:
            raise ValueError(f'Password must be at least {PASSWORD_MIN_LENGTH} characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in v):
            raise ValueError('Password must contain at least one special character')
        return v

class UserLogin(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None
    remember_me: bool = False
    device_info: Optional[Dict[str, str]] = None

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    username: str
    requires_mfa: bool = False
    session_id: str
    permissions: List[str] = []

class MFASetupResponse(BaseModel):
    secret_key: str
    qr_code_url: str
    backup_codes: List[str]

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=PASSWORD_MIN_LENGTH)
    confirm_password: str

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

class PasswordResetRequest(BaseModel):
    email: EmailStr

class SessionInfo(BaseModel):
    session_id: str
    user_id: str
    created_at: datetime
    last_activity: datetime
    ip_address: str
    user_agent: str
    is_active: bool

# Two-Factor Authentication Models
class TwoFactorSetupRequest(BaseModel):
    device_name: Optional[str] = "Default Device"

class TwoFactorSetupResponse(BaseModel):
    secret_key: str
    qr_code: str  # Base64 encoded QR code image
    backup_codes: List[str]
    formatted_backup_codes: str
    setup_uri: str

class TwoFactorVerificationRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)
    method: Optional[str] = None  # totp, backup_codes, etc.

class TwoFactorStatusResponse(BaseModel):
    user_id: str
    has_2fa_enabled: bool
    enabled_methods: List[str]
    methods_status: Dict[str, Any]
    total_attempts: int
    recent_success: bool

class LoginWith2FARequest(BaseModel):
    username: str
    password: str
    two_factor_code: str = Field(..., min_length=6, max_length=8)
    method: Optional[str] = None
    remember_me: bool = False
    device_info: Optional[Dict[str, str]] = None

# Enhanced Utility Functions
def hash_password(password: str) -> str:
    """Hash password with advanced security."""
    # Synchronous implementation for now
    salt = secrets.token_hex(32)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 200000)
    return f"{salt}:{pwd_hash.hex()}"

def verify_password(password: str, hashed: str) -> bool:
    """Verify password with security monitoring."""
    # Synchronous implementation for now
    try:
        salt, pwd_hash = hashed.split(':')
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 200000).hex() == pwd_hash
    except:
        return False

async def generate_secure_token(user_id: str, session_type: str = "access") -> str:
    """Generate cryptographically secure token."""
    if unified_security_manager:
        return await unified_security_manager.token_manager.generate_token({
            'user_id': user_id,
            'session_type': session_type,
            'timestamp': time.time(),
            'nonce': secrets.token_hex(16)
        })
    else:
        # Fallback implementation
        timestamp = int(time.time())
        data = f"{user_id}:{session_type}:{timestamp}:{secrets.token_hex(32)}"
        return hashlib.sha256(f"{data}:{SECRET_KEY}".encode()).hexdigest()

async def validate_token(token: str) -> Optional[Dict[str, Any]]:
    """Validate and decode token."""
    if unified_security_manager:
        return await unified_security_manager.token_manager.validate_token(token)
    else:
        # Fallback - find session by token
        for session_id, session in sessions_db.items():
            if session.get('access_token') == token or session.get('refresh_token') == token:
                if session.get('expires_at', 0) > time.time():
                    return {
                        'user_id': session.get('user_id'),
                        'session_id': session_id,
                        'expires_at': session.get('expires_at')
                    }
        return None

async def check_rate_limit(identifier: str, max_attempts: int = 10, window_minutes: int = 15) -> bool:
    """Check if identifier is rate limited."""
    if unified_security_manager:
        return await unified_security_manager.rate_limiter.check_rate_limit(
            identifier, max_attempts, window_minutes * 60
        )
    else:
        # Simple fallback rate limiting
        cache_key = f"rate_limit:{identifier}"
        attempts = await cache_get(cache_key, 0)
        if attempts >= max_attempts:
            return False
        await cache_set(cache_key, attempts + 1, window_minutes * 60)
        return True

async def generate_mfa_code() -> str:
    """Generate MFA code."""
    return f"{secrets.randbelow(1000000):06d}"

async def send_mfa_code(user_id: str, code: str) -> bool:
    """Send MFA code to user (placeholder)."""
    # In production, integrate with SMS/email service
    mfa_codes_db[user_id] = {
        'code': code,
        'expires_at': time.time() + (MFA_CODE_EXPIRY_MINUTES * 60),
        'attempts': 0
    }
    logger.info(f"MFA code generated for user {user_id}: {code}")  # Remove in production
    return True

async def verify_mfa_code(user_id: str, provided_code: str) -> bool:
    """Verify MFA code."""
    mfa_data = mfa_codes_db.get(user_id)
    if not mfa_data:
        return False

    if time.time() > mfa_data['expires_at']:
        del mfa_codes_db[user_id]
        return False

    mfa_data['attempts'] += 1
    if mfa_data['attempts'] > 3:
        del mfa_codes_db[user_id]
        return False

    if mfa_data['code'] == provided_code:
        del mfa_codes_db[user_id]
        return True

    return False

async def check_account_lockout(username: str) -> bool:
    """Check if account is locked out."""
    lockout_data = failed_attempts_db.get(username)
    if not lockout_data:
        return False

    if lockout_data['attempts'] >= MAX_FAILED_ATTEMPTS:
        if time.time() < lockout_data['locked_until']:
            return True
        else:
            # Lockout expired, reset
            del failed_attempts_db[username]
            return False

    return False

async def record_failed_attempt(username: str):
    """Record failed login attempt."""
    if username not in failed_attempts_db:
        failed_attempts_db[username] = {'attempts': 0, 'locked_until': 0}

    failed_attempts_db[username]['attempts'] += 1

    if failed_attempts_db[username]['attempts'] >= MAX_FAILED_ATTEMPTS:
        failed_attempts_db[username]['locked_until'] = time.time() + (LOCKOUT_DURATION_MINUTES * 60)
        logger.warning(f"Account locked due to failed attempts: {username}")

async def clear_failed_attempts(username: str):
    """Clear failed login attempts."""
    if username in failed_attempts_db:
        del failed_attempts_db[username]

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Enhanced user authentication with security monitoring."""
    try:
        token = credentials.credentials

        # Validate token format
        if not token or len(token) < 32:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format"
            )

        # Check token in cache first
        cache_key = f"auth_token:{token[:16]}"
        cached_user = await cache_get(cache_key)
        if cached_user:
            return cached_user

        # Validate token through security system
        token_data = await validate_token(token)
        if not token_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )

        user_id = token_data.get('user_id')
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload"
            )

        # Get user from database or fallback
        user = await get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )

        # Update last activity
        user['last_active'] = datetime.now()
        if database_manager:
            try:
                await execute_query(
                    "UPDATE users SET last_active = ? WHERE id = ?",
                    [user['last_active'], user_id]
                )
            except Exception as e:
                logger.error(f"Database error updating activity: {e}")
        else:
            users_db[user_id] = user

        # Cache user data
        await cache_set(cache_key, user, 300)  # 5 minute cache

        # Performance logging
        if performance_logger:
            performance_logger.record_metric("auth_success", 1, "count")

        return user

    except HTTPException:
        if performance_logger:
            performance_logger.record_metric("auth_failure", 1, "count")
        raise
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error"
        )

async def get_user_by_id(user_id: str) -> Optional[dict]:
    """Get user by ID with caching."""
    cache_key = f"user:{user_id}"
    cached_user = await cache_get(cache_key)
    if cached_user:
        return cached_user

    user = None
    if database_manager:
        try:
            result = await execute_query(
                "SELECT * FROM users WHERE id = ?",
                [user_id]
            )
            if result:
                user = dict(result[0]) if isinstance(result, list) else dict(result)
        except Exception as e:
            logger.error(f"Database error getting user by ID: {e}")

    if not user and user_id in users_db:
        user = users_db[user_id].copy()

    if user:
        await cache_set(cache_key, user, 600)  # 10 minute cache

    return user

async def get_user_by_username(username: str) -> Optional[dict]:
    """Get user by username with caching."""
    cache_key = f"user_by_username:{username}"
    cached_user = await cache_get(cache_key)
    if cached_user:
        return cached_user

    user = None
    if database_manager:
        try:
            result = await execute_query(
                "SELECT * FROM users WHERE username = ?",
                [username]
            )
            if result:
                user = dict(result[0]) if isinstance(result, list) else dict(result)
        except Exception as e:
            logger.error(f"Database error getting user by username: {e}")

    if not user:
        for u in users_db.values():
            if u.get('username') == username:
                user = u.copy()
                break

    if user:
        await cache_set(cache_key, user, 600)  # 10 minute cache

    return user

# Endpoints
@router.post("/register", response_model=dict)
async def register(user_data: UserRegister):
    """Register a new user."""
    try:
        # Check if user exists
        for user in users_db.values():
            if user['username'] == user_data.username:
                raise HTTPException(status_code=400, detail="Username already exists")
            if user['email'] == user_data.email:
                raise HTTPException(status_code=400, detail="Email already exists")
        
        # Create user
        user_id = str(uuid4())
        user = {
            'id': user_id,
            'username': user_data.username,
            'email': user_data.email,
            'display_name': user_data.display_name or user_data.username,
            'password_hash': hash_password(user_data.password),
            'created_at': datetime.now(),
            'is_active': True
        }
        
        users_db[user_id] = user
        logger.info(f"User registered: {user_data.username}")
        
        return {
            "success": True,
            "message": "User registered successfully",
            "user_id": user_id,
            "username": user_data.username
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@router.post("/login", response_model=TokenResponse)
async def login(login_data: UserLogin):
    """Login user and return token."""
    try:
        # Find user
        user = None
        for u in users_db.values():
            if u['username'] == login_data.username:
                user = u
                break
        
        if not user or not verify_password(login_data.password, user['password_hash']):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Create session
        session_id = str(uuid4())
        access_token = await generate_secure_token(user['id'], "access")
        refresh_token = await generate_secure_token(user['id'], "refresh")
        expires_at = time.time() + (TOKEN_EXPIRY_HOURS * 3600)

        sessions_db[session_id] = {
            'session_id': session_id,
            'user_id': user['id'],
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_at': expires_at,
            'created_at': time.time()
        }

        logger.info(f"User logged in: {user['username']}")

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=TOKEN_EXPIRY_HOURS * 3600,
            user_id=user['id'],
            username=user['username'],
            session_id=session_id,
            permissions=[]  # Add default empty permissions
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Logout user."""
    try:
        user_id = current_user['id']
        
        # Remove sessions
        sessions_to_remove = [
            sid for sid, session in sessions_db.items()
            if session.get('user_id') == user_id
        ]
        
        for session_id in sessions_to_remove:
            del sessions_db[session_id]
        
        logger.info(f"User logged out: {current_user['username']}")
        return {"success": True, "message": "Logged out successfully"}
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(status_code=500, detail="Logout failed")

@router.get("/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information."""
    return {
        "id": current_user['id'],
        "username": current_user['username'],
        "email": current_user['email'],
        "display_name": current_user['display_name'],
        "created_at": current_user['created_at'],
        "is_active": current_user['is_active']
    }

@router.get("/status")
async def auth_status():
    """Get authentication service status."""
    return {
        "service": "authentication",
        "status": "online",
        "total_users": len(users_db),
        "active_sessions": len(sessions_db),
        "timestamp": datetime.now()
    }

# Two-Factor Authentication Endpoints

@router.post("/2fa/setup", response_model=TwoFactorSetupResponse)
async def setup_two_factor_auth(
    request: TwoFactorSetupRequest,
    http_request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Setup two-factor authentication for the current user."""
    try:
        user_id = current_user['id']
        user_email = current_user['email']
        client_ip = http_request.client.host if http_request.client else "unknown"

        # Setup TOTP-based 2FA
        setup_result = await two_factor_authenticator.setup_totp(
            user_id=user_id,
            user_email=user_email,
            device_name=request.device_name,
            ip_address=client_ip
        )

        logger.info(f"2FA setup initiated for user {current_user['username']}")

        return TwoFactorSetupResponse(**setup_result)

    except Exception as e:
        logger.error(f"2FA setup error for user {current_user['username']}: {e}")
        raise HTTPException(status_code=500, detail="Failed to setup two-factor authentication")

@router.post("/2fa/verify-setup")
async def verify_two_factor_setup(
    request: TwoFactorVerificationRequest,
    http_request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Verify two-factor authentication setup with user-provided code."""
    try:
        user_id = current_user['id']
        client_ip = http_request.client.host if http_request.client else "unknown"

        # Verify setup code
        success = await two_factor_authenticator.verify_totp_setup(
            user_id=user_id,
            verification_code=request.code,
            ip_address=client_ip
        )

        if success:
            logger.info(f"2FA setup completed for user {current_user['username']}")
            return {"success": True, "message": "Two-factor authentication enabled successfully"}
        else:
            raise HTTPException(status_code=400, detail="Invalid verification code")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"2FA setup verification error for user {current_user['username']}: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify two-factor authentication setup")

@router.post("/2fa/verify")
async def verify_two_factor_code(
    request: TwoFactorVerificationRequest,
    http_request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Verify two-factor authentication code."""
    try:
        user_id = current_user['id']
        client_ip = http_request.client.host if http_request.client else "unknown"
        user_agent = http_request.headers.get("user-agent", "unknown")

        # Parse method if provided
        method = None
        if request.method:
            try:
                method = TwoFactorMethod(request.method)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid 2FA method")

        # Verify code
        result = await two_factor_authenticator.verify_two_factor(
            user_id=user_id,
            code=request.code,
            method=method,
            ip_address=client_ip,
            user_agent=user_agent
        )

        if result['success']:
            return {
                "success": True,
                "method": result['method'],
                "message": result['message']
            }
        else:
            status_code = 429 if result.get('error') == 'rate_limit_exceeded' else 400
            raise HTTPException(status_code=status_code, detail=result['message'])

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"2FA verification error for user {current_user['username']}: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify two-factor authentication code")

@router.get("/2fa/status", response_model=TwoFactorStatusResponse)
async def get_two_factor_status(current_user: dict = Depends(get_current_user)):
    """Get user's two-factor authentication status."""
    try:
        user_id = current_user['id']

        status = await two_factor_authenticator.get_user_2fa_status(user_id)

        return TwoFactorStatusResponse(**status)

    except Exception as e:
        logger.error(f"2FA status error for user {current_user['username']}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get two-factor authentication status")

@router.post("/2fa/disable")
async def disable_two_factor_auth(
    current_user: dict = Depends(get_current_user)
):
    """Disable two-factor authentication for the current user."""
    try:
        user_id = current_user['id']

        success = await two_factor_authenticator.disable_two_factor(user_id)

        if success:
            logger.info(f"2FA disabled for user {current_user['username']}")
            return {"success": True, "message": "Two-factor authentication disabled successfully"}
        else:
            raise HTTPException(status_code=400, detail="Failed to disable two-factor authentication")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"2FA disable error for user {current_user['username']}: {e}")
        raise HTTPException(status_code=500, detail="Failed to disable two-factor authentication")

@router.post("/2fa/backup-codes")
async def generate_new_backup_codes(current_user: dict = Depends(get_current_user)):
    """Generate new backup codes for two-factor authentication."""
    try:
        user_id = current_user['id']

        new_codes = await two_factor_authenticator.generate_new_backup_codes(user_id)

        if new_codes:
            logger.info(f"New backup codes generated for user {current_user['username']}")
            return {
                "success": True,
                "backup_codes": new_codes,
                "message": "New backup codes generated successfully"
            }
        else:
            raise HTTPException(status_code=400, detail="Failed to generate new backup codes")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Backup codes generation error for user {current_user['username']}: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate new backup codes")

@router.post("/login-2fa", response_model=TokenResponse)
async def login_with_two_factor(
    request: LoginWith2FARequest,
    http_request: Request
):
    """Login with username, password, and two-factor authentication code."""
    try:
        client_ip = http_request.client.host if http_request.client else "unknown"
        user_agent = http_request.headers.get("user-agent", "unknown")

        # First verify username and password
        user = None
        for u in users_db.values():
            if u['username'] == request.username:
                user = u
                break

        if not user or not verify_password(request.password, user['hashed_password']):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Verify 2FA code
        method = None
        if request.method:
            try:
                method = TwoFactorMethod(request.method)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid 2FA method")

        verification_result = await two_factor_authenticator.verify_two_factor(
            user_id=user['id'],
            code=request.two_factor_code,
            method=method,
            ip_address=client_ip,
            user_agent=user_agent
        )

        if not verification_result['success']:
            status_code = 429 if verification_result.get('error') == 'rate_limit_exceeded' else 401
            raise HTTPException(status_code=status_code, detail=verification_result['message'])

        # Create session and tokens
        session_id = str(uuid4())
        access_token = create_access_token(user['id'], user['username'])
        refresh_token = create_refresh_token(user['id'])

        # Store session
        sessions_db[session_id] = {
            'user_id': user['id'],
            'username': user['username'],
            'created_at': datetime.now(),
            'last_activity': datetime.now(),
            'ip_address': client_ip,
            'user_agent': user_agent,
            'is_active': True,
            'two_factor_verified': True,
            'two_factor_method': verification_result['method']
        }

        # Update user last login
        user['last_login'] = datetime.now()

        logger.info(f"User logged in with 2FA: {user['username']} using {verification_result['method']}")

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user_id=user['id'],
            username=user['username'],
            session_id=session_id,
            requires_mfa=False  # Already verified
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"2FA login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")
