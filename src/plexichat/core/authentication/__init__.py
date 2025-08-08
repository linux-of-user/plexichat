"""
PlexiChat Unified Authentication System

Single source of truth for all authentication functionality.
Integrates tightly with the security system for watertight protection.
"""

from typing import Any, Dict, Optional, List, Tuple
import logging
import hashlib
import secrets
import time
from datetime import datetime, timedelta

# Import security components for tight integration
try:
    from ..security import (  # type: ignore
        get_security_manager,  # type: ignore
        validate_input,  # type: ignore
        audit_log,  # type: ignore
        encrypt_data,  # type: ignore
        decrypt_data,  # type: ignore
        SecurityLevel as _SecurityLevel,  # type: ignore
        ThreatLevel,  # type: ignore
    )
    SecurityLevel = _SecurityLevel  # type: ignore
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False
    
    # Fallback security functions
    def get_security_manager():
        return None
    
    def validate_input(data, validation_type="general"):
        return True, None
    
    def audit_log(event, user_id=None, details=None):
        pass
    
    def encrypt_data(data):
        return data
    
    def decrypt_data(data):
        return data
    
    class SecurityLevel:
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"
    
    class ThreatLevel:
        NONE = "none"
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"

# Import logger
try:
    from ..logging import get_logger  # type: ignore
    logger = get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

class AuthenticationError(Exception):
    """Authentication-related errors."""
    def __init__(self, message: str, error_code: Optional[str] = None, threat_level: str = ThreatLevel.MEDIUM):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.threat_level = threat_level
        
        # Log security event
        audit_log("authentication_error", details={
            "message": message,
            "error_code": error_code,
            "threat_level": threat_level
        })

class AuthorizationError(Exception):
    """Authorization-related errors."""
    def __init__(self, message: str, required_permission: Optional[str] = None, threat_level: str = ThreatLevel.HIGH):
        super().__init__(message)
        self.message = message
        self.required_permission = required_permission
        self.threat_level = threat_level
        
        # Log security event
        audit_log("authorization_error", details={
            "message": message,
            "required_permission": required_permission,
            "threat_level": threat_level
        })

class SecureAuthManager:
    """Secure authentication manager with integrated security."""
    
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.failed_attempts = {}
        self.locked_accounts = {}
        self.security_manager = get_security_manager()
        
        # Security settings
        self.max_failed_attempts = 5
        self.lockout_duration = timedelta(minutes=15)
        self.session_timeout = timedelta(hours=24)
        self.password_min_length = 12
        
        logger.info("Secure authentication manager initialized")
    
    def _hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Securely hash a password with salt."""
        if not salt:
            salt = secrets.token_hex(32)
        
        # Use PBKDF2 with SHA-256
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hashed.hex(), salt
    
    def _verify_password(self, password: str, hashed: str, salt: str) -> bool:
        """Verify a password against its hash."""
        test_hash, _ = self._hash_password(password, salt)
        return secrets.compare_digest(test_hash, hashed)
    
    def _is_account_locked(self, username: str) -> bool:
        """Check if account is locked due to failed attempts."""
        if username in self.locked_accounts:
            lock_time = self.locked_accounts[username]
            if datetime.now() - lock_time < self.lockout_duration:
                return True
            else:
                # Unlock account
                del self.locked_accounts[username]
                if username in self.failed_attempts:
                    del self.failed_attempts[username]
        return False
    
    def _record_failed_attempt(self, username: str):
        """Record a failed authentication attempt."""
        self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
        
        if self.failed_attempts[username] >= self.max_failed_attempts:
            self.locked_accounts[username] = datetime.now()
            audit_log("account_locked", details={
                "username": username,
                "failed_attempts": self.failed_attempts[username],
                "threat_level": ThreatLevel.HIGH
            })
            logger.warning(f"Account locked due to failed attempts: {username}")
    
    def create_user(self, username: str, password: str, email: Optional[str] = None, permissions: Optional[List[str]] = None) -> bool:
        """Create a new user with security validation."""
        try:
            # Validate inputs
            valid, error = validate_input(username, "username")
            if not valid:
                raise AuthenticationError(f"Invalid username: {error}", "INVALID_USERNAME")
            
            valid, error = validate_input(password, "password")
            if not valid:
                raise AuthenticationError(f"Invalid password: {error}", "INVALID_PASSWORD")
            
            if len(password) < self.password_min_length:
                raise AuthenticationError(
                    f"Password must be at least {self.password_min_length} characters",
                    "PASSWORD_TOO_SHORT"
                )
            
            if username in self.users:
                raise AuthenticationError("User already exists", "USER_EXISTS")
            
            # Hash password securely
            hashed_password, salt = self._hash_password(password)
            
            # Create user record
            user_data = {
                "username": username,
                "password_hash": hashed_password,
                "salt": salt,
                "email": email,
                "permissions": permissions or [],
                "created_at": datetime.now(),
                "last_login": None,
                "is_active": True,
                "security_level": SecurityLevel.MEDIUM
            }
            
            # Encrypt sensitive data
            encrypted_data = encrypt_data(str(user_data))
            self.users[username] = encrypted_data
            
            audit_log("user_created", user_id=username, details={
                "email": email,
                "permissions": permissions,
                "security_level": SecurityLevel.MEDIUM
            })
            
            logger.info(f"User created successfully: {username}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create user {username}: {e}")
            raise
    
    def authenticate(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """Authenticate a user with security checks."""
        try:
            # Check if account is locked
            if self._is_account_locked(username):
                raise AuthenticationError(
                    "Account is locked due to too many failed attempts",
                    "ACCOUNT_LOCKED",
                    ThreatLevel.HIGH
                )
            
            # Validate inputs
            valid, error = validate_input(username, "username")
            if not valid:
                self._record_failed_attempt(username)
                raise AuthenticationError(f"Invalid username format: {error}", "INVALID_INPUT")
            
            # Check if user exists
            if username not in self.users:
                self._record_failed_attempt(username)
                raise AuthenticationError("Invalid credentials", "INVALID_CREDENTIALS")
            
            # Decrypt and verify user data
            encrypted_data = self.users[username]
            user_data = eval(decrypt_data(encrypted_data))  # Note: In production, use proper JSON
            
            # Verify password
            if not self._verify_password(password, user_data["password_hash"], user_data["salt"]):
                self._record_failed_attempt(username)
                raise AuthenticationError("Invalid credentials", "INVALID_CREDENTIALS")
            
            # Check if user is active
            if not user_data.get("is_active", True):
                raise AuthenticationError("Account is disabled", "ACCOUNT_DISABLED", ThreatLevel.MEDIUM)
            
            # Clear failed attempts on successful login
            if username in self.failed_attempts:
                del self.failed_attempts[username]
            
            # Update last login
            user_data["last_login"] = datetime.now()
            self.users[username] = encrypt_data(str(user_data))
            
            # Create secure session
            session_token = self._create_session(username, user_data)
            
            audit_log("user_authenticated", user_id=username, details={
                "security_level": user_data.get("security_level", SecurityLevel.MEDIUM),
                "session_token": session_token[:8] + "..."  # Log only first 8 chars
            })
            
            logger.info(f"User authenticated successfully: {username}")
            return True, session_token
            
        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"Authentication error for {username}: {e}")
            raise AuthenticationError("Authentication failed", "AUTH_ERROR")
    
    def _create_session(self, username: str, user_data: Dict[str, Any]) -> str:
        """Create a secure session token."""
        session_token = secrets.token_urlsafe(32)
        session_data = {
            "username": username,
            "permissions": user_data.get("permissions", []),
            "security_level": user_data.get("security_level", SecurityLevel.MEDIUM),
            "created_at": datetime.now(),
            "expires_at": datetime.now() + self.session_timeout,
            "ip_address": None,  # Should be set by the calling code
            "user_agent": None   # Should be set by the calling code
        }
        
        # Encrypt session data
        self.sessions[session_token] = encrypt_data(str(session_data))
        return session_token
    
    def validate_session(self, session_token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Validate a session token."""
        try:
            if not session_token or session_token not in self.sessions:
                return False, None
            
            # Decrypt session data
            encrypted_data = self.sessions[session_token]
            session_data = eval(decrypt_data(encrypted_data))
            
            # Check if session has expired
            if datetime.now() > session_data["expires_at"]:
                del self.sessions[session_token]
                return False, None
            
            return True, session_data
            
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return False, None
    
    def authorize(self, session_token: str, required_permission: str) -> bool:
        """Authorize a user for a specific permission."""
        try:
            valid, session_data = self.validate_session(session_token)
            if not valid or not session_data:
                raise AuthorizationError(
                    "Invalid or expired session",
                    required_permission,
                    ThreatLevel.HIGH
                )
            
            user_permissions = session_data.get("permissions", [])
            
            # Check if user has the required permission
            if required_permission not in user_permissions and "admin" not in user_permissions:
                raise AuthorizationError(
                    f"Permission denied: {required_permission}",
                    required_permission,
                    ThreatLevel.MEDIUM
                )
            
            audit_log("authorization_success", user_id=session_data["username"], details={
                "required_permission": required_permission,
                "user_permissions": user_permissions
            })
            
            return True
            
        except AuthorizationError:
            raise
        except Exception as e:
            logger.error(f"Authorization error: {e}")
            raise AuthorizationError("Authorization failed", required_permission)

# Global authentication manager
_auth_manager = SecureAuthManager()

def get_auth_manager() -> SecureAuthManager:
    """Get the global authentication manager."""
    return _auth_manager

def authenticate_user(username: str, password: str) -> Tuple[bool, Optional[str]]:
    """Authenticate a user and return session token."""
    return _auth_manager.authenticate(username, password)

def authorize_user(session_token: str, permission: str) -> bool:
    """Authorize a user for a specific permission."""
    return _auth_manager.authorize(session_token, permission)

def create_user(username: str, password: str, email: Optional[str] = None, permissions: Optional[List[str]] = None) -> bool:
    """Create a new user."""
    return _auth_manager.create_user(username, password, email, permissions)

def validate_session(session_token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Validate a session token."""
    return _auth_manager.validate_session(session_token)

# Security decorators
def require_auth(func):
    """Decorator to require authentication."""
    def wrapper(*args, **kwargs):
        session_token = kwargs.get('session_token') or (args[0] if args else None)
        if not session_token:
            raise AuthenticationError("Authentication required", "NO_SESSION")
        
        valid, _ = validate_session(session_token)
        if not valid:
            raise AuthenticationError("Invalid or expired session", "INVALID_SESSION")
        
        return func(*args, **kwargs)
    return wrapper

def require_permission(permission: str):
    """Decorator to require a specific permission."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            session_token = kwargs.get('session_token') or (args[0] if args else None)
            if not session_token:
                raise AuthenticationError("Authentication required", "NO_SESSION")
            
            if not authorize_user(session_token, permission):
                raise AuthorizationError(f"Permission required: {permission}", permission)
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

def require_admin(func):
    """Decorator to require admin privileges."""
    return require_permission("admin")(func)

# Export all the main classes and functions
__all__ = [
    # Main classes
    "SecureAuthManager",
    "AuthenticationError",
    "AuthorizationError",
    
    # Main functions
    "get_auth_manager",
    "authenticate_user",
    "authorize_user",
    "create_user",
    "validate_session",
    
    # Decorators
    "require_auth",
    "require_permission",
    "require_admin",
]
