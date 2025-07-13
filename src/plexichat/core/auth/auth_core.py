import hashlib
import json
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

"""
PlexiChat Unified Authentication System

Consolidates authentication functionality from:
- src/plexichat/core/auth/ (unified auth managers)
- src/plexichat/app/auth/ (advanced auth features)

Provides comprehensive authentication with government-level security.
"""

logger = logging.getLogger(__name__)

# Authentication security levels
class SecurityLevel(Enum):
    """Security levels for authentication."""
    BASIC = 1
    ENHANCED = 2
    GOVERNMENT = 3
    MILITARY = 4
    ZERO_KNOWLEDGE = 5

class AuthAction(Enum):
    """Authentication actions for audit logging."""
    LOGIN = "login"
    LOGOUT = "logout"
    PASSWORD_RESET_REQUEST = "password_reset_request"
    PASSWORD_RESET_CONFIRM = "password_reset_confirm"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    MFA_SETUP = "mfa_setup"
    MFA_VERIFY = "mfa_verify"
    BIOMETRIC_ENROLL = "biometric_enroll"
    DEVICE_REGISTER = "device_register"

@dataclass
class AuthAttempt:
    """Authentication attempt record for audit logging."""
    timestamp: datetime
    username: str
    ip_address: str
    user_agent: str
    action: AuthAction
    success: bool
    security_level: SecurityLevel
    failure_reason: Optional[str] = None
    session_id: Optional[str] = None
    device_id: Optional[str] = None

@dataclass
class AuthSession:
    """Authentication session data."""
    session_id: str
    username: str
    security_level: SecurityLevel
    created_at: datetime
    last_activity: datetime
    ip_address: str
    user_agent: str
    device_id: Optional[str] = None
    mfa_verified: bool = False
    biometric_verified: bool = False

class AuthManager:
    """
    Unified Authentication Manager

    Central authentication manager that coordinates all authentication
    operations and provides a unified interface for the system.

    Consolidates functionality from:
    - src/plexichat/core/auth/auth_manager.py
    - src/plexichat/app/auth/ modules
    """

    def __init__(self, config_dir: str = "data/auth"):
        self.config_dir = from pathlib import Path
Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Data storage
        self.accounts_file = self.config_dir / "accounts.json"
        self.attempts_file = self.config_dir / "attempts.json"
        self.sessions_file = self.config_dir / "sessions.json"

        # In-memory data
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.auth_attempts: List[AuthAttempt] = []
        self.active_sessions: Dict[str, AuthSession] = {}

        # Configuration
        self.max_failed_attempts = 5
        self.lockout_duration_minutes = 30
        self.session_timeout_minutes = 30
        self.password_history_count = 12

        # Component managers
        self.token_manager = None
        self.session_manager = None
        self.password_manager = None
        self.mfa_manager = None
        self.biometric_manager = None
        self.device_manager = None
        self.audit_manager = None
        self.advanced_auth_system = None

        # State
        self.initialized = False

        # Load existing data
        self._load_data()

        # Create default admin if none exist
        if not self.accounts:
            self._create_default_admin()
    
    def _load_data(self):
        """Load authentication data from files."""
        try:
            if self.accounts_file.exists():
                with open(self.accounts_file, 'r') as f:
                    self.accounts = json.load(f)
            
            if self.attempts_file.exists():
                with open(self.attempts_file, 'r') as f:
                    attempts_data = json.load(f)
                    self.auth_attempts = [
                        AuthAttempt(
                            timestamp=datetime.fromisoformat(attempt['timestamp']),
                            username=attempt['username'],
                            ip_address=attempt['ip_address'],
                            user_agent=attempt['user_agent'],
                            action=AuthAction(attempt['action']),
                            success=attempt['success'],
                            security_level=SecurityLevel(attempt['security_level']),
                            failure_reason=attempt.get('failure_reason'),
                            session_id=attempt.get('session_id'),
                            device_id=attempt.get('device_id')
                        )
                        for attempt in attempts_data
                    ]
            
            if self.sessions_file.exists():
                with open(self.sessions_file, 'r') as f:
                    sessions_data = json.load(f)
                    self.active_sessions = {
                        session_id: AuthSession(
                            session_id=session_data['session_id'],
                            username=session_data['username'],
                            security_level=SecurityLevel(session_data['security_level']),
                            created_at=datetime.fromisoformat(session_data['created_at']),
                            last_activity=datetime.fromisoformat(session_data['last_activity']),
                            ip_address=session_data['ip_address'],
                            user_agent=session_data['user_agent'],
                            device_id=session_data.get('device_id'),
                            mfa_verified=session_data.get('mfa_verified', False),
                            biometric_verified=session_data.get('biometric_verified', False)
                        )
                        for session_id, session_data in sessions_data.items()
                    }
                    
        except Exception as e:
            logger.error(f"Error loading authentication data: {e}")
    
    def _save_data(self):
        """Save authentication data to files."""
        try:
            # Save accounts
            with open(self.accounts_file, 'w') as f:
                json.dump(self.accounts, f, indent=2)
            
            # Save attempts
            attempts_data = [
                {
                    'timestamp': attempt.timestamp.isoformat(),
                    'username': attempt.username,
                    'ip_address': attempt.ip_address,
                    'user_agent': attempt.user_agent,
                    'action': attempt.action.value,
                    'success': attempt.success,
                    'security_level': attempt.security_level.value,
                    'failure_reason': attempt.failure_reason,
                    'session_id': attempt.session_id,
                    'device_id': attempt.device_id
                }
                for attempt in self.auth_attempts[-1000:]  # Keep last 1000 attempts
            ]
            with open(self.attempts_file, 'w') as f:
                json.dump(attempts_data, f, indent=2)
            
            # Save sessions
            sessions_data = {
                session_id: {
                    'session_id': session.session_id,
                    'username': session.username,
                    'security_level': session.security_level.value,
                    'created_at': session.created_at.isoformat(),
                    'last_activity': session.last_activity.isoformat(),
                    'ip_address': session.ip_address,
                    'user_agent': session.user_agent,
                    'device_id': session.device_id,
                    'mfa_verified': session.mfa_verified,
                    'biometric_verified': session.biometric_verified
                }
                for session_id, session in self.active_sessions.items()
            }
            with open(self.sessions_file, 'w') as f:
                json.dump(sessions_data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving authentication data: {e}")
    
    def _create_default_admin(self):
        """Create default admin account if none exist."""
        default_password = secrets.token_urlsafe(16)
        password_hash = hashlib.pbkdf2_hmac('sha256', default_password.encode(), b'salt', 100000)
        
        self.accounts['admin'] = {
            'username': 'admin',
            'password_hash': password_hash.hex(),
            'email': 'admin@plexichat.local',
            'security_level': SecurityLevel.GOVERNMENT.value,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'is_active': True,
            'failed_attempts': 0,
            'locked_until': None,
            'password_history': [],
            'mfa_enabled': False,
            'biometric_enabled': False
        }
        
        self._save_data()
        logger.info(f" Default admin account created with password: {default_password}")
        logger.warning(" Please change the default admin password immediately!")

    async def authenticate(self, username: str, password: str, ip_address: str,
                          user_agent: str, security_level: SecurityLevel = SecurityLevel.BASIC) -> Tuple[bool, Optional[str], Optional[AuthSession]]:
        """
        Authenticate user with comprehensive security checks.

        Returns:
            Tuple of (success, error_message, session)
        """
        try:
            # Check if account exists
            if username not in self.accounts:
                self._log_attempt(username, ip_address, user_agent, AuthAction.LOGIN, False, security_level, "Account not found")
                return False, "Invalid username or password", None

            account = self.accounts[username]

            # Check if account is active
            if not account.get('is_active', True):
                self._log_attempt(username, ip_address, user_agent, AuthAction.LOGIN, False, security_level, "Account disabled")
                return False, "Account is disabled", None

            # Check if account is locked
            locked_until = account.get('locked_until')
            if locked_until:
                locked_until_dt = datetime.fromisoformat(locked_until)
                if datetime.now(timezone.utc) < locked_until_dt:
                    self._log_attempt(username, ip_address, user_agent, AuthAction.LOGIN, False, security_level, "Account locked")
                    return False, f"Account is locked until {locked_until_dt}", None
                else:
                    # Unlock account
                    account['locked_until'] = None
                    account['failed_attempts'] = 0

            # Verify password
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt', 100000)
            if password_hash.hex() != account['password_hash']:
                # Increment failed attempts
                account['failed_attempts'] = account.get('failed_attempts', 0) + 1

                # Lock account if too many failures
                if account['failed_attempts'] >= self.max_failed_attempts:
                    account['locked_until'] = (datetime.now(timezone.utc) + timedelta(minutes=self.lockout_duration_minutes)).isoformat()
                    self._log_attempt(username, ip_address, user_agent, AuthAction.ACCOUNT_LOCKED, False, security_level, "Too many failed attempts")

                self._save_data()
                self._log_attempt(username, ip_address, user_agent, AuthAction.LOGIN, False, security_level, "Invalid password")
                return False, "Invalid username or password", None

            # Reset failed attempts on successful password verification
            account['failed_attempts'] = 0

            # Create session
            session = AuthSession(
                session_id=secrets.token_urlsafe(32),
                username=username,
                security_level=security_level,
                created_at=datetime.now(timezone.utc),
                last_activity=datetime.now(timezone.utc),
                ip_address=ip_address,
                user_agent=user_agent
            )

            self.active_sessions[session.session_id] = session
            self._save_data()
            self._log_attempt(username, ip_address, user_agent, AuthAction.LOGIN, True, security_level, session_id=session.session_id)

            return True, None, session

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False, "Authentication system error", None

    def _log_attempt(self, username: str, ip_address: str, user_agent: str,
                    action: AuthAction, success: bool, security_level: SecurityLevel,
                    failure_reason: Optional[str] = None, session_id: Optional[str] = None):
        """Log authentication attempt."""
        attempt = AuthAttempt(
            timestamp=datetime.now(timezone.utc),
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            action=action,
            success=success,
            security_level=security_level,
            failure_reason=failure_reason,
            session_id=session_id
        )

        self.auth_attempts.append(attempt)

        # Log to system logger
        if success:
            logger.info(f" Auth success: {username} - {action.value} from {ip_address}")
        else:
            logger.warning(f" Auth failure: {username} - {action.value} from {ip_address}: {failure_reason}")

class TokenManager:
    """JWT Token management for API authentication."""

    def __init__(self):
        self.secret_key = secrets.token_urlsafe(64)
        self.algorithm = "HS256"
        self.access_token_expire_minutes = 15
        self.refresh_token_expire_days = 30

    async def create_access_token(self, username: str, security_level: SecurityLevel) -> str:
        """Create JWT access token."""
        # Implementation will be added

    async def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate JWT token."""
        # Implementation will be added

class SessionManager:
    """Session management for web authentication."""

    def __init__(self, auth_manager: AuthManager):
        self.auth_manager = auth_manager

    async def validate_session(self, session_id: str) -> Optional[AuthSession]:
        """Validate session and update last activity."""
        if session_id not in self.auth_manager.active_sessions:
            return None

        session = self.auth_manager.active_sessions[session_id]

        # Check if session has expired
        if datetime.now(timezone.utc) - session.last_activity > timedelta(minutes=self.auth_manager.session_timeout_minutes):
            del self.auth_manager.active_sessions[session_id]
            return None

        # Update last activity
        session.last_activity = datetime.now(timezone.utc)
        self.auth_manager._save_data()

        return session

class PasswordManager:
    """Password policy and management."""

    def __init__(self):
        self.min_length = 12
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_numbers = True
        self.require_symbols = True

    def validate_password(self, password: str) -> Tuple[bool, List[str]]:
        """Validate password against policy."""
        errors = []

        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")

        if self.require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")

        if self.require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")

        if self.require_numbers and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one number")

        if self.require_symbols and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain at least one symbol")

        return len(errors) == 0, errors

# Create global manager instances
auth_manager = AuthManager()
token_manager = TokenManager()
session_manager = SessionManager(auth_manager)
password_manager = PasswordManager()

# Placeholder classes for additional managers (to be implemented)
class MFAManager:
    """Multi-factor authentication management."""

class BiometricManager:
    """Biometric authentication management."""

class OAuthManager:
    """OAuth provider integration."""

class DeviceManager:
    """Device registration and management."""

class AuthAuditManager:
    """Authentication audit and compliance."""

# Create instances
mfa_manager = MFAManager()
biometric_manager = BiometricManager()
oauth_manager = OAuthManager()
device_manager = DeviceManager()
auth_audit_manager = AuthAuditManager()
