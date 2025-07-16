# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import time
import secrets
import hashlib
import logging
import pyotp
import qrcode
import io
import base64
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from dataclasses import dataclass
from datetime import datetime, timedelta
import bcrypt

"""
Enhanced Authentication System
Provides comprehensive authentication with advanced security features.
"""


logger = logging.getLogger(__name__)


class AuthenticationMethod(Enum):
    """Authentication methods."""
    PASSWORD = "password"
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    BIOMETRIC = "biometric"
    HARDWARE_KEY = "hardware_key"


class SessionSecurityLevel(Enum):
    """Session security levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AuthenticationResult:
    """Result of authentication attempt."""
    success: bool
    user_id: Optional[str]
    session_token: Optional[str]
    mfa_required: bool
    available_mfa_methods: List[AuthenticationMethod]
    security_level: SessionSecurityLevel
    expires_at: Optional[datetime]
    warnings: List[str]
    risk_score: float


@dataclass
class UserSecurityProfile:
    """User security profile."""
    user_id: str
    password_hash: str
    salt: str
    mfa_enabled: bool
    mfa_secret: Optional[str]
    backup_codes: List[str]
    failed_attempts: int
    last_failed_attempt: Optional[datetime]
    account_locked: bool
    lock_expires: Optional[datetime]
    last_login: Optional[datetime]
    login_history: List[Dict[str, Any]]
    security_questions: Dict[str, str]
    trusted_devices: List[str]


class EnhancedAuthenticationSystem:
    """Enhanced authentication system with comprehensive security."""

    def __init__(self):
        self.users: Dict[str, UserSecurityProfile] = {}
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.failed_attempts: Dict[str, List[datetime]] = {}
        self.blocked_ips: Dict[str, datetime] = {}
        
        # Security configuration
        self.config = {
            "max_failed_attempts": 5,
            "lockout_duration": 1800,  # 30 minutes
            "session_timeout": 3600,   # 1 hour
            "password_min_length": 12,
            "password_require_special": True,
            "password_require_numbers": True,
            "password_require_uppercase": True,
            "password_require_lowercase": True,
            "mfa_required_for_admin": True,
            "trusted_device_duration": 2592000,  # 30 days
            "max_sessions_per_user": 5,
        }

    def register_user(self, username: str, password: str, email: str) -> Dict[str, Any]:
        """Register a new user with enhanced security."""
        try:
            # Validate password strength
            password_validation = self._validate_password_strength(password)
            if not password_validation["valid"]:
                return {
                    "success": False,
                    "error": "Password does not meet security requirements",
                    "details": password_validation["errors"]
                }

            # Check if user already exists
            if username in self.users:
                return {"success": False, "error": "User already exists"}

            # Generate salt and hash password
            salt = secrets.token_hex(32)
            password_hash = self._hash_password(password, salt)

            # Generate MFA secret
            mfa_secret = pyotp.random_base32()
            backup_codes = [secrets.token_hex(8) for _ in range(10)]

            # Create user profile
            user_profile = UserSecurityProfile(
                user_id=username,
                password_hash=password_hash,
                salt=salt,
                mfa_enabled=False,  # User can enable later
                mfa_secret=mfa_secret,
                backup_codes=backup_codes,
                failed_attempts=0,
                last_failed_attempt=None,
                account_locked=False,
                lock_expires=None,
                last_login=None,
                login_history=[],
                security_questions={},
                trusted_devices=[]
            )

            self.users[username] = user_profile

            # Generate QR code for MFA setup
            totp = pyotp.TOTP(mfa_secret)
            provisioning_uri = totp.provisioning_uri(
                name=username,
                issuer_name="PlexiChat"
            )

            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")
            img_buffer = io.BytesIO()
            img.save(img_buffer, format='PNG')
            qr_code_base64 = base64.b64encode(img_buffer.getvalue()).decode()

            return {
                "success": True,
                "user_id": username,
                "mfa_secret": mfa_secret,
                "backup_codes": backup_codes,
                "qr_code": qr_code_base64,
                "message": "User registered successfully. Please set up MFA for enhanced security."
            }

        except Exception as e:
            logger.error(f"User registration error: {e}")
            return {"success": False, "error": "Registration failed"}

    def authenticate(self, username: str, password: str, mfa_code: Optional[str] = None, 
                    ip_address: str = "", user_agent: str = "") -> AuthenticationResult:
        """Authenticate user with comprehensive security checks."""
        try:
            # Check if IP is blocked
            if self._is_ip_blocked(ip_address):
                return AuthenticationResult(
                    success=False,
                    user_id=None,
                    session_token=None,
                    mfa_required=False,
                    available_mfa_methods=[],
                    security_level=SessionSecurityLevel.LOW,
                    expires_at=None,
                    warnings=["IP address is temporarily blocked"],
                    risk_score=1.0
                )

            # Check if user exists
            if username not in self.users:
                self._record_failed_attempt(ip_address)
                return AuthenticationResult(
                    success=False,
                    user_id=None,
                    session_token=None,
                    mfa_required=False,
                    available_mfa_methods=[],
                    security_level=SessionSecurityLevel.LOW,
                    expires_at=None,
                    warnings=["Invalid credentials"],
                    risk_score=0.8
                )

            user_profile = self.users[username]

            # Check if account is locked
            if user_profile.account_locked:
                if user_profile.lock_expires and datetime.now() > user_profile.lock_expires:
                    # Unlock account
                    user_profile.account_locked = False
                    user_profile.lock_expires = None
                    user_profile.failed_attempts = 0
                else:
                    return AuthenticationResult(
                        success=False,
                        user_id=username,
                        session_token=None,
                        mfa_required=False,
                        available_mfa_methods=[],
                        security_level=SessionSecurityLevel.LOW,
                        expires_at=None,
                        warnings=["Account is temporarily locked"],
                        risk_score=0.9
                    )

            # Verify password
            if not self._verify_password(password, user_profile.password_hash, user_profile.salt):
                self._record_failed_login(user_profile, ip_address)
                return AuthenticationResult(
                    success=False,
                    user_id=username,
                    session_token=None,
                    mfa_required=False,
                    available_mfa_methods=[],
                    security_level=SessionSecurityLevel.LOW,
                    expires_at=None,
                    warnings=["Invalid credentials"],
                    risk_score=0.7
                )

            # Check if MFA is required
            available_mfa_methods = []
            if user_profile.mfa_enabled:
                available_mfa_methods.append(AuthenticationMethod.TOTP)

            # Calculate risk score
            risk_score = self._calculate_risk_score(user_profile, ip_address, user_agent)

            # Determine if MFA is required
            mfa_required = (
                user_profile.mfa_enabled and 
                (mfa_code is None or not self._verify_mfa_code(user_profile, mfa_code))
            )

            if mfa_required and mfa_code is None:
                return AuthenticationResult(
                    success=False,
                    user_id=username,
                    session_token=None,
                    mfa_required=True,
                    available_mfa_methods=available_mfa_methods,
                    security_level=SessionSecurityLevel.MEDIUM,
                    expires_at=None,
                    warnings=[],
                    risk_score=risk_score
                )

            if mfa_required and not self._verify_mfa_code(user_profile, mfa_code):
                self._record_failed_login(user_profile, ip_address)
                return AuthenticationResult(
                    success=False,
                    user_id=username,
                    session_token=None,
                    mfa_required=True,
                    available_mfa_methods=available_mfa_methods,
                    security_level=SessionSecurityLevel.MEDIUM,
                    expires_at=None,
                    warnings=["Invalid MFA code"],
                    risk_score=risk_score
                )

            # Authentication successful - create session
            session_token = self._create_session(user_profile, ip_address, user_agent, risk_score)
            
            # Update user profile
            user_profile.last_login = datetime.now()
            user_profile.failed_attempts = 0
            user_profile.login_history.append({
                "timestamp": datetime.now().isoformat(),
                "ip_address": ip_address,
                "user_agent": user_agent,
                "risk_score": risk_score
            })

            # Keep only last 50 login records
            if len(user_profile.login_history) > 50:
                user_profile.login_history = user_profile.login_history[-50:]

            # Determine security level
            security_level = self._determine_security_level(risk_score, user_profile.mfa_enabled)

            return AuthenticationResult(
                success=True,
                user_id=username,
                session_token=session_token,
                mfa_required=False,
                available_mfa_methods=available_mfa_methods,
                security_level=security_level,
                expires_at=datetime.now() + timedelta(seconds=self.config["session_timeout"]),
                warnings=[],
                risk_score=risk_score
            )

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return AuthenticationResult(
                success=False,
                user_id=None,
                session_token=None,
                mfa_required=False,
                available_mfa_methods=[],
                security_level=SessionSecurityLevel.LOW,
                expires_at=None,
                warnings=["Authentication system error"],
                risk_score=1.0
            )

    def _validate_password_strength(self, password: str) -> Dict[str, Any]:
        """Validate password strength against security requirements."""
        errors = []
        
        if len(password) < self.config["password_min_length"]:
            errors.append(f"Password must be at least {self.config['password_min_length']} characters long")
        
        if self.config["password_require_uppercase"] and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        if self.config["password_require_lowercase"] and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        if self.config["password_require_numbers"] and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one number")
        
        if self.config["password_require_special"] and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain at least one special character")
        
        return {"valid": len(errors) == 0, "errors": errors}

    def _hash_password(self, password: str, salt: str) -> str:
        """Hash password with salt using bcrypt."""
        return bcrypt.hashpw((password + salt).encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def _verify_password(self, password: str, hash_value: str, salt: str) -> bool:
        """Verify password against hash."""
        try:
            return bcrypt.checkpw((password + salt).encode('utf-8'), hash_value.encode('utf-8'))
        except Exception:
            return False

    def _verify_mfa_code(self, user_profile: UserSecurityProfile, mfa_code: str) -> bool:
        """Verify MFA code."""
        if not user_profile.mfa_secret:
            return False
        
        try:
            totp = pyotp.TOTP(user_profile.mfa_secret)
            return totp.verify(mfa_code, valid_window=1)
        except Exception:
            return False

    def _calculate_risk_score(self, user_profile: UserSecurityProfile, ip_address: str, user_agent: str) -> float:
        """Calculate risk score for authentication attempt."""
        risk_score = 0.0
        
        # Check for unusual IP
        recent_ips = [entry.get("ip_address") for entry in user_profile.login_history[-10:]]
        if ip_address not in recent_ips:
            risk_score += 0.3
        
        # Check for unusual user agent
        recent_agents = [entry.get("user_agent") for entry in user_profile.login_history[-10:]]
        if user_agent not in recent_agents:
            risk_score += 0.2
        
        # Check time since last login
        if user_profile.last_login:
            time_diff = datetime.now() - user_profile.last_login
            if time_diff.days > 30:
                risk_score += 0.4
            elif time_diff.days > 7:
                risk_score += 0.2
        
        # Check failed attempts
        if user_profile.failed_attempts > 0:
            risk_score += min(0.3, user_profile.failed_attempts * 0.1)
        
        return min(1.0, risk_score)

    def _create_session(self, user_profile: UserSecurityProfile, ip_address: str, 
                       user_agent: str, risk_score: float) -> str:
        """Create secure session."""
        session_token = secrets.token_urlsafe(32)
        
        session_data = {
            "user_id": user_profile.user_id,
            "created_at": datetime.now(),
            "last_activity": datetime.now(),
            "ip_address": ip_address,
            "user_agent": user_agent,
            "risk_score": risk_score,
            "csrf_token": secrets.token_urlsafe(32)
        }
        
        self.active_sessions[session_token] = session_data
        
        # Clean up old sessions for this user
        self._cleanup_user_sessions(user_profile.user_id)
        
        return session_token

    def _cleanup_user_sessions(self, user_id: str):
        """Clean up old sessions for user."""
        user_sessions = [(token, data) for token, data in self.active_sessions.items() 
                        if data["user_id"] == user_id]
        
        # Sort by creation time and keep only the most recent sessions
        user_sessions.sort(key=lambda x: x[1]["created_at"], reverse=True)
        
        if len(user_sessions) > self.config["max_sessions_per_user"]:
            for token, _ in user_sessions[self.config["max_sessions_per_user"]:]:
                del self.active_sessions[token]

    def _record_failed_login(self, user_profile: UserSecurityProfile, ip_address: str):
        """Record failed login attempt."""
        user_profile.failed_attempts += 1
        user_profile.last_failed_attempt = datetime.now()
        
        # Lock account if too many failed attempts
        if user_profile.failed_attempts >= self.config["max_failed_attempts"]:
            user_profile.account_locked = True
            user_profile.lock_expires = datetime.now() + timedelta(seconds=self.config["lockout_duration"])
        
        self._record_failed_attempt(ip_address)

    def _record_failed_attempt(self, ip_address: str):
        """Record failed attempt from IP."""
        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = []
        
        self.failed_attempts[ip_address].append(datetime.now())
        
        # Clean old attempts
        cutoff = datetime.now() - timedelta(hours=1)
        self.failed_attempts[ip_address] = [
            attempt for attempt in self.failed_attempts[ip_address] 
            if attempt > cutoff
        ]
        
        # Block IP if too many attempts
        if len(self.failed_attempts[ip_address]) >= 10:
            self.blocked_ips[ip_address] = datetime.now() + timedelta(hours=1)

    def _is_ip_blocked(self, ip_address: str) -> bool:
        """Check if IP is blocked."""
        if ip_address in self.blocked_ips:
            if datetime.now() > self.blocked_ips[ip_address]:
                del self.blocked_ips[ip_address]
                return False
            return True
        return False

    def _determine_security_level(self, risk_score: float, mfa_enabled: bool) -> SessionSecurityLevel:
        """Determine session security level."""
        if risk_score > 0.7:
            return SessionSecurityLevel.CRITICAL
        elif risk_score > 0.4:
            return SessionSecurityLevel.HIGH
        elif mfa_enabled:
            return SessionSecurityLevel.HIGH
        else:
            return SessionSecurityLevel.MEDIUM


# Global authentication system instance
_auth_system = None


def get_auth_system() -> EnhancedAuthenticationSystem:
    """Get the global authentication system instance."""
    global _auth_system
    if _auth_system is None:
        _auth_system = EnhancedAuthenticationSystem()
    return _auth_system
