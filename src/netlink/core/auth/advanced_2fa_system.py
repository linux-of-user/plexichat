"""
Advanced 2FA Authentication System
Enterprise-grade authentication with multiple 2FA methods and comprehensive security.
"""

import asyncio
import secrets
import qrcode
import io
import base64
import hashlib
import hmac
import time
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
import pyotp
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

class TwoFactorMethod(str, Enum):
    """Supported 2FA methods."""
    TOTP = "totp"  # Time-based One-Time Password (Google Authenticator, etc.)
    SMS = "sms"    # SMS verification
    EMAIL = "email"  # Email verification
    BACKUP_CODES = "backup_codes"  # Backup recovery codes
    HARDWARE_KEY = "hardware_key"  # Hardware security keys (FIDO2/WebAuthn)
    PUSH = "push"  # Push notifications
    VOICE = "voice"  # Voice call verification

class AuthenticationResult(str, Enum):
    """Authentication result types."""
    SUCCESS = "success"
    INVALID_CREDENTIALS = "invalid_credentials"
    ACCOUNT_LOCKED = "account_locked"
    REQUIRES_2FA = "requires_2fa"
    INVALID_2FA = "invalid_2fa"
    EXPIRED_SESSION = "expired_session"
    RATE_LIMITED = "rate_limited"
    ACCOUNT_DISABLED = "account_disabled"

@dataclass
class TwoFactorConfig:
    """2FA configuration for a user."""
    user_id: str
    enabled_methods: List[TwoFactorMethod]
    totp_secret: Optional[str] = None
    backup_codes: List[str] = None
    phone_number: Optional[str] = None
    email: Optional[str] = None
    hardware_keys: List[Dict[str, Any]] = None
    created_at: datetime = None
    last_used: Optional[datetime] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.backup_codes is None:
            self.backup_codes = []
        if self.hardware_keys is None:
            self.hardware_keys = []

@dataclass
class AuthSession:
    """Authentication session information."""
    session_id: str
    user_id: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    ip_address: str
    user_agent: str
    is_2fa_verified: bool = False
    device_fingerprint: Optional[str] = None
    location: Optional[Dict[str, str]] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class LoginAttempt:
    """Login attempt tracking."""
    user_id: str
    ip_address: str
    timestamp: datetime
    success: bool
    failure_reason: Optional[str] = None
    user_agent: Optional[str] = None
    location: Optional[Dict[str, str]] = None

class Advanced2FASystem:
    """Advanced 2FA authentication system with multiple methods."""
    
    def __init__(self, config_path: str = "auth_config.json"):
        self.config_path = Path(config_path)
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher = Fernet(self.encryption_key)
        
        # Storage
        self.user_2fa_configs: Dict[str, TwoFactorConfig] = {}
        self.active_sessions: Dict[str, AuthSession] = {}
        self.login_attempts: List[LoginAttempt] = []
        self.pending_2fa: Dict[str, Dict[str, Any]] = {}  # Temporary 2FA verification storage
        
        # Security settings
        self.max_login_attempts = 5
        self.lockout_duration = timedelta(minutes=30)
        self.session_duration = timedelta(hours=24)
        self.totp_window = 1  # Allow 1 time step tolerance
        self.backup_codes_count = 10
        
        # Load configuration
        self.load_config()
        
        # Start cleanup task
        self._cleanup_task = None
        
    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for sensitive data."""
        key_file = Path("auth_encryption.key")
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            return key
    
    def load_config(self):
        """Load authentication configuration."""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    data = json.load(f)
                
                # Load 2FA configurations
                for config_data in data.get('user_2fa_configs', []):
                    config = TwoFactorConfig(**config_data)
                    self.user_2fa_configs[config.user_id] = config
                
                # Load active sessions
                for session_data in data.get('active_sessions', []):
                    session = AuthSession(**session_data)
                    self.active_sessions[session.session_id] = session
                
                # Load login attempts (recent ones only)
                cutoff_time = datetime.now() - timedelta(hours=24)
                for attempt_data in data.get('login_attempts', []):
                    attempt = LoginAttempt(**attempt_data)
                    if attempt.timestamp > cutoff_time:
                        self.login_attempts.append(attempt)
                
                logger.info(f"Loaded auth config: {len(self.user_2fa_configs)} 2FA configs, {len(self.active_sessions)} sessions")
                
            except Exception as e:
                logger.error(f"Failed to load auth config: {e}")
    
    def save_config(self):
        """Save authentication configuration."""
        try:
            data = {
                'user_2fa_configs': [asdict(config) for config in self.user_2fa_configs.values()],
                'active_sessions': [asdict(session) for session in self.active_sessions.values()],
                'login_attempts': [asdict(attempt) for attempt in self.login_attempts[-1000:]],  # Keep last 1000
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.config_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
                
        except Exception as e:
            logger.error(f"Failed to save auth config: {e}")
    
    def setup_totp(self, user_id: str, user_email: str) -> Tuple[str, str]:
        """Set up TOTP 2FA for a user."""
        # Generate secret
        secret = pyotp.random_base32()
        
        # Create TOTP URI for QR code
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user_email,
            issuer_name="NetLink"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        qr_code_base64 = base64.b64encode(img_buffer.getvalue()).decode()
        
        # Store encrypted secret temporarily (will be confirmed later)
        encrypted_secret = self.cipher.encrypt(secret.encode()).decode()
        
        if user_id not in self.user_2fa_configs:
            self.user_2fa_configs[user_id] = TwoFactorConfig(
                user_id=user_id,
                enabled_methods=[]
            )
        
        # Store temporarily until confirmed
        self.pending_2fa[user_id] = {
            'method': TwoFactorMethod.TOTP,
            'secret': encrypted_secret,
            'setup_time': datetime.now()
        }
        
        return secret, qr_code_base64
    
    def confirm_totp_setup(self, user_id: str, verification_code: str) -> bool:
        """Confirm TOTP setup with verification code."""
        if user_id not in self.pending_2fa:
            return False
        
        pending = self.pending_2fa[user_id]
        if pending['method'] != TwoFactorMethod.TOTP:
            return False
        
        # Decrypt secret
        encrypted_secret = pending['secret']
        secret = self.cipher.decrypt(encrypted_secret.encode()).decode()
        
        # Verify code
        totp = pyotp.TOTP(secret)
        if totp.verify(verification_code, valid_window=self.totp_window):
            # Setup confirmed, save configuration
            config = self.user_2fa_configs[user_id]
            config.totp_secret = encrypted_secret
            if TwoFactorMethod.TOTP not in config.enabled_methods:
                config.enabled_methods.append(TwoFactorMethod.TOTP)
            
            # Generate backup codes
            config.backup_codes = self._generate_backup_codes()
            
            # Clean up pending
            del self.pending_2fa[user_id]
            
            self.save_config()
            logger.info(f"TOTP 2FA enabled for user: {user_id}")
            return True
        
        return False
    
    def _generate_backup_codes(self) -> List[str]:
        """Generate backup recovery codes."""
        codes = []
        for _ in range(self.backup_codes_count):
            code = secrets.token_hex(4).upper()  # 8-character hex codes
            codes.append(code)
        return codes
    
    def verify_totp(self, user_id: str, code: str) -> bool:
        """Verify TOTP code."""
        config = self.user_2fa_configs.get(user_id)
        if not config or TwoFactorMethod.TOTP not in config.enabled_methods:
            return False
        
        if not config.totp_secret:
            return False
        
        try:
            # Decrypt secret
            secret = self.cipher.decrypt(config.totp_secret.encode()).decode()
            totp = pyotp.TOTP(secret)
            
            # Verify with window tolerance
            is_valid = totp.verify(code, valid_window=self.totp_window)
            
            if is_valid:
                config.last_used = datetime.now()
                self.save_config()
            
            return is_valid
            
        except Exception as e:
            logger.error(f"TOTP verification error for {user_id}: {e}")
            return False
    
    def verify_backup_code(self, user_id: str, code: str) -> bool:
        """Verify and consume backup code."""
        config = self.user_2fa_configs.get(user_id)
        if not config or not config.backup_codes:
            return False

    async def send_sms_code(self, user_id: str, phone_number: str) -> bool:
        """Send SMS verification code."""
        # Generate 6-digit code
        code = f"{secrets.randbelow(1000000):06d}"

        # Store code temporarily
        self.pending_2fa[f"{user_id}_sms"] = {
            'code': code,
            'phone': phone_number,
            'timestamp': datetime.now(),
            'attempts': 0
        }

        # TODO: Integrate with SMS service (Twilio, AWS SNS, etc.)
        # For now, log the code (in production, this should be removed)
        logger.info(f"SMS code for {user_id}: {code}")

        return True

    async def send_email_code(self, user_id: str, email: str) -> bool:
        """Send email verification code."""
        # Generate 6-digit code
        code = f"{secrets.randbelow(1000000):06d}"

        # Store code temporarily
        self.pending_2fa[f"{user_id}_email"] = {
            'code': code,
            'email': email,
            'timestamp': datetime.now(),
            'attempts': 0
        }

        # TODO: Send email with code
        # For now, log the code (in production, this should be removed)
        logger.info(f"Email code for {user_id}: {code}")

        return True

    def verify_sms_code(self, user_id: str, code: str) -> bool:
        """Verify SMS code."""
        key = f"{user_id}_sms"
        if key not in self.pending_2fa:
            return False

        pending = self.pending_2fa[key]
        pending['attempts'] += 1

        # Check if code is correct and not expired (5 minutes)
        if (pending['code'] == code and
            datetime.now() - pending['timestamp'] < timedelta(minutes=5) and
            pending['attempts'] <= 3):

            del self.pending_2fa[key]
            return True

        # Clean up if too many attempts or expired
        if pending['attempts'] >= 3 or datetime.now() - pending['timestamp'] > timedelta(minutes=5):
            del self.pending_2fa[key]

        return False

    def verify_email_code(self, user_id: str, code: str) -> bool:
        """Verify email code."""
        key = f"{user_id}_email"
        if key not in self.pending_2fa:
            return False

        pending = self.pending_2fa[key]
        pending['attempts'] += 1

        # Check if code is correct and not expired (10 minutes)
        if (pending['code'] == code and
            datetime.now() - pending['timestamp'] < timedelta(minutes=10) and
            pending['attempts'] <= 3):

            del self.pending_2fa[key]
            return True

        # Clean up if too many attempts or expired
        if pending['attempts'] >= 3 or datetime.now() - pending['timestamp'] > timedelta(minutes=10):
            del self.pending_2fa[key]

        return False

    def create_session(self, user_id: str, ip_address: str, user_agent: str,
                      is_2fa_verified: bool = False) -> str:
        """Create authentication session."""
        session_id = secrets.token_urlsafe(32)

        session = AuthSession(
            session_id=session_id,
            user_id=user_id,
            created_at=datetime.now(),
            last_activity=datetime.now(),
            expires_at=datetime.now() + self.session_duration,
            ip_address=ip_address,
            user_agent=user_agent,
            is_2fa_verified=is_2fa_verified
        )

        self.active_sessions[session_id] = session
        self.save_config()

        logger.info(f"Session created for user {user_id}: {session_id}")
        return session_id

    def validate_session(self, session_id: str, ip_address: str = None) -> Optional[AuthSession]:
        """Validate and update session."""
        session = self.active_sessions.get(session_id)
        if not session:
            return None

        # Check if session is expired
        if datetime.now() > session.expires_at:
            del self.active_sessions[session_id]
            self.save_config()
            return None

        # Check IP address if provided (optional security check)
        if ip_address and session.ip_address != ip_address:
            logger.warning(f"IP address mismatch for session {session_id}: {session.ip_address} vs {ip_address}")
            # Could be more strict here depending on security requirements

        # Update last activity
        session.last_activity = datetime.now()
        self.save_config()

        return session

    def revoke_session(self, session_id: str) -> bool:
        """Revoke a session."""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            self.save_config()
            logger.info(f"Session revoked: {session_id}")
            return True
        return False

    def revoke_all_user_sessions(self, user_id: str) -> int:
        """Revoke all sessions for a user."""
        revoked_count = 0
        sessions_to_remove = []

        for session_id, session in self.active_sessions.items():
            if session.user_id == user_id:
                sessions_to_remove.append(session_id)

        for session_id in sessions_to_remove:
            del self.active_sessions[session_id]
            revoked_count += 1

        if revoked_count > 0:
            self.save_config()
            logger.info(f"Revoked {revoked_count} sessions for user: {user_id}")

        return revoked_count

    def record_login_attempt(self, user_id: str, ip_address: str, success: bool,
                           failure_reason: str = None, user_agent: str = None):
        """Record login attempt for security monitoring."""
        attempt = LoginAttempt(
            user_id=user_id,
            ip_address=ip_address,
            timestamp=datetime.now(),
            success=success,
            failure_reason=failure_reason,
            user_agent=user_agent
        )

        self.login_attempts.append(attempt)

        # Keep only recent attempts in memory
        cutoff_time = datetime.now() - timedelta(hours=24)
        self.login_attempts = [a for a in self.login_attempts if a.timestamp > cutoff_time]

        self.save_config()

    def is_account_locked(self, user_id: str, ip_address: str = None) -> bool:
        """Check if account or IP is locked due to failed attempts."""
        cutoff_time = datetime.now() - self.lockout_duration

        # Check user-based lockout
        user_failures = [
            a for a in self.login_attempts
            if a.user_id == user_id and not a.success and a.timestamp > cutoff_time
        ]

        if len(user_failures) >= self.max_login_attempts:
            return True

        # Check IP-based lockout if IP provided
        if ip_address:
            ip_failures = [
                a for a in self.login_attempts
                if a.ip_address == ip_address and not a.success and a.timestamp > cutoff_time
            ]

            if len(ip_failures) >= self.max_login_attempts * 2:  # More lenient for IP
                return True

        return False

    def get_user_2fa_methods(self, user_id: str) -> List[TwoFactorMethod]:
        """Get enabled 2FA methods for a user."""
        config = self.user_2fa_configs.get(user_id)
        return config.enabled_methods if config else []

    def disable_2fa_method(self, user_id: str, method: TwoFactorMethod) -> bool:
        """Disable a 2FA method for a user."""
        config = self.user_2fa_configs.get(user_id)
        if not config:
            return False

        if method in config.enabled_methods:
            config.enabled_methods.remove(method)

            # Clear method-specific data
            if method == TwoFactorMethod.TOTP:
                config.totp_secret = None
            elif method == TwoFactorMethod.BACKUP_CODES:
                config.backup_codes = []

            self.save_config()
            logger.info(f"Disabled 2FA method {method} for user: {user_id}")
            return True

        return False

    def regenerate_backup_codes(self, user_id: str) -> List[str]:
        """Regenerate backup codes for a user."""
        config = self.user_2fa_configs.get(user_id)
        if not config:
            return []

        new_codes = self._generate_backup_codes()
        config.backup_codes = new_codes

        if TwoFactorMethod.BACKUP_CODES not in config.enabled_methods:
            config.enabled_methods.append(TwoFactorMethod.BACKUP_CODES)

        self.save_config()
        logger.info(f"Regenerated backup codes for user: {user_id}")
        return new_codes

    def get_security_summary(self, user_id: str) -> Dict[str, Any]:
        """Get security summary for a user."""
        config = self.user_2fa_configs.get(user_id)

        # Count active sessions
        active_sessions = [s for s in self.active_sessions.values() if s.user_id == user_id]

        # Recent login attempts
        recent_attempts = [
            a for a in self.login_attempts
            if a.user_id == user_id and a.timestamp > datetime.now() - timedelta(days=7)
        ]

        return {
            "user_id": user_id,
            "2fa_enabled": bool(config and config.enabled_methods),
            "enabled_2fa_methods": config.enabled_methods if config else [],
            "backup_codes_remaining": len(config.backup_codes) if config and config.backup_codes else 0,
            "last_2fa_use": config.last_used.isoformat() if config and config.last_used else None,
            "active_sessions": len(active_sessions),
            "recent_login_attempts": len(recent_attempts),
            "successful_logins_last_week": len([a for a in recent_attempts if a.success]),
            "failed_logins_last_week": len([a for a in recent_attempts if not a.success]),
            "account_locked": self.is_account_locked(user_id)
        }

    def get_system_security_stats(self) -> Dict[str, Any]:
        """Get system-wide security statistics."""
        total_users = len(self.user_2fa_configs)
        users_with_2fa = len([c for c in self.user_2fa_configs.values() if c.enabled_methods])

        # Method usage statistics
        method_usage = {}
        for method in TwoFactorMethod:
            count = len([c for c in self.user_2fa_configs.values() if method in c.enabled_methods])
            method_usage[method.value] = count

        # Recent activity
        recent_cutoff = datetime.now() - timedelta(hours=24)
        recent_attempts = [a for a in self.login_attempts if a.timestamp > recent_cutoff]

        return {
            "total_users_with_2fa_config": total_users,
            "users_with_2fa_enabled": users_with_2fa,
            "2fa_adoption_rate": (users_with_2fa / total_users * 100) if total_users > 0 else 0,
            "method_usage": method_usage,
            "active_sessions": len(self.active_sessions),
            "login_attempts_24h": len(recent_attempts),
            "successful_logins_24h": len([a for a in recent_attempts if a.success]),
            "failed_logins_24h": len([a for a in recent_attempts if not a.success]),
            "unique_ips_24h": len(set(a.ip_address for a in recent_attempts))
        }

    async def start_cleanup_task(self):
        """Start background cleanup task."""
        if self._cleanup_task:
            return

        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("Auth cleanup task started")

    async def stop_cleanup_task(self):
        """Stop background cleanup task."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
            logger.info("Auth cleanup task stopped")

    async def _cleanup_loop(self):
        """Background cleanup loop."""
        while True:
            try:
                await self._cleanup_expired_data()
                await asyncio.sleep(3600)  # Run every hour
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in auth cleanup: {e}")
                await asyncio.sleep(300)  # Sleep 5 minutes on error

    async def _cleanup_expired_data(self):
        """Clean up expired sessions and old data."""
        current_time = datetime.now()

        # Clean expired sessions
        expired_sessions = [
            sid for sid, session in self.active_sessions.items()
            if current_time > session.expires_at
        ]

        for session_id in expired_sessions:
            del self.active_sessions[session_id]

        # Clean old login attempts (keep 7 days)
        cutoff_time = current_time - timedelta(days=7)
        self.login_attempts = [
            a for a in self.login_attempts
            if a.timestamp > cutoff_time
        ]

        # Clean expired pending 2FA
        expired_pending = []
        for key, pending in self.pending_2fa.items():
            if 'timestamp' in pending:
                if current_time - pending['timestamp'] > timedelta(minutes=15):
                    expired_pending.append(key)

        for key in expired_pending:
            del self.pending_2fa[key]

        if expired_sessions or expired_pending:
            self.save_config()
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions and {len(expired_pending)} expired 2FA attempts")

    def export_user_data(self, user_id: str) -> Dict[str, Any]:
        """Export user authentication data (for GDPR compliance)."""
        config = self.user_2fa_configs.get(user_id)
        user_sessions = [s for s in self.active_sessions.values() if s.user_id == user_id]
        user_attempts = [a for a in self.login_attempts if a.user_id == user_id]

        return {
            "user_id": user_id,
            "2fa_config": {
                "enabled_methods": config.enabled_methods if config else [],
                "created_at": config.created_at.isoformat() if config and config.created_at else None,
                "last_used": config.last_used.isoformat() if config and config.last_used else None,
                "backup_codes_count": len(config.backup_codes) if config and config.backup_codes else 0
            },
            "active_sessions": [
                {
                    "session_id": s.session_id,
                    "created_at": s.created_at.isoformat(),
                    "last_activity": s.last_activity.isoformat(),
                    "ip_address": s.ip_address,
                    "user_agent": s.user_agent
                }
                for s in user_sessions
            ],
            "login_history": [
                {
                    "timestamp": a.timestamp.isoformat(),
                    "ip_address": a.ip_address,
                    "success": a.success,
                    "user_agent": a.user_agent
                }
                for a in user_attempts[-100:]  # Last 100 attempts
            ]
        }

    def delete_user_data(self, user_id: str) -> bool:
        """Delete all user authentication data."""
        try:
            # Remove 2FA config
            if user_id in self.user_2fa_configs:
                del self.user_2fa_configs[user_id]

            # Remove all user sessions
            sessions_to_remove = [
                sid for sid, session in self.active_sessions.items()
                if session.user_id == user_id
            ]
            for session_id in sessions_to_remove:
                del self.active_sessions[session_id]

            # Remove login attempts
            self.login_attempts = [
                a for a in self.login_attempts
                if a.user_id != user_id
            ]

            # Remove pending 2FA
            pending_to_remove = [
                key for key in self.pending_2fa.keys()
                if key.startswith(user_id)
            ]
            for key in pending_to_remove:
                del self.pending_2fa[key]

            self.save_config()
            logger.info(f"Deleted all auth data for user: {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete user data for {user_id}: {e}")
            return False
        
        code = code.upper().strip()
        if code in config.backup_codes:
            # Remove used backup code
            config.backup_codes.remove(code)
            config.last_used = datetime.now()
            self.save_config()
            
            logger.info(f"Backup code used for user: {user_id}")
            return True
        
        return False
