import base64
import hashlib
import logging
import secrets
import smtplib
from datetime import datetime, timedelta
from email.mime.multipart import MimeMultipart
from email.mime.text import MimeText
from typing import Any, Dict, List, Optional

import pyotp
from cryptography.fernet import Fernet
from pydantic import BaseModel
import time

logger = logging.getLogger(__name__)

class TwoFactorMethod:
    """2FA method constants."""
        TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    BACKUP_CODES = "backup_codes"
    HARDWARE_KEY = "hardware_key"

class TwoFactorConfig(BaseModel):
    """2FA configuration for a user.
    user_id: int
    enabled: bool = False
    enabled_methods: List[str] = []
    totp_secret: Optional[str] = None
    phone_number: Optional[str] = None
    email: Optional[str] = None
    backup_codes: List[str] = []
    recovery_email: Optional[str] = None
    created_at: datetime
    last_used: Optional[datetime] = None
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None

class Advanced2FASystem:
    """Advanced 2FA system with multiple methods and security features."""
        def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.user_configs: Dict[int, TwoFactorConfig] = {}
        self.pending_setups: Dict[str, Dict[str, Any]] = {}

        # Encryption for sensitive data
        self.cipher = Fernet(self._get_or_create_encryption_key())

        # TOTP settings
        self.totp_window = self.config.get('totp_window', 1)
        self.totp_interval = self.config.get('totp_interval', 30)

        # Security settings
        self.max_failed_attempts = self.config.get('max_failed_attempts', 5)
        self.lockout_duration = self.config.get('lockout_duration', 15)

        # SMTP settings for email 2FA
        self.smtp_config = self.config.get('smtp', None)

        logger.info("Advanced 2FA system initialized")

    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for sensitive data.
        key = self.config.get('encryption_key')
        if not key:
            key = Fernet.generate_key()
        return key if isinstance(key, bytes) else key.encode()

    def generate_totp_secret(self) -> str:
        """Generate a new TOTP secret."""
        return pyotp.random_base32()

    def generate_qr_code(self, secret: str, user_email: str, issuer: str = "PlexiChat") -> bytes:
        """Generate QR code for TOTP setup."""
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user_email,
            issuer_name=issuer
        )

        # In a real implementation, you'd use a QR code library
        # For now, return a placeholder
        return b"qr_code_placeholder"

    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """Generate backup codes for 2FA.
        return [secrets.token_urlsafe(8) for _ in range(count)]

    def hash_backup_code(self, code: str) -> str:
        """Hash a backup code for storage."""
        return hashlib.sha256(code.encode()).hexdigest()

    def initiate_2fa_setup(self, user_id: int, user_email: str, methods: List[str]) -> Dict[str, Any]:
        Initiate 2FA setup for a user."""
        setup_token = secrets.token_urlsafe(32)

        setup_data = {
            "user_id": user_id,
            "user_email": user_email,
            "methods": methods,
            "created_at": datetime.utcnow(),
            "verified": False
        }

        # Generate TOTP secret if requested
        if TwoFactorMethod.TOTP in methods:
            secret = self.generate_totp_secret()
            encrypted_secret = self.cipher.encrypt(secret.encode()).decode()
            setup_data["totp_secret"] = encrypted_secret
            setup_data["totp_secret_plain"] = secret  # For QR code generation
            setup_data["qr_code"] = base64.b64encode(
                self.generate_qr_code(secret, user_email)
            ).decode()

        # Generate backup codes if requested
        if TwoFactorMethod.BACKUP_CODES in methods:
            backup_codes = self.generate_backup_codes()
            hashed_codes = [self.hash_backup_code(code) for code in backup_codes]
            setup_data["backup_codes"] = backup_codes
            setup_data["backup_codes_hashed"] = hashed_codes

        self.pending_setups[setup_token] = setup_data

        logger.info(f"2FA setup initiated for user {user_id} with methods: {methods}")

        return {
            "setup_token": setup_token,
            "methods": methods,
            "totp_secret": setup_data.get("totp_secret_plain"),
            "qr_code": setup_data.get("qr_code"),
            "backup_codes": setup_data.get("backup_codes", [])
        }

    def verify_2fa_setup(self, setup_token: str, verification_code: str) -> Dict[str, Any]:
        """Verify 2FA setup with provided code."""
        if setup_token not in self.pending_setups:
            return {"success": False, "error": "Invalid setup token"}

        setup_data = self.pending_setups[setup_token]

        # Check if setup has expired (30 minutes)
        if datetime.utcnow() - setup_data["created_at"] > timedelta(minutes=30):
            del self.pending_setups[setup_token]
            return {"success": False, "error": "Setup token expired"}

        # Verify TOTP code
        if "totp_secret_plain" in setup_data:
            totp = pyotp.TOTP(setup_data["totp_secret_plain"])
            if totp.verify(verification_code, valid_window=self.totp_window):
                # Setup verified, create user config
                user_config = TwoFactorConfig(
                    user_id=setup_data["user_id"],
                    enabled=True,
                    enabled_methods=setup_data["methods"],
                    totp_secret=setup_data.get("totp_secret"),
                    backup_codes=setup_data.get("backup_codes_hashed", []),
                    created_at=datetime.utcnow()
                )

                self.user_configs[setup_data["user_id"]] = user_config
                del self.pending_setups[setup_token]

                logger.info(f"2FA setup completed for user {setup_data['user_id']}")

                return {
                    "success": True,
                    "message": "2FA setup completed successfully",
                    "backup_codes": setup_data.get("backup_codes", [])
                }}

        return {"success": False, "error": "Invalid verification code"}

    def verify_2fa_login(self, user_id: int, code: str, method: Optional[str] = None) -> Dict[str, Any]:
        """Verify 2FA code during login."""
        if user_id not in self.user_configs:
            return {"success": False, "error": "2FA not configured"}

        config = self.user_configs[user_id]

        # Check if account is locked
        if config.locked_until and datetime.utcnow() < config.locked_until:
            return {"success": False, "error": "Account temporarily locked due to failed attempts"}

        # Try TOTP verification
        if TwoFactorMethod.TOTP in config.enabled_methods and config.totp_secret:
            try:
                encrypted_secret = config.totp_secret
                secret = self.cipher.decrypt(encrypted_secret.encode()).decode()
                totp = pyotp.TOTP(secret)

                if totp.verify(code, valid_window=self.totp_window):
                    # Reset failed attempts on success
                    config.failed_attempts = 0
                    config.last_used = datetime.utcnow()
                    config.locked_until = None

                    logger.info(f"2FA TOTP verification successful for user {user_id}")
                    return {"success": True, "method": "totp"}
            except Exception as e:
                logger.error(f"TOTP verification error for user {user_id}: {e}")

        # Try backup code verification
        if TwoFactorMethod.BACKUP_CODES in config.enabled_methods:
            code_hash = self.hash_backup_code(code)
            if code_hash in config.backup_codes:
                # Remove used backup code
                config.backup_codes.remove(code_hash)
                config.failed_attempts = 0
                config.last_used = datetime.utcnow()
                config.locked_until = None

                logger.info(f"2FA backup code verification successful for user {user_id}")
                return {
                    "success": True,
                    "method": "backup_code",
                    "remaining_codes": len(config.backup_codes)
                }}

        # Failed verification
        config.failed_attempts += 1

        # Lock account if too many failed attempts
        if config.failed_attempts >= self.max_failed_attempts:
            config.locked_until = datetime.utcnow() + timedelta(minutes=self.lockout_duration)
            logger.warning(f"2FA account locked for user {user_id} due to failed attempts")

        logger.warning(f"2FA verification failed for user {user_id}")
        return {"success": False, "error": "Invalid 2FA code"}

    def disable_2fa(self, user_id: int) -> bool:
        """Disable 2FA for a user."""
        if user_id in self.user_configs:
            del self.user_configs[user_id]
            logger.info(f"2FA disabled for user {user_id}")
            return True
        return False

    def get_user_2fa_status(self, user_id: int) -> Dict[str, Any]:
        """Get 2FA status for a user."""
        if user_id not in self.user_configs:
            return {"enabled": False}

        config = self.user_configs[user_id]
        return {
            "enabled": config.enabled,
            "methods": config.enabled_methods,
            "backup_codes_remaining": len(config.backup_codes),
            "last_used": config.last_used.isoformat() if config.last_used else None,
            "failed_attempts": config.failed_attempts,
            "locked_until": config.locked_until.isoformat() if config.locked_until else None
        }}

    def regenerate_backup_codes(self, user_id: int) -> List[str]:
        """Regenerate backup codes for a user."""
        if user_id not in self.user_configs:
            raise ValueError("2FA not configured for user")

        config = self.user_configs[user_id]
        new_codes = self.generate_backup_codes()
        config.backup_codes = [self.hash_backup_code(code) for code in new_codes]

        logger.info(f"Backup codes regenerated for user {user_id}")
        return new_codes

    def send_2fa_email(self, user_email: str, code: str) -> bool:
        """Send 2FA code via email."""
        if not self.smtp_config:
            logger.error("SMTP not configured for email 2FA")
            return False

        try:
            msg = MimeMultipart()
            msg['From'] = self.smtp_config['from_email']
            msg['To'] = user_email
            msg['Subject'] = "PlexiChat 2FA Verification Code"

            body = f"""
            Your PlexiChat verification code is: {code}

            This code will expire in 5 minutes.
            If you didn't request this code, please ignore this email.
            """

            msg.attach(MimeText(body, 'plain'))

            with smtplib.SMTP(self.smtp_config['host'], self.smtp_config['port']) as server:
                if self.smtp_config.get('use_tls'):
                    server.starttls()
                if self.smtp_config.get('username'):
                    server.login(self.smtp_config['username'], self.smtp_config['password'])
                server.send_message(msg)

            logger.info(f"2FA email sent to {user_email}")
            return True

        except Exception as e:
            logger.error(f"Failed to send 2FA email to {user_email}: {e}")
            return False

    def export_user_config(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Export user 2FA configuration (for backup/migration)."""
        if user_id not in self.user_configs:
            return None

        config = self.user_configs[user_id]
        return {
            "user_id": config.user_id,
            "enabled": config.enabled,
            "enabled_methods": config.enabled_methods,
            "totp_secret": config.totp_secret,
            "backup_codes": config.backup_codes,
            "created_at": config.created_at.isoformat(),
            "last_used": config.last_used.isoformat() if config.last_used else None
        }}

# Global instance
mfa_manager = Advanced2FASystem()

# Alias for compatibility
MFAManager = Advanced2FASystem

def require_2fa(user_id: int):
    """Decorator to require 2FA for a function."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Check if user has 2FA enabled
            if not mfa_manager.get_user_2fa_status(user_id)["enabled"]:
                raise ValueError("2FA required but not configured")
            return func(*args, **kwargs)
        return wrapper
    return decorator
