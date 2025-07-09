"""
Two-Factor Authentication (2FA) System
TOTP-based 2FA with backup codes and recovery options.
"""

import secrets
import base64
import qrcode
from io import BytesIO
from typing import List, Optional, Dict, Any
import pyotp
from datetime import datetime, timedelta
import hashlib
import hmac

from app.logger_config import logger
from app.core.config.settings import settings

class TwoFactorAuth:
    """Two-Factor Authentication manager."""
    
    def __init__(self):
        self.issuer_name = getattr(settings, 'APP_NAME', 'Enhanced Chat API')
        
    def generate_secret(self) -> str:
        """Generate a new TOTP secret."""
        return pyotp.random_base32()
        
    def generate_qr_code(self, secret: str, user_email: str) -> bytes:
        """Generate QR code for TOTP setup."""
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user_email,
            issuer_name=self.issuer_name
        )
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        img_buffer = BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        return img_buffer.getvalue()
        
    def verify_token(self, secret: str, token: str, window: int = 1) -> bool:
        """Verify TOTP token."""
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=window)
        except Exception as e:
            logger.error(f"2FA token verification failed: {e}")
            return False
            
    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """Generate backup codes for 2FA recovery."""
        codes = []
        for _ in range(count):
            # Generate 8-character alphanumeric code
            code = secrets.token_hex(4).upper()
            codes.append(f"{code[:4]}-{code[4:]}")
        return codes
        
    def hash_backup_code(self, code: str) -> str:
        """Hash backup code for secure storage."""
        # Remove hyphens and convert to lowercase
        clean_code = code.replace('-', '').lower()
        
        # Use PBKDF2 for hashing
        salt = getattr(settings, 'SECRET_KEY', 'default-salt').encode()
        hashed = hashlib.pbkdf2_hmac('sha256', clean_code.encode(), salt, 100000)
        return base64.b64encode(hashed).decode()
        
    def verify_backup_code(self, code: str, hashed_codes: List[str]) -> bool:
        """Verify backup code against hashed codes."""
        code_hash = self.hash_backup_code(code)
        return code_hash in hashed_codes
        
    def get_current_token(self, secret: str) -> str:
        """Get current TOTP token (for testing)."""
        totp = pyotp.TOTP(secret)
        return totp.now()

class TwoFactorManager:
    """Manages 2FA for users."""
    
    def __init__(self):
        self.tfa = TwoFactorAuth()
        self.pending_setups: Dict[str, Dict[str, Any]] = {}
        
    async def initiate_2fa_setup(self, user_id: int, user_email: str) -> Dict[str, Any]:
        """Initiate 2FA setup for a user."""
        # Generate secret
        secret = self.tfa.generate_secret()
        
        # Generate QR code
        qr_code = self.tfa.generate_qr_code(secret, user_email)
        
        # Store pending setup
        setup_token = secrets.token_urlsafe(32)
        self.pending_setups[setup_token] = {
            "user_id": user_id,
            "secret": secret,
            "created_at": datetime.utcnow(),
            "verified": False
        }
        
        return {
            "setup_token": setup_token,
            "secret": secret,
            "qr_code": base64.b64encode(qr_code).decode(),
            "manual_entry_key": secret
        }
        
    async def verify_2fa_setup(self, setup_token: str, verification_code: str) -> Dict[str, Any]:
        """Verify 2FA setup with user-provided code."""
        setup_data = self.pending_setups.get(setup_token)
        if not setup_data:
            raise ValueError("Invalid setup token")
            
        # Check if setup is expired (15 minutes)
        if datetime.utcnow() - setup_data["created_at"] > timedelta(minutes=15):
            del self.pending_setups[setup_token]
            raise ValueError("Setup token expired")
            
        # Verify the code
        if not self.tfa.verify_token(setup_data["secret"], verification_code):
            raise ValueError("Invalid verification code")
            
        # Generate backup codes
        backup_codes = self.tfa.generate_backup_codes()
        hashed_backup_codes = [self.tfa.hash_backup_code(code) for code in backup_codes]
        
        # Mark as verified
        setup_data["verified"] = True
        setup_data["backup_codes"] = hashed_backup_codes
        
        return {
            "secret": setup_data["secret"],
            "backup_codes": backup_codes,
            "backup_codes_hashed": hashed_backup_codes
        }
        
    async def complete_2fa_setup(self, setup_token: str) -> bool:
        """Complete 2FA setup and clean up pending data."""
        setup_data = self.pending_setups.get(setup_token)
        if not setup_data or not setup_data.get("verified"):
            return False
            
        # Clean up pending setup
        del self.pending_setups[setup_token]
        return True
        
    async def verify_2fa_login(self, secret: str, code: str, backup_codes: List[str] = None) -> Dict[str, Any]:
        """Verify 2FA during login."""
        # First try TOTP
        if self.tfa.verify_token(secret, code):
            return {
                "success": True,
                "method": "totp",
                "backup_code_used": None
            }
            
        # If TOTP fails, try backup codes
        if backup_codes and self.tfa.verify_backup_code(code, backup_codes):
            # Find which backup code was used
            code_hash = self.tfa.hash_backup_code(code)
            used_code_index = backup_codes.index(code_hash) if code_hash in backup_codes else -1
            
            return {
                "success": True,
                "method": "backup_code",
                "backup_code_used": used_code_index
            }
            
        return {
            "success": False,
            "method": None,
            "backup_code_used": None
        }
        
    async def generate_new_backup_codes(self, user_id: int) -> List[str]:
        """Generate new backup codes for a user."""
        backup_codes = self.tfa.generate_backup_codes()
        return backup_codes
        
    async def disable_2fa(self, user_id: int, verification_code: str, secret: str) -> bool:
        """Disable 2FA for a user."""
        # Verify current code before disabling
        if not self.tfa.verify_token(secret, verification_code):
            return False
            
        # 2FA disabled successfully
        logger.info(f"2FA disabled for user {user_id}")
        return True
        
    def cleanup_expired_setups(self):
        """Clean up expired 2FA setups."""
        now = datetime.utcnow()
        expired_tokens = [
            token for token, data in self.pending_setups.items()
            if now - data["created_at"] > timedelta(minutes=15)
        ]
        
        for token in expired_tokens:
            del self.pending_setups[token]
            
        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired 2FA setups")

class RecoveryCodeManager:
    """Manages recovery codes for account recovery."""
    
    def __init__(self):
        self.recovery_codes: Dict[str, Dict[str, Any]] = {}
        
    def generate_recovery_code(self, user_id: int, purpose: str = "account_recovery") -> str:
        """Generate a recovery code for account recovery."""
        code = secrets.token_urlsafe(32)
        
        self.recovery_codes[code] = {
            "user_id": user_id,
            "purpose": purpose,
            "created_at": datetime.utcnow(),
            "used": False
        }
        
        logger.info(f"Generated recovery code for user {user_id}, purpose: {purpose}")
        return code
        
    def verify_recovery_code(self, code: str, user_id: int = None) -> Dict[str, Any]:
        """Verify and use a recovery code."""
        recovery_data = self.recovery_codes.get(code)
        if not recovery_data:
            return {"valid": False, "reason": "Invalid code"}
            
        # Check if already used
        if recovery_data["used"]:
            return {"valid": False, "reason": "Code already used"}
            
        # Check if expired (24 hours)
        if datetime.utcnow() - recovery_data["created_at"] > timedelta(hours=24):
            return {"valid": False, "reason": "Code expired"}
            
        # Check user ID if provided
        if user_id and recovery_data["user_id"] != user_id:
            return {"valid": False, "reason": "Code not valid for this user"}
            
        # Mark as used
        recovery_data["used"] = True
        recovery_data["used_at"] = datetime.utcnow()
        
        return {
            "valid": True,
            "user_id": recovery_data["user_id"],
            "purpose": recovery_data["purpose"]
        }
        
    def cleanup_expired_codes(self):
        """Clean up expired recovery codes."""
        now = datetime.utcnow()
        expired_codes = [
            code for code, data in self.recovery_codes.items()
            if now - data["created_at"] > timedelta(hours=24)
        ]
        
        for code in expired_codes:
            del self.recovery_codes[code]
            
        if expired_codes:
            logger.info(f"Cleaned up {len(expired_codes)} expired recovery codes")

# Global instances
two_factor_manager = TwoFactorManager()
recovery_code_manager = RecoveryCodeManager()
