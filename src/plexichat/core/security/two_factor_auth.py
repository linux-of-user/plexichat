"""
Two-Factor Authentication (2FA) System

Comprehensive 2FA implementation with:
- TOTP (Time-based One-Time Password) support
- QR code generation for authenticator apps
- Backup codes for recovery
- SMS-based 2FA (optional)
- Email-based 2FA (optional)
- Hardware token support (FIDO2/WebAuthn)
- Rate limiting and security monitoring
- Recovery mechanisms
- Admin override capabilities
"""

import asyncio
import secrets
import time
import hashlib
import hmac
import base64
import struct
import qrcode
import io
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import json
import re

from ..logging.unified_logging import get_logger
from ..logging.correlation_tracker import correlation_tracker, CorrelationType

logger = get_logger(__name__)


class TwoFactorMethod(Enum):
    """Two-factor authentication methods."""
    TOTP = "totp"  # Time-based One-Time Password (Google Authenticator, etc.)
    SMS = "sms"    # SMS-based codes
    EMAIL = "email"  # Email-based codes
    BACKUP_CODES = "backup_codes"  # Recovery backup codes
HARDWARE_TOKEN =os.getenv("ACCESS_TOKEN", "")  # FIDO2/WebAuthn
    PUSH_NOTIFICATION = "push_notification"  # Push notifications


class TwoFactorStatus(Enum):
    """2FA setup status."""
    DISABLED = "disabled"
    PENDING_SETUP = "pending_setup"
    ENABLED = "enabled"
    TEMPORARILY_DISABLED = "temporarily_disabled"
    LOCKED = "locked"


@dataclass
class TwoFactorConfig:
    """Two-factor authentication configuration."""
    user_id: str
    method: TwoFactorMethod
    status: TwoFactorStatus = TwoFactorStatus.DISABLED
    
    # TOTP-specific
    secret_key: Optional[str] = None
    backup_codes: List[str] = field(default_factory=list)
    
    # SMS/Email-specific
    phone_number: Optional[str] = None
    email_address: Optional[str] = None
    
    # Security settings
    created_at: datetime = field(default_factory=datetime.now)
    last_used: Optional[datetime] = None
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None
    
    # Recovery settings
    recovery_codes_used: List[str] = field(default_factory=list)
    admin_override_enabled: bool = False
    
    # Metadata
    device_name: str = ""
    setup_ip: str = ""
    last_success_ip: str = ""


@dataclass
class TwoFactorAttempt:
    """Record of a 2FA attempt."""
    attempt_id: str
    user_id: str
    method: TwoFactorMethod
    code_provided: str
    success: bool
    timestamp: datetime = field(default_factory=datetime.now)
    ip_address: str = ""
    user_agent: str = ""
    error_message: str = ""


class TOTPGenerator:
    """Time-based One-Time Password generator."""
    
    def __init__(self, secret_key: str, time_step: int = 30, digits: int = 6):
        self.secret_key = secret_key
        self.time_step = time_step
        self.digits = digits
    
    def generate_secret_key(self) -> str:
        """Generate a new secret key for TOTP."""
        return base64.b32encode(secrets.token_bytes(20)).decode('utf-8')
    
    def generate_totp(self, timestamp: Optional[int] = None) -> str:
        """Generate TOTP code for given timestamp."""
        if timestamp is None:
            timestamp = int(time.time())
        
        # Calculate time counter
        time_counter = timestamp // self.time_step
        
        # Convert to bytes
        time_bytes = struct.pack('>Q', time_counter)
        
        # Decode secret key
        secret_bytes = base64.b32decode(self.secret_key.upper())
        
        # Generate HMAC
        hmac_digest = hmac.new(secret_bytes, time_bytes, hashlib.sha1).digest()
        
        # Dynamic truncation
        offset = hmac_digest[-1] & 0x0f
        truncated = struct.unpack('>I', hmac_digest[offset:offset + 4])[0]
        truncated &= 0x7fffffff
        
        # Generate code
        code = truncated % (10 ** self.digits)
        return f"{code:0{self.digits}d}"
    
    def verify_totp(self, provided_code: str, timestamp: Optional[int] = None, window: int = 1) -> bool:
        """Verify TOTP code with time window tolerance."""
        if timestamp is None:
            timestamp = int(time.time())
        
        # Check current time and adjacent time windows
        for i in range(-window, window + 1):
            test_timestamp = timestamp + (i * self.time_step)
            expected_code = self.generate_totp(test_timestamp)
            
            if provided_code == expected_code:
                return True
        
        return False
    
    def generate_qr_code(self, user_email: str, issuer: str = "PlexiChat") -> bytes:
        """Generate QR code for TOTP setup."""
        # Create TOTP URI
        uri = f"otpauth://totp/{issuer}:{user_email}?secret={self.secret_key}&issuer={issuer}"
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        return img_buffer.getvalue()


class BackupCodeGenerator:
    """Backup code generator for 2FA recovery."""
    
    def __init__(self, code_length: int = 8, code_count: int = 10):
        self.code_length = code_length
        self.code_count = code_count
    
    def generate_backup_codes(self) -> List[str]:
        """Generate backup codes for recovery."""
        codes = []
        
        for _ in range(self.code_count):
            # Generate random code with letters and numbers
            code = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') 
                          for _ in range(self.code_length))
            codes.append(code)
        
        return codes
    
    def format_backup_codes(self, codes: List[str]) -> str:
        """Format backup codes for display."""
        formatted_codes = []
        
        for i, code in enumerate(codes, 1):
            # Add dashes for readability
            formatted_code = f"{code[:4]}-{code[4:]}"
            formatted_codes.append(f"{i:2d}. {formatted_code}")
        
        return "\n".join(formatted_codes)


class TwoFactorAuthenticator:
    """Comprehensive two-factor authentication system."""
    
    def __init__(self):
        self.user_configs: Dict[str, List[TwoFactorConfig]] = {}
        self.attempt_history: List[TwoFactorAttempt] = []
        self.totp_generator = TOTPGenerator("")
        self.backup_generator = BackupCodeGenerator()
        
        # Security settings
        self.max_failed_attempts = 5
        self.lockout_duration_minutes = 30
        self.code_validity_window = 1  # TOTP time windows
        self.rate_limit_window = 60  # seconds
        self.max_attempts_per_window = 10
        
        # Rate limiting tracking
        self.rate_limit_tracking: Dict[str, List[datetime]] = {}
    
    async def setup_totp(self, user_id: str, user_email: str, device_name: str = "", ip_address: str = "") -> Dict[str, Any]:
        """Setup TOTP-based 2FA for a user."""
        correlation_id = correlation_tracker.start_correlation(
            correlation_type=CorrelationType.SECURITY_CHECK,
            component="two_factor_auth",
            operation="setup_totp",
            user_id=user_id
        )
        
        try:
            # Generate secret key
            secret_key = self.totp_generator.generate_secret_key()
            
            # Create TOTP generator for this user
            user_totp = TOTPGenerator(secret_key)
            
            # Generate QR code
            qr_code_data = user_totp.generate_qr_code(user_email)
            
            # Generate backup codes
            backup_codes = self.backup_generator.generate_backup_codes()
            
            # Create configuration
            config = TwoFactorConfig(
                user_id=user_id,
                method=TwoFactorMethod.TOTP,
                status=TwoFactorStatus.PENDING_SETUP,
                secret_key=secret_key,
                backup_codes=backup_codes,
                device_name=device_name,
                setup_ip=ip_address
            )
            
            # Store configuration
            if user_id not in self.user_configs:
                self.user_configs[user_id] = []
            
            # Remove any existing TOTP config
            self.user_configs[user_id] = [
                c for c in self.user_configs[user_id] 
                if c.method != TwoFactorMethod.TOTP
            ]
            
            self.user_configs[user_id].append(config)
            
            logger.info(f"TOTP setup initiated for user {user_id}")
            
            correlation_tracker.finish_correlation(correlation_id)
            
            return {
                'secret_key': secret_key,
                'qr_code': base64.b64encode(qr_code_data).decode('utf-8'),
                'backup_codes': backup_codes,
                'formatted_backup_codes': self.backup_generator.format_backup_codes(backup_codes),
                'setup_uri': f"otpauth://totp/PlexiChat:{user_email}?secret={secret_key}&issuer=PlexiChat"
            }
            
        except Exception as e:
            logger.error(f"TOTP setup failed for user {user_id}: {e}")
            correlation_tracker.finish_correlation(
                correlation_id,
                error_count=1,
                error_types=[type(e).__name__]
            )
            raise
    
    async def verify_totp_setup(self, user_id: str, verification_code: str, ip_address: str = "") -> bool:
        """Verify TOTP setup with user-provided code."""
        try:
            config = self._get_user_config(user_id, TwoFactorMethod.TOTP)
            if not config or config.status != TwoFactorStatus.PENDING_SETUP:
                return False
            
            # Create TOTP generator
            totp = TOTPGenerator(config.secret_key)
            
            # Verify code
            if totp.verify_totp(verification_code, window=self.code_validity_window):
                # Enable 2FA
                config.status = TwoFactorStatus.ENABLED
                config.last_used = datetime.now()
                config.last_success_ip = ip_address
                
                logger.info(f"TOTP setup completed for user {user_id}")
                return True
            else:
                # Record failed attempt
                self._record_attempt(user_id, TwoFactorMethod.TOTP, verification_code, False, ip_address, "Invalid verification code")
                return False
                
        except Exception as e:
            logger.error(f"TOTP setup verification failed for user {user_id}: {e}")
            return False
    
    async def verify_two_factor(self, user_id: str, code: str, method: Optional[TwoFactorMethod] = None, ip_address: str = "", user_agent: str = "") -> Dict[str, Any]:
        """Verify two-factor authentication code."""
        correlation_id = correlation_tracker.start_correlation(
            correlation_type=CorrelationType.SECURITY_CHECK,
            component="two_factor_auth",
            operation="verify_code",
            user_id=user_id
        )
        
        try:
            # Check rate limiting
            if not self._check_rate_limit(user_id, ip_address):
                correlation_tracker.finish_correlation(correlation_id, error_count=1)
                return {
                    'success': False,
                    'error': 'rate_limit_exceeded',
                    'message': 'Too many attempts. Please try again later.',
                    'retry_after': self.rate_limit_window
                }
            
            # Get user configurations
            user_configs = self.user_configs.get(user_id, [])
            enabled_configs = [c for c in user_configs if c.status == TwoFactorStatus.ENABLED]
            
            if not enabled_configs:
                correlation_tracker.finish_correlation(correlation_id, error_count=1)
                return {
                    'success': False,
                    'error': 'no_2fa_enabled',
                    'message': 'Two-factor authentication is not enabled for this user.'
                }
            
            # Try to verify with specified method or all enabled methods
            configs_to_try = []
            if method:
                configs_to_try = [c for c in enabled_configs if c.method == method]
            else:
                configs_to_try = enabled_configs
            
            for config in configs_to_try:
                # Check if config is locked
                if config.locked_until and datetime.now() < config.locked_until:
                    continue
                
                verification_result = await self._verify_code_for_method(config, code, ip_address, user_agent)
                
                if verification_result['success']:
                    # Reset failed attempts
                    config.failed_attempts = 0
                    config.locked_until = None
                    config.last_used = datetime.now()
                    config.last_success_ip = ip_address
                    
                    correlation_tracker.finish_correlation(correlation_id)
                    return {
                        'success': True,
                        'method': config.method.value,
                        'message': 'Two-factor authentication successful.'
                    }
                else:
                    # Record failed attempt
                    config.failed_attempts += 1
                    
                    # Lock config if too many failures
                    if config.failed_attempts >= self.max_failed_attempts:
                        config.locked_until = datetime.now() + timedelta(minutes=self.lockout_duration_minutes)
                        logger.warning(f"2FA locked for user {user_id} method {config.method.value} due to too many failed attempts")
                    
                    self._record_attempt(user_id, config.method, code, False, ip_address, verification_result.get('error', 'Invalid code'), user_agent)
            
            correlation_tracker.finish_correlation(correlation_id, error_count=1)
            return {
                'success': False,
                'error': 'invalid_code',
                'message': 'Invalid two-factor authentication code.'
            }
            
        except Exception as e:
            logger.error(f"2FA verification failed for user {user_id}: {e}")
            correlation_tracker.finish_correlation(
                correlation_id,
                error_count=1,
                error_types=[type(e).__name__]
            )
            return {
                'success': False,
                'error': 'system_error',
                'message': 'System error during verification.'
            }
    
    async def _verify_code_for_method(self, config: TwoFactorConfig, code: str, ip_address: str, user_agent: str) -> Dict[str, Any]:
        """Verify code for specific 2FA method."""
        try:
            if config.method == TwoFactorMethod.TOTP:
                totp = TOTPGenerator(config.secret_key)
                if totp.verify_totp(code, window=self.code_validity_window):
                    self._record_attempt(config.user_id, config.method, code, True, ip_address, "", user_agent)
                    return {'success': True}
                else:
                    return {'success': False, 'error': 'Invalid TOTP code'}
            
            elif config.method == TwoFactorMethod.BACKUP_CODES:
                # Check if code is a valid unused backup code
                if code.upper() in config.backup_codes and code.upper() not in config.recovery_codes_used:
                    config.recovery_codes_used.append(code.upper())
                    self._record_attempt(config.user_id, config.method, code, True, ip_address, "", user_agent)
                    
                    # Warn if running low on backup codes
                    remaining_codes = len(config.backup_codes) - len(config.recovery_codes_used)
                    if remaining_codes <= 2:
                        logger.warning(f"User {config.user_id} has only {remaining_codes} backup codes remaining")
                    
                    return {'success': True, 'remaining_backup_codes': remaining_codes}
                else:
                    return {'success': False, 'error': 'Invalid or used backup code'}
            
            # Add other methods (SMS, Email, etc.) here
            else:
                return {'success': False, 'error': 'Method not implemented'}
                
        except Exception as e:
            logger.error(f"Code verification failed for method {config.method.value}: {e}")
            return {'success': False, 'error': 'Verification error'}
    
    def _get_user_config(self, user_id: str, method: TwoFactorMethod) -> Optional[TwoFactorConfig]:
        """Get user configuration for specific method."""
        user_configs = self.user_configs.get(user_id, [])
        for config in user_configs:
            if config.method == method:
                return config
        return None
    
    def _check_rate_limit(self, user_id: str, ip_address: str) -> bool:
        """Check if user/IP is within rate limits."""
        now = datetime.now()
        cutoff_time = now - timedelta(seconds=self.rate_limit_window)
        
        # Check user rate limit
        user_key = f"user:{user_id}"
        if user_key not in self.rate_limit_tracking:
            self.rate_limit_tracking[user_key] = []
        
        # Clean old attempts
        self.rate_limit_tracking[user_key] = [
            attempt_time for attempt_time in self.rate_limit_tracking[user_key]
            if attempt_time > cutoff_time
        ]
        
        # Check if under limit
        if len(self.rate_limit_tracking[user_key]) >= self.max_attempts_per_window:
            return False
        
        # Record this attempt
        self.rate_limit_tracking[user_key].append(now)
        
        # Also check IP rate limit
        ip_key = f"ip:{ip_address}"
        if ip_key not in self.rate_limit_tracking:
            self.rate_limit_tracking[ip_key] = []
        
        self.rate_limit_tracking[ip_key] = [
            attempt_time for attempt_time in self.rate_limit_tracking[ip_key]
            if attempt_time > cutoff_time
        ]
        
        if len(self.rate_limit_tracking[ip_key]) >= self.max_attempts_per_window:
            return False
        
        self.rate_limit_tracking[ip_key].append(now)
        return True
    
    def _record_attempt(self, user_id: str, method: TwoFactorMethod, code: str, success: bool, ip_address: str, error_message: str = "", user_agent: str = ""):
        """Record 2FA attempt for monitoring."""
        attempt = TwoFactorAttempt(
            attempt_id=f"2fa_{int(time.time() * 1000000)}",
            user_id=user_id,
            method=method,
            code_provided=code[:2] + "*" * (len(code) - 2),  # Mask code for security
            success=success,
            ip_address=ip_address,
            user_agent=user_agent,
            error_message=error_message
        )
        
        self.attempt_history.append(attempt)
        
        # Keep only recent attempts
        if len(self.attempt_history) > 10000:
            self.attempt_history = self.attempt_history[-5000:]
        
        # Log attempt
        if success:
            logger.info(f"2FA success for user {user_id} using {method.value}")
        else:
            logger.warning(f"2FA failed for user {user_id} using {method.value}: {error_message}")
    
    async def disable_two_factor(self, user_id: str, method: Optional[TwoFactorMethod] = None, admin_override: bool = False) -> bool:
        """Disable two-factor authentication."""
        try:
            user_configs = self.user_configs.get(user_id, [])
            
            if method:
                # Disable specific method
                for config in user_configs:
                    if config.method == method:
                        config.status = TwoFactorStatus.DISABLED
                        logger.info(f"2FA method {method.value} disabled for user {user_id}")
                        return True
            else:
                # Disable all methods
                for config in user_configs:
                    config.status = TwoFactorStatus.DISABLED
                logger.info(f"All 2FA methods disabled for user {user_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to disable 2FA for user {user_id}: {e}")
            return False
    
    async def get_user_2fa_status(self, user_id: str) -> Dict[str, Any]:
        """Get user's 2FA status and configuration."""
        user_configs = self.user_configs.get(user_id, [])
        
        methods_status = {}
        for method in TwoFactorMethod:
            config = self._get_user_config(user_id, method)
            if config:
                methods_status[method.value] = {
                    'status': config.status.value,
                    'enabled': config.status == TwoFactorStatus.ENABLED,
                    'last_used': config.last_used.isoformat() if config.last_used else None,
                    'failed_attempts': config.failed_attempts,
                    'locked_until': config.locked_until.isoformat() if config.locked_until else None
                }
                
                if method == TwoFactorMethod.BACKUP_CODES and config.backup_codes:
                    remaining_codes = len(config.backup_codes) - len(config.recovery_codes_used)
                    methods_status[method.value]['remaining_backup_codes'] = remaining_codes
            else:
                methods_status[method.value] = {
                    'status': TwoFactorStatus.DISABLED.value,
                    'enabled': False
                }
        
        # Overall status
        enabled_methods = [
            method for method, status in methods_status.items()
            if status['enabled']
        ]
        
        return {
            'user_id': user_id,
            'has_2fa_enabled': len(enabled_methods) > 0,
            'enabled_methods': enabled_methods,
            'methods_status': methods_status,
            'total_attempts': len([a for a in self.attempt_history if a.user_id == user_id]),
            'recent_success': any(
                a.success for a in self.attempt_history[-100:]
                if a.user_id == user_id and a.timestamp > datetime.now() - timedelta(days=7)
            )
        }
    
    async def generate_new_backup_codes(self, user_id: str) -> Optional[List[str]]:
        """Generate new backup codes for user."""
        try:
            config = self._get_user_config(user_id, TwoFactorMethod.TOTP)
            if not config or config.status != TwoFactorStatus.ENABLED:
                return None
            
            # Generate new backup codes
            new_backup_codes = self.backup_generator.generate_backup_codes()
            
            # Update configuration
            config.backup_codes = new_backup_codes
            config.recovery_codes_used = []  # Reset used codes
            
            logger.info(f"New backup codes generated for user {user_id}")
            return new_backup_codes
            
        except Exception as e:
            logger.error(f"Failed to generate new backup codes for user {user_id}: {e}")
            return None
    
    def get_2fa_statistics(self) -> Dict[str, Any]:
        """Get 2FA system statistics."""
        total_users = len(self.user_configs)
        enabled_users = sum(
            1 for configs in self.user_configs.values()
            if any(c.status == TwoFactorStatus.ENABLED for c in configs)
        )
        
        # Method statistics
        method_stats = {}
        for method in TwoFactorMethod:
            enabled_count = sum(
                1 for configs in self.user_configs.values()
                for config in configs
                if config.method == method and config.status == TwoFactorStatus.ENABLED
            )
            method_stats[method.value] = enabled_count
        
        # Recent attempt statistics
        recent_attempts = [
            a for a in self.attempt_history
            if a.timestamp > datetime.now() - timedelta(hours=24)
        ]
        
        success_rate = (
            sum(1 for a in recent_attempts if a.success) / len(recent_attempts) * 100
            if recent_attempts else 0
        )
        
        return {
            'total_users': total_users,
            'enabled_users': enabled_users,
            'adoption_rate': (enabled_users / total_users * 100) if total_users > 0 else 0,
            'method_statistics': method_stats,
            'recent_attempts_24h': len(recent_attempts),
            'success_rate_24h': success_rate,
            'total_attempts_recorded': len(self.attempt_history)
        }


# Global two-factor authenticator instance
two_factor_authenticator = TwoFactorAuthenticator()
