# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import base64
import io
import json
import logging
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import time

import pyotp
import qrcode
from cryptography.fernet import Fernet

from plexichat.interfaces.web.core.config_manager import get_webui_config

logger = logging.getLogger(__name__)

@dataclass
class MFADevice:
    """MFA device information."""
    device_id: str
    device_type: str  # 'totp', 'sms', 'email', 'biometric'
    device_name: str
    secret_key: Optional[str] = None
    phone_number: Optional[str] = None
    email_address: Optional[str] = None
    is_active: bool = True
    created_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    backup_codes: Optional[List[str]] = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

@dataclass
class MFASession:
    """MFA session information."""
    session_id: str
    user_id: str
    username: str
    mfa_required: bool
    mfa_completed: bool
    mfa_methods_completed: List[str]
    created_at: datetime
    expires_at: datetime
    ip_address: str
    user_agent: str
    device_fingerprint: Optional[str] = None

class MFAManager:
    """Multi-Factor Authentication Manager."""
    def __init__(self):
        self.config = get_webui_config()
        self.mfa_config = self.config.mfa_config

        # Storage for MFA devices and sessions
        self.devices_storage = {}  # user_id -> List[MFADevice]
        self.sessions_storage = {}  # session_id -> MFASession
        self.backup_codes_storage = {}  # user_id -> List[str]

        # Encryption for sensitive data
        self.cipher = Fernet(self.config.encryption_key)

        logger.info("MFA Manager initialized")

    def is_mfa_enabled(self) -> bool:
        """Check if MFA is enabled globally."""
        return self.mfa_config.enabled

    def is_mfa_required_for_user(self, user_id: str, user_role: str = "user") -> bool:
        """Check if MFA is required for a specific user."""
        if not self.mfa_config.enabled:
            return False

        # Admin users always require MFA if configured
        if user_role == "admin" and self.mfa_config.require_mfa_for_admin:
            return True

        # Check if user has MFA devices configured
        user_devices = self.get_user_mfa_devices(user_id)
        return len(user_devices) > 0

    def get_available_mfa_methods(self, user_role: str = "user") -> List[str]:
        """Get available MFA methods for a user role."""
        return self.config.get_mfa_methods_for_user(user_role)

    def setup_totp_device(self, user_id: str, username: str, device_name: str) -> Dict[str, Any]:
        """Set up a new TOTP device for a user."""
        try:
            # Generate secret key
            secret_key = pyotp.random_base32()

            # Create TOTP URI
            totp = pyotp.TOTP(secret_key)
            provisioning_uri = totp.provisioning_uri(name=username, issuer_name="PlexiChat")
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)

            qr_image = qr.make_image(fill_color="black", back_color="white")
            qr_buffer = io.BytesIO()
            qr_image.save(qr_buffer, format='PNG')
            qr_code_base64 = base64.b64encode(qr_buffer.getvalue()).decode()

            # Create device
            device_id = secrets.token_hex(16)
            device = MFADevice(
                device_id=device_id,
                device_type="totp",
                device_name=device_name,
                secret_key=secret_key,
                is_active=False  # Will be activated after verification
            )

            # Store device (temporarily until verified)
            if user_id not in self.devices_storage:
                self.devices_storage[user_id] = []

            # Store encrypted
            encrypted_device = self._encrypt_device_data(device)
            self.devices_storage[user_id].append(encrypted_device)

            return {
                'device_id': device_id,
                'secret_key': secret_key,
                'qr_code': qr_code_base64,
                'provisioning_uri': provisioning_uri,
                'backup_codes': self._generate_backup_codes(user_id)
            }

        except Exception as e:
            logger.error(f"Failed to setup TOTP device: {e}")
            raise

    def verify_totp_setup(self, user_id: str, device_id: str, verification_code: str) -> bool:
        """Verify TOTP setup with a verification code."""
        try:
            device = self._get_device(user_id, device_id)
            if not device or device.device_type != "totp":
                return False

            totp = pyotp.TOTP(device.secret_key)
            if totp.verify(verification_code, valid_window=2):
                # Activate the device
                device.is_active = True
                device.last_used = datetime.now()
                self._update_device(user_id, device)

                logger.info(f"TOTP device {device_id} activated for user {user_id}")
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to verify TOTP setup: {e}")
            return False

    def verify_totp_code(self, user_id: str, device_id: str, code: str) -> bool:
        """Verify a TOTP code."""
        try:
            device = self._get_device(user_id, device_id)
            if not device or device.device_type != "totp" or not device.is_active:
                return False

            totp = pyotp.TOTP(device.secret_key)
            if totp.verify(code, valid_window=2):
                device.last_used = datetime.now()
                self._update_device(user_id, device)
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to verify TOTP code: {e}")
            return False

    def _generate_backup_codes(self, user_id: str) -> List[str]:
        """Generate backup codes for a user."""
        backup_codes = []
        for _ in range(self.mfa_config.backup_codes_count):
            code = secrets.token_hex(4).upper()
            backup_codes.append(code)

        # Store encrypted backup codes
        encrypted_codes = [self.cipher.encrypt(code.encode()).decode() for code in backup_codes]
        self.backup_codes_storage[user_id] = encrypted_codes

        return backup_codes

    def verify_backup_code(self, user_id: str, code: str) -> bool:
        """Verify a backup code."""
        try:
            if user_id not in self.backup_codes_storage:
                return False

            encrypted_codes = self.backup_codes_storage[user_id]
            code_upper = code.upper()

            for i, encrypted_code in enumerate(encrypted_codes):
                try:
                    decrypted_code = self.cipher.decrypt(encrypted_code.encode()).decode()
                    if decrypted_code == code_upper:
                        # Remove used backup code
                        encrypted_codes.pop(i)
                        logger.info(f"Backup code used for user {user_id}")
                        return True
                except Exception:
                    continue

            return False

        except Exception as e:
            logger.error(f"Failed to verify backup code: {e}")
            return False

    def get_user_mfa_devices(self, user_id: str) -> List[MFADevice]:
        """Get all MFA devices for a user."""
        if user_id not in self.devices_storage:
            return []

        devices = []
        for encrypted_device in self.devices_storage[user_id]:
            try:
                device = self._decrypt_device_data(encrypted_device)
                devices.append(device)
            except Exception as e:
                logger.error(f"Failed to decrypt device data: {e}")

        return [d for d in devices if d.is_active]

    def create_mfa_session(self, user_id: str, username: str, ip_address: str, user_agent: str, user_role: str = "user") -> MFASession:
        """Create a new MFA session."""
        session_id = secrets.token_hex(32)
        mfa_required = self.is_mfa_required_for_user(user_id, user_role)

        now = datetime.now()
        session = MFASession(
            session_id=session_id,
            user_id=user_id,
            username=username,
            mfa_required=mfa_required,
            mfa_completed=not mfa_required,  # If MFA not required, mark as completed
            mfa_methods_completed=[],
            created_at=now,
            expires_at=now + timedelta(seconds=self.config.get_session_timeout(False)),
            ip_address=ip_address,
            user_agent=user_agent
        )

        self.sessions_storage[session_id] = session
        return session

    def complete_mfa_for_session(self, session_id: str, method: str) -> bool:
        """Mark MFA method as completed for a session."""
        if session_id not in self.sessions_storage:
            return False

        session = self.sessions_storage[session_id]
        if method not in session.mfa_methods_completed:
            session.mfa_methods_completed.append(method)

        # Check if MFA is fully completed
        required_methods = self.get_available_mfa_methods()
        if any(method in session.mfa_methods_completed for method in required_methods):
            session.mfa_completed = True
            session.expires_at = datetime.now() + timedelta(seconds=self.config.get_session_timeout(True))

        return session.mfa_completed

    def is_session_valid(self, session_id: str) -> bool:
        """Check if a session is valid."""
        if session_id not in self.sessions_storage:
            return False

        session = self.sessions_storage[session_id]

        # Check expiration
        if datetime.utcnow() > session.expires_at:
            del self.sessions_storage[session_id]
            return False

        # Check MFA completion if required
        if session.mfa_required and not session.mfa_completed:
            return False

        return True

    def get_session(self, session_id: str) -> Optional[MFASession]:
        """Get session information."""
        if self.is_session_valid(session_id):
            return self.sessions_storage.get(session_id)
        return None

    def remove_device(self, user_id: str, device_id: str) -> bool:
        """Remove an MFA device."""
        try:
            if user_id not in self.devices_storage:
                return False

            devices = self.devices_storage[user_id]
            for i, encrypted_device in enumerate(devices):
                try:
                    device = self._decrypt_device_data(encrypted_device)
                    if device.device_id == device_id:
                        devices.pop(i)
                        logger.info(f"MFA device {device_id} removed for user {user_id}")
                        return True
                except Exception:
                    continue

            return False

        except Exception as e:
            logger.error(f"Failed to remove MFA device: {e}")
            return False

    def _encrypt_device_data(self, device: MFADevice) -> str:
        """Encrypt device data."""
        device_json = json.dumps(asdict(device), default=str)
        encrypted_data = self.cipher.encrypt(device_json.encode())
        return encrypted_data.decode()

    def _decrypt_device_data(self, encrypted_data: str) -> MFADevice:
        """Decrypt device data."""
        decrypted_data = self.cipher.decrypt(encrypted_data.encode())
        device_dict = json.loads(decrypted_data.decode())

        # Convert datetime strings back to datetime objects
        if device_dict.get('created_at'):
            device_dict['created_at'] = datetime.fromisoformat(device_dict['created_at'])
        if device_dict.get('last_used'):
            device_dict['last_used'] = datetime.fromisoformat(device_dict['last_used'])

        return MFADevice(**device_dict)

    def _get_device(self, user_id: str, device_id: str) -> Optional[MFADevice]:
        """Get a specific device for a user."""
        devices = self.get_user_mfa_devices(user_id)
        for device in devices:
            if device.device_id == device_id:
                return device
        return None

    def _update_device(self, user_id: str, updated_device: MFADevice):
        """Update a device in storage."""
        if user_id not in self.devices_storage:
            return

        devices = self.devices_storage[user_id]
        for i, encrypted_device in enumerate(devices):
            try:
                device = self._decrypt_device_data(encrypted_device)
                if device.device_id == updated_device.device_id:
                    devices[i] = self._encrypt_device_data(updated_device)
                    break
            except Exception:
                continue

# Global MFA manager instance
mfa_manager = MFAManager()

def get_mfa_manager() -> MFAManager:
    """Get the global MFA manager."""
    return mfa_manager
