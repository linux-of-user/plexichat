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
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pyotp
import qrcode
from cryptography.fernet import Fernet

from plexichat.interfaces.web.core.config_manager import get_webui_config
from plexichat.core.authentication import get_auth_manager, SessionInfo

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
            self.created_at = datetime.now(timezone.utc)

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
    """Multi-Factor Authentication Manager integrated with UnifiedAuthManager."""
    def __init__(self):
        self.config = get_webui_config()
        self.mfa_config = self.config.mfa_config

        # Unified auth manager integration
        self.auth_manager = get_auth_manager()

        # Local references for convenience
        self.devices_storage = self.auth_manager.mfa_store.mfa_devices
        self.sessions_storage = self.auth_manager.mfa_store.mfa_sessions
        self.backup_codes_storage = self.auth_manager.mfa_store.mfa_backup_codes
        self.challenges_storage = self.auth_manager.mfa_store.mfa_challenges

        # Encryption for sensitive data
        # Use the same encryption key that webui config provides
        self.cipher = Fernet(self.config.encryption_key)

        logger.info("MFA Manager initialized and integrated with UnifiedAuthManager")

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

        # Check if user has MFA devices configured in unified storage
        user_devices = self.get_user_mfa_devices(user_id)
        return len(user_devices) > 0

    def get_available_mfa_methods(self, user_role: str = "user") -> List[str]:
        """Get available MFA methods for a user role."""
        return self.config.get_mfa_methods_for_user(user_role)

    def setup_totp_device(self, user_id: str, username: str, device_name: str) -> Dict[str, Any]:
        """Set up a new TOTP device for a user and store it in unified storage."""
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

            # Create device object
            device_id = secrets.token_hex(16)
            # Use TOTP issuer from config if present
            try:
                from plexichat.core.config_manager import get_config
                issuer = str(get_config("security.totp_issuer", "PlexiChat"))
            except Exception:
                issuer = "PlexiChat"
            device = MFADevice(
                device_id=device_id,
                device_type="totp",
                device_name=device_name or issuer,
                secret_key=secret_key,
                is_active=False  # Will be activated after verification
            )

            # Persist TOTP secret in MFA store for backend verification
            try:
                if hasattr(self.auth_manager, 'mfa_store') and hasattr(self.auth_manager.mfa_store, 'set_totp_secret'):
                    self.auth_manager.mfa_store.set_totp_secret(user_id, secret_key)
            except Exception:
                logger.debug("Failed to persist TOTP secret in MFA store")

            # Store encrypted device in unified storage
            encrypted_device = self._encrypt_device_data(device)
            devices = self.auth_manager.mfa_store.get_devices(user_id)
            devices.append(encrypted_device)
            self.auth_manager.mfa_store.set_devices(user_id, devices)

            # Generate backup codes and attach them to unified backup storage
            backup_codes = self._generate_backup_codes(user_id)

            # Optionally generate an initial challenge tied to this setup flow
            challenge_id = secrets.token_urlsafe(24)
            self.auth_manager.mfa_store.set_challenge(challenge_id, {
                "type": "totp_setup",
                "user_id": user_id,
                "device_id": device_id,
                "created_at": datetime.now(timezone.utc).isoformat()
            })

            return {
                'device_id': device_id,
                'secret_key': secret_key,
                'qr_code': qr_code_base64,
                'provisioning_uri': provisioning_uri,
                'backup_codes': backup_codes,
                'challenge_id': challenge_id
            }

        except Exception as e:
            logger.error(f"Failed to setup TOTP device: {e}")
            raise

    def verify_totp_setup(self, user_id: str, device_id: str, verification_code: str) -> bool:
        """Verify TOTP setup with a verification code and activate device in unified storage."""
        try:
            device = self._get_device(user_id, device_id)
            if not device or device.device_type != "totp":
                return False

            totp = pyotp.TOTP(device.secret_key)
            if totp.verify(verification_code, valid_window=2):
                # Activate the device
                device.is_active = True
                device.last_used = datetime.now(timezone.utc)
                self._update_device(user_id, device)

                logger.info(f"TOTP device {device_id} activated for user {user_id}")
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to verify TOTP setup: {e}")
            return False

    def verify_totp_code(self, user_id: str, device_id: str, code: str, session_id: Optional[str] = None) -> bool:
        """
        Verify a TOTP code against a user's device and mark MFA as complete for the session.
        If session_id is provided, link the result to the MFASession stored in unified storage.
        """
        try:
            device = self._get_device(user_id, device_id)
            if not device or device.device_type != "totp" or not device.is_active:
                return False

            totp = pyotp.TOTP(device.secret_key)
            if totp.verify(code, valid_window=2):
                device.last_used = datetime.now(timezone.utc)
                self._update_device(user_id, device)

                # If a session id is provided, mark method completed and finalize MFA if possible.
                if session_id:
                    completed = self.complete_mfa_for_session(session_id, "totp")
                    if completed:
                        # On completion, create/activate a unified session so the user gets a real access token
                        mfa_session = self.auth_manager.mfa_store.get_session(session_id)
                        if mfa_session:
                            # Build a SessionInfo compatible with UnifiedAuthManager and activate it
                            now = datetime.now(timezone.utc)
                            permissions = set(self.auth_manager.get_user_permissions(mfa_session.user_id))
                            unified_session = SessionInfo(
                                session_id=mfa_session.session_id,
                                user_id=mfa_session.user_id,
                                created_at=now,
                                last_accessed=now,
                                expires_at=now + self.auth_manager.session_timeout,
                                permissions=permissions,
                                ip_address=mfa_session.ip_address,
                                user_agent=mfa_session.user_agent,
                                is_active=True
                            )
                            # Store in unified active sessions
                            self.auth_manager.active_sessions[unified_session.session_id] = unified_session

                            # Optionally create a short-lived access token via unified auth manager
                            try:
                                token = self.auth_manager.create_access_token(unified_session.user_id, unified_session.permissions)
                                # Store the issued token as a challenge result for retrieval by the web layer
                                current_challenge = self.auth_manager.mfa_store.get_challenge(session_id) or {}
                                current_challenge.update({
                                    "mfa_completed": True,
                                    "access_token": token,
                                    "issued_at": datetime.now(timezone.utc).isoformat()
                                })
                                self.auth_manager.mfa_store.set_challenge(session_id, current_challenge)
                            except Exception:
                                logger.debug("Failed to create access token upon MFA completion")
                        return True

                return True

            return False

        except Exception as e:
            logger.error(f"Failed to verify TOTP code: {e}")
            return False

    def _generate_backup_codes(self, user_id: str) -> List[str]:
        """Generate backup codes for a user and store them in unified storage (encrypted)."""
        # Generate backup codes, count is configurable in security.backup_codes_count
        try:
            from plexichat.core.config_manager import get_config
            count = int(get_config("security.backup_codes_count", self.mfa_config.backup_codes_count))
        except Exception:
            count = self.mfa_config.backup_codes_count
        backup_codes = []
        for _ in range(max(1, min(count, 50))):
            code = secrets.token_hex(4).upper()
            backup_codes.append(code)

        # Store encrypted backup codes in unified storage
        encrypted_codes = [self.cipher.encrypt(code.encode()).decode() for code in backup_codes]
        self.auth_manager.mfa_store.set_backup_codes(user_id, encrypted_codes)

        # Also store hashed backup codes for backend verification/consumption
        try:
            if hasattr(self.auth_manager.mfa_store, 'set_backup_codes_hashed'):
                self.auth_manager.mfa_store.set_backup_codes_hashed(user_id, backup_codes)
        except Exception:
            logger.debug("Failed to persist hashed backup codes")

        return backup_codes

    def verify_backup_code(self, user_id: str, code: str, session_id: Optional[str] = None) -> bool:
        """Verify a backup code and mark MFA as complete for the session if provided."""
        try:
            encrypted_codes = self.auth_manager.mfa_store.get_backup_codes(user_id)
            if not encrypted_codes:
                return False

            code_upper = code.upper()

            for i, encrypted_code in enumerate(encrypted_codes):
                try:
                    decrypted_code = self.cipher.decrypt(encrypted_code.encode()).decode()
                    if decrypted_code == code_upper:
                        # Remove used backup code
                        encrypted_codes.pop(i)
                        logger.info(f"Backup code used for user {user_id}")
                        # Update storage
                        self.auth_manager.mfa_store.set_backup_codes(user_id, encrypted_codes)
                        # Mark MFA completed for session if provided
                        if session_id:
                            self.complete_mfa_for_session(session_id, "backup_code")
                        return True
                except Exception:
                    continue

            return False

        except Exception as e:
            logger.error(f"Failed to verify backup code: {e}")
            return False

    def get_user_mfa_devices(self, user_id: str) -> List[MFADevice]:
        """Get all active MFA devices for a user from unified storage."""
        devices = []
        for encrypted_device in self.auth_manager.mfa_store.get_devices(user_id):
            try:
                device = self._decrypt_device_data(encrypted_device)
                devices.append(device)
            except Exception as e:
                logger.error(f"Failed to decrypt device data: {e}")

        return [d for d in devices if d.is_active]

    def create_mfa_session(self, user_id: str, username: str, ip_address: str, user_agent: str, user_role: str = "user") -> MFASession:
        """
        Create a new MFA session and store it in the UnifiedAuthManager context.
        Returns the MFASession object.
        """
        session_id = secrets.token_hex(32)
        mfa_required = self.is_mfa_required_for_user(user_id, user_role)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=self.config.get_session_timeout(False))

        session = MFASession(
            session_id=session_id,
            user_id=user_id,
            username=username,
            mfa_required=mfa_required,
            mfa_completed=not mfa_required,  # If MFA not required, mark as completed
            mfa_methods_completed=[],
            created_at=now,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent
        )

        # Store in unified session storage
        self.auth_manager.mfa_store.set_session(session_id, session)

        # Create a short-lived placeholder entry in unified auth manager active_sessions to reserve session id (inactive until MFA completes)
        try:
            now = datetime.now(timezone.utc)
            placeholder = SessionInfo(
                session_id=session_id,
                user_id=user_id,
                created_at=now,
                last_accessed=now,
                expires_at=now + timedelta(seconds=self.config.get_session_timeout(False)),
                permissions=set(),
                ip_address=ip_address,
                user_agent=user_agent,
                is_active=False
            )
            self.auth_manager.active_sessions[session_id] = placeholder
        except Exception:
            logger.debug("Failed to create placeholder unified session for MFA flow")

        # Optionally create a challenge token for the session that frontend can poll
        challenge_id = secrets.token_urlsafe(24)
        self.auth_manager.mfa_store.set_challenge(challenge_id, {
            "type": "mfa_session",
            "session_id": session_id,
            "user_id": user_id,
            "created_at": now.isoformat()
        })

        # Link challenge id to session for convenience
        current_challenge = self.auth_manager.mfa_store.get_challenge(session_id) or {}
        current_challenge.update({
            "challenge_id": challenge_id,
            "mfa_required": mfa_required
        })
        self.auth_manager.mfa_store.set_challenge(session_id, current_challenge)

        return session

    def complete_mfa_for_session(self, session_id: str, method: str) -> bool:
        """Mark MFA method as completed for a session stored in unified storage."""
        session = self.auth_manager.mfa_store.get_session(session_id)
        if not session:
            return False

        if method not in session.mfa_methods_completed:
            session.mfa_methods_completed.append(method)

        # Check if MFA is fully completed based on available methods rules
        required_methods = self.get_available_mfa_methods()
        # Consider MFA completed if any required method is present in completed list,
        # or if MFA is not strictly required by configuration.
        if not session.mfa_required or any(m in session.mfa_methods_completed for m in required_methods):
            session.mfa_completed = True
            # Extend expiry to MFA-completed timeout
            session.expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.config.get_session_timeout(True))

            # Update unified session active state and permissions
            try:
                # Pull permissions via unified auth manager
                permissions = set(self.auth_manager.get_user_permissions(session.user_id))
                now = datetime.now(timezone.utc)
                unified_session = SessionInfo(
                    session_id=session.session_id,
                    user_id=session.user_id,
                    created_at=now,
                    last_accessed=now,
                    expires_at=now + self.auth_manager.session_timeout,
                    permissions=permissions,
                    ip_address=session.ip_address,
                    user_agent=session.user_agent,
                    is_active=True
                )
                self.auth_manager.active_sessions[session.session_id] = unified_session

                # Create an access token for the user upon MFA completion and store it in challenge storage
                try:
                    token = self.auth_manager.create_access_token(unified_session.user_id, unified_session.permissions)
                    current_challenge = self.auth_manager.mfa_store.get_challenge(session_id) or {}
                    current_challenge.update({
                        "mfa_completed": True,
                        "access_token": token,
                        "issued_at": datetime.now(timezone.utc).isoformat()
                    })
                    self.auth_manager.mfa_store.set_challenge(session_id, current_challenge)
                except Exception:
                    logger.debug("Failed to create access token in complete_mfa_for_session")

            except Exception as e:
                logger.error(f"Failed to finalize unified session on MFA completion: {e}")

        return session.mfa_completed

    def is_session_valid(self, session_id: str) -> bool:
        """Check if an MFA session is valid by consulting unified storage."""
        session = self.auth_manager.mfa_store.get_session(session_id)
        if not session:
            return False

        # Check expiration
        if datetime.now(timezone.utc) > session.expires_at:
            try:
                # Remove unified placeholders and session
                self.auth_manager.mfa_store.delete_session(session_id)
                if session_id in self.auth_manager.active_sessions:
                    del self.auth_manager.active_sessions[session_id]
            except Exception:
                pass
            return False

        # Check MFA completion if required
        if session.mfa_required and not session.mfa_completed:
            return False

        return True

    def get_session(self, session_id: str) -> Optional[MFASession]:
        """Get session information from unified storage."""
        return self.auth_manager.mfa_store.get_session(session_id)

    def remove_device(self, user_id: str, device_id: str) -> bool:
        """Remove an MFA device from unified storage."""
        try:
            devices = self.auth_manager.mfa_store.get_devices(user_id)
            if not devices:
                return False

            for i, encrypted_device in enumerate(list(devices)):
                try:
                    device = self._decrypt_device_data(encrypted_device)
                    if device.device_id == device_id:
                        devices.pop(i)
                        self.auth_manager.mfa_store.set_devices(user_id, devices)
                        logger.info(f"MFA device {device_id} removed for user {user_id}")
                        return True
                except Exception:
                    continue

            return False

        except Exception as e:
            logger.error(f"Failed to remove MFA device: {e}")
            return False

    def _encrypt_device_data(self, device: MFADevice) -> str:
        """Encrypt device data for storage."""
        device_json = json.dumps(asdict(device), default=str)
        encrypted_data = self.cipher.encrypt(device_json.encode())
        return encrypted_data.decode()

    def _decrypt_device_data(self, encrypted_data: str) -> MFADevice:
        """Decrypt device data."""
        decrypted_data = self.cipher.decrypt(encrypted_data.encode())
        device_dict = json.loads(decrypted_data.decode())

        # Convert datetime strings back to datetime objects if present
        if device_dict.get('created_at'):
            try:
                device_dict['created_at'] = datetime.fromisoformat(device_dict['created_at'])
            except Exception:
                device_dict['created_at'] = datetime.now(timezone.utc)
        if device_dict.get('last_used'):
            try:
                device_dict['last_used'] = datetime.fromisoformat(device_dict['last_used'])
            except Exception:
                device_dict['last_used'] = None

        return MFADevice(**device_dict)

    def _get_device(self, user_id: str, device_id: str) -> Optional[MFADevice]:
        """Get a specific device for a user from unified storage."""
        devices = []
        for encrypted_device in self.auth_manager.mfa_store.get_devices(user_id):
            try:
                device = self._decrypt_device_data(encrypted_device)
                devices.append(device)
            except Exception:
                continue

        for device in devices:
            if device.device_id == device_id:
                return device
        return None

    def _update_device(self, user_id: str, updated_device: MFADevice):
        """Update a device in unified storage."""
        devices = self.auth_manager.mfa_store.get_devices(user_id)
        if not devices:
            return

        for i, encrypted_device in enumerate(list(devices)):
            try:
                device = self._decrypt_device_data(encrypted_device)
                if device.device_id == updated_device.device_id:
                    devices[i] = self._encrypt_device_data(updated_device)
                    self.auth_manager.mfa_store.set_devices(user_id, devices)
                    break
            except Exception:
                continue

    # Additional utility methods to expose unified challenge/results to web layer
    def get_challenge_result(self, challenge_id_or_session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve stored challenge results (like access token issued upon MFA completion)."""
        return self.auth_manager.mfa_store.get_challenge(challenge_id_or_session_id)

    def invalidate_mfa_session(self, session_id: str) -> bool:
        """Invalidate an MFA session and any related unified placeholder session."""
        try:
            self.auth_manager.mfa_store.delete_session(session_id)
            if session_id in self.auth_manager.active_sessions:
                del self.auth_manager.active_sessions[session_id]
            self.auth_manager.mfa_store.delete_challenge(session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to invalidate MFA session {session_id}: {e}")
            return False

# Global MFA manager instance integrated with UnifiedAuthManager
mfa_manager = MFAManager()

def get_mfa_manager() -> MFAManager:
    """Get the global MFA manager."""
    return mfa_manager
