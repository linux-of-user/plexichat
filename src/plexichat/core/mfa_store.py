import hashlib
from typing import Any

# Centralized logging system
try:
    from plexichat.core.logging.logger import get_logger

    logger = get_logger(__name__)
except Exception:  # Fallback to std logging if centralized logging not available
    import logging

    logger = logging.getLogger(__name__)

# TOTP verification
try:
    import pyotp  # type: ignore
except Exception:
    pyotp = None  # Will degrade gracefully


class MFAStore:
    """
    Dedicated store for Multi-Factor Authentication (MFA) related data.
    This centralizes MFA data storage, preventing dynamic attribute mutation
    on other core objects like UnifiedAuthManager.
    Security improvements:
    - Real TOTP secret storage and verification (if pyotp available)
    - One-time backup codes stored hashed and consumed on use
    """

    def __init__(self):
        self.mfa_devices: dict[str, list[str]] = (
            {}
        )  # user_id -> List[str] (encrypted device JSON)
        self.mfa_sessions: dict[str, Any] = (
            {}
        )  # session_id -> MFASession (or dict representation)
        # Store backup codes list (legacy support for WebUI encrypted codes)
        self.mfa_backup_codes: dict[str, list[str]] = {}  # user_id -> List[str]
        # Additionally, maintain hashed codes for backend verification
        self.mfa_backup_codes_hashed: dict[str, set[str]] = {}  # user_id -> Set[str]
        self.mfa_challenges: dict[str, Any] = {}  # challenge_id -> dict(meta)
        # Store TOTP secrets per user (consider encrypting at rest via config/key vault)
        self.mfa_totp_secrets: dict[str, str] = {}
        logger.info("MFAStore initialized")

    # Device/session management
    def get_devices(self, user_id: str) -> list[str]:
        return self.mfa_devices.get(user_id, [])

    def set_devices(self, user_id: str, devices: list[str]):
        self.mfa_devices[user_id] = devices

    def get_session(self, session_id: str) -> Any | None:
        return self.mfa_sessions.get(session_id)

    def set_session(self, session_id: str, session_data: Any):
        self.mfa_sessions[session_id] = session_data

    def delete_session(self, session_id: str):
        if session_id in self.mfa_sessions:
            del self.mfa_sessions[session_id]

    # TOTP secret management
    def set_totp_secret(self, user_id: str, secret: str) -> None:
        self.mfa_totp_secrets[user_id] = secret
        logger.info(f"Set TOTP secret for user {user_id}")

    def get_totp_secret(self, user_id: str) -> str | None:
        return self.mfa_totp_secrets.get(user_id)

    # Backup codes management
    def get_backup_codes(self, user_id: str) -> list[str]:
        # Return legacy list for WebUI (encrypted strings)
        return self.mfa_backup_codes.get(user_id, [])

    def set_backup_codes(self, user_id: str, codes: list[str]):
        # Store legacy encrypted list (for WebUI)
        self.mfa_backup_codes[user_id] = codes
        logger.info(
            f"Stored {len(codes)} backup codes (encrypted list) for user {user_id}"
        )

    # Additional secure hashed backup codes for backend verification
    def set_backup_codes_hashed(self, user_id: str, codes: list[str]):
        # Store SHA256 hashes of normalized codes
        hashed = {self._hash_code(c) for c in codes if c and isinstance(c, str)}
        self.mfa_backup_codes_hashed[user_id] = hashed
        logger.info(
            f"Configured {len(hashed)} backup codes (hashed) for user {user_id}"
        )

    def _hash_code(self, code: str) -> str:
        return hashlib.sha256(code.strip().upper().encode("utf-8")).hexdigest()

    def get_challenge(self, challenge_id: str) -> Any | None:
        return self.mfa_challenges.get(challenge_id)

    def set_challenge(self, challenge_id: str, challenge_data: Any):
        self.mfa_challenges[challenge_id] = challenge_data

    def delete_challenge(self, challenge_id: str):
        if challenge_id in self.mfa_challenges:
            del self.mfa_challenges[challenge_id]

    async def verify_totp(self, user_id: str, code: str) -> bool:
        """Verify TOTP code for user using stored TOTP secret.
        Falls back to rejecting if no secret or pyotp unavailable.
        """
        try:
            if not code or not code.isdigit() or len(code) not in (6, 8):
                return False
            secret = self.get_totp_secret(user_id)
            if not secret or not pyotp:
                logger.warning(f"TOTP verification unavailable for user {user_id}")
                return False
            totp = pyotp.TOTP(secret)
            ok = bool(totp.verify(code, valid_window=1))
            if not ok:
                logger.warning(f"Invalid TOTP for user {user_id}")
            return ok
        except Exception as e:
            logger.error(f"Error verifying TOTP for user {user_id}: {e}")
            return False

    async def verify_backup_code(self, user_id: str, code: str) -> bool:
        """Verify backup code for user and consume it on success."""
        try:
            if not code:
                return False
            hashed = self._hash_code(code)
            bucket = self.mfa_backup_codes_hashed.get(user_id)
            if not bucket or hashed not in bucket:
                logger.warning(f"Invalid backup code for user {user_id}")
                return False
            # Consume used code
            bucket.remove(hashed)
            logger.info(f"Backup code used for user {user_id}; {len(bucket)} remaining")
            return True
        except Exception as e:
            logger.error(f"Error verifying backup code for user {user_id}: {e}")
            return False
