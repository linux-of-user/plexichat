import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

class MFAStore:
    """
    Dedicated store for Multi-Factor Authentication (MFA) related data.
    This centralizes MFA data storage, preventing dynamic attribute mutation
    on other core objects like UnifiedAuthManager.
    """
    def __init__(self):
        self.mfa_devices: Dict[str, List[str]] = {}  # user_id -> List[str] (encrypted device JSON)
        self.mfa_sessions: Dict[str, Any] = {}  # session_id -> MFASession (or dict representation)
        self.mfa_backup_codes: Dict[str, List[str]] = {}  # user_id -> List[str] (encrypted)
        self.mfa_challenges: Dict[str, Any] = {}  # challenge_id -> dict(meta)
        logger.info("MFAStore initialized")

    def get_devices(self, user_id: str) -> List[str]:
        return self.mfa_devices.get(user_id, [])

    def set_devices(self, user_id: str, devices: List[str]):
        self.mfa_devices[user_id] = devices

    def get_session(self, session_id: str) -> Optional[Any]:
        return self.mfa_sessions.get(session_id)

    def set_session(self, session_id: str, session_data: Any):
        self.mfa_sessions[session_id] = session_data

    def delete_session(self, session_id: str):
        if session_id in self.mfa_sessions:
            del self.mfa_sessions[session_id]

    def get_backup_codes(self, user_id: str) -> List[str]:
        return self.mfa_backup_codes.get(user_id, [])

    def set_backup_codes(self, user_id: str, codes: List[str]):
        self.mfa_backup_codes[user_id] = codes

    def get_challenge(self, challenge_id: str) -> Optional[Any]:
        return self.mfa_challenges.get(challenge_id)

    def set_challenge(self, challenge_id: str, challenge_data: Any):
        self.mfa_challenges[challenge_id] = challenge_data

    def delete_challenge(self, challenge_id: str):
        if challenge_id in self.mfa_challenges:
            del self.mfa_challenges[challenge_id]
