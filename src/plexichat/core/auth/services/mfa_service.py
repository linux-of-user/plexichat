"""
MFA Service
Manages multi-factor authentication with TOTP and SMS support.
"""

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, List, Optional, Tuple

import pyotp

from plexichat.core.auth.services.interfaces import IMFAProvider
from plexichat.core.logging import get_logger

logger = get_logger(__name__)


class MFAType(Enum):
    """MFA method types."""

    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"


@dataclass
class MFAChallenge:
    """MFA challenge data."""

    challenge_id: str
    user_id: str
    mfa_type: MFAType
    secret: str
    code: str
    expires_at: datetime
    attempts: int = 0
    max_attempts: int = 3
    is_used: bool = False


@dataclass
class MFAEnrollment:
    """MFA enrollment data."""

    user_id: str
    mfa_type: MFAType
    secret: str
    backup_codes: List[str] = field(default_factory=list)
    enrolled_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True


class MFAService(IMFAProvider):
    """Multi-factor authentication service."""

    def __init__(self):
        super().__init__()
        self.challenges: Dict[str, MFAChallenge] = {}
        self.enrollments: Dict[str, MFAEnrollment] = {}
        self.challenge_timeout = 300  # 5 minutes
        self.max_attempts = 3

    async def create_mfa_challenge(
        self, user_id: str, mfa_type: MFAType = MFAType.TOTP
    ) -> str:
        """Create a new MFA challenge."""
        challenge_id = self._generate_challenge_id()

        if mfa_type == MFAType.TOTP:
            secret = pyotp.random_base32()
            totp = pyotp.TOTP(secret)
            code = totp.now()
        else:
            # For SMS/Email, generate numeric code
            code = str(secrets.randbelow(999999)).zfill(6)
            secret = self._hash_secret(code)

        challenge = MFAChallenge(
            challenge_id=challenge_id,
            user_id=user_id,
            mfa_type=mfa_type,
            secret=secret,
            code=code,
            expires_at=datetime.now(timezone.utc)
            + timedelta(seconds=self.challenge_timeout),
        )

        self.challenges[challenge_id] = challenge

        logger.info(
            f"Created MFA challenge {challenge_id} for user {user_id} ({mfa_type.value})"
        )
        return challenge_id

    async def verify_mfa_challenge(
        self, user_id: str, challenge_id: str, code: str
    ) -> bool:
        """Verify an MFA challenge."""
        challenge = self.challenges.get(challenge_id)

        if not challenge or challenge.user_id != user_id:
            return False

        if challenge.is_used or datetime.now(timezone.utc) > challenge.expires_at:
            return False

        if challenge.attempts >= challenge.max_attempts:
            return False

        challenge.attempts += 1

        # Verify code
        if challenge.mfa_type == MFAType.TOTP:
            totp = pyotp.TOTP(challenge.secret)
            is_valid = totp.verify(code)
        else:
            # For SMS/Email, compare hashed codes
            is_valid = self._verify_code(code, challenge.secret)

        if is_valid:
            challenge.is_used = True
            logger.info(f"MFA challenge {challenge_id} verified for user {user_id}")
            return True
        else:
            logger.warning(
                f"Invalid MFA code for challenge {challenge_id}, attempt {challenge.attempts}"
            )
            return False

    async def enroll_mfa(
        self, user_id: str, mfa_type: MFAType = MFAType.TOTP
    ) -> Tuple[bool, str]:
        """Enroll a user for MFA."""
        if user_id in self.enrollments:
            return False, "User already enrolled in MFA"

        secret = (
            pyotp.random_base32() if mfa_type == MFAType.TOTP else secrets.token_hex(16)
        )

        # Generate backup codes
        backup_codes = [str(secrets.randbelow(999999)).zfill(6) for _ in range(10)]

        enrollment = MFAEnrollment(
            user_id=user_id, mfa_type=mfa_type, secret=secret, backup_codes=backup_codes
        )

        self.enrollments[user_id] = enrollment

        logger.info(f"Enrolled user {user_id} in MFA ({mfa_type.value})")
        return True, secret

    async def unenroll_mfa(self, user_id: str) -> bool:
        """Unenroll a user from MFA."""
        if user_id not in self.enrollments:
            return False

        del self.enrollments[user_id]

        # Clean up any active challenges
        challenges_to_remove = [
            cid
            for cid, challenge in self.challenges.items()
            if challenge.user_id == user_id
        ]

        for cid in challenges_to_remove:
            del self.challenges[cid]

        logger.info(f"Unenrolled user {user_id} from MFA")
        return True

    async def is_mfa_enrolled(self, user_id: str) -> bool:
        """Check if user is enrolled in MFA."""
        enrollment = self.enrollments.get(user_id)
        return enrollment is not None and enrollment.is_active

    async def get_mfa_status(self, user_id: str) -> Optional[Dict]:
        """Get MFA status for a user."""
        enrollment = self.enrollments.get(user_id)
        if not enrollment:
            return None

        return {
            "enrolled": True,
            "type": enrollment.mfa_type.value,
            "enrolled_at": enrollment.enrolled_at.isoformat(),
            "backup_codes_remaining": len(enrollment.backup_codes),
        }

    async def cleanup_expired_challenges(self) -> int:
        """Clean up expired MFA challenges."""
        expired_challenges = []
        now = datetime.now(timezone.utc)

        for challenge_id, challenge in self.challenges.items():
            if now > challenge.expires_at or challenge.is_used:
                expired_challenges.append(challenge_id)

        for challenge_id in expired_challenges:
            del self.challenges[challenge_id]

        if expired_challenges:
            logger.info(f"Cleaned up {len(expired_challenges)} expired MFA challenges")

        return len(expired_challenges)

    def _generate_challenge_id(self) -> str:
        """Generate a unique challenge ID."""
        import uuid

        return f"mfa_{uuid.uuid4().hex}"

    def _hash_secret(self, secret: str) -> str:
        """Hash a secret for storage."""
        return hashlib.sha256(secret.encode()).hexdigest()

    def _verify_code(self, code: str, hashed_secret: str) -> bool:
        """Verify a code against hashed secret."""
        return self._hash_secret(code) == hashed_secret
