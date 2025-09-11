"""
Token Service
Manages JWT tokens with advanced security features.
"""

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import jwt

from plexichat.core.auth.services.interfaces import ITokenService
from plexichat.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class TokenMetadata:
    """Token metadata for tracking and validation."""

    token_id: str
    user_id: str
    token_type: str
    issued_at: datetime
    expires_at: datetime
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    is_revoked: bool = False
    revocation_reason: Optional[str] = None


class TokenService(ITokenService):
    """Advanced JWT token management service."""

    def __init__(self, secret_key: Optional[str] = None):
        super().__init__()
        self.secret_key = secret_key or secrets.token_hex(32)
        self.algorithm = "HS256"
        self.access_token_expiry = 3600  # 1 hour
        self.refresh_token_expiry = 86400 * 7  # 7 days
        self.issuer = "plexichat"
        self.audience = "plexichat-users"

        # Token storage (in production, use Redis/database)
        self.active_tokens: Dict[str, TokenMetadata] = {}
        self.revoked_tokens: Dict[str, TokenMetadata] = {}

    async def create_access_token(
        self,
        user_id: str,
        permissions: list,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> str:
        """Create a new access token."""
        token_id = self._generate_token_id()
        issued_at = datetime.now(timezone.utc)
        expires_at = issued_at + timedelta(seconds=self.access_token_expiry)

        payload = {
            "token_id": token_id,
            "user_id": user_id,
            "permissions": permissions,
            "token_type": "access",
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "iss": self.issuer,
            "aud": self.audience,
            "device_id": device_id,
            "ip_address": ip_address,
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        # Store metadata
        metadata = TokenMetadata(
            token_id=token_id,
            user_id=user_id,
            token_type="access",
            issued_at=issued_at,
            expires_at=expires_at,
            device_id=device_id,
            ip_address=ip_address,
        )
        self.active_tokens[token_id] = metadata

        logger.info(f"Created access token {token_id} for user {user_id}")
        return token

    async def create_refresh_token(
        self,
        user_id: str,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> str:
        """Create a new refresh token."""
        token_id = self._generate_token_id()
        issued_at = datetime.now(timezone.utc)
        expires_at = issued_at + timedelta(seconds=self.refresh_token_expiry)

        payload = {
            "token_id": token_id,
            "user_id": user_id,
            "token_type": "refresh",
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "iss": self.issuer,
            "aud": self.audience,
            "device_id": device_id,
            "ip_address": ip_address,
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        # Store metadata
        metadata = TokenMetadata(
            token_id=token_id,
            user_id=user_id,
            token_type="refresh",
            issued_at=issued_at,
            expires_at=expires_at,
            device_id=device_id,
            ip_address=ip_address,
        )
        self.active_tokens[token_id] = metadata

        logger.info(f"Created refresh token {token_id} for user {user_id}")
        return token

    async def verify_token(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Verify and decode a token."""
        try:
            # Decode without verification first to get token_id
            decoded = jwt.decode(token, options={"verify_signature": False})
            token_id = decoded.get("token_id")

            if not token_id or token_id not in self.active_tokens:
                return False, None

            metadata = self.active_tokens[token_id]
            if metadata.is_revoked:
                return False, None

            # Verify with full validation
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=self.issuer,
            )

            # Update last activity
            metadata.last_activity = datetime.now(timezone.utc)

            return True, payload

        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return False, None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return False, None
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return False, None

    async def revoke_token(self, token: str, reason: Optional[str] = None) -> bool:
        """Revoke a token."""
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            token_id = decoded.get("token_id")

            if token_id and token_id in self.active_tokens:
                metadata = self.active_tokens[token_id]
                metadata.is_revoked = True
                metadata.revocation_reason = reason
                self.revoked_tokens[token_id] = metadata
                del self.active_tokens[token_id]

                logger.info(f"Revoked token {token_id}: {reason}")
                return True

            return False

        except Exception as e:
            logger.error(f"Token revocation error: {e}")
            return False

    async def revoke_user_tokens(
        self, user_id: str, reason: Optional[str] = None
    ) -> int:
        """Revoke all tokens for a user."""
        revoked_count = 0
        tokens_to_revoke = []

        for token_id, metadata in self.active_tokens.items():
            if metadata.user_id == user_id:
                tokens_to_revoke.append(token_id)

        for token_id in tokens_to_revoke:
            metadata = self.active_tokens[token_id]
            metadata.is_revoked = True
            metadata.revocation_reason = reason
            self.revoked_tokens[token_id] = metadata
            del self.active_tokens[token_id]
            revoked_count += 1

        if revoked_count > 0:
            logger.info(f"Revoked {revoked_count} tokens for user {user_id}: {reason}")

        return revoked_count

    async def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """Create new access token using refresh token."""
        valid, payload = await self.verify_token(refresh_token)

        if not valid or payload.get("token_type") != "refresh":
            return None

        user_id = payload.get("user_id")
        permissions = payload.get("permissions", [])
        device_id = payload.get("device_id")
        ip_address = payload.get("ip_address")

        # Revoke old refresh token
        await self.revoke_token(refresh_token, "Token refreshed")

        # Create new access token
        return await self.create_access_token(
            user_id=user_id,
            permissions=permissions,
            device_id=device_id,
            ip_address=ip_address,
        )

    async def cleanup_expired_tokens(self) -> int:
        """Clean up expired tokens."""
        expired_tokens = []
        now = datetime.now(timezone.utc)

        for token_id, metadata in self.active_tokens.items():
            if now > metadata.expires_at:
                expired_tokens.append(token_id)

        for token_id in expired_tokens:
            del self.active_tokens[token_id]

        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired tokens")

        return len(expired_tokens)

    def _generate_token_id(self) -> str:
        """Generate a unique token ID."""
        import uuid

        return f"token_{uuid.uuid4().hex}"
