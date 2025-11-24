from dataclasses import dataclass, field
from typing import Any, Optional
from datetime import datetime, timedelta

from plexichat.core.auth.services.authentication import auth_service
from plexichat.core.logging import get_logger

logger = get_logger(__name__)

from enum import Enum

class Role(str, Enum):
    ADMIN = "admin"
    USER = "user"
    SYSTEM = "system"
    GUEST = "guest"
    MODERATOR = "moderator"
    SUPER_ADMIN = "super_admin"

class AuthProvider(str, Enum):
    LOCAL = "local"
    GOOGLE = "google"
    GITHUB = "github"
    DISCORD = "discord"

class MFAMethod(str, Enum):
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    BACKUP_CODE = "backup_code"

@dataclass
class MFAChallenge:
    challenge_id: str
    method: MFAMethod
    expires_at: datetime
    user_id: str

@dataclass
class SessionInfo:
    session_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_active: bool = True

@dataclass
class AuthResult:
    success: bool
    user_id: Optional[str] = None
    token: Optional[str] = None
    permissions: set[str] = field(default_factory=set)
    security_context: Any = None
    error: Optional[str] = None

class UnifiedAuthManager:
    """
    Unified Authentication Manager that integrates with the core AuthenticationService.
    """
    def __init__(self):
        self.auth_service = auth_service

    async def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> AuthResult:
        try:
            user = await self.auth_service.authenticate_user(username, password)
            if user:
                # Assuming user object has id and permissions
                # If permissions are not on user object, we might need to fetch them
                permissions = getattr(user, "permissions", set())
                if isinstance(permissions, list):
                    permissions = set(permissions)
                
                return AuthResult(
                    success=True,
                    user_id=user.id,
                    permissions=permissions,
                    security_context=user # Or some other context object
                )
            else:
                return AuthResult(success=False, error="Invalid credentials")
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return AuthResult(success=False, error=str(e))

    def create_access_token(
        self,
        subject: str,
        permissions: set[str],
        expires_delta: timedelta | None = None,
    ) -> str:
        # Map to auth_service.create_access_token
        # auth_service.create_access_token takes (data: dict, expires_delta)
        data = {"sub": subject, "permissions": list(permissions)}
        return self.auth_service.create_access_token(data, expires_delta)

    def register_user(self, username: str, password: str, permissions: set[str]) -> bool:
        """
        Register a user with the auth system.
        This is a placeholder/wrapper. In a real system, this might create the user in the DB
        or just update permissions.
        Since UserService creates the user in DB, this might just be for syncing or validation.
        For now, we'll return True as a success indicator.
        """
        # TODO: Implement actual registration logic if needed (e.g. creating auth record separate from user profile)
        return True

_auth_manager = UnifiedAuthManager()

def get_auth_manager() -> UnifiedAuthManager:
    return _auth_manager
