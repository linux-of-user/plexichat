"""
Authentication Service Interfaces
Defines contracts for authentication services with dependency injection support.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from plexichat.core.authentication import (
    AuthProvider,
    AuthResult,
    DeviceInfo,
    MFAChallenge,
    MFAMethod,
    Role,
    SessionInfo,
)


class IAuthenticationService(ABC):
    """Interface for authentication service operations."""

    @abstractmethod
    async def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        mfa_code: Optional[str] = None,
        device_trust: bool = False,
    ) -> AuthResult:
        """Authenticate a user with credentials."""
        pass

    @abstractmethod
    async def authenticate_oauth2(
        self, provider: AuthProvider, authorization_code: str, state: str
    ) -> AuthResult:
        """Authenticate user via OAuth2."""
        pass

    @abstractmethod
    def get_oauth2_authorization_url(
        self, provider: AuthProvider, state: Optional[str] = None
    ) -> Optional[str]:
        """Get OAuth2 authorization URL."""
        pass

    @abstractmethod
    async def validate_token(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Validate JWT token."""
        pass

    @abstractmethod
    async def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate API key."""
        pass


class IUserService(ABC):
    """Interface for user management operations."""

    @abstractmethod
    def register_user(
        self,
        username: str,
        password: str,
        permissions: Optional[Set[str]] = None,
        roles: Optional[Set[Role]] = None,
    ) -> Tuple[bool, List[str]]:
        """Register a new user."""
        pass

    @abstractmethod
    async def change_password(
        self, user_id: str, old_password: str, new_password: str
    ) -> Tuple[bool, List[str]]:
        """Change user password."""
        pass

    @abstractmethod
    def get_user_permissions(self, user_id: str) -> Set[str]:
        """Get user permissions."""
        pass

    @abstractmethod
    def update_user_permissions(self, user_id: str, permissions: Set[str]) -> bool:
        """Update user permissions."""
        pass

    @abstractmethod
    def assign_role(self, user_id: str, role: Role) -> bool:
        """Assign role to user."""
        pass

    @abstractmethod
    def revoke_role(self, user_id: str, role: Role) -> bool:
        """Revoke role from user."""
        pass


class ISessionService(ABC):
    """Interface for session management operations."""

    @abstractmethod
    async def validate_session(
        self, session_id: str
    ) -> Tuple[bool, Optional[SessionInfo]]:
        """Validate session."""
        pass

    @abstractmethod
    async def invalidate_session(self, session_id: str) -> bool:
        """Invalidate session."""
        pass

    @abstractmethod
    async def invalidate_user_sessions(self, user_id: str) -> int:
        """Invalidate all sessions for user."""
        pass

    @abstractmethod
    async def elevate_session(self, session_id: str, password: str) -> bool:
        """Elevate session for admin operations."""
        pass

    @abstractmethod
    def get_active_sessions(self, user_id: Optional[str] = None) -> List[SessionInfo]:
        """Get active sessions."""
        pass

    @abstractmethod
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions."""
        pass


class ITokenService(ABC):
    """Interface for token management operations."""

    @abstractmethod
    def create_access_token(
        self,
        user_id: str,
        permissions: Set[str],
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """Create access token."""
        pass

    @abstractmethod
    def create_refresh_token(self, user_id: str) -> str:
        """Create refresh token."""
        pass

    @abstractmethod
    async def revoke_token(self, token: str) -> bool:
        """Revoke token."""
        pass

    @abstractmethod
    async def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """Refresh access token."""
        pass

    @abstractmethod
    def get_token_info(self, token: str) -> Optional[Dict[str, Any]]:
        """Get token information."""
        pass


class IMFAProvider(ABC):
    """Interface for multi-factor authentication operations."""

    @abstractmethod
    async def create_challenge(
        self, user_id: str, method: MFAMethod
    ) -> Optional[MFAChallenge]:
        """Create MFA challenge."""
        pass

    @abstractmethod
    async def verify_challenge(self, challenge_id: str, user_code: str) -> bool:
        """Verify MFA challenge."""
        pass

    @abstractmethod
    async def verify_totp(self, user_id: str, code: str) -> bool:
        """Verify TOTP code."""
        pass

    @abstractmethod
    async def verify_backup_code(self, user_id: str, code: str) -> bool:
        """Verify backup code."""
        pass

    @abstractmethod
    def get_available_methods(self, user_id: str) -> List[MFAMethod]:
        """Get available MFA methods for user."""
        pass

    @abstractmethod
    def is_mfa_enabled(self, user_id: str) -> bool:
        """Check if MFA is enabled for user."""
        pass


class IAuditService(ABC):
    """Interface for audit logging operations."""

    @abstractmethod
    def log_authentication_event(
        self,
        event_type: str,
        user_id: Optional[str],
        ip_address: Optional[str],
        user_agent: Optional[str],
        success: bool,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log authentication event."""
        pass

    @abstractmethod
    def log_security_event(
        self,
        event_type: str,
        severity: str,
        user_id: Optional[str],
        ip_address: Optional[str],
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log security event."""
        pass

    @abstractmethod
    def log_admin_action(
        self,
        action: str,
        admin_user_id: str,
        target_user_id: Optional[str],
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log admin action."""
        pass

    @abstractmethod
    def get_audit_logs(
        self,
        user_id: Optional[str] = None,
        event_type: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get audit logs."""
        pass


__all__ = [
    "IAuthenticationService",
    "IUserService",
    "ISessionService",
    "ITokenService",
    "IMFAProvider",
    "IAuditService",
]
