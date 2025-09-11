"""
Repository Interfaces
Defines contracts for data access operations in the authentication system.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from plexichat.core.authentication import DeviceInfo, SessionInfo


class IUserRepository(ABC):
    """Interface for user data operations."""

    @abstractmethod
    def get_user_credentials(self, user_id: str) -> dict[str, Any] | None:
        """Get user credentials by user ID."""
        pass

    @abstractmethod
    def save_user_credentials(self, user_id: str, credentials: dict[str, Any]) -> bool:
        """Save user credentials."""
        pass

    @abstractmethod
    def update_user_permissions(self, user_id: str, permissions: set[str]) -> bool:
        """Update user permissions."""
        pass

    @abstractmethod
    def get_user_permissions(self, user_id: str) -> set[str]:
        """Get user permissions."""
        pass

    @abstractmethod
    def user_exists(self, user_id: str) -> bool:
        """Check if user exists."""
        pass

    @abstractmethod
    def delete_user(self, user_id: str) -> bool:
        """Delete user."""
        pass


class ISessionRepository(ABC):
    """Interface for session data operations."""

    @abstractmethod
    def save_session(self, session: SessionInfo) -> bool:
        """Save session information."""
        pass

    @abstractmethod
    def get_session(self, session_id: str) -> SessionInfo | None:
        """Get session by ID."""
        pass

    @abstractmethod
    def update_session_access(self, session_id: str, access_time: datetime) -> bool:
        """Update session last access time."""
        pass

    @abstractmethod
    def delete_session(self, session_id: str) -> bool:
        """Delete session."""
        pass

    @abstractmethod
    def get_user_sessions(self, user_id: str) -> list[SessionInfo]:
        """Get all sessions for a user."""
        pass

    @abstractmethod
    def delete_user_sessions(self, user_id: str) -> int:
        """Delete all sessions for a user."""
        pass

    @abstractmethod
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions."""
        pass

    @abstractmethod
    def get_active_sessions_count(self) -> int:
        """Get count of active sessions."""
        pass


class IAuditRepository(ABC):
    """Interface for audit logging operations."""

    @abstractmethod
    def log_event(self, event_data: dict[str, Any]) -> bool:
        """Log an audit event."""
        pass

    @abstractmethod
    def get_events(
        self,
        user_id: str | None = None,
        event_type: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get audit events with filtering."""
        pass

    @abstractmethod
    def get_security_events(
        self,
        severity: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Get security-related audit events."""
        pass

    @abstractmethod
    def cleanup_old_events(self, retention_days: int) -> int:
        """Clean up old audit events."""
        pass


class IDeviceRepository(ABC):
    """Interface for device tracking operations."""

    @abstractmethod
    def save_device(self, device: DeviceInfo) -> bool:
        """Save device information."""
        pass

    @abstractmethod
    def get_device(self, device_id: str) -> DeviceInfo | None:
        """Get device by ID."""
        pass

    @abstractmethod
    def update_device_last_seen(self, device_id: str, last_seen: datetime) -> bool:
        """Update device last seen time."""
        pass

    @abstractmethod
    def mark_device_trusted(self, device_id: str) -> bool:
        """Mark device as trusted."""
        pass

    @abstractmethod
    def get_user_devices(self, user_id: str) -> list[DeviceInfo]:
        """Get all devices for a user."""
        pass

    @abstractmethod
    def get_trusted_devices(self, user_id: str) -> list[DeviceInfo]:
        """Get trusted devices for a user."""
        pass

    @abstractmethod
    def delete_device(self, device_id: str) -> bool:
        """Delete device record."""
        pass

    @abstractmethod
    def cleanup_old_devices(self, days_old: int) -> int:
        """Clean up old device records."""
        pass


__all__ = [
    "IAuditRepository",
    "IDeviceRepository",
    "ISessionRepository",
    "IUserRepository",
]
