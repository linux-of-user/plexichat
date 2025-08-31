"""
Repository Interfaces
Defines contracts for data access operations in the authentication system.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set, Any
from datetime import datetime

from plexichat.core.authentication import (
    SessionInfo,
    DeviceInfo,
    Role
)


class IUserRepository(ABC):
    """Interface for user data operations."""

    @abstractmethod
    def get_user_credentials(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user credentials by user ID."""
        pass

    @abstractmethod
    def save_user_credentials(self, user_id: str, credentials: Dict[str, Any]) -> bool:
        """Save user credentials."""
        pass

    @abstractmethod
    def update_user_permissions(self, user_id: str, permissions: Set[str]) -> bool:
        """Update user permissions."""
        pass

    @abstractmethod
    def get_user_permissions(self, user_id: str) -> Set[str]:
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
    def get_session(self, session_id: str) -> Optional[SessionInfo]:
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
    def get_user_sessions(self, user_id: str) -> List[SessionInfo]:
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
    def log_event(self, event_data: Dict[str, Any]) -> bool:
        """Log an audit event."""
        pass

    @abstractmethod
    def get_events(
        self,
        user_id: Optional[str] = None,
        event_type: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get audit events with filtering."""
        pass

    @abstractmethod
    def get_security_events(
        self,
        severity: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
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
    def get_device(self, device_id: str) -> Optional[DeviceInfo]:
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
    def get_user_devices(self, user_id: str) -> List[DeviceInfo]:
        """Get all devices for a user."""
        pass

    @abstractmethod
    def get_trusted_devices(self, user_id: str) -> List[DeviceInfo]:
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
    "IUserRepository",
    "ISessionRepository",
    "IAuditRepository",
    "IDeviceRepository"
]