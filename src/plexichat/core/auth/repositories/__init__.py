"""
Authentication Repositories Module
Provides data access layer with repository pattern for authentication components.
"""

from .audit_repository import AuditRepository
from .device_repository import DeviceRepository
from .interfaces import (
    IAuditRepository,
    IDeviceRepository,
    ISessionRepository,
    IUserRepository,
)
from .session_repository import SessionRepository
from .user_repository import UserRepository

__all__ = [
    "IUserRepository",
    "ISessionRepository",
    "IAuditRepository",
    "IDeviceRepository",
    "UserRepository",
    "SessionRepository",
    "AuditRepository",
    "DeviceRepository",
]
