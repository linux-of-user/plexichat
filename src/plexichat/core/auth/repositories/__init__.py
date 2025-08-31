"""
Authentication Repositories Module
Provides data access layer with repository pattern for authentication components.
"""

from .interfaces import (
    IUserRepository,
    ISessionRepository,
    IAuditRepository,
    IDeviceRepository
)
from .user_repository import UserRepository
from .session_repository import SessionRepository
from .audit_repository import AuditRepository
from .device_repository import DeviceRepository

__all__ = [
    "IUserRepository",
    "ISessionRepository",
    "IAuditRepository",
    "IDeviceRepository",
    "UserRepository",
    "SessionRepository",
    "AuditRepository",
    "DeviceRepository"
]