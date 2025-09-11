"""
Authentication Repositories Module
Provides data access layer with repository pattern for authentication components.
"""

from .interfaces import (
    IAuditRepository,
    IDeviceRepository,
    ISessionRepository,
    IUserRepository,
)

__all__ = [
    "IUserRepository",
    "ISessionRepository",
    "IAuditRepository",
    "IDeviceRepository",
]