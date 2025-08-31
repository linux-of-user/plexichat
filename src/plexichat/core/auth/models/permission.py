"""
Permission model for authorization.
"""

from enum import Enum


class Permission(Enum):
    """User permissions."""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    NO_READ = "no_read"