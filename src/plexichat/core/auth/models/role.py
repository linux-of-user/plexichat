"""
Role model for authorization.
"""

from enum import Enum


class Role(Enum):
    """User roles."""

    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"
