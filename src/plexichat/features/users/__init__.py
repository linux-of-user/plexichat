# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat User Management Features - MODERN ARCHITECTURE

Comprehensive user management system with:
- User profiles and settings
- Device management
- File management
- Message management
- Moderation tools
- Activity tracking
- Enhanced backup
- Calling features

Uses shared components for consistent error handling and type definitions.
"""

import logging


# Import shared components (NEW ARCHITECTURE)
from ...shared.models import User, Message, Session, Permission, Role, Priority, Status  # type: ignore
from ...shared.types import UserId, JSON, ConfigDict  # type: ignore
# Exceptions not used in this module
# Constants not used in this module

# Core imports not used in this module

# Performance imports not used in this module

logger = logging.getLogger(__name__)

def import_user_modules():
    """Import user modules with error handling."""
    try:
        import importlib
        importlib.import_module("plexichat.features.users.user")
        importlib.import_module("plexichat.features.users.models")
        importlib.import_module("plexichat.features.users.message")
        importlib.import_module("plexichat.features.users.files")
        logger.info("User modules imported")
    except ImportError as e:
        logger.warning(f"Could not import user modules: {e}")

    try:
        import importlib
        importlib.import_module("plexichat.features.users.user_service")
        logger.info("User service imported")
    except ImportError as e:
        logger.warning(f"Could not import user service: {e}")

import_user_modules()

# Export all user management components
__version__ = "3.0.0"
__all__ = [
    # Shared components re-exports
    "User",
    "Message",
    "Session",
    "Permission",
    "Role",
    "Priority",
    "Status",
    "UserId",
    "JSON",
    "ConfigDict",
]
