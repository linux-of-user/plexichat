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
from typing import Any, Dict, Optional

# Import shared components (NEW ARCHITECTURE)
from ...shared.models import User, Message, Session, Permission, Role, Priority, Status  # type: ignore
from ...shared.types import UserId, JSON, ConfigDict  # type: ignore
from ...shared.exceptions import (  # type: ignore
    ValidationError, AuthorizationError, ResourceNotFoundError,
    QuotaExceededError
)
from ...shared.constants import (
    MAX_USERNAME_LENGTH, MAX_EMAIL_LENGTH, MAX_DISPLAY_NAME_LENGTH
)

# Core imports
try:
    from plexichat.core.database.manager import database_manager
    from plexichat.core.auth.unified_auth_manager import unified_auth_manager
except ImportError:
    database_manager = None
    unified_auth_manager = None

try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)

def import_user_modules():
    """Import user modules with error handling."""
    try:
        from .user import UserService, user_service
        from .models import UserProfile, UserSettings, UserActivity, user_model_service
        from .message import MessageService, message_service
        from .files import FileRecord, FileService, file_service
        logger.info("User modules imported")
    except ImportError as e:
        logger.warning(f"Could not import user modules: {e}")

    try:
        from .user_service import UserManagementService
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

    # Exceptions
    "ValidationError",
    "AuthorizationError",
    "ResourceNotFoundError",
    "QuotaExceededError",

    # User management components (imported dynamically)
    # "UserService",
    # "UserProfile",
    # "UserSettings",
    # "UserActivity",
    # "MessageService",
    # "FileService",
    # "UserManagementService",
]

__all__ = [
    "User",
    "UserProfile",
    "UserSettings",
    "UserActivity",
    "Message",
    "FileRecord",
    "user_service",
    "user_model_service",
    "message_service",
    "file_service",
]
