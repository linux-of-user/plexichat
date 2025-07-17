# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""PlexiChat User Features"""

import logging
from typing import Any, Dict, Optional

try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

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
        from .user import User, UserService, user_service
        from .models import UserProfile, UserSettings, UserActivity, user_model_service
        from .message import Message, MessageService, message_service
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

__version__ = "1.0.0"
