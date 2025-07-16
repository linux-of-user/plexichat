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
"""
PlexiChat User Features

Enhanced user features with comprehensive functionality and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import logging
from typing import Any, Dict, Optional

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core_system.logging.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

# Safe imports with error handling
def import_user_modules():
    """Import user modules with error handling."""
    try:
        # User models
        try:
            from .user import User, UserService, user_service
            from .models import UserProfile, UserSettings, UserActivity, user_model_service
            from .message import Message, MessageService, message_service
            from .files import FileRecord, FileService, file_service
            logger.info("User modules imported successfully")
        except ImportError as e:
            logger.warning(f"Could not import user modules: {e}")
        
        # User services
        try:
            from .user_service import UserManagementService
            logger.info("User service imported successfully")
        except ImportError as e:
            logger.warning(f"Could not import user service: {e}")
        
    except Exception as e:
        logger.error(f"Error importing user modules: {e}")

# Import user modules
import_user_modules()

# Export commonly used items
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

# Version info
__version__ = "1.0.0"
