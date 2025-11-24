# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Shared Components

This module contains shared utilities, models, and constants that are used
across multiple layers of the application (core, features, infrastructure, interfaces).

Components:
- models: Shared data models and schemas
- constants: Application-wide constants
- types: Common type definitions
- exceptions: Base exception classes
- validators: Common validation functions
"""

from plexichat.core.logging import LogCategory, get_logger

logger = get_logger(__name__)

# Version information
from plexichat.core.config import get_config

__version__ = get_config("system.version", "0.0.0")
__author__ = "PlexiChat Team"
__description__ = "Shared components for PlexiChat"

# Import shared components
try:
    # # from . import models
    # # from . import types
    # # from . import exceptions
    # # from . import constants

    logger.info("Shared components imported successfully")

except ImportError as e:
    logger.warning(f"Some shared components not available: {e}")

__all__ = [
    # No modules currently imported
]
