"""Core errors module with shared base functionality."""
try:
    from plexichat.core.utils.fallbacks import (
        ErrorManager, ErrorSeverity, ErrorCategory, BaseAPIException,
        AuthenticationError, ValidationError, DatabaseError,
        get_error_manager, create_error_response, handle_exception, log_error,
        get_module_version
    )
except ImportError:
    # Fallback definitions if utils not available
    from .base import *  # Assume base has some definitions

__version__ = get_module_version()
__all__ = [
    "ErrorSeverity",
    "ErrorCategory",
    "PlexiChatErrorCode",
    "PlexiChatException",
    "ErrorResponse",
    "create_error_response",
    "handle_exception",
    "log_error",
    "ErrorManager",
    "BaseAPIException",
    "AuthenticationError",
    "ValidationError",
    "DatabaseError",
    "get_error_manager",
]