"""Core errors module with shared base functionality."""

from plexichat.core.utils.fallbacks import (
    AuthenticationError,
    BaseAPIException,
    DatabaseError,
    ErrorCategory,
    ErrorManager,
    ErrorSeverity,
    ValidationError,
    create_error_response,
    get_error_manager,
    get_module_version,
    handle_exception,
    log_error,
)

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
