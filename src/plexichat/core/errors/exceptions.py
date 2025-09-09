"""
PlexiChat Core Exceptions
Essential exception classes for the entire application.
"""

import logging
from typing import Any, Dict, Optional

from .base import (
    PlexiChatException,
    ErrorCategory,
    ErrorSeverity,
    create_error_response,
    handle_exception,
    PlexiChatErrorCode,
    AuthenticationError as BaseAuthenticationError,
    AuthorizationError as BaseAuthorizationError,
    ValidationError as BaseValidationError,
    DatabaseError as BaseDatabaseError,
    NetworkError as BaseNetworkError,
    FileError as BaseFileError,
    ExternalServiceError as BaseExternalServiceError,
    RateLimitError as BaseRateLimitError,
    ConfigurationError as BaseConfigurationError,
    ProcessLockError as BaseProcessLockError,
    StartupError as BaseStartupError,
)

logger = logging.getLogger(__name__)


class BaseAPIException(PlexiChatException):
    """Base exception for all API errors."""

    def __init__(
        self,
        error_code: PlexiChatErrorCode = PlexiChatErrorCode.SYSTEM_INTERNAL_ERROR,
        message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            error_code=error_code,
            details=details,
            context=context,
            correlation_id=correlation_id,
            cause=cause,
            message=message,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary using base ErrorResponse."""
        error_response = self.to_error_response()
        return error_response.to_dict(include_technical_details=True)


class AuthenticationError(BaseAuthenticationError):
    """Authentication failed."""
    pass


class AuthorizationError(BaseAuthorizationError):
    """Authorization failed."""
    pass


class ValidationError(BaseValidationError):
    """Data validation failed."""
    pass


class DatabaseError(BaseDatabaseError):
    """Database operation failed."""
    pass


class NetworkError(BaseNetworkError):
    """Network operation failed."""
    pass


class FileError(BaseFileError):
    """File operation failed."""
    pass


class ExternalServiceError(BaseExternalServiceError):
    """External service error."""
    pass


class RateLimitError(BaseRateLimitError):
    """Rate limit exceeded."""
    pass


class ConfigurationError(BaseConfigurationError):
    """Configuration error."""
    pass


class ProcessLockError(BaseProcessLockError):
    """Process lock error."""
    pass


class StartupError(BaseStartupError):
    """Startup error."""
    pass


# Export all exception classes
__all__ = [
    "BaseAPIException",
    "AuthenticationError",
    "AuthorizationError",
    "ValidationError",
    "DatabaseError",
    "NetworkError",
    "FileError",
    "ExternalServiceError",
    "RateLimitError",
    "ConfigurationError",
    "ProcessLockError",
    "StartupError",
]