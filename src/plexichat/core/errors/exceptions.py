"""
PlexiChat Core Exceptions
Essential exception classes for the entire application.
"""

import logging
from typing import Any

from .base import (
    AuthenticationError as BaseAuthenticationError,
)
from .base import (
    AuthorizationError as BaseAuthorizationError,
)
from .base import (
    ConfigurationError as BaseConfigurationError,
)
from .base import (
    DatabaseError as BaseDatabaseError,
)
from .base import (
    ExternalServiceError as BaseExternalServiceError,
)
from .base import (
    FileError as BaseFileError,
)
from .base import (
    NetworkError as BaseNetworkError,
)
from .base import (
    PlexiChatErrorCode,
    PlexiChatException,
)
from .base import (
    ProcessLockError as BaseProcessLockError,
)
        self,
        error_code: PlexiChatErrorCode = PlexiChatErrorCode.SYSTEM_INTERNAL_ERROR,
        message: str | None = None,
        details: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(
            error_code=error_code,
            details=details,
            context=context,
            correlation_id=correlation_id,
            cause=cause,
            message=message,
        )

    def to_dict(self) -> dict[str, Any]:
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
    "AuthenticationError",
    "AuthorizationError",
    "BaseAPIException",
    "ConfigurationError",
    "DatabaseError",
    "ExternalServiceError",
    "FileError",
    "NetworkError",
    "ProcessLockError",
    "RateLimitError",
    "StartupError",
    "ValidationError",
]
