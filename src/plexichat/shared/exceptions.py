"""
PlexiChat Shared Exceptions - Minimal working version
"""

from typing import Any


class PlexiChatError(Exception):
    """Base exception for all PlexiChat errors."""

    def __init__(
        self,
        message: str,
        error_code: str | None = None,
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}


class ValidationError(PlexiChatError):
    """Raised when validation fails."""

    pass


class AuthenticationError(PlexiChatError):
    """Raised when authentication fails."""

    pass


class AuthorizationError(PlexiChatError):
    """Raised when authorization fails."""

    pass


class NotFoundError(PlexiChatError):
    """Raised when a resource is not found."""

    pass


class ConflictError(PlexiChatError):
    """Raised when there's a conflict."""

    pass


class ServiceUnavailableError(PlexiChatError):
    """Raised when a service is unavailable."""

    pass


class RateLimitError(PlexiChatError):
    """Raised when rate limit is exceeded."""

    pass


class ConfigurationError(PlexiChatError):
    """Raised when there's a configuration error."""

    pass


class DatabaseError(PlexiChatError):
    """Raised when there's a database error."""

    pass


class NetworkError(PlexiChatError):
    """Raised when there's a network error."""

    pass


class SecurityError(PlexiChatError):
    """Raised when there's a security-related error."""

    pass


def get_exception_for_status_code(status_code: int) -> type:
    """Get appropriate exception class for HTTP status code."""
    mapping = {
        400: ValidationError,
        401: AuthenticationError,
        403: AuthorizationError,
        404: NotFoundError,
        409: ConflictError,
        429: RateLimitError,
        503: ServiceUnavailableError,
    }
    return mapping.get(status_code, PlexiChatError)


def create_exception_from_response(
    status_code: int,
    message: str,
    error_code: str | None = None,
    details: dict[str, Any] | None = None,
) -> PlexiChatError:
    """Create exception from HTTP response."""
    exception_class = get_exception_for_status_code(status_code)
    return exception_class(message, error_code=error_code, details=details)


# Export all exceptions
__all__ = [
    "AuthenticationError",
    "AuthorizationError",
    "ConfigurationError",
    "ConflictError",
    "DatabaseError",
    "NetworkError",
    "NotFoundError",
    "PlexiChatError",
    "RateLimitError",
    "SecurityError",
    "ServiceUnavailableError",
    "ValidationError",
    "create_exception_from_response",
    "get_exception_for_status_code",
]
