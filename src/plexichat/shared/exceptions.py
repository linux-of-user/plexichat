# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Shared Exceptions

Base exception classes and common exceptions used across the application.


from typing import Any, Dict, Optional


class PlexiChatError(Exception):
    """Base exception for all PlexiChat errors."""
        def __init__(self, message: str, error_code: Optional[str] = None,
                details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        Convert exception to dictionary."""
        result = {
            "error": self.__class__.__name__,
            "message": self.message
        }

        if self.error_code:
            result["error_code"] = self.error_code

        if self.details:
            result["details"] = self.details

        return result


class ValidationError(PlexiChatError):
    """Raised when validation fails."""
        def __init__(self, message: str, field: Optional[str] = None,
                value: Optional[Any] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.field = field
        self.value = value

        if field:
            self.details["field"] = field
        if value is not None:
            self.details["value"] = str(value)


class AuthenticationError(PlexiChatError):
    """Raised when authentication fails.
        pass


class AuthorizationError(PlexiChatError):
    """Raised when authorization fails."""
    pass


class ConfigurationError(PlexiChatError):
    Raised when configuration is invalid."""
        pass


class DatabaseError(PlexiChatError):
    """Raised when database operations fail.
    pass


class NetworkError(PlexiChatError):
    """Raised when network operations fail."""
        pass


class PluginError(PlexiChatError):
    Raised when plugin operations fail."""

    def __init__(self, message: str, plugin_name: Optional[str] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.plugin_name = plugin_name

        if plugin_name:
            self.details["plugin_name"] = plugin_name


class SecurityError(PlexiChatError):
    """Raised when security violations occur.
        pass


class RateLimitError(PlexiChatError):
    """Raised when rate limits are exceeded."""

    def __init__(self, message: str, retry_after: Optional[int] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.retry_after = retry_after

        if retry_after:
            self.details["retry_after"] = retry_after


class ResourceNotFoundError(PlexiChatError):
    """Raised when a resource is not found."""
        def __init__(self, message: str, resource_type: Optional[str] = None,
                resource_id: Optional[str] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.resource_type = resource_type
        self.resource_id = resource_id

        if resource_type:
            self.details["resource_type"] = resource_type
        if resource_id:
            self.details["resource_id"] = resource_id


class ResourceConflictError(PlexiChatError):
    """Raised when a resource conflict occurs.
        pass


class QuotaExceededError(PlexiChatError):
    """Raised when quotas are exceeded."""

    def __init__(self, message: str, quota_type: Optional[str] = None,
                current_value: Optional[Any] = None,
                limit_value: Optional[Any] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.quota_type = quota_type
        self.current_value = current_value
        self.limit_value = limit_value

        if quota_type:
            self.details["quota_type"] = quota_type
        if current_value is not None:
            self.details["current_value"] = current_value
        if limit_value is not None:
            self.details["limit_value"] = limit_value


class TimeoutError(PlexiChatError):
    """Raised when operations timeout."""
        def __init__(self, message: str, timeout_seconds: Optional[float] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.timeout_seconds = timeout_seconds

        if timeout_seconds:
            self.details["timeout_seconds"] = timeout_seconds


class ServiceUnavailableError(PlexiChatError):
    """Raised when a service is unavailable."""
        def __init__(self, message: str, service_name: Optional[str] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.service_name = service_name

        if service_name:
            self.details["service_name"] = service_name


class MaintenanceError(PlexiChatError):
    """Raised when system is in maintenance mode."""
        def __init__(self, message: str, estimated_duration: Optional[int] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.estimated_duration = estimated_duration

        if estimated_duration:
            self.details["estimated_duration"] = estimated_duration


class BackupError(PlexiChatError):
    """Raised when backup operations fail.
        pass


class RestoreError(PlexiChatError):
    """Raised when restore operations fail."""
    pass


class MonitoringError(PlexiChatError):
    Raised when monitoring operations fail."""
        pass


class AnalyticsError(PlexiChatError):
    """Raised when analytics operations fail.
    pass


class CacheError(PlexiChatError):
    """Raised when cache operations fail."""
        pass


class FileError(PlexiChatError):
    Raised when file operations fail."""

    def __init__(self, message: str, file_path: Optional[str] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.file_path = file_path

        if file_path:
            self.details["file_path"] = file_path


class SerializationError(PlexiChatError):
    """Raised when serialization/deserialization fails.
        pass


class EncryptionError(PlexiChatError):
    """Raised when encryption/decryption fails."""
    pass


class CompressionError(PlexiChatError):
    Raised when compression/decompression fails."""
        pass


class WebSocketError(PlexiChatError):
    """Raised when WebSocket operations fail.
    pass


class APIError(PlexiChatError):
    """Raised when API operations fail."""
        def __init__(self, message: str, status_code: Optional[int] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.status_code = status_code

        if status_code:
            self.details["status_code"] = status_code


class ClusterError(PlexiChatError):
    """Raised when cluster operations fail.
        pass


class MigrationError(PlexiChatError):
    """Raised when database migrations fail."""
    pass


class SchedulerError(PlexiChatError):
    Raised when scheduler operations fail."""
        pass


class NotificationError(PlexiChatError):
    """Raised when notification operations fail.
    pass


class ProcessLockError(PlexiChatError):
    """Raised when unable to acquire process lock."""
        pass


class StartupError(PlexiChatError):
    Raised when application startup fails."""
    pass





class LoggingError(PlexiChatError):
    """Raised when logging operations fail.
        pass


# Exception mapping for HTTP status codes
HTTP_EXCEPTION_MAP = {
    400: ValidationError,
    401: AuthenticationError,
    403: AuthorizationError,
    404: ResourceNotFoundError,
    409: ResourceConflictError,
    429: RateLimitError,
    500: PlexiChatError,
    502: ServiceUnavailableError,
    503: MaintenanceError,
    504: TimeoutError,
}


def get_exception_for_status_code(status_code: int) -> type:
    """Get exception class for HTTP status code."""
    return HTTP_EXCEPTION_MAP.get(status_code, PlexiChatError)


def create_exception_from_response(status_code: int, message: str,
                                error_code: Optional[str] = None,
                                details: Optional[Dict[str, Any]] = None) -> PlexiChatError:
    Create exception from HTTP response."""
    exception_class = get_exception_for_status_code(status_code)
    return exception_class(message, error_code=error_code, details=details)


# Export all exceptions
__all__ = [
    # Base exception
    'PlexiChatError',

    # Core exceptions
    'ValidationError',
    'AuthenticationError',
    'AuthorizationError',
    'ConfigurationError',
    'DatabaseError',
    'NetworkError',
    'PluginError',
    'SecurityError',
    'RateLimitError',
    'ResourceNotFoundError',
    'ResourceConflictError',
    'QuotaExceededError',
    'TimeoutError',
    'ServiceUnavailableError',
    'MaintenanceError',

    # Feature exceptions
    'BackupError',
    'RestoreError',
    'MonitoringError',
    'AnalyticsError',
    'CacheError',
    'FileError',
    'SerializationError',
    'EncryptionError',
    'CompressionError',
    'WebSocketError',
    'APIError',
    'ClusterError',
    'MigrationError',
    'SchedulerError',
    'NotificationError',
    'ProcessLockError',
    'StartupError',
    'ServiceUnavailableError',
    'LoggingError',

    # Utilities
    'HTTP_EXCEPTION_MAP',
    'get_exception_for_status_code',
    'create_exception_from_response',
]
