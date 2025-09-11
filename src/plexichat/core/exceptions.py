"""
PlexiChat Core Exceptions

Standardized exception classes with proper type annotations for the entire application.
Defines base PlexiChatError class and specific exception types for different error categories.
"""

from __future__ import annotations

import logging
from datetime import datetime
from enum import Enum
from http import HTTPStatus
from typing import Any, Dict, List, Optional, Type, TypeVar, Union

logger = logging.getLogger(__name__)

# Type variable for exception chaining
ExceptionType = TypeVar("ExceptionType", bound="PlexiChatError")


class ErrorCode(Enum):
    """Typed error codes for all PlexiChat exceptions."""
    
    # Authentication Errors (1000-1099)
    AUTH_INVALID_CREDENTIALS = "PC1001"
    AUTH_TOKEN_EXPIRED = "PC1002"
    AUTH_TOKEN_INVALID = "PC1003"
    AUTH_TOKEN_MISSING = "PC1004"
    AUTH_USER_NOT_FOUND = "PC1005"
    AUTH_USER_DISABLED = "PC1006"
    AUTH_PASSWORD_WEAK = "PC1007"
    AUTH_LOGIN_ATTEMPTS_EXCEEDED = "PC1008"
    AUTH_SESSION_EXPIRED = "PC1009"
    AUTH_MFA_REQUIRED = "PC1010"
    AUTH_MFA_INVALID = "PC1011"
    AUTH_BIOMETRIC_FAILED = "PC1012"
    AUTH_DEVICE_NOT_TRUSTED = "PC1013"
    AUTH_OAUTH_ERROR = "PC1014"
    AUTH_ACCOUNT_LOCKED = "PC1015"

    # Authorization Errors (1100-1199)
    AUTHZ_INSUFFICIENT_PERMISSIONS = "PC1101"
    AUTHZ_RESOURCE_FORBIDDEN = "PC1102"
    AUTHZ_ROLE_REQUIRED = "PC1103"
    AUTHZ_SCOPE_INSUFFICIENT = "PC1104"
    AUTHZ_ACCESS_DENIED = "PC1105"
    AUTHZ_ADMIN_REQUIRED = "PC1106"
    AUTHZ_OWNER_REQUIRED = "PC1107"

    # Database Errors (1200-1299)
    DB_CONNECTION_FAILED = "PC1201"
    DB_QUERY_FAILED = "PC1202"
    DB_TRANSACTION_FAILED = "PC1203"
    DB_CONSTRAINT_VIOLATION = "PC1204"
    DB_RECORD_NOT_FOUND = "PC1205"
    DB_DUPLICATE_ENTRY = "PC1206"
    DB_MIGRATION_FAILED = "PC1207"
    DB_BACKUP_FAILED = "PC1208"
    DB_RESTORE_FAILED = "PC1209"
    DB_DEADLOCK_DETECTED = "PC1210"
    DB_TIMEOUT = "PC1211"
    DB_INTEGRITY_ERROR = "PC1212"

    # Plugin Errors (1300-1399)
    PLUGIN_NOT_FOUND = "PC1301"
    PLUGIN_LOAD_FAILED = "PC1302"
    PLUGIN_INIT_FAILED = "PC1303"
    PLUGIN_EXECUTION_FAILED = "PC1304"
    PLUGIN_DEPENDENCY_MISSING = "PC1305"
    PLUGIN_VERSION_INCOMPATIBLE = "PC1306"
    PLUGIN_CONFIG_INVALID = "PC1307"
    PLUGIN_PERMISSION_DENIED = "PC1308"
    PLUGIN_RESOURCE_EXHAUSTED = "PC1309"
    PLUGIN_TIMEOUT = "PC1310"
    PLUGIN_SECURITY_VIOLATION = "PC1311"

    # Networking Errors (1400-1499)
    NET_CONNECTION_FAILED = "PC1401"
    NET_TIMEOUT = "PC1402"
    NET_DNS_RESOLUTION_FAILED = "PC1403"
    NET_SSL_ERROR = "PC1404"
    NET_PROXY_ERROR = "PC1405"
    NET_BANDWIDTH_EXCEEDED = "PC1406"
    NET_UNREACHABLE = "PC1407"
    NET_PROTOCOL_ERROR = "PC1408"
    NET_CERTIFICATE_INVALID = "PC1409"
    NET_FIREWALL_BLOCKED = "PC1410"

    # Validation Errors (1500-1599)
    VALIDATION_REQUIRED_FIELD = "PC1501"
    VALIDATION_INVALID_FORMAT = "PC1502"
    VALIDATION_OUT_OF_RANGE = "PC1503"
    VALIDATION_DUPLICATE_VALUE = "PC1504"
    VALIDATION_INVALID_TYPE = "PC1505"
    VALIDATION_LENGTH_EXCEEDED = "PC1506"
    VALIDATION_PATTERN_MISMATCH = "PC1507"
    VALIDATION_INVALID_EMAIL = "PC1508"
    VALIDATION_INVALID_URL = "PC1509"
    VALIDATION_INVALID_JSON = "PC1510"
    VALIDATION_SCHEMA_VIOLATION = "PC1511"

    # System Errors (1600-1699)
    SYSTEM_INTERNAL_ERROR = "PC1601"
    SYSTEM_SERVICE_UNAVAILABLE = "PC1602"
    SYSTEM_TIMEOUT = "PC1603"
    SYSTEM_RESOURCE_EXHAUSTED = "PC1604"
    SYSTEM_MAINTENANCE_MODE = "PC1605"
    SYSTEM_STARTUP_FAILED = "PC1606"
    SYSTEM_SHUTDOWN_ERROR = "PC1607"
    SYSTEM_MEMORY_ERROR = "PC1608"
    SYSTEM_DISK_FULL = "PC1609"
    SYSTEM_PROCESS_LOCK_ERROR = "PC1610"

    # File System Errors (1700-1799)
    FILE_NOT_FOUND = "PC1701"
    FILE_PERMISSION_DENIED = "PC1702"
    FILE_ALREADY_EXISTS = "PC1703"
    FILE_SIZE_EXCEEDED = "PC1704"
    FILE_CORRUPTED = "PC1705"
    FILE_UPLOAD_FAILED = "PC1706"
    FILE_DOWNLOAD_FAILED = "PC1707"
    FILE_INVALID_FORMAT = "PC1708"
    FILE_VIRUS_DETECTED = "PC1709"

    # Rate Limiting Errors (1800-1899)
    RATE_LIMIT_EXCEEDED = "PC1801"
    RATE_LIMIT_QUOTA_EXCEEDED = "PC1802"
    RATE_LIMIT_BURST_EXCEEDED = "PC1803"
    RATE_LIMIT_DAILY_LIMIT = "PC1804"
    RATE_LIMIT_HOURLY_LIMIT = "PC1805"

    # Configuration Errors (1900-1999)
    CONFIG_INVALID = "PC1901"
    CONFIG_MISSING = "PC1902"
    CONFIG_PARSE_ERROR = "PC1903"
    CONFIG_VALIDATION_FAILED = "PC1904"
    CONFIG_ENVIRONMENT_MISMATCH = "PC1905"
    CONFIG_SECRET_MISSING = "PC1906"


class PlexiChatError(Exception):
    """
    Base exception class for all PlexiChat errors with proper type annotations.
    
    Provides standardized error handling with error codes, context, and message parameters.
    """

    def __init__(
        self,
        message: str,
        error_code: ErrorCode,
        details: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        correlation_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> None:
        """
        Initialize PlexiChat base exception.
        
        Args:
            message: Human-readable error message
            error_code: Typed error code from ErrorCode enum
            details: Additional error details and parameters
            context: Contextual information about the error
            cause: Original exception that caused this error
            correlation_id: Request correlation ID for tracing
            timestamp: Error occurrence timestamp
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.context = context or {}
        self.cause = cause
        self.correlation_id = correlation_id
        self.timestamp = timestamp or datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary representation."""
        return {
            "error_code": self.error_code.value,
            "message": self.message,
            "details": self.details,
            "context": self.context,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "cause": str(self.cause) if self.cause else None,
        }

    def __str__(self) -> str:
        """String representation of the exception."""
        return f"[{self.error_code.value}] {self.message}"

    def __repr__(self) -> str:
        """Detailed representation of the exception."""
        return (
            f"{self.__class__.__name__}("
            f"error_code={self.error_code.value}, "
            f"message='{self.message}', "
            f"details={self.details})"
        )


# Authentication Exceptions
class AuthenticationError(PlexiChatError):
    """Authentication-related errors."""

    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.AUTH_INVALID_CREDENTIALS,
        user_id: Optional[str] = None,
        auth_method: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize authentication error.
        
        Args:
            message: Error message
            error_code: Authentication-specific error code
            user_id: ID of the user attempting authentication
            auth_method: Authentication method used
            **kwargs: Additional arguments passed to base class
        """
        details = kwargs.pop("details", {})
        if user_id:
            details["user_id"] = user_id
        if auth_method:
            details["auth_method"] = auth_method
        
        super().__init__(message, error_code, details=details, **kwargs)


class AuthorizationError(PlexiChatError):
    """Authorization-related errors."""

    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.AUTHZ_ACCESS_DENIED,
        user_id: Optional[str] = None,
        resource: Optional[str] = None,
        required_permission: Optional[str] = None,
        current_permissions: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize authorization error.
        
        Args:
            message: Error message
            error_code: Authorization-specific error code
            user_id: ID of the user being authorized
            resource: Resource being accessed
            required_permission: Permission required for access
            current_permissions: User's current permissions
            **kwargs: Additional arguments passed to base class
        """
        details = kwargs.pop("details", {})
        if user_id:
            details["user_id"] = user_id
        if resource:
            details["resource"] = resource
        if required_permission:
            details["required_permission"] = required_permission
        if current_permissions:
            details["current_permissions"] = current_permissions
        
        super().__init__(message, error_code, details=details, **kwargs)


# Database Exceptions
class DatabaseError(PlexiChatError):
    """Database-related errors."""

    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.DB_QUERY_FAILED,
        table: Optional[str] = None,
        operation: Optional[str] = None,
        query: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize database error.
        
        Args:
            message: Error message
            error_code: Database-specific error code
            table: Database table involved in the error
            operation: Database operation being performed
            query: SQL query that failed (if applicable)
            **kwargs: Additional arguments passed to base class
        """
        details = kwargs.pop("details", {})
        if table:
            details["table"] = table
        if operation:
            details["operation"] = operation
        if query:
            # Only include first 500 chars of query for security/log size
            details["query"] = query[:500] + "..." if len(query) > 500 else query
        
        super().__init__(message, error_code, details=details, **kwargs)


# Plugin Exceptions
class PluginError(PlexiChatError):
    """Plugin-related errors."""

    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.PLUGIN_EXECUTION_FAILED,
        plugin_name: Optional[str] = None,
        plugin_version: Optional[str] = None,
        plugin_author: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize plugin error.
        
        Args:
            message: Error message
            error_code: Plugin-specific error code
            plugin_name: Name of the plugin
            plugin_version: Version of the plugin
            plugin_author: Author of the plugin
            **kwargs: Additional arguments passed to base class
        """
        details = kwargs.pop("details", {})
        if plugin_name:
            details["plugin_name"] = plugin_name
        if plugin_version:
            details["plugin_version"] = plugin_version
        if plugin_author:
            details["plugin_author"] = plugin_author
        
        super().__init__(message, error_code, details=details, **kwargs)


# Networking Exceptions
class NetworkError(PlexiChatError):
    """Network-related errors."""

    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.NET_CONNECTION_FAILED,
        url: Optional[str] = None,
        method: Optional[str] = None,
        status_code: Optional[int] = None,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize network error.
        
        Args:
            message: Error message
            error_code: Network-specific error code
            url: URL that caused the error
            method: HTTP method used
            status_code: HTTP status code received
            timeout: Timeout value used
            **kwargs: Additional arguments passed to base class
        """
        details = kwargs.pop("details", {})
        if url:
            details["url"] = url
        if method:
            details["method"] = method
        if status_code:
            details["status_code"] = status_code
        if timeout:
            details["timeout"] = timeout
        
        super().__init__(message, error_code, details=details, **kwargs)


# Validation Exceptions
class ValidationError(PlexiChatError):
    """Validation-related errors."""

    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.VALIDATION_INVALID_FORMAT,
        field: Optional[str] = None,
        value: Optional[Any] = None,
        expected_type: Optional[str] = None,
        validation_rules: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize validation error.
        
        Args:
            message: Error message
            error_code: Validation-specific error code
            field: Field that failed validation
            value: Value that failed validation (sanitized for logging)
            expected_type: Expected data type
            validation_rules: Validation rules that were violated
            **kwargs: Additional arguments passed to base class
        """
        details = kwargs.pop("details", {})
        if field:
            details["field"] = field
        if value is not None:
            # Sanitize sensitive values
            if isinstance(value, str) and len(value) > 100:
                details["value"] = f"<{type(value).__name__}:length={len(value)}>"
            elif field and any(sensitive in field.lower() for sensitive in 
                              ["password", "token", "secret", "key", "credential"]):
                details["value"] = "<sensitive>"
            else:
                details["value"] = value
        if expected_type:
            details["expected_type"] = expected_type
        if validation_rules:
            details["validation_rules"] = validation_rules
        
        super().__init__(message, error_code, details=details, **kwargs)


# System Exceptions
class SystemError(PlexiChatError):
    """System-related errors."""

    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.SYSTEM_INTERNAL_ERROR,
        component: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize system error.
        
        Args:
            message: Error message
            error_code: System-specific error code
            component: System component that failed
            resource_type: Type of resource involved
            resource_id: ID of the resource
            **kwargs: Additional arguments passed to base class
        """
        details = kwargs.pop("details", {})
        if component:
            details["component"] = component
        if resource_type:
            details["resource_type"] = resource_type
        if resource_id:
            details["resource_id"] = resource_id
        
        super().__init__(message, error_code, details=details, **kwargs)


# File System Exceptions
class FileError(PlexiChatError):
    """File system-related errors."""

    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.FILE_NOT_FOUND,
        file_path: Optional[str] = None,
        operation: Optional[str] = None,
        file_size: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize file error.
        
        Args:
            message: Error message
            error_code: File-specific error code
            file_path: Path to the file
            operation: File operation being performed
            file_size: Size of the file
            **kwargs: Additional arguments passed to base class
        """
        details = kwargs.pop("details", {})
        if file_path:
            details["file_path"] = file_path
        if operation:
            details["operation"] = operation
        if file_size:
            details["file_size"] = file_size
        
        super().__init__(message, error_code, details=details, **kwargs)


# Rate Limiting Exceptions
class RateLimitError(PlexiChatError):
    """Rate limiting-related errors."""

    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.RATE_LIMIT_EXCEEDED,
        limit: Optional[int] = None,
        window_seconds: Optional[int] = None,
        retry_after: Optional[int] = None,
        identifier: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize rate limit error.
        
        Args:
            message: Error message
            error_code: Rate limit-specific error code
            limit: Rate limit threshold
            window_seconds: Time window for rate limiting
            retry_after: Seconds to wait before retrying
            identifier: Identifier being rate limited (IP, user ID, etc.)
            **kwargs: Additional arguments passed to base class
        """
        details = kwargs.pop("details", {})
        if limit:
            details["limit"] = limit
        if window_seconds:
            details["window_seconds"] = window_seconds
        if retry_after:
            details["retry_after"] = retry_after
        if identifier:
            details["identifier"] = identifier
        
        super().__init__(message, error_code, details=details, **kwargs)


# Configuration Exceptions
class ConfigurationError(PlexiChatError):
    """Configuration-related errors."""

    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.CONFIG_INVALID,
        config_key: Optional[str] = None,
        config_file: Optional[str] = None,
        expected_format: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize configuration error.
        
        Args:
            message: Error message
            error_code: Configuration-specific error code
            config_key: Configuration key that is invalid
            config_file: Configuration file path
            expected_format: Expected configuration format
            **kwargs: Additional arguments passed to base class
        """
        details = kwargs.pop("details", {})
        if config_key:
            details["config_key"] = config_key
        if config_file:
            details["config_file"] = config_file
        if expected_format:
            details["expected_format"] = expected_format
        
        super().__init__(message, error_code, details=details, **kwargs)


# Exception handler type annotations
ExceptionHandler = Union[
    PlexiChatError,
    AuthenticationError,
    AuthorizationError,
    DatabaseError,
    PluginError,
    NetworkError,
    ValidationError,
    SystemError,
    FileError,
    RateLimitError,
    ConfigurationError,
]


def handle_exception(
    exception: Exception,
    context: Optional[Dict[str, Any]] = None,
    correlation_id: Optional[str] = None,
    logger_instance: Optional[logging.Logger] = None,
) -> PlexiChatError:
    """
    Convert generic exceptions to typed PlexiChat exceptions.
    
    Args:
        exception: Original exception to convert
        context: Additional context information
        correlation_id: Request correlation ID
        logger_instance: Logger instance to use for logging
        
    Returns:
        Properly typed PlexiChat exception
    """
    log = logger_instance or logger
    
    # If already a PlexiChat exception, just add context if needed
    if isinstance(exception, PlexiChatError):
        if context:
            exception.context.update(context)
        if correlation_id and not exception.correlation_id:
            exception.correlation_id = correlation_id
        return exception
    
    # Map common Python exceptions to PlexiChat exceptions
    error_mapping = {
        ValueError: (ValidationError, ErrorCode.VALIDATION_INVALID_FORMAT),
        TypeError: (ValidationError, ErrorCode.VALIDATION_INVALID_TYPE),
        KeyError: (ValidationError, ErrorCode.VALIDATION_REQUIRED_FIELD),
        FileNotFoundError: (FileError, ErrorCode.FILE_NOT_FOUND),
        PermissionError: (FileError, ErrorCode.FILE_PERMISSION_DENIED),
        ConnectionError: (NetworkError, ErrorCode.NET_CONNECTION_FAILED),
        TimeoutError: (NetworkError, ErrorCode.NET_TIMEOUT),
        OSError: (SystemError, ErrorCode.SYSTEM_INTERNAL_ERROR),
        MemoryError: (SystemError, ErrorCode.SYSTEM_MEMORY_ERROR),
        RuntimeError: (SystemError, ErrorCode.SYSTEM_INTERNAL_ERROR),
    }
    
    exception_type = type(exception)
    if exception_type in error_mapping:
        plexichat_cls, error_code = error_mapping[exception_type]
        plexichat_exception = plexichat_cls(
            message=str(exception),
            error_code=error_code,
            context=context,
            correlation_id=correlation_id,
            cause=exception,
        )
    else:
        # Default to generic system error
        plexichat_exception = SystemError(
            message=f"Unhandled exception: {str(exception)}",
            error_code=ErrorCode.SYSTEM_INTERNAL_ERROR,
            context=context,
            correlation_id=correlation_id,
            cause=exception,
        )
    
    log.error(
        "Exception handled",
        extra={
            "error_code": plexichat_exception.error_code.value,
            "original_exception": exception_type.__name__,
            "correlation_id": correlation_id,
            "context": context,
        },
        exc_info=True,
    )
    
    return plexichat_exception


# Export all exception classes and utilities
__all__ = [
    "ErrorCode",
    "PlexiChatError",
    "AuthenticationError",
    "AuthorizationError", 
    "DatabaseError",
    "PluginError",
    "NetworkError",
    "ValidationError",
    "SystemError",
    "FileError",
    "RateLimitError",
    "ConfigurationError",
    "ExceptionHandler",
    "handle_exception",
]