"""
PlexiChat Centralized Error Code Management System

This module provides a comprehensive error code management system with:
- Standardized error codes organized by category
- HTTP status mappings
- User-friendly messages
- Helper functions for consistent error responses
"""

from http import HTTPStatus
import logging
from typing import Any

from .base import (
    ErrorCategory,
    ErrorSeverity,
)
from .base import (
    PlexiChatErrorCode as BasePlexiChatErrorCode,
)

logger = logging.getLogger(__name__)


class PlexiChatErrorCode(BasePlexiChatErrorCode):
    """Centralized error codes for the PlexiChat application."""
    pass


class ErrorCodeMapping:
    """Maps error codes to their properties and HTTP status codes."""

    _mappings = {
        # Authentication Errors
        PlexiChatErrorCode.AUTH_INVALID_CREDENTIALS: {
            "category": ErrorCategory.AUTHENTICATION,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.UNAUTHORIZED,
            "message": "Invalid username or password",
            "user_message": "Please check your credentials and try again",
        },
        PlexiChatErrorCode.AUTH_TOKEN_EXPIRED: {
            "category": ErrorCategory.AUTHENTICATION,
            "severity": ErrorSeverity.LOW,
            "http_status": HTTPStatus.UNAUTHORIZED,
            "message": "Authentication token has expired",
            "user_message": "Your session has expired. Please log in again",
        },
        PlexiChatErrorCode.AUTH_TOKEN_INVALID: {
            "category": ErrorCategory.AUTHENTICATION,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.UNAUTHORIZED,
            "message": "Invalid authentication token",
            "user_message": "Authentication failed. Please log in again",
        },
        PlexiChatErrorCode.AUTH_TOKEN_MISSING: {
            "category": ErrorCategory.AUTHENTICATION,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.UNAUTHORIZED,
            "message": "Authentication token is required",
            "user_message": "Please log in to access this resource",
        },
        PlexiChatErrorCode.AUTH_USER_NOT_FOUND: {
            "category": ErrorCategory.AUTHENTICATION,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.UNAUTHORIZED,
            "message": "User account not found",
            "user_message": "Invalid credentials provided",
        },
        PlexiChatErrorCode.AUTH_USER_DISABLED: {
            "category": ErrorCategory.AUTHENTICATION,
            "severity": ErrorSeverity.HIGH,
            "http_status": HTTPStatus.FORBIDDEN,
            "message": "User account is disabled",
            "user_message": "Your account has been disabled. Please contact support",
        },
        PlexiChatErrorCode.AUTH_LOGIN_ATTEMPTS_EXCEEDED: {
            "category": ErrorCategory.AUTHENTICATION,
            "severity": ErrorSeverity.HIGH,
            "http_status": HTTPStatus.TOO_MANY_REQUESTS,
            "message": "Too many login attempts",
            "user_message": "Too many failed login attempts. Please try again later",
        },
        # Authorization Errors
        PlexiChatErrorCode.AUTHZ_INSUFFICIENT_PERMISSIONS: {
            "category": ErrorCategory.AUTHORIZATION,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.FORBIDDEN,
            "message": "Insufficient permissions to access resource",
            "user_message": "You don't have permission to access this resource",
        },
        PlexiChatErrorCode.AUTHZ_RESOURCE_FORBIDDEN: {
            "category": ErrorCategory.AUTHORIZATION,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.FORBIDDEN,
            "message": "Access to resource is forbidden",
            "user_message": "Access denied",
        },
        # Validation Errors
        PlexiChatErrorCode.VALIDATION_REQUIRED_FIELD: {
            "category": ErrorCategory.VALIDATION,
            "severity": ErrorSeverity.LOW,
            "http_status": HTTPStatus.BAD_REQUEST,
            "message": "Required field is missing",
            "user_message": "Please fill in all required fields",
        },
        PlexiChatErrorCode.VALIDATION_INVALID_FORMAT: {
            "category": ErrorCategory.VALIDATION,
            "severity": ErrorSeverity.LOW,
            "http_status": HTTPStatus.BAD_REQUEST,
            "message": "Invalid data format",
            "user_message": "Please check the format of your input",
        },
        PlexiChatErrorCode.VALIDATION_INVALID_EMAIL: {
            "category": ErrorCategory.VALIDATION,
            "severity": ErrorSeverity.LOW,
            "http_status": HTTPStatus.BAD_REQUEST,
            "message": "Invalid email address format",
            "user_message": "Please enter a valid email address",
        },
        # System Errors
        PlexiChatErrorCode.SYSTEM_INTERNAL_ERROR: {
            "category": ErrorCategory.SYSTEM,
            "severity": ErrorSeverity.CRITICAL,
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR,
            "message": "Internal system error occurred",
            "user_message": "An unexpected error occurred. Please try again later",
        },
        PlexiChatErrorCode.SYSTEM_SERVICE_UNAVAILABLE: {
            "category": ErrorCategory.SYSTEM,
            "severity": ErrorSeverity.HIGH,
            "http_status": HTTPStatus.SERVICE_UNAVAILABLE,
            "message": "Service is temporarily unavailable",
            "user_message": "Service is temporarily unavailable. Please try again later",
        },
        PlexiChatErrorCode.SYSTEM_TIMEOUT: {
            "category": ErrorCategory.SYSTEM,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.REQUEST_TIMEOUT,
            "message": "Request timeout",
            "user_message": "Request timed out. Please try again",
        },
        # Security Errors
        PlexiChatErrorCode.SECURITY_SUSPICIOUS_ACTIVITY: {
            "category": ErrorCategory.SECURITY,
            "severity": ErrorSeverity.HIGH,
            "http_status": HTTPStatus.FORBIDDEN,
            "message": "Suspicious activity detected",
            "user_message": "Suspicious activity detected. Access temporarily restricted",
        },
        PlexiChatErrorCode.SECURITY_IP_BLOCKED: {
            "category": ErrorCategory.SECURITY,
            "severity": ErrorSeverity.HIGH,
            "http_status": HTTPStatus.FORBIDDEN,
            "message": "IP address is blocked",
            "user_message": "Access denied from your location",
        },
        PlexiChatErrorCode.SECURITY_MALICIOUS_REQUEST: {
            "category": ErrorCategory.SECURITY,
            "severity": ErrorSeverity.CRITICAL,
            "http_status": HTTPStatus.FORBIDDEN,
            "message": "Malicious request detected",
            "user_message": "Request blocked for security reasons",
        },
        # Database Errors
        PlexiChatErrorCode.DB_CONNECTION_FAILED: {
            "category": ErrorCategory.DATABASE,
            "severity": ErrorSeverity.CRITICAL,
            "http_status": HTTPStatus.SERVICE_UNAVAILABLE,
            "message": "Database connection failed",
            "user_message": "Service temporarily unavailable. Please try again later",
        },
        PlexiChatErrorCode.DB_RECORD_NOT_FOUND: {
            "category": ErrorCategory.DATABASE,
            "severity": ErrorSeverity.LOW,
            "http_status": HTTPStatus.NOT_FOUND,
            "message": "Requested record not found",
            "user_message": "The requested item was not found",
        },
        # Rate Limiting Errors
        PlexiChatErrorCode.RATE_LIMIT_EXCEEDED: {
            "category": ErrorCategory.RATE_LIMITING,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.TOO_MANY_REQUESTS,
            "message": "Rate limit exceeded",
            "user_message": "Too many requests. Please slow down and try again later",
        },
        # File System Errors
        PlexiChatErrorCode.FILE_NOT_FOUND: {
            "category": ErrorCategory.FILE_SYSTEM,
            "severity": ErrorSeverity.LOW,
            "http_status": HTTPStatus.NOT_FOUND,
            "message": "File not found",
            "user_message": "The requested file was not found",
        },
        PlexiChatErrorCode.FILE_SIZE_EXCEEDED: {
            "category": ErrorCategory.FILE_SYSTEM,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.PAYLOAD_TOO_LARGE,
            "message": "File size exceeds maximum allowed",
            "user_message": "File is too large. Please upload a smaller file",
        },
        # Backup System Errors
        PlexiChatErrorCode.BACKUP_CREATION_FAILED: {
            "category": ErrorCategory.BACKUP,
            "severity": ErrorSeverity.HIGH,
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR,
            "message": "Backup creation failed",
            "user_message": "Failed to create backup. Please try again",
        },
        # WAF Errors
        PlexiChatErrorCode.WAF_BLOCKED_REQUEST: {
            "category": ErrorCategory.WAF,
            "severity": ErrorSeverity.HIGH,
            "http_status": HTTPStatus.FORBIDDEN,
            "message": "Request blocked by Web Application Firewall",
            "user_message": "Request blocked for security reasons",
        },
    }

    @classmethod
    def get_mapping(cls, error_code: PlexiChatErrorCode) -> dict[str, Any]:
        """Get the complete mapping for an error code."""
        return cls._mappings.get(
            error_code,
            {
                "category": ErrorCategory.SYSTEM,
                "severity": ErrorSeverity.MEDIUM,
                "http_status": HTTPStatus.INTERNAL_SERVER_ERROR,
                "message": "Unknown error occurred",
                "user_message": "An unexpected error occurred",
            },
        )

    @classmethod
    def get_http_status(cls, error_code: PlexiChatErrorCode) -> HTTPStatus:
        """Get HTTP status code for an error."""
        return cls.get_mapping(error_code).get(
            "http_status", HTTPStatus.INTERNAL_SERVER_ERROR
        )

    @classmethod
    def get_category(cls, error_code: PlexiChatErrorCode) -> ErrorCategory:
        """Get category for an error."""
        return cls.get_mapping(error_code).get("category", ErrorCategory.SYSTEM)

    @classmethod
    def get_severity(cls, error_code: PlexiChatErrorCode) -> ErrorSeverity:
        """Get severity for an error."""
        return cls.get_mapping(error_code).get("severity", ErrorSeverity.MEDIUM)

    @classmethod
    def get_message(cls, error_code: PlexiChatErrorCode) -> str:
        """Get technical message for an error."""
        return cls.get_mapping(error_code).get("message", "Unknown error occurred")

    @classmethod
    def get_user_message(cls, error_code: PlexiChatErrorCode) -> str:
        """Get user-friendly message for an error."""
        return cls.get_mapping(error_code).get(
            "user_message", "An unexpected error occurred"
        )


def get_errors_by_category(category: ErrorCategory) -> list[PlexiChatErrorCode]:
    """Get all error codes for a specific category."""
    return [
        error_code
        for error_code in PlexiChatErrorCode
        if ErrorCodeMapping.get_category(error_code) == category
    ]


def get_errors_by_severity(severity: ErrorSeverity) -> list[PlexiChatErrorCode]:
    """Get all error codes for a specific severity level."""
    return [
        error_code
        for error_code in PlexiChatErrorCode
        if ErrorCodeMapping.get_severity(error_code) == severity
    ]


def get_critical_errors() -> list[PlexiChatErrorCode]:
    """Get all critical error codes."""
    return get_errors_by_severity(ErrorSeverity.CRITICAL)


def log_error(
    error_code: PlexiChatErrorCode,
    details: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
    correlation_id: str | None = None,
    exception: Exception | None = None,
) -> None:
    """Log an error with standardized format."""
    mapping = ErrorCodeMapping.get_mapping(error_code)
    severity = mapping["severity"]

    log_data = {
        "error_code": error_code.value,
        "category": mapping["category"].value,
        "severity": severity.value,
        "message": mapping["message"],
    }

    if details:
        log_data["details"] = details
    if context:
        log_data["context"] = context
    if correlation_id:
        log_data["correlation_id"] = correlation_id
    if exception:
        log_data["exception"] = str(exception)
        log_data["exception_type"] = type(exception).__name__

    # Log at appropriate level based on severity
    if severity == ErrorSeverity.CRITICAL:
        logger.critical("Critical error occurred", extra=log_data)
    elif severity == ErrorSeverity.HIGH:
        logger.error("High severity error occurred", extra=log_data)
    elif severity == ErrorSeverity.MEDIUM:
        logger.warning("Medium severity error occurred", extra=log_data)
    else:
        logger.info("Low severity error occurred", extra=log_data)


# Export all public classes and functions
__all__ = [
    "ErrorCodeMapping",
    "PlexiChatErrorCode",
    "get_critical_errors",
    "get_errors_by_category",
    "get_errors_by_severity",
    "log_error",
]
