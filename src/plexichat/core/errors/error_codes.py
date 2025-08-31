"""
PlexiChat Centralized Error Code Management System

This module provides a comprehensive error code management system with:
- Standardized error codes organized by category
- HTTP status mappings
- User-friendly messages
- Helper functions for consistent error responses
"""

from enum import Enum, IntEnum
from typing import Any, Dict, Optional, Union, List
from http import HTTPStatus
import logging

logger = logging.getLogger(__name__)


class ErrorCategory(Enum):
    """Error categories for organizing different types of errors."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    SYSTEM = "system"
    SECURITY = "security"
    DATABASE = "database"
    NETWORK = "network"
    FILE_SYSTEM = "file_system"
    EXTERNAL_SERVICE = "external_service"
    RATE_LIMITING = "rate_limiting"
    CONFIGURATION = "configuration"
    BACKUP = "backup"
    LOGGING = "logging"
    PERFORMANCE = "performance"
    WAF = "waf"


class ErrorSeverity(Enum):
    """Error severity levels for prioritizing and handling errors."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PlexiChatErrorCode(Enum):
    """Centralized error codes for the PlexiChat application."""
    
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
    
    # Authorization Errors (1100-1199)
    AUTHZ_INSUFFICIENT_PERMISSIONS = "PC1101"
    AUTHZ_RESOURCE_FORBIDDEN = "PC1102"
    AUTHZ_ROLE_REQUIRED = "PC1103"
    AUTHZ_SCOPE_INSUFFICIENT = "PC1104"
    AUTHZ_ACCESS_DENIED = "PC1105"
    AUTHZ_ADMIN_REQUIRED = "PC1106"
    AUTHZ_OWNER_REQUIRED = "PC1107"
    
    # Validation Errors (1200-1299)
    VALIDATION_REQUIRED_FIELD = "PC1201"
    VALIDATION_INVALID_FORMAT = "PC1202"
    VALIDATION_OUT_OF_RANGE = "PC1203"
    VALIDATION_DUPLICATE_VALUE = "PC1204"
    VALIDATION_INVALID_TYPE = "PC1205"
    VALIDATION_LENGTH_EXCEEDED = "PC1206"
    VALIDATION_PATTERN_MISMATCH = "PC1207"
    VALIDATION_INVALID_EMAIL = "PC1208"
    VALIDATION_INVALID_URL = "PC1209"
    VALIDATION_INVALID_JSON = "PC1210"
    VALIDATION_SCHEMA_VIOLATION = "PC1211"
    
    # System Errors (1300-1399)
    SYSTEM_INTERNAL_ERROR = "PC1301"
    SYSTEM_SERVICE_UNAVAILABLE = "PC1302"
    SYSTEM_TIMEOUT = "PC1303"
    SYSTEM_RESOURCE_EXHAUSTED = "PC1304"
    SYSTEM_MAINTENANCE_MODE = "PC1305"
    SYSTEM_STARTUP_FAILED = "PC1306"
    SYSTEM_SHUTDOWN_ERROR = "PC1307"
    SYSTEM_MEMORY_ERROR = "PC1308"
    SYSTEM_DISK_FULL = "PC1309"
    SYSTEM_PROCESS_LOCK_ERROR = "PC1310"
    
    # Security Errors (1400-1499)
    SECURITY_SUSPICIOUS_ACTIVITY = "PC1401"
    SECURITY_IP_BLOCKED = "PC1402"
    SECURITY_MALICIOUS_REQUEST = "PC1403"
    SECURITY_ENCRYPTION_FAILED = "PC1404"
    SECURITY_DECRYPTION_FAILED = "PC1405"
    SECURITY_CERTIFICATE_INVALID = "PC1406"
    SECURITY_SIGNATURE_INVALID = "PC1407"
    SECURITY_CSRF_TOKEN_INVALID = "PC1408"
    SECURITY_XSS_DETECTED = "PC1409"
    SECURITY_SQL_INJECTION_DETECTED = "PC1410"
    SECURITY_PAYLOAD_TOO_LARGE = "PC1411"
    
    # Database Errors (1500-1599)
    DB_CONNECTION_FAILED = "PC1501"
    DB_QUERY_FAILED = "PC1502"
    DB_TRANSACTION_FAILED = "PC1503"
    DB_CONSTRAINT_VIOLATION = "PC1504"
    DB_RECORD_NOT_FOUND = "PC1505"
    DB_DUPLICATE_ENTRY = "PC1506"
    DB_MIGRATION_FAILED = "PC1507"
    DB_BACKUP_FAILED = "PC1508"
    DB_RESTORE_FAILED = "PC1509"
    DB_DEADLOCK_DETECTED = "PC1510"
    DB_TIMEOUT = "PC1511"
    
    # Network Errors (1600-1699)
    NETWORK_CONNECTION_FAILED = "PC1601"
    NETWORK_TIMEOUT = "PC1602"
    NETWORK_DNS_RESOLUTION_FAILED = "PC1603"
    NETWORK_SSL_ERROR = "PC1604"
    NETWORK_PROXY_ERROR = "PC1605"
    NETWORK_BANDWIDTH_EXCEEDED = "PC1606"
    NETWORK_UNREACHABLE = "PC1607"
    NETWORK_PROTOCOL_ERROR = "PC1608"
    
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
    
    # External Service Errors (1800-1899)
    EXT_SERVICE_UNAVAILABLE = "PC1801"
    EXT_SERVICE_TIMEOUT = "PC1802"
    EXT_SERVICE_RATE_LIMITED = "PC1803"
    EXT_SERVICE_AUTH_FAILED = "PC1804"
    EXT_SERVICE_INVALID_RESPONSE = "PC1805"
    EXT_SERVICE_QUOTA_EXCEEDED = "PC1806"
    EXT_SERVICE_DEPRECATED = "PC1807"
    
    # Rate Limiting Errors (1900-1999)
    RATE_LIMIT_EXCEEDED = "PC1901"
    RATE_LIMIT_QUOTA_EXCEEDED = "PC1902"
    RATE_LIMIT_BURST_EXCEEDED = "PC1903"
    RATE_LIMIT_DAILY_LIMIT = "PC1904"
    RATE_LIMIT_HOURLY_LIMIT = "PC1905"
    
    # Configuration Errors (2000-2099)
    CONFIG_INVALID = "PC2001"
    CONFIG_MISSING = "PC2002"
    CONFIG_PARSE_ERROR = "PC2003"
    CONFIG_VALIDATION_FAILED = "PC2004"
    CONFIG_ENVIRONMENT_MISMATCH = "PC2005"
    CONFIG_SECRET_MISSING = "PC2006"
    
    # Backup System Errors (2100-2199)
    BACKUP_CREATION_FAILED = "PC2101"
    BACKUP_RESTORATION_FAILED = "PC2102"
    BACKUP_VERIFICATION_FAILED = "PC2103"
    BACKUP_ENCRYPTION_FAILED = "PC2104"
    BACKUP_STORAGE_FULL = "PC2105"
    BACKUP_SHARD_CORRUPTED = "PC2106"
    BACKUP_METADATA_INVALID = "PC2107"
    BACKUP_CLOUD_SYNC_FAILED = "PC2108"
    
    # Logging Errors (2200-2299)
    LOG_WRITE_FAILED = "PC2201"
    LOG_ROTATION_FAILED = "PC2202"
    LOG_DIRECTORY_CREATION_FAILED = "PC2203"
    LOG_PERMISSION_DENIED = "PC2204"
    LOG_FORMAT_INVALID = "PC2205"
    
    # Performance Errors (2300-2399)
    PERF_LATENCY_EXCEEDED = "PC2301"
    PERF_MEMORY_THRESHOLD_EXCEEDED = "PC2302"
    PERF_CPU_THRESHOLD_EXCEEDED = "PC2303"
    PERF_CACHE_MISS_RATE_HIGH = "PC2304"
    PERF_OPTIMIZATION_FAILED = "PC2305"
    
    # WAF Errors (2400-2499)
    WAF_BLOCKED_REQUEST = "PC2401"
    WAF_RULE_VIOLATION = "PC2402"
    WAF_PATTERN_MATCH = "PC2403"
    WAF_REPUTATION_BLOCKED = "PC2404"
    WAF_GEOLOCATION_BLOCKED = "PC2405"


class ErrorCodeMapping:
    """Maps error codes to their properties and HTTP status codes."""
    
    _mappings = {
        # Authentication Errors
        PlexiChatErrorCode.AUTH_INVALID_CREDENTIALS: {
            "category": ErrorCategory.AUTHENTICATION,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.UNAUTHORIZED,
            "message": "Invalid username or password",
            "user_message": "Please check your credentials and try again"
        },
        PlexiChatErrorCode.AUTH_TOKEN_EXPIRED: {
            "category": ErrorCategory.AUTHENTICATION,
            "severity": ErrorSeverity.LOW,
            "http_status": HTTPStatus.UNAUTHORIZED,
            "message": "Authentication token has expired",
            "user_message": "Your session has expired. Please log in again"
        },
        PlexiChatErrorCode.AUTH_TOKEN_INVALID: {
            "category": ErrorCategory.AUTHENTICATION,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.UNAUTHORIZED,
            "message": "Invalid authentication token",
            "user_message": "Authentication failed. Please log in again"
        },
        PlexiChatErrorCode.AUTH_TOKEN_MISSING: {
            "category": ErrorCategory.AUTHENTICATION,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.UNAUTHORIZED,
            "message": "Authentication token is required",
            "user_message": "Please log in to access this resource"
        },
        PlexiChatErrorCode.AUTH_USER_NOT_FOUND: {
            "category": ErrorCategory.AUTHENTICATION,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.UNAUTHORIZED,
            "message": "User account not found",
            "user_message": "Invalid credentials provided"
        },
        PlexiChatErrorCode.AUTH_USER_DISABLED: {
            "category": ErrorCategory.AUTHENTICATION,
            "severity": ErrorSeverity.HIGH,
            "http_status": HTTPStatus.FORBIDDEN,
            "message": "User account is disabled",
            "user_message": "Your account has been disabled. Please contact support"
        },
        PlexiChatErrorCode.AUTH_LOGIN_ATTEMPTS_EXCEEDED: {
            "category": ErrorCategory.AUTHENTICATION,
            "severity": ErrorSeverity.HIGH,
            "http_status": HTTPStatus.TOO_MANY_REQUESTS,
            "message": "Too many login attempts",
            "user_message": "Too many failed login attempts. Please try again later"
        },
        
        # Authorization Errors
        PlexiChatErrorCode.AUTHZ_INSUFFICIENT_PERMISSIONS: {
            "category": ErrorCategory.AUTHORIZATION,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.FORBIDDEN,
            "message": "Insufficient permissions to access resource",
            "user_message": "You don't have permission to access this resource"
        },
        PlexiChatErrorCode.AUTHZ_RESOURCE_FORBIDDEN: {
            "category": ErrorCategory.AUTHORIZATION,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.FORBIDDEN,
            "message": "Access to resource is forbidden",
            "user_message": "Access denied"
        },
        
        # Validation Errors
        PlexiChatErrorCode.VALIDATION_REQUIRED_FIELD: {
            "category": ErrorCategory.VALIDATION,
            "severity": ErrorSeverity.LOW,
            "http_status": HTTPStatus.BAD_REQUEST,
            "message": "Required field is missing",
            "user_message": "Please fill in all required fields"
        },
        PlexiChatErrorCode.VALIDATION_INVALID_FORMAT: {
            "category": ErrorCategory.VALIDATION,
            "severity": ErrorSeverity.LOW,
            "http_status": HTTPStatus.BAD_REQUEST,
            "message": "Invalid data format",
            "user_message": "Please check the format of your input"
        },
        PlexiChatErrorCode.VALIDATION_INVALID_EMAIL: {
            "category": ErrorCategory.VALIDATION,
            "severity": ErrorSeverity.LOW,
            "http_status": HTTPStatus.BAD_REQUEST,
            "message": "Invalid email address format",
            "user_message": "Please enter a valid email address"
        },
        
        # System Errors
        PlexiChatErrorCode.SYSTEM_INTERNAL_ERROR: {
            "category": ErrorCategory.SYSTEM,
            "severity": ErrorSeverity.CRITICAL,
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR,
            "message": "Internal system error occurred",
            "user_message": "An unexpected error occurred. Please try again later"
        },
        PlexiChatErrorCode.SYSTEM_SERVICE_UNAVAILABLE: {
            "category": ErrorCategory.SYSTEM,
            "severity": ErrorSeverity.HIGH,
            "http_status": HTTPStatus.SERVICE_UNAVAILABLE,
            "message": "Service is temporarily unavailable",
            "user_message": "Service is temporarily unavailable. Please try again later"
        },
        PlexiChatErrorCode.SYSTEM_TIMEOUT: {
            "category": ErrorCategory.SYSTEM,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.REQUEST_TIMEOUT,
            "message": "Request timeout",
            "user_message": "Request timed out. Please try again"
        },
        
        # Security Errors
        PlexiChatErrorCode.SECURITY_SUSPICIOUS_ACTIVITY: {
            "category": ErrorCategory.SECURITY,
            "severity": ErrorSeverity.HIGH,
            "http_status": HTTPStatus.FORBIDDEN,
            "message": "Suspicious activity detected",
            "user_message": "Suspicious activity detected. Access temporarily restricted"
        },
        PlexiChatErrorCode.SECURITY_IP_BLOCKED: {
            "category": ErrorCategory.SECURITY,
            "severity": ErrorSeverity.HIGH,
            "http_status": HTTPStatus.FORBIDDEN,
            "message": "IP address is blocked",
            "user_message": "Access denied from your location"
        },
        PlexiChatErrorCode.SECURITY_MALICIOUS_REQUEST: {
            "category": ErrorCategory.SECURITY,
            "severity": ErrorSeverity.CRITICAL,
            "http_status": HTTPStatus.FORBIDDEN,
            "message": "Malicious request detected",
            "user_message": "Request blocked for security reasons"
        },
        
        # Database Errors
        PlexiChatErrorCode.DB_CONNECTION_FAILED: {
            "category": ErrorCategory.DATABASE,
            "severity": ErrorSeverity.CRITICAL,
            "http_status": HTTPStatus.SERVICE_UNAVAILABLE,
            "message": "Database connection failed",
            "user_message": "Service temporarily unavailable. Please try again later"
        },
        PlexiChatErrorCode.DB_RECORD_NOT_FOUND: {
            "category": ErrorCategory.DATABASE,
            "severity": ErrorSeverity.LOW,
            "http_status": HTTPStatus.NOT_FOUND,
            "message": "Requested record not found",
            "user_message": "The requested item was not found"
        },
        
        # Rate Limiting Errors
        PlexiChatErrorCode.RATE_LIMIT_EXCEEDED: {
            "category": ErrorCategory.RATE_LIMITING,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.TOO_MANY_REQUESTS,
            "message": "Rate limit exceeded",
            "user_message": "Too many requests. Please slow down and try again later"
        },
        
        # File System Errors
        PlexiChatErrorCode.FILE_NOT_FOUND: {
            "category": ErrorCategory.FILE_SYSTEM,
            "severity": ErrorSeverity.LOW,
            "http_status": HTTPStatus.NOT_FOUND,
            "message": "File not found",
            "user_message": "The requested file was not found"
        },
        PlexiChatErrorCode.FILE_SIZE_EXCEEDED: {
            "category": ErrorCategory.FILE_SYSTEM,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "message": "File size exceeds maximum allowed",
            "user_message": "File is too large. Please upload a smaller file"
        },
        
        # Backup System Errors
        PlexiChatErrorCode.BACKUP_CREATION_FAILED: {
            "category": ErrorCategory.BACKUP,
            "severity": ErrorSeverity.HIGH,
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR,
            "message": "Backup creation failed",
            "user_message": "Failed to create backup. Please try again"
        },
        
        # WAF Errors
        PlexiChatErrorCode.WAF_BLOCKED_REQUEST: {
            "category": ErrorCategory.WAF,
            "severity": ErrorSeverity.HIGH,
            "http_status": HTTPStatus.FORBIDDEN,
            "message": "Request blocked by Web Application Firewall",
            "user_message": "Request blocked for security reasons"
        }
    }
    
    @classmethod
    def get_mapping(cls, error_code: PlexiChatErrorCode) -> Dict[str, Any]:
        """Get the complete mapping for an error code."""
        return cls._mappings.get(error_code, {
            "category": ErrorCategory.SYSTEM,
            "severity": ErrorSeverity.MEDIUM,
            "http_status": HTTPStatus.INTERNAL_SERVER_ERROR,
            "message": "Unknown error occurred",
            "user_message": "An unexpected error occurred"
        })
    
    @classmethod
    def get_http_status(cls, error_code: PlexiChatErrorCode) -> HTTPStatus:
        """Get HTTP status code for an error."""
        return cls.get_mapping(error_code).get("http_status", HTTPStatus.INTERNAL_SERVER_ERROR)
    
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
        return cls.get_mapping(error_code).get("user_message", "An unexpected error occurred")


class ErrorResponse:
    """Standardized error response structure."""
    
    def __init__(
        self,
        error_code: PlexiChatErrorCode,
        details: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None
    ):
        self.error_code = error_code
        self.details = details or {}
        self.context = context or {}
        self.correlation_id = correlation_id
        self.mapping = ErrorCodeMapping.get_mapping(error_code)
    
    def to_dict(self, include_technical_details: bool = False) -> Dict[str, Any]:
        """Convert error response to dictionary."""
        response = {
            "success": False,
            "error": {
                "code": self.error_code.value,
                "message": self.mapping["user_message"],
                "category": self.mapping["category"].value,
                "severity": self.mapping["severity"].value
            }
        }
        
        if include_technical_details:
            response["error"]["technical_message"] = self.mapping["message"]
            response["error"]["details"] = self.details
            response["error"]["context"] = self.context
        
        if self.correlation_id:
            response["correlation_id"] = self.correlation_id
        
        return response
    
    def get_http_status_code(self) -> int:
        """Get HTTP status code for this error."""
        return self.mapping["http_status"].value


class PlexiChatException(Exception):
    """Base exception class for PlexiChat with error code support."""
    
    def __init__(
        self,
        error_code: PlexiChatErrorCode,
        details: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
        cause: Optional[Exception] = None
    ):
        self.error_code = error_code
        self.details = details or {}
        self.context = context or {}
        self.correlation_id = correlation_id
        self.cause = cause
        
        mapping = ErrorCodeMapping.get_mapping(error_code)
        message = mapping["message"]
        if details:
            message += f" - Details: {details}"
        
        super().__init__(message)
    
    def to_error_response(self, include_technical_details: bool = False) -> ErrorResponse:
        """Convert exception to error response."""
        return ErrorResponse(
            error_code=self.error_code,
            details=self.details,
            context=self.context,
            correlation_id=self.correlation_id
        )
    
    def get_http_status_code(self) -> int:
        """Get HTTP status code for this exception."""
        return ErrorCodeMapping.get_http_status(self.error_code).value


# Helper functions for creating standardized error responses
def create_error_response(
    error_code: PlexiChatErrorCode,
    details: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
    correlation_id: Optional[str] = None,
    include_technical_details: bool = False
) -> Dict[str, Any]:
    """Create a standardized error response dictionary."""
    error_response = ErrorResponse(error_code, details, context, correlation_id)
    return error_response.to_dict(include_technical_details)


def create_validation_error_response(
    field_name: str,
    field_value: Any = None,
    validation_rule: Optional[str] = None,
    correlation_id: Optional[str] = None
) -> Dict[str, Any]:
    """Create a validation error response with field details."""
    details = {"field": field_name}
    if field_value is not None:
        details["value"] = str(field_value)
    if validation_rule:
        details["rule"] = validation_rule
    
    return create_error_response(
        PlexiChatErrorCode.VALIDATION_REQUIRED_FIELD,
        details=details,
        correlation_id=correlation_id
    )


def create_authentication_error_response(
    reason: str = "invalid_credentials",
    correlation_id: Optional[str] = None
) -> Dict[str, Any]:
    """Create an authentication error response."""
    error_code_map = {
        "invalid_credentials": PlexiChatErrorCode.AUTH_INVALID_CREDENTIALS,
        "token_expired": PlexiChatErrorCode.AUTH_TOKEN_EXPIRED,
        "token_invalid": PlexiChatErrorCode.AUTH_TOKEN_INVALID,
        "token_missing": PlexiChatErrorCode.AUTH_TOKEN_MISSING,
        "user_not_found": PlexiChatErrorCode.AUTH_USER_NOT_FOUND,
        "user_disabled": PlexiChatErrorCode.AUTH_USER_DISABLED,
        "too_many_attempts": PlexiChatErrorCode.AUTH_LOGIN_ATTEMPTS_EXCEEDED
    }
    
    error_code = error_code_map.get(reason, PlexiChatErrorCode.AUTH_INVALID_CREDENTIALS)
    return create_error_response(error_code, correlation_id=correlation_id)


def create_authorization_error_response(
    resource: Optional[str] = None,
    required_permission: Optional[str] = None,
    correlation_id: Optional[str] = None
) -> Dict[str, Any]:
    """Create an authorization error response."""
    details = {}
    if resource:
        details["resource"] = resource
    if required_permission:
        details["required_permission"] = required_permission
    
    return create_error_response(
        PlexiChatErrorCode.AUTHZ_INSUFFICIENT_PERMISSIONS,
        details=details,
        correlation_id=correlation_id
    )


def create_system_error_response(
    error_type: str = "internal_error",
    correlation_id: Optional[str] = None
) -> Dict[str, Any]:
    """Create a system error response."""
    error_code_map = {
        "internal_error": PlexiChatErrorCode.SYSTEM_INTERNAL_ERROR,
        "service_unavailable": PlexiChatErrorCode.SYSTEM_SERVICE_UNAVAILABLE,
        "timeout": PlexiChatErrorCode.SYSTEM_TIMEOUT,
        "resource_exhausted": PlexiChatErrorCode.SYSTEM_RESOURCE_EXHAUSTED,
        "maintenance": PlexiChatErrorCode.SYSTEM_MAINTENANCE_MODE
    }
    
    error_code = error_code_map.get(error_type, PlexiChatErrorCode.SYSTEM_INTERNAL_ERROR)
    return create_error_response(error_code, correlation_id=correlation_id)


def get_errors_by_category(category: ErrorCategory) -> List[PlexiChatErrorCode]:
    """Get all error codes for a specific category."""
    return [
        error_code for error_code in PlexiChatErrorCode
        if ErrorCodeMapping.get_category(error_code) == category
    ]


def get_errors_by_severity(severity: ErrorSeverity) -> List[PlexiChatErrorCode]:
    """Get all error codes for a specific severity level."""
    return [
        error_code for error_code in PlexiChatErrorCode
        if ErrorCodeMapping.get_severity(error_code) == severity
    ]


def get_critical_errors() -> List[PlexiChatErrorCode]:
    """Get all critical error codes."""
    return get_errors_by_severity(ErrorSeverity.CRITICAL)


def log_error(
    error_code: PlexiChatErrorCode,
    details: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
    correlation_id: Optional[str] = None,
    exception: Optional[Exception] = None
) -> None:
    """Log an error with standardized format."""
    mapping = ErrorCodeMapping.get_mapping(error_code)
    severity = mapping["severity"]
    
    log_data = {
        "error_code": error_code.value,
        "category": mapping["category"].value,
        "severity": severity.value,
        "message": mapping["message"]
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
    # Enums
    "ErrorCategory",
    "ErrorSeverity", 
    "PlexiChatErrorCode",
    
    # Classes
    "ErrorCodeMapping",
    "ErrorResponse",
    "PlexiChatException",
    
    # Helper functions
    "create_error_response",
    "create_validation_error_response",
    "create_authentication_error_response",
    "create_authorization_error_response",
    "create_system_error_response",
    "get_errors_by_category",
    "get_errors_by_severity",
    "get_critical_errors",
    "log_error"
]
