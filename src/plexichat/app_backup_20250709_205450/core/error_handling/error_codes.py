"""
Comprehensive Error Code System
Standardized error codes for all application errors with detailed descriptions.
"""

from enum import Enum
from typing import Dict, Any, Optional
from dataclasses import dataclass

class ErrorCode(Enum):
    """Standardized error codes for the application."""
    
    # General System Errors (1000-1999)
    SYSTEM_ERROR = "SYS_1000"
    SYSTEM_UNAVAILABLE = "SYS_1001"
    SYSTEM_MAINTENANCE = "SYS_1002"
    SYSTEM_OVERLOAD = "SYS_1003"
    SYSTEM_TIMEOUT = "SYS_1004"
    SYSTEM_CONFIG_ERROR = "SYS_1005"
    
    # Authentication Errors (2000-2999)
    AUTH_INVALID_CREDENTIALS = "AUTH_2000"
    AUTH_TOKEN_EXPIRED = "AUTH_2001"
    AUTH_TOKEN_INVALID = "AUTH_2002"
    AUTH_TOKEN_MISSING = "AUTH_2003"
    AUTH_USER_NOT_FOUND = "AUTH_2004"
    AUTH_USER_DISABLED = "AUTH_2005"
    AUTH_PASSWORD_INCORRECT = "AUTH_2006"
    AUTH_ACCOUNT_LOCKED = "AUTH_2007"
    AUTH_2FA_REQUIRED = "AUTH_2008"
    AUTH_2FA_INVALID = "AUTH_2009"
    AUTH_OAUTH_ERROR = "AUTH_2010"
    AUTH_SESSION_EXPIRED = "AUTH_2011"
    
    # Authorization Errors (3000-3999)
    AUTHZ_INSUFFICIENT_PERMISSIONS = "AUTHZ_3000"
    AUTHZ_ACCESS_DENIED = "AUTHZ_3001"
    AUTHZ_ADMIN_REQUIRED = "AUTHZ_3002"
    AUTHZ_RESOURCE_FORBIDDEN = "AUTHZ_3003"
    AUTHZ_ROLE_REQUIRED = "AUTHZ_3004"
    
    # Validation Errors (4000-4999)
    VALIDATION_REQUIRED_FIELD = "VAL_4000"
    VALIDATION_INVALID_FORMAT = "VAL_4001"
    VALIDATION_INVALID_LENGTH = "VAL_4002"
    VALIDATION_INVALID_TYPE = "VAL_4003"
    VALIDATION_INVALID_VALUE = "VAL_4004"
    VALIDATION_DUPLICATE_VALUE = "VAL_4005"
    VALIDATION_CONSTRAINT_VIOLATION = "VAL_4006"
    VALIDATION_INVALID_EMAIL = "VAL_4007"
    VALIDATION_INVALID_PASSWORD = "VAL_4008"
    VALIDATION_INVALID_USERNAME = "VAL_4009"
    
    # Database Errors (5000-5999)
    DB_CONNECTION_ERROR = "DB_5000"
    DB_QUERY_ERROR = "DB_5001"
    DB_CONSTRAINT_VIOLATION = "DB_5002"
    DB_RECORD_NOT_FOUND = "DB_5003"
    DB_DUPLICATE_RECORD = "DB_5004"
    DB_TRANSACTION_ERROR = "DB_5005"
    DB_MIGRATION_ERROR = "DB_5006"
    DB_TIMEOUT = "DB_5007"
    DB_LOCK_ERROR = "DB_5008"
    
    # API Errors (6000-6999)
    API_INVALID_REQUEST = "API_6000"
    API_INVALID_ENDPOINT = "API_6001"
    API_METHOD_NOT_ALLOWED = "API_6002"
    API_RATE_LIMIT_EXCEEDED = "API_6003"
    API_REQUEST_TOO_LARGE = "API_6004"
    API_INVALID_CONTENT_TYPE = "API_6005"
    API_MALFORMED_JSON = "API_6006"
    API_MISSING_PARAMETER = "API_6007"
    API_INVALID_PARAMETER = "API_6008"
    API_VERSION_NOT_SUPPORTED = "API_6009"
    
    # File Errors (7000-7999)
    FILE_NOT_FOUND = "FILE_7000"
    FILE_TOO_LARGE = "FILE_7001"
    FILE_INVALID_TYPE = "FILE_7002"
    FILE_UPLOAD_FAILED = "FILE_7003"
    FILE_DOWNLOAD_FAILED = "FILE_7004"
    FILE_PERMISSION_DENIED = "FILE_7005"
    FILE_VIRUS_DETECTED = "FILE_7006"
    FILE_CORRUPTED = "FILE_7007"
    FILE_STORAGE_FULL = "FILE_7008"
    
    # Message Errors (8000-8999)
    MSG_NOT_FOUND = "MSG_8000"
    MSG_TOO_LONG = "MSG_8001"
    MSG_EMPTY = "MSG_8002"
    MSG_INVALID_CONTENT = "MSG_8003"
    MSG_CHANNEL_NOT_FOUND = "MSG_8004"
    MSG_PERMISSION_DENIED = "MSG_8005"
    MSG_EDIT_TIME_EXPIRED = "MSG_8006"
    MSG_ALREADY_DELETED = "MSG_8007"
    
    # User Errors (9000-9999)
    USER_NOT_FOUND = "USER_9000"
    USER_ALREADY_EXISTS = "USER_9001"
    USER_EMAIL_EXISTS = "USER_9002"
    USER_USERNAME_EXISTS = "USER_9003"
    USER_PROFILE_INCOMPLETE = "USER_9004"
    USER_ACCOUNT_SUSPENDED = "USER_9005"
    USER_EMAIL_NOT_VERIFIED = "USER_9006"
    USER_PASSWORD_RESET_REQUIRED = "USER_9007"
    
    # Network Errors (10000-10999)
    NET_CONNECTION_FAILED = "NET_10000"
    NET_TIMEOUT = "NET_10001"
    NET_DNS_ERROR = "NET_10002"
    NET_SSL_ERROR = "NET_10003"
    NET_PROXY_ERROR = "NET_10004"
    NET_FIREWALL_BLOCKED = "NET_10005"
    
    # External Service Errors (11000-11999)
    EXT_SERVICE_UNAVAILABLE = "EXT_11000"
    EXT_SERVICE_TIMEOUT = "EXT_11001"
    EXT_SERVICE_ERROR = "EXT_11002"
    EXT_API_QUOTA_EXCEEDED = "EXT_11003"
    EXT_API_KEY_INVALID = "EXT_11004"
    
    # Backup Errors (12000-12999)
    BACKUP_CREATION_FAILED = "BACKUP_12000"
    BACKUP_NOT_FOUND = "BACKUP_12001"
    BACKUP_CORRUPTED = "BACKUP_12002"
    BACKUP_RESTORE_FAILED = "BACKUP_12003"
    BACKUP_SHARD_NOT_FOUND = "BACKUP_12004"
    BACKUP_ENCRYPTION_FAILED = "BACKUP_12005"
    BACKUP_DECRYPTION_FAILED = "BACKUP_12006"
    BACKUP_STORAGE_FULL = "BACKUP_12007"
    
    # WebSocket Errors (13000-13999)
    WS_CONNECTION_FAILED = "WS_13000"
    WS_CONNECTION_CLOSED = "WS_13001"
    WS_INVALID_MESSAGE = "WS_13002"
    WS_MESSAGE_TOO_LARGE = "WS_13003"
    WS_RATE_LIMITED = "WS_13004"
    
    # Testing Errors (14000-14999)
    TEST_SETUP_FAILED = "TEST_14000"
    TEST_EXECUTION_FAILED = "TEST_14001"
    TEST_ASSERTION_FAILED = "TEST_14002"
    TEST_TIMEOUT = "TEST_14003"
    TEST_ENVIRONMENT_ERROR = "TEST_14004"

@dataclass
class ErrorDetails:
    """Detailed error information."""
    code: ErrorCode
    message: str
    description: str
    http_status: int
    category: str
    severity: str
    user_message: str
    resolution_steps: list
    documentation_url: Optional[str] = None

class ErrorCodeManager:
    """Manages error codes and their details."""
    
    def __init__(self):
        self.error_details: Dict[ErrorCode, ErrorDetails] = {}
        self._initialize_error_details()
    
    def _initialize_error_details(self):
        """Initialize error details for all error codes."""
        
        # System Errors
        self.error_details[ErrorCode.SYSTEM_ERROR] = ErrorDetails(
            code=ErrorCode.SYSTEM_ERROR,
            message="Internal system error occurred",
            description="An unexpected error occurred in the system",
            http_status=500,
            category="system",
            severity="high",
            user_message="We're experiencing technical difficulties. Please try again later.",
            resolution_steps=[
                "Check system logs for details",
                "Verify system resources",
                "Contact system administrator if issue persists"
            ]
        )
        
        self.error_details[ErrorCode.SYSTEM_UNAVAILABLE] = ErrorDetails(
            code=ErrorCode.SYSTEM_UNAVAILABLE,
            message="System is currently unavailable",
            description="The system is temporarily unavailable for maintenance or due to high load",
            http_status=503,
            category="system",
            severity="high",
            user_message="The service is temporarily unavailable. Please try again in a few minutes.",
            resolution_steps=[
                "Wait a few minutes and try again",
                "Check system status page",
                "Contact support if issue persists"
            ]
        )
        
        # Authentication Errors
        self.error_details[ErrorCode.AUTH_INVALID_CREDENTIALS] = ErrorDetails(
            code=ErrorCode.AUTH_INVALID_CREDENTIALS,
            message="Invalid username or password",
            description="The provided credentials are incorrect",
            http_status=401,
            category="authentication",
            severity="medium",
            user_message="Invalid username or password. Please check your credentials and try again.",
            resolution_steps=[
                "Verify username and password",
                "Check for caps lock",
                "Use password reset if needed"
            ]
        )
        
        self.error_details[ErrorCode.AUTH_TOKEN_EXPIRED] = ErrorDetails(
            code=ErrorCode.AUTH_TOKEN_EXPIRED,
            message="Authentication token has expired",
            description="The authentication token is no longer valid",
            http_status=401,
            category="authentication",
            severity="low",
            user_message="Your session has expired. Please log in again.",
            resolution_steps=[
                "Log in again to get a new token",
                "Enable automatic token refresh if available"
            ]
        )
        
        # Validation Errors
        self.error_details[ErrorCode.VALIDATION_REQUIRED_FIELD] = ErrorDetails(
            code=ErrorCode.VALIDATION_REQUIRED_FIELD,
            message="Required field is missing",
            description="A required field was not provided in the request",
            http_status=422,
            category="validation",
            severity="low",
            user_message="Please fill in all required fields.",
            resolution_steps=[
                "Check which fields are required",
                "Provide values for all required fields",
                "Verify field names are correct"
            ]
        )
        
        # Database Errors
        self.error_details[ErrorCode.DB_CONNECTION_ERROR] = ErrorDetails(
            code=ErrorCode.DB_CONNECTION_ERROR,
            message="Database connection failed",
            description="Unable to establish connection to the database",
            http_status=503,
            category="database",
            severity="critical",
            user_message="We're experiencing database connectivity issues. Please try again later.",
            resolution_steps=[
                "Check database server status",
                "Verify connection parameters",
                "Check network connectivity",
                "Contact database administrator"
            ]
        )
        
        # API Errors
        self.error_details[ErrorCode.API_RATE_LIMIT_EXCEEDED] = ErrorDetails(
            code=ErrorCode.API_RATE_LIMIT_EXCEEDED,
            message="Rate limit exceeded",
            description="Too many requests have been made in a short period",
            http_status=429,
            category="api",
            severity="medium",
            user_message="You're making requests too quickly. Please slow down and try again.",
            resolution_steps=[
                "Wait before making another request",
                "Implement exponential backoff",
                "Check rate limit headers",
                "Consider upgrading your plan"
            ]
        )
        
        # File Errors
        self.error_details[ErrorCode.FILE_TOO_LARGE] = ErrorDetails(
            code=ErrorCode.FILE_TOO_LARGE,
            message="File size exceeds maximum allowed",
            description="The uploaded file is larger than the maximum allowed size",
            http_status=413,
            category="file",
            severity="medium",
            user_message="The file you're trying to upload is too large. Please choose a smaller file.",
            resolution_steps=[
                "Compress the file",
                "Choose a smaller file",
                "Check maximum file size limits",
                "Contact support for larger file limits"
            ]
        )
        
        # Add more error details as needed...
        
    def get_error_details(self, error_code: ErrorCode) -> ErrorDetails:
        """Get detailed information about an error code."""
        return self.error_details.get(error_code, self._get_default_error_details(error_code))
    
    def _get_default_error_details(self, error_code: ErrorCode) -> ErrorDetails:
        """Get default error details for unknown error codes."""
        return ErrorDetails(
            code=error_code,
            message="An error occurred",
            description="An unspecified error occurred",
            http_status=500,
            category="unknown",
            severity="medium",
            user_message="An unexpected error occurred. Please try again.",
            resolution_steps=["Try again", "Contact support if issue persists"]
        )
    
    def format_error_response(self, error_code: ErrorCode, 
                            context: Dict[str, Any] = None,
                            include_debug: bool = False) -> Dict[str, Any]:
        """Format error response for API."""
        details = self.get_error_details(error_code)
        
        response = {
            "success": False,
            "error": {
                "code": details.code.value,
                "message": details.message,
                "user_message": details.user_message,
                "category": details.category,
                "severity": details.severity,
                "timestamp": __import__('datetime').datetime.utcnow().isoformat()
            }
        }
        
        if context:
            response["error"]["context"] = context
        
        if include_debug:
            response["error"]["debug"] = {
                "description": details.description,
                "resolution_steps": details.resolution_steps,
                "documentation_url": details.documentation_url
            }
        
        return response
    
    def get_http_status(self, error_code: ErrorCode) -> int:
        """Get HTTP status code for an error."""
        details = self.get_error_details(error_code)
        return details.http_status
    
    def get_error_categories(self) -> Dict[str, list]:
        """Get errors grouped by category."""
        categories = {}
        for error_code, details in self.error_details.items():
            category = details.category
            if category not in categories:
                categories[category] = []
            categories[category].append({
                "code": error_code.value,
                "message": details.message,
                "severity": details.severity
            })
        return categories

# Global error code manager
error_code_manager = ErrorCodeManager()
