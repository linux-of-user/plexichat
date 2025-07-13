import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

"""
PlexiChat Error Handling Exceptions

Unified exception classes and error codes for the PlexiChat error handling system.
Consolidates all error types into a single, comprehensive module.
"""

class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    EMERGENCY = "EMERGENCY"


class ErrorCategory(Enum):
    """Error categories for classification."""
    SYSTEM = "system"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    DATABASE = "database"
    NETWORK = "network"
    EXTERNAL_SERVICE = "external_service"
    FILE_OPERATION = "file_operation"
    RATE_LIMITING = "rate_limiting"
    BUSINESS_LOGIC = "business_logic"
    UNKNOWN = "unknown"


class ErrorCode:
    """Error code management."""
    
    def __init__(self, code: str, message: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 category: ErrorCategory = ErrorCategory.UNKNOWN):
        self.code = code
        self.message = message
        self.severity = severity
        self.category = category
        self.timestamp = from datetime import datetime
datetime.now()
    
    def __str__(self):
        return f"{self.code}: {self.message}"


class ErrorDetails:
    """Detailed error information."""
    
    def __init__(self, error_code: ErrorCode, context: Dict[str, Any] = None,
                 stack_trace: str = None, user_id: str = None):
        self.error_id = str(uuid.uuid4())
        self.error_code = error_code
        self.context = context or {}
        self.stack_trace = stack_trace
        self.user_id = user_id
        self.timestamp = from datetime import datetime
datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'error_id': self.error_id,
            'code': self.error_code.code,
            'message': self.error_code.message,
            'severity': self.error_code.severity.value,
            'category': self.error_code.category.value,
            'context': self.context,
            'stack_trace': self.stack_trace,
            'user_id': self.user_id,
            'timestamp': self.timestamp.isoformat()
        }


# Base Exception Classes
class BaseAPIException(Exception):
    """Base exception for all API-related errors."""
    
    def __init__(self, message: str, error_code: str = None, 
                 details: Dict[str, Any] = None, status_code: int = 500):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "API_ERROR"
        self.details = details or {}
        self.status_code = status_code
        self.timestamp = from datetime import datetime
datetime.now()


class ValidationError(BaseAPIException):
    """Raised when data validation fails."""
    
    def __init__(self, message: str = "Validation failed", 
                 field: str = None, value: Any = None,
                 error_code: str = "VALIDATION_ERROR", status_code: int = 400):
        super().__init__(message, error_code, status_code=status_code)
        self.field = field
        self.value = value


class AuthenticationError(BaseAPIException):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication failed",
                 error_code: str = "AUTH_FAILED", status_code: int = 401):
        super().__init__(message, error_code, status_code=status_code)


class AuthorizationError(BaseAPIException):
    """Raised when authorization fails."""
    
    def __init__(self, message: str = "Authorization failed",
                 required_permission: str = None,
                 error_code: str = "AUTHZ_FAILED", status_code: int = 403):
        super().__init__(message, error_code, status_code=status_code)
        self.required_permission = required_permission


class DatabaseError(BaseAPIException):
    """Raised when database operations fail."""
    
    def __init__(self, message: str = "Database operation failed",
                 operation: str = None, table: str = None,
                 error_code: str = "DB_ERROR", status_code: int = 500):
        super().__init__(message, error_code, status_code=status_code)
        self.operation = operation
        self.table = table


class NetworkError(BaseAPIException):
    """Raised when network operations fail."""
    
    def __init__(self, message: str = "Network operation failed",
                 url: str = None, timeout: bool = False,
                 error_code: str = "NETWORK_ERROR", status_code: int = 503):
        super().__init__(message, error_code, status_code=status_code)
        self.url = url
        self.timeout = timeout


class ExternalServiceError(BaseAPIException):
    """Raised when external service calls fail."""
    
    def __init__(self, message: str = "External service error",
                 service_name: str = None, service_status: int = None,
                 error_code: str = "EXTERNAL_SERVICE_ERROR", status_code: int = 502):
        super().__init__(message, error_code, status_code=status_code)
        self.service_name = service_name
        self.service_status = service_status


class FileError(BaseAPIException):
    """Raised when file operations fail."""
    
    def __init__(self, message: str = "File operation failed",
                 file_path: str = None, operation: str = None,
                 error_code: str = "FILE_ERROR", status_code: int = 500):
        super().__init__(message, error_code, status_code=status_code)
        self.file_path = file_path
        self.operation = operation


class RateLimitError(BaseAPIException):
    """Raised when rate limits are exceeded."""
    
    def __init__(self, message: str = "Rate limit exceeded",
                 limit: int = None, window: int = None,
                 error_code: str = "RATE_LIMIT_ERROR", status_code: int = 429):
        super().__init__(message, error_code, status_code=status_code)
        self.limit = limit
        self.window = window


# Error Code Manager
class ErrorCodeManager:
    """Manages error codes and their details."""
    
    def __init__(self):
        self.error_codes: Dict[str, ErrorCode] = {}
        self._load_default_error_codes()
    
    def _load_default_error_codes(self):
        """Load default error codes."""
        default_codes = [
            ErrorCode("API_ERROR", "General API error", ErrorSeverity.MEDIUM, ErrorCategory.SYSTEM),
            ErrorCode("VALIDATION_ERROR", "Data validation failed", ErrorSeverity.LOW, ErrorCategory.VALIDATION),
            ErrorCode("AUTH_FAILED", "Authentication failed", ErrorSeverity.HIGH, ErrorCategory.AUTHENTICATION),
            ErrorCode("AUTHZ_FAILED", "Authorization failed", ErrorSeverity.HIGH, ErrorCategory.AUTHORIZATION),
            ErrorCode("DB_ERROR", "Database operation failed", ErrorSeverity.HIGH, ErrorCategory.DATABASE),
            ErrorCode("NETWORK_ERROR", "Network operation failed", ErrorSeverity.MEDIUM, ErrorCategory.NETWORK),
            ErrorCode("EXTERNAL_SERVICE_ERROR", "External service error", ErrorSeverity.MEDIUM, ErrorCategory.EXTERNAL_SERVICE),
            ErrorCode("FILE_ERROR", "File operation failed", ErrorSeverity.MEDIUM, ErrorCategory.FILE_OPERATION),
            ErrorCode("RATE_LIMIT_ERROR", "Rate limit exceeded", ErrorSeverity.LOW, ErrorCategory.RATE_LIMITING),
        ]
        
        for code in default_codes:
            self.error_codes[code.code] = code
    
    def get_error_code(self, code: str) -> Optional[ErrorCode]:
        """Get error code by code string."""
        return self.error_codes.get(code)
    
    def register_error_code(self, error_code: ErrorCode):
        """Register a new error code."""
        self.error_codes[error_code.code] = error_code
    
    def get_all_codes(self) -> List[ErrorCode]:
        """Get all registered error codes."""
        return list(self.error_codes.values())


# Global error code manager instance
error_code_manager = ErrorCodeManager()
