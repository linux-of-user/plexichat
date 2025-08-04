"""
PlexiChat Core Exceptions
Essential exception classes for the entire application.
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class ErrorSeverity:
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory:
    """Error categories."""
    SYSTEM = "system"
    USER = "user"
    NETWORK = "network"
    DATABASE = "database"
    AUTH = "auth"
    VALIDATION = "validation"
    FILE = "file"
    EXTERNAL = "external"


class BaseAPIException(Exception):
    """Base exception for all API errors."""
    
    def __init__(self, message: str, code: str = None, details: Dict[str, Any] = None):
        super().__init__(message)
        self.message = message
        self.code = code or self.__class__.__name__
        self.details = details or {}
        self.timestamp = datetime.now()
        self.severity = ErrorSeverity.MEDIUM
        self.category = ErrorCategory.SYSTEM
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary."""
        return {}}
            "error": self.code,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "category": self.category
        }


class AuthenticationError(BaseAPIException):
    """Authentication failed."""
    
    def __init__(self, message: str = "Authentication failed", **kwargs):
        super().__init__(message, **kwargs)
        self.severity = ErrorSeverity.HIGH
        self.category = ErrorCategory.AUTH


class AuthorizationError(BaseAPIException):
    """Authorization failed."""
    
    def __init__(self, message: str = "Access denied", **kwargs):
        super().__init__(message, **kwargs)
        self.severity = ErrorSeverity.HIGH
        self.category = ErrorCategory.AUTH


class ValidationError(BaseAPIException):
    """Data validation failed."""
    
    def __init__(self, message: str = "Validation failed", field: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.field = field
        self.severity = ErrorSeverity.MEDIUM
        self.category = ErrorCategory.VALIDATION
        if field:
            self.details["field"] = field


class DatabaseError(BaseAPIException):
    """Database operation failed."""
    
    def __init__(self, message: str = "Database error", **kwargs):
        super().__init__(message, **kwargs)
        self.severity = ErrorSeverity.HIGH
        self.category = ErrorCategory.DATABASE


class NetworkError(BaseAPIException):
    """Network operation failed."""
    
    def __init__(self, message: str = "Network error", **kwargs):
        super().__init__(message, **kwargs)
        self.severity = ErrorSeverity.MEDIUM
        self.category = ErrorCategory.NETWORK


class FileError(BaseAPIException):
    """File operation failed."""
    
    def __init__(self, message: str = "File error", **kwargs):
        super().__init__(message, **kwargs)
        self.severity = ErrorSeverity.MEDIUM
        self.category = ErrorCategory.FILE


class ExternalServiceError(BaseAPIException):
    """External service error."""
    
    def __init__(self, message: str = "External service error", service: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.service = service
        self.severity = ErrorSeverity.MEDIUM
        self.category = ErrorCategory.EXTERNAL
        if service:
            self.details["service"] = service


class RateLimitError(BaseAPIException):
    """Rate limit exceeded."""
    
    def __init__(self, message: str = "Rate limit exceeded", limit: int = None, **kwargs):
        super().__init__(message, **kwargs)
        self.limit = limit
        self.severity = ErrorSeverity.MEDIUM
        self.category = ErrorCategory.SYSTEM
        if limit:
            self.details["limit"] = limit


class ConfigurationError(BaseAPIException):
    """Configuration error."""
    
    def __init__(self, message: str = "Configuration error", **kwargs):
        super().__init__(message, **kwargs)
        self.severity = ErrorSeverity.HIGH
        self.category = ErrorCategory.SYSTEM


class ProcessLockError(BaseAPIException):
    """Process lock error."""
    
    def __init__(self, message: str = "Process lock error", **kwargs):
        super().__init__(message, **kwargs)
        self.severity = ErrorSeverity.HIGH
        self.category = ErrorCategory.SYSTEM


class StartupError(BaseAPIException):
    """Startup error."""
    
    def __init__(self, message: str = "Startup error", **kwargs):
        super().__init__(message, **kwargs)
        self.severity = ErrorSeverity.CRITICAL
        self.category = ErrorCategory.SYSTEM


# Exception handling utilities
def handle_exception(exc: Exception, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Handle any exception and return error info."""
    try:
        if isinstance(exc, BaseAPIException):
            error_info = exc.to_dict()
        else:
            error_info = {
                "error": type(exc).__name__,
                "message": str(exc),
                "timestamp": datetime.now().isoformat(),
                "severity": ErrorSeverity.MEDIUM,
                "category": ErrorCategory.SYSTEM
            }
        
        if context:
            error_info["context"] = context
        
        logger.error(f"Exception handled: {error_info}")
        return error_info
        
    except Exception as e:
        logger.error(f"Error in exception handler: {e}")
        return {}}
            "error": "ExceptionHandlerError",
            "message": "Failed to handle exception",
            "timestamp": datetime.now().isoformat()
        }


def create_error_response(exc: Exception, status_code: int = 500) -> Dict[str, Any]:
    """Create a standardized error response."""
    error_info = handle_exception(exc)
    return {}}
        "success": False,
        "error": error_info,
        "status_code": status_code,
        "timestamp": datetime.now().isoformat()
    }


# Export all exception classes
__all__ = [
    "ErrorSeverity", "ErrorCategory", "BaseAPIException",
    "AuthenticationError", "AuthorizationError", "ValidationError",
    "DatabaseError", "NetworkError", "FileError", "ExternalServiceError",
    "RateLimitError", "ConfigurationError", "ProcessLockError", "StartupError",
    "handle_exception", "create_error_response"
]
