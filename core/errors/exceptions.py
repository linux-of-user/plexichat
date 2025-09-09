"""Specific exception classes inheriting from base."""
from typing import Optional, Dict, Any
from .base import ErrorSeverity, ErrorCategory, create_error_response, handle_exception, PlexiChatException, PlexiChatErrorCode

class BaseAPIException(PlexiChatException):
    """Base API exception inheriting from PlexiChatException."""
    def __init__(self, code: str = PlexiChatErrorCode.SYSTEM_INTERNAL_ERROR.value, details: Optional[Dict[str, Any]] = None):
        super().__init__(code, details=details)
        self.severity = ErrorSeverity.HIGH  # Using base enum
        self.category = ErrorCategory.SYSTEM  # Using base enum

class AuthenticationError(BaseAPIException):
    """Authentication specific error."""
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(PlexiChatErrorCode.AUTH_INVALID_CREDENTIALS.value, details=details)
        self.category = ErrorCategory.AUTHENTICATION

class ValidationError(BaseAPIException):
    """Validation specific error."""
    def __init__(self, field: str, value: Any, reason: str, details: Optional[Dict[str, Any]] = None):
        base_details = {field: {"value": value, "reason": reason}}
        if details:
            base_details.update(details)
        super().__init__(PlexiChatErrorCode.VALIDATION_ERROR.value, details=base_details)
        self.category = ErrorCategory.VALIDATION

# Additional specific exceptions (e.g., DatabaseError, NetworkError, etc.)
class DatabaseError(BaseAPIException):
    """Database specific error."""
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(PlexiChatErrorCode.DATABASE_CONNECTION_FAILED.value, details=details)
        self.category = ErrorCategory.DATABASE

# Removed duplicated ErrorSeverity, ErrorCategory enums; removed local create_error_response, handle_exception
# Updated to_dict to match base ErrorResponse.to_dict (via inheritance)
# Preserve details handling in constructors
# Expected reduction: ~100 lines