"""
Custom Exception Classes
Comprehensive exception hierarchy with error codes and detailed information.
"""

from typing import Dict, Any, Optional
from app.core.error_handling.error_codes import ErrorCode, error_code_manager

class BaseAPIException(Exception):
    """Base exception class for all API errors."""
    
    def __init__(self, 
                 error_code: ErrorCode,
                 message: str = None,
                 context: Dict[str, Any] = None,
                 original_exception: Exception = None):
        self.error_code = error_code
        self.context = context or {}
        self.original_exception = original_exception
        
        # Get error details
        error_details = error_code_manager.get_error_details(error_code)
        self.message = message or error_details.message
        self.user_message = error_details.user_message
        self.http_status = error_details.http_status
        self.category = error_details.category
        self.severity = error_details.severity
        
        super().__init__(self.message)
    
    def to_dict(self, include_debug: bool = False) -> Dict[str, Any]:
        """Convert exception to dictionary format."""
        return error_code_manager.format_error_response(
            self.error_code,
            self.context,
            include_debug
        )
    
    def __str__(self) -> str:
        return f"[{self.error_code.value}] {self.message}"

# System Exceptions
class SystemException(BaseAPIException):
    """System-level exceptions."""
    pass

class SystemUnavailableException(SystemException):
    def __init__(self, message: str = None, context: Dict[str, Any] = None):
        super().__init__(ErrorCode.SYSTEM_UNAVAILABLE, message, context)

class SystemTimeoutException(SystemException):
    def __init__(self, message: str = None, context: Dict[str, Any] = None):
        super().__init__(ErrorCode.SYSTEM_TIMEOUT, message, context)

class SystemConfigException(SystemException):
    def __init__(self, message: str = None, context: Dict[str, Any] = None):
        super().__init__(ErrorCode.SYSTEM_CONFIG_ERROR, message, context)

# Authentication Exceptions
class AuthenticationException(BaseAPIException):
    """Authentication-related exceptions."""
    pass

class InvalidCredentialsException(AuthenticationException):
    def __init__(self, message: str = None, context: Dict[str, Any] = None):
        super().__init__(ErrorCode.AUTH_INVALID_CREDENTIALS, message, context)

class TokenExpiredException(AuthenticationException):
    def __init__(self, message: str = None, context: Dict[str, Any] = None):
        super().__init__(ErrorCode.AUTH_TOKEN_EXPIRED, message, context)

class TokenInvalidException(AuthenticationException):
    def __init__(self, message: str = None, context: Dict[str, Any] = None):
        super().__init__(ErrorCode.AUTH_TOKEN_INVALID, message, context)

class TokenMissingException(AuthenticationException):
    def __init__(self, message: str = None, context: Dict[str, Any] = None):
        super().__init__(ErrorCode.AUTH_TOKEN_MISSING, message, context)

class UserNotFoundException(AuthenticationException):
    def __init__(self, message: str = None, context: Dict[str, Any] = None):
        super().__init__(ErrorCode.AUTH_USER_NOT_FOUND, message, context)

class UserDisabledException(AuthenticationException):
    def __init__(self, message: str = None, context: Dict[str, Any] = None):
        super().__init__(ErrorCode.AUTH_USER_DISABLED, message, context)

class TwoFactorRequiredException(AuthenticationException):
    def __init__(self, message: str = None, context: Dict[str, Any] = None):
        super().__init__(ErrorCode.AUTH_2FA_REQUIRED, message, context)

class TwoFactorInvalidException(AuthenticationException):
    def __init__(self, message: str = None, context: Dict[str, Any] = None):
        super().__init__(ErrorCode.AUTH_2FA_INVALID, message, context)

# Authorization Exceptions
class AuthorizationException(BaseAPIException):
    """Authorization-related exceptions."""
    pass

class InsufficientPermissionsException(AuthorizationException):
    def __init__(self, message: str = None, context: Dict[str, Any] = None):
        super().__init__(ErrorCode.AUTHZ_INSUFFICIENT_PERMISSIONS, message, context)

class AccessDeniedException(AuthorizationException):
    def __init__(self, message: str = None, context: Dict[str, Any] = None):
        super().__init__(ErrorCode.AUTHZ_ACCESS_DENIED, message, context)

class AdminRequiredException(AuthorizationException):
    def __init__(self, message: str = None, context: Dict[str, Any] = None):
        super().__init__(ErrorCode.AUTHZ_ADMIN_REQUIRED, message, context)

# Validation Exceptions
class ValidationException(BaseAPIException):
    """Validation-related exceptions."""
    pass

class RequiredFieldException(ValidationException):
    def __init__(self, field_name: str, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context["field"] = field_name
        super().__init__(ErrorCode.VALIDATION_REQUIRED_FIELD, message, context)

class InvalidFormatException(ValidationException):
    def __init__(self, field_name: str, expected_format: str, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context.update({"field": field_name, "expected_format": expected_format})
        super().__init__(ErrorCode.VALIDATION_INVALID_FORMAT, message, context)

class InvalidLengthException(ValidationException):
    def __init__(self, field_name: str, min_length: int = None, max_length: int = None, 
                 message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context.update({
            "field": field_name,
            "min_length": min_length,
            "max_length": max_length
        })
        super().__init__(ErrorCode.VALIDATION_INVALID_LENGTH, message, context)

class DuplicateValueException(ValidationException):
    def __init__(self, field_name: str, value: str, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context.update({"field": field_name, "value": value})
        super().__init__(ErrorCode.VALIDATION_DUPLICATE_VALUE, message, context)

# Database Exceptions
class DatabaseException(BaseAPIException):
    """Database-related exceptions."""
    pass

class DatabaseConnectionException(DatabaseException):
    def __init__(self, message: str = None, context: Dict[str, Any] = None):
        super().__init__(ErrorCode.DB_CONNECTION_ERROR, message, context)

class DatabaseQueryException(DatabaseException):
    def __init__(self, query: str = None, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        if query:
            context["query"] = query
        super().__init__(ErrorCode.DB_QUERY_ERROR, message, context)

class RecordNotFoundException(DatabaseException):
    def __init__(self, table: str = None, record_id: Any = None, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        if table:
            context["table"] = table
        if record_id:
            context["record_id"] = str(record_id)
        super().__init__(ErrorCode.DB_RECORD_NOT_FOUND, message, context)

class DuplicateRecordException(DatabaseException):
    def __init__(self, table: str = None, field: str = None, value: str = None, 
                 message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context.update({
            "table": table,
            "field": field,
            "value": value
        })
        super().__init__(ErrorCode.DB_DUPLICATE_RECORD, message, context)

# API Exceptions
class APIException(BaseAPIException):
    """API-related exceptions."""
    pass

class InvalidRequestException(APIException):
    def __init__(self, message: str = None, context: Dict[str, Any] = None):
        super().__init__(ErrorCode.API_INVALID_REQUEST, message, context)

class InvalidEndpointException(APIException):
    def __init__(self, endpoint: str, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context["endpoint"] = endpoint
        super().__init__(ErrorCode.API_INVALID_ENDPOINT, message, context)

class MethodNotAllowedException(APIException):
    def __init__(self, method: str, allowed_methods: list, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context.update({"method": method, "allowed_methods": allowed_methods})
        super().__init__(ErrorCode.API_METHOD_NOT_ALLOWED, message, context)

class RateLimitExceededException(APIException):
    def __init__(self, limit: int, window: int, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context.update({"limit": limit, "window": window})
        super().__init__(ErrorCode.API_RATE_LIMIT_EXCEEDED, message, context)

class RequestTooLargeException(APIException):
    def __init__(self, size: int, max_size: int, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context.update({"size": size, "max_size": max_size})
        super().__init__(ErrorCode.API_REQUEST_TOO_LARGE, message, context)

# File Exceptions
class FileException(BaseAPIException):
    """File-related exceptions."""
    pass

class FileNotFoundException(FileException):
    def __init__(self, filename: str, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context["filename"] = filename
        super().__init__(ErrorCode.FILE_NOT_FOUND, message, context)

class FileTooLargeException(FileException):
    def __init__(self, size: int, max_size: int, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context.update({"size": size, "max_size": max_size})
        super().__init__(ErrorCode.FILE_TOO_LARGE, message, context)

class InvalidFileTypeException(FileException):
    def __init__(self, file_type: str, allowed_types: list, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context.update({"file_type": file_type, "allowed_types": allowed_types})
        super().__init__(ErrorCode.FILE_INVALID_TYPE, message, context)

class FileUploadFailedException(FileException):
    def __init__(self, filename: str, reason: str = None, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context.update({"filename": filename, "reason": reason})
        super().__init__(ErrorCode.FILE_UPLOAD_FAILED, message, context)

# Message Exceptions
class MessageException(BaseAPIException):
    """Message-related exceptions."""
    pass

class MessageNotFoundException(MessageException):
    def __init__(self, message_id: int, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context["message_id"] = message_id
        super().__init__(ErrorCode.MSG_NOT_FOUND, message, context)

class MessageTooLongException(MessageException):
    def __init__(self, length: int, max_length: int, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context.update({"length": length, "max_length": max_length})
        super().__init__(ErrorCode.MSG_TOO_LONG, message, context)

class ChannelNotFoundException(MessageException):
    def __init__(self, channel_id: int, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context["channel_id"] = channel_id
        super().__init__(ErrorCode.MSG_CHANNEL_NOT_FOUND, message, context)

# User Exceptions
class UserException(BaseAPIException):
    """User-related exceptions."""
    pass

class UserAlreadyExistsException(UserException):
    def __init__(self, username: str = None, email: str = None, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        if username:
            context["username"] = username
        if email:
            context["email"] = email
        super().__init__(ErrorCode.USER_ALREADY_EXISTS, message, context)

class EmailAlreadyExistsException(UserException):
    def __init__(self, email: str, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context["email"] = email
        super().__init__(ErrorCode.USER_EMAIL_EXISTS, message, context)

class UsernameAlreadyExistsException(UserException):
    def __init__(self, username: str, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context["username"] = username
        super().__init__(ErrorCode.USER_USERNAME_EXISTS, message, context)

# Network Exceptions
class NetworkException(BaseAPIException):
    """Network-related exceptions."""
    pass

class ConnectionFailedException(NetworkException):
    def __init__(self, host: str, port: int = None, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context.update({"host": host, "port": port})
        super().__init__(ErrorCode.NET_CONNECTION_FAILED, message, context)

class NetworkTimeoutException(NetworkException):
    def __init__(self, timeout: float, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context["timeout"] = timeout
        super().__init__(ErrorCode.NET_TIMEOUT, message, context)

# Backup Exceptions
class BackupException(BaseAPIException):
    """Backup-related exceptions."""
    pass

class BackupCreationFailedException(BackupException):
    def __init__(self, reason: str = None, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        if reason:
            context["reason"] = reason
        super().__init__(ErrorCode.BACKUP_CREATION_FAILED, message, context)

class BackupNotFoundException(BackupException):
    def __init__(self, backup_id: str, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context["backup_id"] = backup_id
        super().__init__(ErrorCode.BACKUP_NOT_FOUND, message, context)

class BackupCorruptedException(BackupException):
    def __init__(self, backup_id: str, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context["backup_id"] = backup_id
        super().__init__(ErrorCode.BACKUP_CORRUPTED, message, context)

# WebSocket Exceptions
class WebSocketException(BaseAPIException):
    """WebSocket-related exceptions."""
    pass

class WebSocketConnectionFailedException(WebSocketException):
    def __init__(self, reason: str = None, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        if reason:
            context["reason"] = reason
        super().__init__(ErrorCode.WS_CONNECTION_FAILED, message, context)

class WebSocketMessageTooLargeException(WebSocketException):
    def __init__(self, size: int, max_size: int, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context.update({"size": size, "max_size": max_size})
        super().__init__(ErrorCode.WS_MESSAGE_TOO_LARGE, message, context)

# Testing Exceptions
class TestingException(BaseAPIException):
    """Testing-related exceptions."""
    pass

class TestSetupFailedException(TestingException):
    def __init__(self, test_name: str, reason: str = None, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context.update({"test_name": test_name, "reason": reason})
        super().__init__(ErrorCode.TEST_SETUP_FAILED, message, context)

class TestExecutionFailedException(TestingException):
    def __init__(self, test_name: str, reason: str = None, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context.update({"test_name": test_name, "reason": reason})
        super().__init__(ErrorCode.TEST_EXECUTION_FAILED, message, context)

class TestTimeoutException(TestingException):
    def __init__(self, test_name: str, timeout: float, message: str = None, context: Dict[str, Any] = None):
        context = context or {}
        context.update({"test_name": test_name, "timeout": timeout})
        super().__init__(ErrorCode.TEST_TIMEOUT, message, context)
