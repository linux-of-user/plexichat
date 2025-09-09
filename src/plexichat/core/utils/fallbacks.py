"""
PlexiChat Core Fallbacks
Centralized fallback implementations for core modules.
"""

import asyncio
import logging
from enum import Enum, unique
from typing import Any, Callable, Dict, List, Optional, Type, Union

logger = logging.getLogger(__name__)
logger.info("Fallbacks module loaded")


def get_module_version() -> str:
    """Get module version from config or fallback."""
    try:
        from plexichat.core.config import get_config

        return get_config("system.version", "0.0.0")
    except ImportError:
        return "0.0.0"


# Fallback factories
def get_fallback_class(class_name: str) -> Type:
    """Dynamic fallback class factory."""
    fallback_classes = {
        "EventManager": EventManager,
        "Event": Event,
        "EventHandler": EventHandler,
        "FileManager": FileManager,
        "FileMetadata": FileMetadata,
        "UnifiedMessagingManager": UnifiedMessagingManager,
        "MessageEncryption": MessageEncryption,
        "MessageValidator": MessageValidator,
        "MessageRouter": MessageRouter,
        "ChannelManager": ChannelManager,
        "MessageMetadata": MessageMetadata,
        "MessageDelivery": MessageDelivery,
        "ChannelSettings": ChannelSettings,
        "BaseAPIException": BaseAPIException,
        "AuthenticationError": AuthenticationError,
        "AuthorizationError": AuthorizationError,
        "ValidationError": ValidationError,
        "DatabaseError": DatabaseError,
        "NetworkError": NetworkError,
        "FileError": FileError,
        "ExternalServiceError": ExternalServiceError,
        "RateLimitError": RateLimitError,
        "ConfigurationError": ConfigurationError,
        "ProcessLockError": ProcessLockError,
        "StartupError": StartupError,
        "SecurityError": SecurityError,
        "ErrorManager": ErrorManager,
        "CircuitBreaker": CircuitBreaker,
        # Enums
        "EventPriority": EventPriority,
        "MessageType": MessageType,
        "ChannelType": ChannelType,
        "MessageStatus": MessageStatus,
        "EncryptionLevel": EncryptionLevel,
        "ErrorSeverity": ErrorSeverity,
        "ErrorCategory": ErrorCategory,
        "ErrorCode": ErrorCode,
    }
    return fallback_classes.get(class_name, object)


def get_fallback_instance(class_name: str, *args, **kwargs) -> Any:
    """Create fallback instance."""
    cls = get_fallback_class(class_name)
    return cls(*args, **kwargs)


# Events fallbacks
class EventManager:
    def __init__(self):
        pass


class Event:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class EventHandler:
    def __init__(self):
        pass


class EventPriority:
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


def emit_event(*args, **kwargs):
    pass


def register_event_handler(*args, **kwargs):
    pass


def unregister_event_handler(*args, **kwargs):
    pass


def get_events(*args, **kwargs):
    return []


def event_handler(*args, **kwargs):
    def decorator(func):
        return func

    return decorator


# Files fallbacks
class FileManager:
    def __init__(self):
        pass


class FileMetadata:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def upload_file(*args, **kwargs):
    return None


def get_file_metadata(*args, **kwargs):
    return None


def get_file_data(*args, **kwargs):
    return None


def delete_file(*args, **kwargs):
    return False


# Messaging fallbacks
class UnifiedMessagingManager:
    def __init__(self):
        pass


class MessageEncryption:
    def __init__(self):
        pass


class MessageValidator:
    def __init__(self):
        pass


class MessageRouter:
    def __init__(self):
        pass


class ChannelManager:
    def __init__(self):
        pass


class MessageMetadata:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class MessageDelivery:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class ChannelSettings:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class MessageType:
    TEXT = "text"
    IMAGE = "image"
    FILE = "file"


class ChannelType:
    PUBLIC = "public"
    PRIVATE = "private"
    GROUP = "group"


class MessageStatus:
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"


class EncryptionLevel:
    NONE = "none"
    BASIC = "basic"
    ADVANCED = "advanced"


async def send_message(*args, **kwargs):
    return None


async def get_message(*args, **kwargs):
    return None


async def get_channel_messages(*args, **kwargs):
    return []


async def create_channel(*args, **kwargs):
    return None


def get_messaging_manager():
    return UnifiedMessagingManager()


# Errors fallbacks
class BaseAPIException(Exception):
    def __init__(
        self,
        message: str = "",
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class ErrorSeverity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory:
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    DATABASE = "database"
    NETWORK = "network"
    SECURITY = "security"
    SYSTEM = "system"
    FILE = "file"
    EXTERNAL = "external"


class AuthenticationError(BaseAPIException):
    def __init__(self, message: str = "Authentication failed", **kwargs):
        super().__init__(message, status_code=401, **kwargs)


class AuthorizationError(BaseAPIException):
    def __init__(self, message: str = "Authorization failed", **kwargs):
        super().__init__(message, status_code=403, **kwargs)


class ValidationError(BaseAPIException):
    def __init__(self, message: str = "Validation failed", **kwargs):
        super().__init__(message, status_code=400, **kwargs)


class DatabaseError(BaseAPIException):
    def __init__(self, message: str = "Database error", **kwargs):
        super().__init__(message, status_code=500, **kwargs)


class NetworkError(BaseAPIException):
    def __init__(self, message: str = "Network error", **kwargs):
        super().__init__(message, status_code=503, **kwargs)


class FileError(BaseAPIException):
    def __init__(self, message: str = "File error", **kwargs):
        super().__init__(message, status_code=500, **kwargs)


class ExternalServiceError(BaseAPIException):
    def __init__(self, message: str = "External service error", **kwargs):
        super().__init__(message, status_code=502, **kwargs)


class RateLimitError(BaseAPIException):
    def __init__(self, message: str = "Rate limit exceeded", **kwargs):
        super().__init__(message, status_code=429, **kwargs)


class ConfigurationError(BaseAPIException):
    def __init__(self, message: str = "Configuration error", **kwargs):
        super().__init__(message, status_code=500, **kwargs)


class ProcessLockError(BaseAPIException):
    def __init__(self, message: str = "Process lock error", **kwargs):
        super().__init__(message, status_code=500, **kwargs)


class StartupError(BaseAPIException):
    def __init__(self, message: str = "Startup error", **kwargs):
        super().__init__(message, status_code=500, **kwargs)


class SecurityError(BaseAPIException):
    def __init__(self, message: str = "Security error", **kwargs):
        super().__init__(message, status_code=403, **kwargs)


def handle_exception(exc: Exception) -> Dict[str, Any]:
    return {
        "type": type(exc).__name__,
        "message": str(exc),
        "details": getattr(exc, "details", {}),
    }


def create_error_response(exc: Exception, status_code: int = 500) -> Dict[str, Any]:
    return {
        "success": False,
        "error": handle_exception(exc),
        "status_code": status_code,
    }


def handle_404(request, exc):
    return {"error": "Not found", "status_code": 404}


def handle_500(request, exc):
    return {"error": "Internal server error", "status_code": 500}


def handle_validation_error(request, exc):
    return {"error": "Validation failed", "status_code": 400}


def handle_authentication_error(request, exc):
    return {"error": "Authentication failed", "status_code": 401}


def handle_authorization_error(request, exc):
    return {"error": "Authorization failed", "status_code": 403}


def handle_rate_limit_error(request, exc):
    return {"error": "Rate limit exceeded", "status_code": 429}


try:
    from fastapi.responses import JSONResponse

    async def not_found_handler(request, exc):
        return JSONResponse(
            status_code=404,
            content={
                "error": "Not Found",
                "message": "The requested resource was not found",
                "path": str(request.url.path),
            },
        )

    async def internal_error_handler(request, exc):
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal Server Error",
                "message": "An internal server error occurred",
            },
        )

except ImportError:

    async def not_found_handler(request, exc):
        pass

    async def internal_error_handler(request, exc):
        pass


def register_error_handlers(app):
    try:
        if hasattr(app, "register_error_handler"):
            app.register_error_handler(404, handle_404)
            app.register_error_handler(500, handle_500)
            app.register_error_handler(ValidationError, handle_validation_error)
            app.register_error_handler(AuthenticationError, handle_authentication_error)
            app.register_error_handler(AuthorizationError, handle_authorization_error)
            app.register_error_handler(RateLimitError, handle_rate_limit_error)
    except Exception:
        logger.debug(
            "register_error_handlers: best-effort registration failed", exc_info=True
        )
        pass


class CircuitBreaker:
    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, func):
        return func


class ErrorManager:
    def __init__(self):
        self.errors: List[Dict[str, Any]] = []

    def log_error(self, error: Union[Exception, Dict[str, Any], str]) -> None:
        entry = {
            "error": str(error) if not isinstance(error, dict) else error,
            "type": type(error).__name__ if not isinstance(error, dict) else "dict",
        }
        self.errors.append(entry)


def get_error_manager():
    return ErrorManager()


@unique
class ErrorCode(Enum):
    AUTH_INVALID_CREDENTIALS = (
        "AUTH_INVALID_CREDENTIALS",
        401,
        "Invalid credentials",
        ErrorCategory.AUTHENTICATION,
        ErrorSeverity.HIGH,
    )
    AUTH_TOKEN_EXPIRED = (
        "AUTH_TOKEN_EXPIRED",
        401,
        "Authentication token has expired",
        ErrorCategory.AUTHENTICATION,
        ErrorSeverity.MEDIUM,
    )
    AUTH_NO_TOKEN = (
        "AUTH_NO_TOKEN",
        401,
        "Authentication token missing",
        ErrorCategory.AUTHENTICATION,
        ErrorSeverity.MEDIUM,
    )
    AUTHZ_FORBIDDEN = (
        "AUTHZ_FORBIDDEN",
        403,
        "Action is forbidden",
        ErrorCategory.AUTHORIZATION,
        ErrorSeverity.HIGH,
    )
    VALIDATION_FIELD_MISSING = (
        "VALIDATION_FIELD_MISSING",
        400,
        "Required field is missing",
        ErrorCategory.VALIDATION,
        ErrorSeverity.MEDIUM,
    )
    VALIDATION_INVALID_FORMAT = (
        "VALIDATION_INVALID_FORMAT",
        400,
        "Invalid field format",
        ErrorCategory.VALIDATION,
        ErrorSeverity.MEDIUM,
    )
    DB_CONNECTION_FAILED = (
        "DB_CONNECTION_FAILED",
        500,
        "Failed to connect to database",
        ErrorCategory.DATABASE,
        ErrorSeverity.CRITICAL,
    )
    DB_QUERY_FAILED = (
        "DB_QUERY_FAILED",
        500,
        "Database query failed",
        ErrorCategory.DATABASE,
        ErrorSeverity.HIGH,
    )
    NETWORK_TIMEOUT = (
        "NETWORK_TIMEOUT",
        503,
        "Network timeout",
        ErrorCategory.NETWORK,
        ErrorSeverity.MEDIUM,
    )
    SECURITY_SQL_INJECTION = (
        "SECURITY_SQL_INJECTION",
        400,
        "Potential SQL injection detected",
        ErrorCategory.SECURITY,
        ErrorSeverity.CRITICAL,
    )
    SECURITY_XSS_DETECTED = (
        "SECURITY_XSS_DETECTED",
        400,
        "Potential cross-site scripting detected",
        ErrorCategory.SECURITY,
        ErrorSeverity.CRITICAL,
    )
    SECURITY_RATE_LIMIT = (
        "SECURITY_RATE_LIMIT",
        429,
        "Rate limit exceeded",
        ErrorCategory.SECURITY,
        ErrorSeverity.MEDIUM,
    )
    SYSTEM_CONFIGURATION_ERROR = (
        "SYSTEM_CONFIGURATION_ERROR",
        500,
        "System configuration error",
        ErrorCategory.SYSTEM,
        ErrorSeverity.CRITICAL,
    )
    SYSTEM_STARTUP_ERROR = (
        "SYSTEM_STARTUP_ERROR",
        500,
        "System startup error",
        ErrorCategory.SYSTEM,
        ErrorSeverity.CRITICAL,
    )
    FILE_NOT_FOUND = (
        "FILE_NOT_FOUND",
        404,
        "Requested file not found",
        ErrorCategory.FILE,
        ErrorSeverity.MEDIUM,
    )
    EXTERNAL_SERVICE_FAILURE = (
        "EXTERNAL_SERVICE_FAILURE",
        502,
        "External service failure",
        ErrorCategory.EXTERNAL,
        ErrorSeverity.HIGH,
    )

    def __init__(
        self, code: str, http_status: int, message: str, category: str, severity: str
    ):
        self._code = code
        self._http_status = http_status
        self._message = message
        self._category = category
        self._severity = severity

    @property
    def code(self) -> str:
        return self._code

    @property
    def status(self) -> int:
        return self._http_status

    @property
    def message(self) -> str:
        return self._message

    @property
    def category(self) -> str:
        return self._category

    @property
    def severity(self) -> str:
        return self._severity


ERROR_CODE_MAP: Dict[str, ErrorCode] = {ec.code: ec for ec in ErrorCode}


def get_error_code(identifier: Union[str, ErrorCode]) -> Optional[ErrorCode]:
    if isinstance(identifier, ErrorCode):
        return identifier
    if not isinstance(identifier, str):
        return None
    return ERROR_CODE_MAP.get(identifier)


def error_to_response(
    error_code: Union[str, ErrorCode], details: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    ec = get_error_code(error_code)
    if ec is None:
        logger.debug("error_to_response: unknown error code provided: %s", error_code)
        return {
            "success": False,
            "error": {
                "code": "UNKNOWN_ERROR",
                "message": "An unknown error occurred",
                "category": ErrorCategory.SYSTEM,
                "severity": ErrorSeverity.MEDIUM,
                "details": details or {},
            },
            "status_code": 500,
        }
    return {
        "success": False,
        "error": {
            "code": ec.code,
            "message": ec.message,
            "category": ec.category,
            "severity": ec.severity,
            "details": details or {},
        },
        "status_code": ec.status,
    }


def raise_for_code(
    error_code: Union[str, ErrorCode], details: Optional[Dict[str, Any]] = None
) -> None:
    ec = get_error_code(error_code)
    if ec is None:
        raise BaseAPIException(
            "Unknown error code", status_code=500, details=details or {}
        )
    raise BaseAPIException(ec.message, status_code=ec.status, details=details or {})


def list_error_codes() -> List[Dict[str, Any]]:
    codes = []
    for ec in ErrorCode:
        codes.append(
            {
                "code": ec.code,
                "status": ec.status,
                "message": ec.message,
                "category": ec.category,
                "severity": ec.severity,
            }
        )
    return codes


logger.info("Fallbacks module initialized with %d error codes", len(ERROR_CODE_MAP))

__version__ = get_module_version()
