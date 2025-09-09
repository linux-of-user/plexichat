"""
PlexiChat Unified Error System

Single source of truth for all error handling functionality.
Consolidates error_handling/, error_handlers.py, and exceptions.py into one clean system.
"""

import logging
from enum import Enum, unique
from typing import Any, Dict, List, Optional, Type, Union

# Use shared fallback implementations
logger = logging.getLogger(__name__)

try:
    from plexichat.core.utils.fallbacks import (  # Exceptions; Enums; Utilities; Error Manager; ErrorCode system
        ERROR_CODE_MAP,
        AuthenticationError,
        AuthorizationError,
        BaseAPIException,
        CircuitBreaker,
        ConfigurationError,
        DatabaseError,
        ErrorCategory,
        ErrorCode,
        ErrorManager,
        ErrorSeverity,
        ExternalServiceError,
        FileError,
        NetworkError,
        ProcessLockError,
        RateLimitError,
        SecurityError,
        StartupError,
        ValidationError,
        create_error_response,
        error_to_response,
        get_error_code,
        get_error_manager,
        get_fallback_instance,
        handle_404,
        handle_500,
        handle_authentication_error,
        handle_authorization_error,
        handle_exception,
        handle_rate_limit_error,
        handle_validation_error,
        internal_error_handler,
        list_error_codes,
        not_found_handler,
        raise_for_code,
        register_error_handlers,
    )

    USE_SHARED_FALLBACKS = True
    logger.info("Using shared fallback implementations for errors")
except ImportError:
    # Fallback to local definitions if shared fallbacks unavailable
    USE_SHARED_FALLBACKS = False
    logger.warning("Shared fallbacks unavailable, using local implementations")

if USE_SHARED_FALLBACKS:
    error_manager = get_error_manager()
else:
    # Local fallbacks (preserved for compatibility)
    # Fallback error components
    class BaseAPIException(Exception):  # type: ignore
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

    class ErrorSeverity:  # type: ignore
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"

    class ErrorCategory:  # type: ignore
        AUTHENTICATION = "authentication"
        AUTHORIZATION = "authorization"
        VALIDATION = "validation"
        DATABASE = "database"
        NETWORK = "network"
        SECURITY = "security"
        SYSTEM = "system"
        FILE = "file"
        EXTERNAL = "external"

    # Specific exceptions
    class AuthenticationError(BaseAPIException):  # type: ignore
        def __init__(self, message: str = "Authentication failed", **kwargs):
            super().__init__(message, status_code=401, **kwargs)

    class AuthorizationError(BaseAPIException):  # type: ignore
        def __init__(self, message: str = "Authorization failed", **kwargs):
            super().__init__(message, status_code=403, **kwargs)

    class ValidationError(BaseAPIException):  # type: ignore
        def __init__(self, message: str = "Validation failed", **kwargs):
            super().__init__(message, status_code=400, **kwargs)

    class DatabaseError(BaseAPIException):  # type: ignore
        def __init__(self, message: str = "Database error", **kwargs):
            super().__init__(message, status_code=500, **kwargs)

    class NetworkError(BaseAPIException):  # type: ignore
        def __init__(self, message: str = "Network error", **kwargs):
            super().__init__(message, status_code=503, **kwargs)

    class FileError(BaseAPIException):  # type: ignore
        def __init__(self, message: str = "File error", **kwargs):
            super().__init__(message, status_code=500, **kwargs)

    class ExternalServiceError(BaseAPIException):  # type: ignore
        def __init__(self, message: str = "External service error", **kwargs):
            super().__init__(message, status_code=502, **kwargs)

    class RateLimitError(BaseAPIException):  # type: ignore
        def __init__(self, message: str = "Rate limit exceeded", **kwargs):
            super().__init__(message, status_code=429, **kwargs)

    class ConfigurationError(BaseAPIException):  # type: ignore
        def __init__(self, message: str = "Configuration error", **kwargs):
            super().__init__(message, status_code=500, **kwargs)

    class ProcessLockError(BaseAPIException):  # type: ignore
        def __init__(self, message: str = "Process lock error", **kwargs):
            super().__init__(message, status_code=500, **kwargs)

    class StartupError(BaseAPIException):  # type: ignore
        def __init__(self, message: str = "Startup error", **kwargs):
            super().__init__(message, status_code=500, **kwargs)

    class SecurityError(BaseAPIException):  # type: ignore
        def __init__(self, message: str = "Security error", **kwargs):
            super().__init__(message, status_code=403, **kwargs)

    # Utility functions
    def handle_exception(exc: Exception) -> Dict[str, Any]:
        """Handle exception and return error info."""
        return {
            "type": type(exc).__name__,
            "message": str(exc),
            "details": getattr(exc, "details", {}),
        }

    def create_error_response(exc: Exception, status_code: int = 500) -> Dict[str, Any]:
        """Create error response."""
        return {
            "success": False,
            "error": handle_exception(exc),
            "status_code": status_code,
        }

    # Fallback error handlers
    def handle_404(request, exc):
        """Handle 404 errors."""
        return {"error": "Not found", "status_code": 404}

    def handle_500(request, exc):
        """Handle 500 errors."""
        return {"error": "Internal server error", "status_code": 500}

    def handle_validation_error(request, exc):
        """Handle validation errors."""
        return {"error": "Validation failed", "status_code": 400}

    def handle_authentication_error(request, exc):
        """Handle authentication errors."""
        return {"error": "Authentication failed", "status_code": 401}

    def handle_authorization_error(request, exc):
        """Handle authorization errors."""
        return {"error": "Authorization failed", "status_code": 403}

    def handle_rate_limit_error(request, exc):
        """Handle rate limit errors."""
        return {"error": "Rate limit exceeded", "status_code": 429}

    # FastAPI-compatible error handlers - import from handlers.py
    try:
        from .handlers import internal_error_handler, not_found_handler
    except ImportError:
        # Fallback if handlers.py is not available
        from fastapi.responses import JSONResponse

        async def not_found_handler(request, exc):
            """Handle 404 errors for FastAPI."""
            return JSONResponse(
                status_code=404,
                content={
                    "error": "Not Found",
                    "message": "The requested resource was not found",
                    "path": str(request.url.path),
                },
            )

        async def internal_error_handler(request, exc):
            """Handle 500 errors for FastAPI."""
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Internal Server Error",
                    "message": "An internal server error occurred",
                },
            )

    def register_error_handlers(app):
        """Register error handlers with the application."""
        # Basic fallback implementation: attempt to register common handlers if framework methods exist.
        # This keeps backward compatibility and avoids hard dependency on a specific web framework.
        try:
            if hasattr(app, "register_error_handler"):
                # Flask-like
                app.register_error_handler(404, handle_404)
                app.register_error_handler(500, handle_500)
                app.register_error_handler(ValidationError, handle_validation_error)
                app.register_error_handler(
                    AuthenticationError, handle_authentication_error
                )
                app.register_error_handler(
                    AuthorizationError, handle_authorization_error
                )
                app.register_error_handler(RateLimitError, handle_rate_limit_error)
        except Exception:
            # If registration fails, log and continue - this is a best-effort fallback.
            logger.debug(
                "register_error_handlers: best-effort registration failed",
                exc_info=True,
            )
            pass

    # Fallback circuit breaker
    class CircuitBreaker:
        """Fallback circuit breaker."""

        def __init__(self, *args, **kwargs):
            pass

        def __call__(self, func):
            return func

    # Fallback error manager
    class ErrorManager:
        """Fallback error manager."""

        def __init__(self):
            self.errors: List[Dict[str, Any]] = []

        def log_error(self, error: Union[Exception, Dict[str, Any], str]) -> None:
            entry = {
                "error": str(error) if not isinstance(error, dict) else error,
                "type": type(error).__name__ if not isinstance(error, dict) else "dict",
            }
            self.errors.append(entry)

    def get_error_manager():
        """Get error manager instance."""
        return ErrorManager()

    # Standardized Error Code System
    @unique
    class ErrorCode(Enum):
        # Authentication
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

        # Authorization
        AUTHZ_FORBIDDEN = (
            "AUTHZ_FORBIDDEN",
            403,
            "Action is forbidden",
            ErrorCategory.AUTHORIZATION,
            ErrorSeverity.HIGH,
        )

        # Validation
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

        # Database
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

        # Network
        NETWORK_TIMEOUT = (
            "NETWORK_TIMEOUT",
            503,
            "Network timeout",
            ErrorCategory.NETWORK,
            ErrorSeverity.MEDIUM,
        )

        # Security
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

        # System
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

        # File / External
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
            self,
            code: str,
            http_status: int,
            message: str,
            category: str,
            severity: str,
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

    # Build a map for quick lookups
    ERROR_CODE_MAP: Dict[str, ErrorCode] = {ec.code: ec for ec in ErrorCode}

    def get_error_code(identifier: Union[str, ErrorCode]) -> Optional[ErrorCode]:
        """
        Resolve an ErrorCode by string identifier or return the ErrorCode if provided.

        Example:
            get_error_code("AUTH_INVALID_CREDENTIALS") -> ErrorCode.AUTH_INVALID_CREDENTIALS
            get_error_code(ErrorCode.AUTH_INVALID_CREDENTIALS) -> ErrorCode.AUTH_INVALID_CREDENTIALS
        """
        if isinstance(identifier, ErrorCode):
            return identifier
        if not isinstance(identifier, str):
            return None
        return ERROR_CODE_MAP.get(identifier)

    def error_to_response(
        error_code: Union[str, ErrorCode], details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create a standardized error response dictionary from an ErrorCode.

        Returns:
            {
                "success": False,
                "error": {
                    "code": <code>,
                    "message": <message>,
                    "category": <category>,
                    "severity": <severity>,
                    "details": {...}
                },
                "status_code": <http status>
            }
        """
        ec = get_error_code(error_code)
        if ec is None:
            # Fallback to generic error response
            logger.debug(
                "error_to_response: unknown error code provided: %s", error_code
            )
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
        """
        Raise a BaseAPIException constructed from the provided ErrorCode.

        This helper allows code to raise standardized exceptions:
            raise_for_code("AUTH_INVALID_CREDENTIALS", {"user_id": 123})
        """
        ec = get_error_code(error_code)
        if ec is None:
            raise BaseAPIException(
                "Unknown error code", status_code=500, details=details or {}
            )
        raise BaseAPIException(ec.message, status_code=ec.status, details=details or {})

    def list_error_codes() -> List[Dict[str, Any]]:
        """Return a list of all standardized error codes with metadata."""
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

    # Log that the standardized error code system is available
    logger.info(
        "Standardized ErrorCode system initialized with %d codes", len(ERROR_CODE_MAP)
    )

    # Ensure error_manager is always available
    error_manager = get_error_manager()

    # Export all the main classes and functions
    __all__ = [
        # Exceptions
        "BaseAPIException",
        "AuthenticationError",
        "AuthorizationError",
        "ValidationError",
        "DatabaseError",
        "NetworkError",
        "FileError",
        "ExternalServiceError",
        "RateLimitError",
        "ConfigurationError",
        "ProcessLockError",
        "StartupError",
        "SecurityError",
        "handle_exception",
        "create_error_response",
        # Handlers
        "handle_404",
        "handle_500",
        "handle_validation_error",
        "handle_authentication_error",
        "handle_authorization_error",
        "handle_rate_limit_error",
        "not_found_handler",
        "internal_error_handler",
        "register_error_handlers",
        # Circuit breaker
        "CircuitBreaker",
        # Error manager
        "ErrorManager",
        "get_error_manager",
        # Severity & Category
        "ErrorSeverity",
        "ErrorCategory",
        # Standardized error codes
        "ErrorCode",
        "ERROR_CODE_MAP",
        "get_error_code",
        "error_to_response",
        "raise_for_code",
        "list_error_codes",
    ]

    from plexichat.core.utils.fallbacks import get_module_version

    __version__ = get_module_version()
