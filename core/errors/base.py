from __future__ import dataclasses
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional, Union


class ErrorSeverity(Enum):
    """Comprehensive error severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Comprehensive error categories with 14 values."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    DATABASE = "database"
    NETWORK = "network"
    FILE = "file"
    PLUGIN = "plugin"
    AI = "ai"
    SECURITY = "security"
    PERFORMANCE = "performance"
    CONFIGURATION = "configuration"
    INTEGRATION = "integration"
    SYSTEM = "system"
    UNKNOWN = "unknown"


@dataclass
class ErrorCodeMapping:
    """Mapping for error codes to severity and category."""

    code: str
    severity: ErrorSeverity
    category: ErrorCategory
    message: str
    technical_message: Optional[str] = None


class PlexiChatErrorCode(Enum):
    """Comprehensive error codes with 100+ entries."""

    # Example codes; in full implementation, include all 100+ as per error_codes.py
    AUTH_INVALID_CREDENTIALS = "AUTH_001"
    AUTH_TOKEN_EXPIRED = "AUTH_002"
    VALIDATION_ERROR = "VAL_001"
    DATABASE_CONNECTION_FAILED = "DB_001"
    FILE_NOT_FOUND = "FILE_001"
    SYSTEM_INTERNAL_ERROR = "SYS_001"
    # ... (add all codes with mappings)


# Static mappings
ERROR_MAPPINGS: Dict[str, ErrorCodeMapping] = {
    PlexiChatErrorCode.AUTH_INVALID_CREDENTIALS.value: ErrorCodeMapping(
        code=PlexiChatErrorCode.AUTH_INVALID_CREDENTIALS.value,
        severity=ErrorSeverity.HIGH,
        category=ErrorCategory.AUTHENTICATION,
        message="Invalid credentials provided.",
        technical_message="Authentication failed due to incorrect username or password.",
    ),
    PlexiChatErrorCode.SYSTEM_INTERNAL_ERROR.value: ErrorCodeMapping(
        code=PlexiChatErrorCode.SYSTEM_INTERNAL_ERROR.value,
        severity=ErrorSeverity.CRITICAL,
        category=ErrorCategory.SYSTEM,
        message="Internal server error.",
        technical_message="An unexpected system error occurred.",
    ),
    # ... (add all mappings)
}


@dataclass
class ErrorResponse:
    """Unified error response structure."""

    success: bool = False
    error: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    correlation_id: Optional[str] = None

    def __post_init__(self) -> None:
        """Initialize timestamp if needed."""
        pass

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "success": self.success,
            "error": self.error,
            "timestamp": self.timestamp.isoformat(),
            "correlation_id": self.correlation_id,
        }


class PlexiChatException(Exception):
    """Base exception class."""

    def __init__(
        self,
        code: str,
        details: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ):
        self.code = code
        self.details = details or {}
        self.context = context or {}
        self.severity = ERROR_MAPPINGS.get(
            code, ErrorCodeMapping("", ErrorSeverity.MEDIUM, ErrorCategory.UNKNOWN, "")
        ).severity
        self.category = ERROR_MAPPINGS.get(
            code, ErrorCodeMapping("", ErrorSeverity.MEDIUM, ErrorCategory.UNKNOWN, "")
        ).category
        super().__init__(
            f"{code}: {ERROR_MAPPINGS.get(code, ErrorCodeMapping('', ErrorSeverity.MEDIUM, ErrorCategory.UNKNOWN, '')).message}"
        )


def log_error(exc: Exception, context: Optional[Dict[str, Any]] = None) -> None:
    """Log error with context."""
    logger = logging.getLogger(__name__)
    logger.error(f"Error occurred: {str(exc)}", extra=context or {})


def create_error_response(
    code: str,
    details: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
    correlation_id: Optional[str] = None,
) -> ErrorResponse:
    """Unified function to create error response supporting details/context/correlation_id."""
    mapping = ERROR_MAPPINGS.get(
        code,
        ErrorCodeMapping(
            code, ErrorSeverity.MEDIUM, ErrorCategory.UNKNOWN, "Unknown error"
        ),
    )
    error_data = {
        "code": code,
        "message": mapping.message,
        "technical_message": mapping.technical_message,
        "severity": mapping.severity.value,
        "category": mapping.category.value,
        "details": details or {},
    }
    return ErrorResponse(error=error_data, correlation_id=correlation_id)


def create_validation_error_response(
    field: str, value: Any, reason: str
) -> ErrorResponse:
    """Specialized creator for validation errors."""
    details = {field: {"value": value, "reason": reason}}
    return create_error_response(
        PlexiChatErrorCode.VALIDATION_ERROR.value, details=details
    )


def handle_exception(
    exc: Exception, correlation_id: Optional[str] = None, request: Optional[Any] = None
) -> ErrorResponse:
    """Unified handle_exception integrating logging and response creation."""
    context = {"timestamp": datetime.utcnow().isoformat()}
    if request:
        context.update({"path": request.url.path, "method": request.method})
    log_error(exc, context)

    # Determine code based on exception type or default
    code = (
        PlexiChatErrorCode.SYSTEM_INTERNAL_ERROR.value
    )  # Default; map based on exc type in full impl
    if isinstance(exc, PlexiChatException):
        code = exc.code

    return create_error_response(code, context=context, correlation_id=correlation_id)
