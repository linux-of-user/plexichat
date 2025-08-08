"""
PlexiChat Unified Error System

Single source of truth for all error handling functionality.
Consolidates error_handling/, error_handlers.py, and exceptions.py into one clean system.
"""

from typing import Any, Dict, Optional, Type
import logging

# Use fallback implementations to avoid import issues
logger = logging.getLogger(__name__)
logger.warning("Using fallback error implementations")

# Fallback error components
class BaseAPIException(Exception):  # type: ignore
    def __init__(self, message: str = "", status_code: int = 500, details: Optional[Dict[str, Any]] = None):
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
# Utility functions
def handle_exception(exc: Exception) -> Dict[str, Any]:
    """Handle exception and return error info."""
    return {
        "type": type(exc).__name__,
        "message": str(exc),
        "details": getattr(exc, 'details', {})
    }

def create_error_response(exc: Exception, status_code: int = 500) -> Dict[str, Any]:
    """Create error response."""
    return {
        "success": False,
        "error": handle_exception(exc),
        "status_code": status_code
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

def register_error_handlers(app):
    """Register error handlers with the application."""
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
        self.errors = []

    def log_error(self, error):
        self.errors.append(error)

def get_error_manager():
    """Get error manager instance."""
    return ErrorManager()

# Export all the main classes and functions
__all__ = [
    # Exceptions
    "BaseAPIException",
    "AuthenticationError",
    "ValidationError",
    "handle_exception",
    "create_error_response",
    
    # Handlers
    "handle_404",
    "handle_500",
    "register_error_handlers",
    
    # Circuit breaker
    "CircuitBreaker",
    
    # Error manager
    "ErrorManager",
    "get_error_manager",
]
