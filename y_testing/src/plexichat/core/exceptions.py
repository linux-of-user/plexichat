"""
import time
PlexiChat Core Exceptions

Enhanced exception handling with comprehensive error types and performance optimization.
Uses EXISTING performance optimization systems.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
except ImportError:
    PerformanceOptimizationEngine = None

try:
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    class MockPerformanceLogger:
        def __init__(self):
            self.logger = logging.getLogger(__name__)
        def record_metric(self, name, value, unit):
            self.logger.debug(f"Metric {name}: {value} {unit}")

    def get_performance_logger():
        return MockPerformanceLogger()

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

class PlexiChatException(Exception):
    """Base exception for PlexiChat with enhanced error tracking."""

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
        self.user_id = user_id
        self.timestamp = datetime.now()

        # Log exception with performance tracking
        self._log_exception()

    def _log_exception(self):
        """Log exception with performance metrics."""
        try:
            error_data = {
                "error_code": self.error_code,
                "message": self.message,
                "details": self.details,
                "user_id": self.user_id,
                "timestamp": self.timestamp.isoformat()
            }

            logger.error(f"PlexiChat Exception: {error_data}")

            # Performance tracking
            if performance_logger and hasattr(performance_logger, 'record_metric'):
                performance_logger.record_metric("exceptions_raised", 1, "count")
                performance_logger.record_metric(f"exception_{self.error_code}", 1, "count")

        except Exception as e:
            logger.error(f"Error logging exception: {e}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary."""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details,
            "user_id": self.user_id,
            "timestamp": self.timestamp.isoformat()
        }

class AuthenticationError(PlexiChatException):
    """Authentication related errors."""
    pass

class AuthorizationError(PlexiChatException):
    """Authorization related errors."""
    pass

class ValidationError(PlexiChatException):
    """Data validation errors."""

    def __init__(
        self,
        message: str,
        field_errors: Optional[Dict[str, List[str]]] = None,
        **kwargs
    ):
        self.field_errors = field_errors or {}
        super().__init__(message, **kwargs)

class DatabaseError(PlexiChatException):
    """Database operation errors."""

    def __init__(
        self,
        message: str,
        operation: Optional[str] = None,
        table: Optional[str] = None,
        **kwargs
    ):
        self.operation = operation
        self.table = table
        super().__init__(message, **kwargs)

class FileError(PlexiChatException):
    """File operation errors."""

    def __init__(
        self,
        message: str,
        file_path: Optional[str] = None,
        file_size: Optional[int] = None,
        **kwargs
    ):
        self.file_path = file_path
        self.file_size = file_size
        super().__init__(message, **kwargs)

class NetworkError(PlexiChatException):
    """Network operation errors."""

    def __init__(
        self,
        message: str,
        url: Optional[str] = None,
        status_code: Optional[int] = None,
        **kwargs
    ):
        self.url = url
        self.status_code = status_code
        super().__init__(message, **kwargs)

class ConfigurationError(PlexiChatException):
    """Configuration related errors."""

    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        config_value: Optional[Any] = None,
        **kwargs
    ):
        self.config_key = config_key
        self.config_value = config_value
        super().__init__(message, **kwargs)

class RateLimitError(PlexiChatException):
    """Rate limiting errors."""

    def __init__(
        self,
        message: str,
        limit: Optional[int] = None,
        window: Optional[int] = None,
        retry_after: Optional[int] = None,
        **kwargs
    ):
        self.limit = limit
        self.window = window
        self.retry_after = retry_after
        super().__init__(message, **kwargs)

class SecurityError(PlexiChatException):
    """Security related errors."""

    def __init__(
        self,
        message: str,
        threat_type: Optional[str] = None,
        severity: str = "medium",
        **kwargs
    ):
        self.threat_type = threat_type
        self.severity = severity
        super().__init__(message, **kwargs)

        # Log security events separately
        self._log_security_event()

    def _log_security_event(self):
        """Log security event."""
        try:
            from plexichat.core.logging import log_security_event
            log_security_event()
                event_type=self.threat_type or "security_exception",
                severity=self.severity,
                details=self.to_dict()
            )
        except Exception as e:
            logger.error(f"Error logging security event: {e}")

class PerformanceError(PlexiChatException):
    """Performance related errors."""

    def __init__(
        self,
        message: str,
        operation: Optional[str] = None,
        duration: Optional[float] = None,
        threshold: Optional[float] = None,
        **kwargs
    ):
        self.operation = operation
        self.duration = duration
        self.threshold = threshold
        super().__init__(message, **kwargs)

class ClusterError(PlexiChatException):
    """Cluster operation errors."""

    def __init__(
        self,
        message: str,
        node_id: Optional[str] = None,
        cluster_id: Optional[str] = None,
        **kwargs
    ):
        self.node_id = node_id
        self.cluster_id = cluster_id
        super().__init__(message, **kwargs)

class ExceptionHandler:
    """Enhanced exception handler with performance optimization."""

    def __init__(self):
        self.performance_logger = performance_logger
        self.exception_counts: Dict[str, int] = {}
        self.last_reset = datetime.now()

    def handle_exception():
        self,
        exception: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Handle exception and return error response."""
        try:
            # Update exception counts
            exception_type = type(exception).__name__
            self.exception_counts[exception_type] = self.exception_counts.get(exception_type, 0) + 1

            # Reset counts hourly
            if (datetime.now() - self.last_reset).total_seconds() > 3600:
                self.exception_counts.clear()
                self.last_reset = datetime.now()

            # Handle PlexiChat exceptions
            if isinstance(exception, PlexiChatException):
                return self._handle_plexichat_exception(exception, context)

            # Handle standard exceptions
            return self._handle_standard_exception(exception, context)

        except Exception as e:
            logger.error(f"Error in exception handler: {e}")
            return {
                "error_code": "HANDLER_ERROR",
                "message": "Internal error handling exception",
                "timestamp": datetime.now().isoformat()
            }

    def _handle_plexichat_exception():
        self,
        exception: PlexiChatException,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Handle PlexiChat specific exceptions."""
        error_response = exception.to_dict()

        if context:
            error_response["context"] = context

        # Add exception count
        error_response["occurrence_count"] = self.exception_counts.get()
            type(exception).__name__, 1
        )

        return error_response

    def _handle_standard_exception():
        self,
        exception: Exception,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Handle standard Python exceptions."""
        error_response = {
            "error_code": type(exception).__name__,
            "message": str(exception),
            "timestamp": datetime.now().isoformat(),
            "occurrence_count": self.exception_counts.get(type(exception).__name__, 1)
        }

        if context:
            error_response["context"] = context

        # Log standard exception
        logger.error(f"Standard Exception: {error_response}")

        # Performance tracking
        if self.performance_logger and hasattr(self.performance_logger, 'record_metric'):
            self.performance_logger.record_metric("standard_exceptions", 1, "count")

        return error_response

    def get_exception_stats(self) -> Dict[str, Any]:
        """Get exception statistics."""
        return {
            "exception_counts": self.exception_counts.copy(),
            "total_exceptions": sum(self.exception_counts.values()),
            "unique_exception_types": len(self.exception_counts),
            "last_reset": self.last_reset.isoformat(),
            "timestamp": datetime.now().isoformat()
        }

# Global exception handler
exception_handler = ExceptionHandler()

# Convenience functions
def handle_exception():
    exception: Exception,
    context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Handle exception and return error response."""
    return exception_handler.handle_exception(exception, context)

def get_exception_stats() -> Dict[str, Any]:
    """Get exception statistics."""
    return exception_handler.get_exception_stats()

# Exception decorators
def handle_exceptions(default_return=None):
    """Decorator to handle exceptions in functions."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_response = handle_exception(e, {"function": func.__name__})
                logger.error(f"Exception in {func.__name__}: {error_response}")
                return default_return
        return wrapper
    return decorator

def handle_async_exceptions(default_return=None):
    """Decorator to handle exceptions in async functions."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                error_response = handle_exception(e, {"function": func.__name__})
                logger.error(f"Exception in {func.__name__}: {error_response}")
                return default_return
        return wrapper
    return decorator
