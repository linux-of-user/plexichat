import asyncio
import logging
import traceback
import uuid
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Optional


"""
PlexiChat Error Context and Boundary Management

Provides error context tracking and error boundary management
for fault isolation and recovery.
"""

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class ErrorCategory(Enum):
    """Error categories."""
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


@dataclass
class ErrorContext:
    """
    Comprehensive error context information.
    
    Contains all relevant information about an error including
    timing, user context, system state, and recovery attempts.
    """
    error_id: str
    timestamp: datetime
    exception: Exception
    severity: ErrorSeverity
    category: ErrorCategory
    
    # Context information
    component: Optional[str] = None
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    
    # Technical details
    stack_trace: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    additional_data: Dict[str, Any] = field(default_factory=dict)
    
    # Recovery information
    recovery_attempted: bool = False
    recovery_successful: bool = False
    recovery_strategy: Optional[str] = None
    recovery_details: Dict[str, Any] = field(default_factory=dict)
    
    # Request/Response context
    endpoint: Optional[str] = None
    method: Optional[str] = None
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    
    # System context
    system_metrics: Dict[str, Any] = field(default_factory=dict)
    environment: Optional[str] = None
    version: Optional[str] = None
    
    # Timing information
    processing_time: Optional[float] = None
    resolution_time: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error context to dictionary."""
        return {
            "error_id": self.error_id,
            "timestamp": self.timestamp.isoformat(),
            "exception": {
                "type": type(self.exception).__name__,
                "message": str(self.exception),
                "args": self.exception.args
            },
            "severity": self.severity.value,
            "category": self.category.value,
            "component": self.component,
            "user_id": self.user_id,
            "request_id": self.request_id,
            "session_id": self.session_id,
            "stack_trace": self.stack_trace,
            "context": self.context,
            "additional_data": self.additional_data,
            "recovery": {
                "attempted": self.recovery_attempted,
                "successful": self.recovery_successful,
                "strategy": self.recovery_strategy,
                "details": self.recovery_details
            },
            "request": {
                "endpoint": self.endpoint,
                "method": self.method,
                "user_agent": self.user_agent,
                "ip_address": self.ip_address
            },
            "system": {
                "metrics": self.system_metrics,
                "environment": self.environment,
                "version": self.version
            },
            "timing": {
                "processing_time": self.processing_time,
                "resolution_time": self.resolution_time
            }
        }
    
    def get_user_friendly_message(self) -> str:
        """Get a user-friendly error message."""
        severity_messages = {
            ErrorSeverity.LOW: "We encountered a minor issue, but everything should work normally.",
            ErrorSeverity.MEDIUM: "We're experiencing some technical difficulties. Please try again.",
            ErrorSeverity.HIGH: "We're having technical problems. Our team has been notified.",
            ErrorSeverity.CRITICAL: "We're experiencing serious technical issues. Please contact support.",
            ErrorSeverity.EMERGENCY: "Critical system error. Please contact support immediately."
        }
        
        base_message = severity_messages.get(
            self.severity, 
            "We encountered an unexpected error."
        )
        
        if self.error_id:
            return f"{base_message} (Error ID: {self.error_id})"
        
        return base_message
    
    def get_technical_summary(self) -> str:
        """Get a technical summary of the error."""
        return (
            f"Error {self.error_id}: {type(self.exception).__name__} "
            f"in {self.component or 'unknown component'} "
            f"[{self.severity.value.upper()}] - {str(self.exception)}"
        )


class ErrorBoundary:
    """
    Error boundary for fault isolation and recovery.
    
    Provides a context manager that catches errors, handles them
    appropriately, and optionally provides fallback behavior.
    """
    
    def __init__(self, 
                 name: str,
                 fallback_value: Any = None,
                 fallback_function: Optional[Callable] = None,
                 recovery_enabled: bool = True,
                 suppress_errors: bool = False,
                 error_handler: Optional[Callable] = None,
                 severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 category: ErrorCategory = ErrorCategory.UNKNOWN):
        self.name = name
        self.fallback_value = fallback_value
        self.fallback_function = fallback_function
        self.recovery_enabled = recovery_enabled
        self.suppress_errors = suppress_errors
        self.error_handler = error_handler
        self.severity = severity
        self.category = category
        
        self.error_context: Optional[ErrorContext] = None
        self.start_time: Optional[float] = None
    
    def __enter__(self):
        """Enter the error boundary context."""
        self.start_time = asyncio.get_event_loop().time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the error boundary context."""
        if exc_type is not None:
            return self._handle_error(exc_val)
        return False
    
    async def __aenter__(self):
        """Enter the async error boundary context."""
        self.start_time = asyncio.get_event_loop().time()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit the async error boundary context."""
        if exc_type is not None:
            return await self._handle_error_async(exc_val)
        return False
    
    def _handle_error(self, exception: Exception) -> bool:
        """Handle error in sync context."""
        try:
            # Create error context
            self.error_context = ErrorContext(
                error_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                exception=exception,
                severity=self.severity,
                category=self.category,
                component=self.name,
                stack_trace=traceback.format_exc(),
                processing_time=asyncio.get_event_loop().time() - self.start_time if self.start_time else None
            )
            
            # Log the error
            logger.error(
                f"Error in boundary '{self.name}': {type(exception).__name__}: {exception}",
                extra={
                    "error_id": self.error_context.error_id,
                    "boundary": self.name,
                    "severity": self.severity.value,
                    "category": self.category.value
                }
            )
            
            # Call custom error handler if provided
            if self.error_handler:
                try:
                    self.error_handler(self.error_context)
                except Exception as handler_error:
                    logger.error(f"Error handler failed in boundary '{self.name}': {handler_error}")
            
            # Attempt recovery if enabled
            if self.recovery_enabled:
                recovery_result = self._attempt_recovery()
                if recovery_result:
                    return True  # Suppress the exception
            
            # Use fallback if available
            if self.fallback_function:
                try:
                    self.fallback_value = self.fallback_function()
                    return True  # Suppress the exception
                except Exception as fallback_error:
                    logger.error(f"Fallback function failed in boundary '{self.name}': {fallback_error}")
            
            if self.fallback_value is not None:
                return True  # Suppress the exception
            
            # Suppress errors if configured
            if self.suppress_errors:
                return True
            
        except Exception as boundary_error:
            logger.error(f"Error boundary '{self.name}' failed: {boundary_error}")
        
        return False  # Let the exception propagate
    
    async def _handle_error_async(self, exception: Exception) -> bool:
        """Handle error in async context."""
        try:
            # Create error context
            self.error_context = ErrorContext(
                error_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                exception=exception,
                severity=self.severity,
                category=self.category,
                component=self.name,
                stack_trace=traceback.format_exc(),
                processing_time=asyncio.get_event_loop().time() - self.start_time if self.start_time else None
            )
            
            # Log the error
            logger.error(
                f"Error in async boundary '{self.name}': {type(exception).__name__}: {exception}",
                extra={
                    "error_id": self.error_context.error_id,
                    "boundary": self.name,
                    "severity": self.severity.value,
                    "category": self.category.value
                }
            )
            
            # Call custom error handler if provided
            if self.error_handler:
                try:
                    if asyncio.iscoroutinefunction(self.error_handler):
                        await self.error_handler(self.error_context)
                    else:
                        self.error_handler(self.error_context)
                except Exception as handler_error:
                    logger.error(f"Async error handler failed in boundary '{self.name}': {handler_error}")
            
            # Attempt recovery if enabled
            if self.recovery_enabled:
                recovery_result = await self._attempt_recovery_async()
                if recovery_result:
                    return True  # Suppress the exception
            
            # Use fallback if available
            if self.fallback_function:
                try:
                    if asyncio.iscoroutinefunction(self.fallback_function):
                        self.fallback_value = await self.fallback_function()
                    else:
                        self.fallback_value = self.fallback_function()
                    return True  # Suppress the exception
                except Exception as fallback_error:
                    logger.error(f"Async fallback function failed in boundary '{self.name}': {fallback_error}")
            
            if self.fallback_value is not None:
                return True  # Suppress the exception
            
            # Suppress errors if configured
            if self.suppress_errors:
                return True
            
        except Exception as boundary_error:
            logger.error(f"Async error boundary '{self.name}' failed: {boundary_error}")
        
        return False  # Let the exception propagate
    
    def _attempt_recovery(self) -> bool:
        """Attempt to recover from the error."""
        # Basic recovery logic - can be extended
        return False
    
    async def _attempt_recovery_async(self) -> bool:
        """Attempt to recover from the error in async context."""
        # Basic async recovery logic - can be extended
        return False
    
    def get_result(self) -> Any:
        """Get the result (fallback value if error occurred)."""
        return self.fallback_value


# Convenience functions for creating error boundaries
@contextmanager
def error_boundary(name: str, **kwargs):
    """Create a sync error boundary context manager."""
    boundary = ErrorBoundary(name, **kwargs)
    with boundary:
        yield boundary


@asynccontextmanager
async def async_error_boundary(name: str, **kwargs):
    """Create an async error boundary context manager."""
    boundary = ErrorBoundary(name, **kwargs)
    async with boundary:
        yield boundary


def safe_execute(func: Callable, *args, fallback_value=None, **kwargs) -> Any:
    """Safely execute a function with error boundary."""
    with error_boundary(
        name=f"safe_execute_{func.__name__}",
        fallback_value=fallback_value,
        suppress_errors=True
    ) as boundary:
        return func(*args, **kwargs)
    
    return boundary.get_result()


async def safe_execute_async(func: Callable, *args, fallback_value=None, **kwargs) -> Any:
    """Safely execute an async function with error boundary."""
    async with async_error_boundary(
        name=f"safe_execute_async_{func.__name__}",
        fallback_value=fallback_value,
        suppress_errors=True
    ) as boundary:
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            return func(*args, **kwargs)
    
    return boundary.get_result()


# Error context builder for complex scenarios
class ErrorContextBuilder:
    """Builder for creating complex error contexts."""
    
    def __init__(self):
        self.data = {}
    
    def with_error(self, exception: Exception) -> 'ErrorContextBuilder':
        """Set the exception."""
        self.data['exception'] = exception
        return self
    
    def with_severity(self, severity: ErrorSeverity) -> 'ErrorContextBuilder':
        """Set the severity."""
        self.data['severity'] = severity
        return self
    
    def with_category(self, category: ErrorCategory) -> 'ErrorContextBuilder':
        """Set the category."""
        self.data['category'] = category
        return self
    
    def with_component(self, component: str) -> 'ErrorContextBuilder':
        """Set the component."""
        self.data['component'] = component
        return self
    
    def with_user(self, user_id: str) -> 'ErrorContextBuilder':
        """Set the user ID."""
        self.data['user_id'] = user_id
        return self
    
    def with_request(self, request_id: str) -> 'ErrorContextBuilder':
        """Set the request ID."""
        self.data['request_id'] = request_id
        return self
    
    def with_context(self, context: Dict[str, Any]) -> 'ErrorContextBuilder':
        """Set additional context."""
        self.data['context'] = context
        return self
    
    def build(self) -> ErrorContext:
        """Build the error context."""
        return ErrorContext(
            error_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            stack_trace=traceback.format_exc(),
            **self.data
        )
