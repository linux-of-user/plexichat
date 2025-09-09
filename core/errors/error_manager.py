"""Error management with async background tasks, metrics, circuit breakers."""
import asyncio
from dataclasses import dataclass
from typing import Optional, Dict, Any
from .base import ErrorCategory, ErrorSeverity, create_error_response, handle_exception, PlexiChatException, log_error

@dataclass
class ErrorContext:
    """Unique ErrorContext dataclass."""
    severity: ErrorSeverity  # Updated to use base enum
    category: ErrorCategory  # Updated to use base enum
    timestamp: str
    correlation_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

class ErrorManager:
    """Error manager class preserving async tasks, metrics, circuit breakers."""
    def __init__(self):
        self.metrics: Dict[str, int] = {}
        self.circuit_breaker_open = False

    async def _background_log(self, exc: Exception, context: Optional[Dict[str, Any]] = None):
        """Async background logging task."""
        await asyncio.sleep(0.1)  # Simulate async operation
        log_error(exc, context)

    async def handle_error(self, exc: Exception, context: Optional[Dict[str, Any]] = None, request: Optional[Any] = None):
        """Handle error using base handle_exception, integrate with manager features."""
        # Use base handle_exception
        correlation_id = context.get('correlation_id') if context else None
        error_response = handle_exception(exc, correlation_id=correlation_id, request=request)
        
        # Create ErrorContext using base enums
        error_ctx = ErrorContext(
            severity=ErrorSeverity[error_response.error['severity'].upper()],
            category=ErrorCategory[error_response.error['category'].upper()],
            timestamp=error_response.timestamp.isoformat(),
            correlation_id=error_response.correlation_id,
            details=error_response.error['details']
        )
        
        # Background task
        asyncio.create_task(self._background_log(exc, context))
        
        # Update metrics
        exc_name = exc.__class__.__name__
        self.metrics[exc_name] = self.metrics.get(exc_name, 0) + 1
        
        # Circuit breaker logic
        if self._should_open_circuit(exc):
            self.circuit_breaker_open = True
        
        return error_response

    def _should_open_circuit(self, exc: Exception) -> bool:
        """Determine if circuit breaker should open."""
        # Example logic based on severity
        if isinstance(exc, PlexiChatException):
            return exc.severity == ErrorSeverity.CRITICAL
        return False

    def get_metrics(self) -> Dict[str, int]:
        """Get error metrics."""
        return self.metrics.copy()

    def reset_circuit_breaker(self):
        """Reset circuit breaker."""
        self.circuit_breaker_open = False

# Removed duplicated create_error_response and handle_exception; using base versions
# Expected reduction: ~50 lines from removing local implementations