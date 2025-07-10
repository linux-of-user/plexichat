"""
Advanced error handling and recovery system with circuit breakers,
retry mechanisms, graceful degradation, and comprehensive error tracking.
"""

import asyncio
import time
import traceback
import sys
from typing import Dict, Any, Optional, Callable, List, Type
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from contextlib import asynccontextmanager
import json
import uuid

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration

from app.logger_config import logger
from app.core.config.settings import settings

class ErrorSeverity(str, Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class CircuitState(str, Enum):
    """Circuit breaker states."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

@dataclass
class ErrorContext:
    """Error context information."""
    error_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    user_id: Optional[int] = None
    request_id: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""
    failure_threshold: int = 5
    recovery_timeout: int = 60
    expected_exception: Type[Exception] = Exception
    fallback_function: Optional[Callable] = None

class CircuitBreaker:
    """Circuit breaker implementation for fault tolerance."""
    
    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = 0
        self.success_count = 0
    
    async def call(self, func: Callable, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure_time > self.config.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
            else:
                if self.config.fallback_function:
                    return await self.config.fallback_function(*args, **kwargs)
                raise HTTPException(
                    status_code=503,
                    detail="Service temporarily unavailable"
                )
        
        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except self.config.expected_exception as e:
            await self._on_failure()
            raise e
    
    async def _on_success(self):
        """Handle successful execution."""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= 3:  # Require 3 successes to close
                self.state = CircuitState.CLOSED
                self.failure_count = 0
        else:
            self.failure_count = max(0, self.failure_count - 1)
    
    async def _on_failure(self):
        """Handle failed execution."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.config.failure_threshold:
            self.state = CircuitState.OPEN
            logger.warning(f"Circuit breaker opened after {self.failure_count} failures")

class RetryConfig:
    """Retry configuration."""
    
    def __init__(self, max_attempts: int = 3, base_delay: float = 1.0, 
                 max_delay: float = 60.0, exponential_base: float = 2.0,
                 jitter: bool = True):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter

def retry_with_backoff(config: RetryConfig):
    """Decorator for retry with exponential backoff."""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(config.max_attempts):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    if attempt == config.max_attempts - 1:
                        break
                    
                    # Calculate delay with exponential backoff
                    delay = min(
                        config.base_delay * (config.exponential_base ** attempt),
                        config.max_delay
                    )
                    
                    # Add jitter to prevent thundering herd
                    if config.jitter:
                        import random
                        delay *= (0.5 + random.random() * 0.5)
                    
                    logger.warning(f"Attempt {attempt + 1} failed, retrying in {delay:.2f}s: {e}")
                    await asyncio.sleep(delay)
            
            raise last_exception
        return wrapper
    return decorator

class ErrorTracker:
    """Track and analyze errors for insights."""
    
    def __init__(self):
        self.error_counts = {}
        self.error_history = []
        self.max_history = 1000
    
    def record_error(self, error: Exception, context: ErrorContext):
        """Record an error occurrence."""
        error_key = f"{type(error).__name__}:{str(error)[:100]}"
        self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
        
        error_record = {
            'error_id': context.error_id,
            'timestamp': context.timestamp,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'context': context.__dict__
        }
        
        self.error_history.append(error_record)
        
        # Keep only recent errors
        if len(self.error_history) > self.max_history:
            self.error_history = self.error_history[-self.max_history:]
    
    def get_error_stats(self) -> Dict[str, Any]:
        """Get error statistics."""
        total_errors = len(self.error_history)
        recent_errors = [
            e for e in self.error_history 
            if time.time() - e['timestamp'] < 3600  # Last hour
        ]
        
        return {
            'total_errors': total_errors,
            'recent_errors': len(recent_errors),
            'top_errors': sorted(
                self.error_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
            'error_rate': len(recent_errors) / 60 if recent_errors else 0  # Per minute
        }

class ErrorHandler:
    """Centralized error handling system."""
    
    def __init__(self):
        self.circuit_breakers = {}
        self.error_tracker = ErrorTracker()
        self._initialize_sentry()
    
    def _initialize_sentry(self):
        """Initialize Sentry for error tracking."""
        sentry_dsn = getattr(settings, 'SENTRY_DSN', None)
        if sentry_dsn:
            sentry_sdk.init(
                dsn=sentry_dsn,
                integrations=[
                    FastApiIntegration(auto_enable=True),
                    SqlalchemyIntegration()
                ],
                traces_sample_rate=0.1,
                environment=getattr(settings, 'ENVIRONMENT', 'development')
            )
            logger.info("Sentry error tracking initialized")
    
    def get_circuit_breaker(self, name: str, config: CircuitBreakerConfig) -> CircuitBreaker:
        """Get or create a circuit breaker."""
        if name not in self.circuit_breakers:
            self.circuit_breakers[name] = CircuitBreaker(config)
        return self.circuit_breakers[name]
    
    async def handle_error(self, error: Exception, context: ErrorContext) -> JSONResponse:
        """Handle an error and return appropriate response."""
        # Record error
        self.error_tracker.record_error(error, context)
        
        # Log error
        logger.error(
            f"Error {context.error_id}: {type(error).__name__}: {error}",
            extra={
                'error_id': context.error_id,
                'user_id': context.user_id,
                'endpoint': context.endpoint,
                'traceback': traceback.format_exc()
            }
        )
        
        # Send to Sentry
        with sentry_sdk.push_scope() as scope:
            scope.set_tag("error_id", context.error_id)
            if context.user_id:
                scope.set_user({"id": context.user_id})
            if context.endpoint:
                scope.set_tag("endpoint", context.endpoint)
            
            sentry_sdk.capture_exception(error)
        
        # Determine error response
        if isinstance(error, HTTPException):
            return JSONResponse(
                status_code=error.status_code,
                content={
                    "error": "http_error",
                    "message": error.detail,
                    "error_id": context.error_id,
                    "timestamp": context.timestamp
                }
            )
        
        # Determine severity and response
        severity = self._determine_severity(error)
        status_code, error_type, message = self._get_error_response(error, severity)
        
        return JSONResponse(
            status_code=status_code,
            content={
                "error": error_type,
                "message": message,
                "error_id": context.error_id,
                "timestamp": context.timestamp,
                "severity": severity
            }
        )
    
    def _determine_severity(self, error: Exception) -> ErrorSeverity:
        """Determine error severity."""
        if isinstance(error, (ConnectionError, TimeoutError)):
            return ErrorSeverity.HIGH
        elif isinstance(error, (ValueError, TypeError)):
            return ErrorSeverity.MEDIUM
        elif isinstance(error, PermissionError):
            return ErrorSeverity.MEDIUM
        else:
            return ErrorSeverity.LOW
    
    def _get_error_response(self, error: Exception, severity: ErrorSeverity) -> tuple:
        """Get appropriate error response."""
        if severity == ErrorSeverity.CRITICAL:
            return 500, "critical_error", "A critical error occurred. Please try again later."
        elif severity == ErrorSeverity.HIGH:
            return 503, "service_error", "Service temporarily unavailable. Please try again."
        elif severity == ErrorSeverity.MEDIUM:
            return 400, "client_error", "Invalid request. Please check your input."
        else:
            return 500, "internal_error", "An unexpected error occurred."

class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Middleware for global error handling."""
    
    def __init__(self, app, error_handler: ErrorHandler):
        super().__init__(app)
        self.error_handler = error_handler
    
    async def dispatch(self, request: Request, call_next):
        """Handle requests with error catching."""
        try:
            response = await call_next(request)
            return response
        except Exception as error:
            # Create error context
            context = ErrorContext(
                user_id=getattr(request.state, 'user_id', None),
                request_id=getattr(request.state, 'request_id', None),
                endpoint=request.url.path,
                method=request.method,
                user_agent=request.headers.get('user-agent'),
                ip_address=request.client.host if request.client else None
            )
            
            return await self.error_handler.handle_error(error, context)

@asynccontextmanager
async def error_boundary(name: str, fallback_value=None, 
                        circuit_breaker_config: Optional[CircuitBreakerConfig] = None):
    """Context manager for error boundaries with optional circuit breaker."""
    try:
        if circuit_breaker_config:
            circuit_breaker = error_handler.get_circuit_breaker(name, circuit_breaker_config)
            # Note: This is a simplified version - full implementation would need more work
        
        yield
    except Exception as e:
        logger.error(f"Error in boundary '{name}': {e}")
        if fallback_value is not None:
            return fallback_value
        raise

def graceful_degradation(fallback_func: Callable):
    """Decorator for graceful degradation."""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                logger.warning(f"Function {func.__name__} failed, using fallback: {e}")
                return await fallback_func(*args, **kwargs)
        return wrapper
    return decorator

# Global error handler instance
error_handler = ErrorHandler()

# Utility functions
async def safe_execute(func: Callable, *args, default=None, **kwargs):
    """Safely execute a function with error handling."""
    try:
        return await func(*args, **kwargs)
    except Exception as e:
        logger.error(f"Safe execution failed for {func.__name__}: {e}")
        return default

def create_error_response(message: str, error_code: str = "error", 
                         status_code: int = 500, details: Dict[str, Any] = None) -> JSONResponse:
    """Create standardized error response."""
    content = {
        "error": error_code,
        "message": message,
        "timestamp": time.time(),
        "error_id": str(uuid.uuid4())
    }
    
    if details:
        content["details"] = details
    
    return JSONResponse(status_code=status_code, content=content)

# Health check with error tracking
async def health_check_with_errors() -> Dict[str, Any]:
    """Health check that includes error statistics."""
    error_stats = error_handler.error_tracker.get_error_stats()
    
    # Determine health status based on error rate
    if error_stats['error_rate'] > 10:  # More than 10 errors per minute
        status = "unhealthy"
    elif error_stats['error_rate'] > 5:
        status = "degraded"
    else:
        status = "healthy"
    
    return {
        "status": status,
        "error_stats": error_stats,
        "circuit_breakers": {
            name: {
                "state": cb.state,
                "failure_count": cb.failure_count
            }
            for name, cb in error_handler.circuit_breakers.items()
        }
    }
