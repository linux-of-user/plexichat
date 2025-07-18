"""
import asyncio
PlexiChat Error Handling System

Centralized error handling, monitoring, and recovery system.
This is the ONLY place for error handling in the entire application.
"""

import logging
from typing import Any, Callable, Dict, List, Optional

# Core imports - only import what actually exists
try:
    from .exceptions import (
        ErrorSeverity,
        ErrorCategory,
        BaseAPIException,
        AuthenticationError,
        AuthorizationError,
        DatabaseError,
        NetworkError,
        ValidationError,
        FileError,
        ExternalServiceError,
        RateLimitError,
    )
except ImportError:
    # Define basic exceptions if the module doesn't exist
    class ErrorSeverity:
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"

    class ErrorCategory:
        SYSTEM = "system"
        USER = "user"
        NETWORK = "network"
        DATABASE = "database"

    class BaseAPIException(Exception):
        pass

    class AuthenticationError(BaseAPIException):
        pass

    class AuthorizationError(BaseAPIException):
        pass

    class DatabaseError(BaseAPIException):
        pass

    class NetworkError(BaseAPIException):
        pass

    class ValidationError(BaseAPIException):
        pass

    class FileError(BaseAPIException):
        pass

    class ExternalServiceError(BaseAPIException):
        pass

    class RateLimitError(BaseAPIException):
        pass

# Try to import enhanced components
try:
    from .enhanced_error_handler import EnhancedErrorHandler
except ImportError:
    EnhancedErrorHandler = None

try:
    from .circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitState
except ImportError:
    CircuitBreaker = None
    CircuitBreakerConfig = None
    CircuitState = None

try:
    from .crash_reporter import CrashContext, CrashReporter
except ImportError:
    CrashContext = None
    CrashReporter = None

# Logger for this module
logger = logging.getLogger(__name__)

# Export main classes and functions
__all__ = [
    'ErrorSeverity',
    'ErrorCategory',
    'BaseAPIException',
    'AuthenticationError',
    'AuthorizationError',
    'DatabaseError',
    'NetworkError',
    'ValidationError',
    'FileError',
    'ExternalServiceError',
    'RateLimitError',
    'handle_error',
    'setup_error_handling',
    'global_error_handler',
]

# Add optional components to exports if they exist
if CircuitBreaker:
    __all__.extend(['CircuitBreaker', 'CircuitBreakerConfig', 'CircuitState'])
if CrashReporter:
    __all__.extend(['CrashReporter', 'CrashContext'])
if EnhancedErrorHandler:
    __all__.append('EnhancedErrorHandler')

# Initialize global error handler if available
try:
    if EnhancedErrorHandler:
        global_error_handler = EnhancedErrorHandler()
    else:
        global_error_handler = None
except Exception as e:
    logger.warning(f"Could not initialize global error handler: {e}")
    global_error_handler = None

# Initialize crash reporter if available
try:
    if CrashReporter:
        global_crash_reporter = CrashReporter()
    else:
        global_crash_reporter = None
except Exception as e:
    logger.warning(f"Could not initialize crash reporter: {e}")
    global_crash_reporter = None

# Module version
__version__ = "2.0.0"

# Global recovery strategies registry
_recovery_strategies: Dict[type, Callable] = {}

# Error handling system constants
ERROR_SYSTEM_VERSION = "2.0.0"
MAX_ERROR_HISTORY = 10000
DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5
DEFAULT_RECOVERY_ATTEMPTS = 3
ERROR_REPORTING_ENABLED = True

# Error severity levels
ERROR_SEVERITY_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
    "EMERGENCY": 5
}

# Error categories
ERROR_CATEGORIES = {
    "SYSTEM": "system",
    "AUTHENTICATION": "authentication",
    "AUTHORIZATION": "authorization",
    "VALIDATION": "validation",
    "DATABASE": "database",
    "NETWORK": "network",
    "EXTERNAL_SERVICE": "external_service",
    "FILE_OPERATION": "file_operation",
    "RATE_LIMITING": "rate_limiting",
    "BUSINESS_LOGIC": "business_logic",
    "UNKNOWN": "unknown"
}

# Default error handling configuration
DEFAULT_ERROR_CONFIG = {
    "error_tracking": {
        "enabled": True,
        "max_history_size": 10000,
        "cleanup_interval_hours": 24,
        "detailed_logging": True
    },
    "crash_reporting": {
        "enabled": True,
        "auto_report": True,
        "include_system_info": True,
        "include_stack_trace": True,
        "save_to_file": True,
        "send_to_external": False
    },
    "circuit_breaker": {
        "enabled": True,
        "default_failure_threshold": 5,
        "default_timeout_seconds": 60,
        "default_recovery_timeout": 30
    },
    "error_recovery": {
        "enabled": True,
        "max_retry_attempts": 3,
        "retry_delay_seconds": 1,
        "exponential_backoff": True
    },
    "monitoring": {
        "enabled": True,
        "real_time_alerts": True,
        "error_rate_threshold": 0.05,
        "performance_tracking": True
    },
    "analytics": {
        "enabled": True,
        "pattern_detection": True,
        "trend_analysis": True,
        "predictive_alerts": True
    },
    "reporting": {
        "enabled": True,
        "external_services": [],
        "notification_channels": [],
        "report_frequency": "immediate"
    }
}

# Error response templates
ERROR_RESPONSE_TEMPLATES = {
    "api_error": {
        "error": "{error_type}",
        "message": "{message}",
        "error_id": "{error_id}",
        "timestamp": "{timestamp}",
        "details": "{details}"
    },
    "user_friendly": {
        "success": False,
        "message": "{user_message}",
        "error_code": "{error_code}",
        "support_id": "{error_id}"
    },
    "detailed": {
        "error": {
            "type": "{error_type}",
            "code": "{error_code}",
            "message": "{message}",
            "details": "{details}",
            "context": "{context}",
            "stack_trace": "{stack_trace}",
            "recovery_suggestions": "{recovery_suggestions}"
        },
        "request": {
            "id": "{request_id}",
            "timestamp": "{timestamp}",
            "endpoint": "{endpoint}",
            "method": "{method}"
        },
        "system": {
            "version": "{system_version}",
            "environment": "{environment}"
        }
    }
}

# Circuit breaker configurations for different services
CIRCUIT_BREAKER_CONFIGS = {
    "database": {
        "failure_threshold": 3,
        "timeout_seconds": 30,
        "recovery_timeout": 60,
        "expected_exceptions": [DatabaseError]
    },
    "external_api": {
        "failure_threshold": 5,
        "timeout_seconds": 10,
        "recovery_timeout": 30,
        "expected_exceptions": [NetworkError, ExternalServiceError]
    },
    "file_operations": {
        "failure_threshold": 3,
        "timeout_seconds": 15,
        "recovery_timeout": 45,
        "expected_exceptions": [FileError]
    },
    "authentication": {
        "failure_threshold": 10,
        "timeout_seconds": 5,
        "recovery_timeout": 300,  # 5 minutes
        "expected_exceptions": [AuthenticationError]
    }
}

# Error recovery strategies
RECOVERY_STRATEGIES = {
    "retry": {
        "max_attempts": 3,
        "delay_seconds": 1,
        "exponential_backoff": True,
        "applicable_errors": [NetworkError, ExternalServiceError]
    },
    "fallback": {
        "use_cache": True,
        "default_response": True,
        "applicable_errors": [ExternalServiceError, DatabaseError]
    },
    "circuit_breaker": {
        "auto_enable": True,
        "applicable_errors": [NetworkError, ExternalServiceError, DatabaseError]
    },
    "graceful_degradation": {
        "disable_features": True,
        "notify_users": True,
        "applicable_errors": [ExternalServiceError, DatabaseError]
    }
}

# Monitoring thresholds
MONITORING_THRESHOLDS = {
    "error_rate": {
        "warning": 0.02,  # 2%
        "critical": 0.05  # 5%
    },
    "response_time": {
        "warning": 2.0,   # 2 seconds
        "critical": 5.0   # 5 seconds
    },
    "circuit_breaker_trips": {
        "warning": 3,
        "critical": 5
    },
    "crash_frequency": {
        "warning": 5,     # per hour
        "critical": 10    # per hour
    }
}

# External service integrations
EXTERNAL_INTEGRATIONS = {
    "sentry": {
        "enabled": False,
        "dsn": None,
        "environment": "production",
        "sample_rate": 1.0
    },
    "rollbar": {
        "enabled": False,
        "access_token": None,
        "environment": "production"
    },
    "bugsnag": {
        "enabled": False,
        "api_key": None,
        "release_stage": "production"
    },
    "slack": {
        "enabled": False,
        "webhook_url": None,
        "channel": "#alerts"
    },
    "email": {
        "enabled": False,
        "smtp_server": None,
        "recipients": []
    }
}

async def initialize_error_handling_system(config: Optional[Dict[str, Any]] = None) -> bool:
    """
    Initialize the unified error handling system.

    Args:
        config: Optional configuration dictionary

    Returns:
        bool: True if initialization successful
    """
    try:
        # Merge with default configuration
        system_config = DEFAULT_ERROR_CONFIG.copy()
        if config:
            system_config.update(config)

        # Initialize core components if available
        if global_error_handler:
            logger.info("Error handler initialized")
        if global_crash_reporter:
            logger.info("Crash reporter initialized")

        return True

    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Error during error handling system initialization: {e}", exc_info=True)
        return False

async def shutdown_error_handling_system():
    """Gracefully shutdown the error handling system."""
    try:
        # Shutdown components in reverse order with error handling
        components = [
            ('error_reporter', error_reporter),
            ('error_analytics', error_analytics),
            ('error_monitor', error_monitor),
            ('recovery_manager', recovery_manager),
            ('crash_reporter', crash_reporter),
            ('error_manager', error_manager)
        ]

        for name, component in components:
            try:
                if component and hasattr(component, 'shutdown'):
                    if asyncio.iscoroutinefunction(component.shutdown):
                        await component.shutdown()
                    else:
                        component.shutdown()
            except Exception as e:
                logger.info(f"Warning: Failed to shutdown {name}: {e}")

    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Error during error handling system shutdown: {e}")

# Convenience functions for common operations
logger = logging.getLogger(__name__)
def handle_error(exception: Exception, context: Optional[Dict[str, Any]] = None, severity: str = "MEDIUM") -> Optional['ErrorContext']:
    """Handle an error with comprehensive logging and recovery."""
    try:
        # Convert string severity to enum
        severity_map = {
            "LOW": ErrorSeverity.LOW,
            "MEDIUM": ErrorSeverity.MEDIUM,
            "HIGH": ErrorSeverity.HIGH,
            "CRITICAL": ErrorSeverity.CRITICAL
        }
        severity_enum = severity_map.get(severity.upper(), ErrorSeverity.MEDIUM)

        if global_error_handler:
            # Use the enhanced error handler if available
            try:
                return global_error_handler.handle_error(exception, context or {})
            except Exception as handler_error:
                logger.error(f"Error handler failed: {handler_error}")

        # Fallback error handling
        error_info = {
            "exception_type": type(exception).__name__,
            "message": str(exception),
            "severity": severity,
            "context": context or {},
            "timestamp": logger.handlers[0].formatter.formatTime(logging.LogRecord("", 0, "", 0, "", (), None)) if logger.handlers else "unknown"
        }
        logger.error(f"Error handled: {error_info}")
        return error_info
    except Exception as e:
        logger.info(f"Error in handle_error: {e}")
        return None

def report_crash(exception: Exception, context: Optional[Dict[str, Any]] = None):
    """Report a crash with detailed context."""
    try:
        if crash_reporter:
            return crash_reporter.report_crash(exception, ErrorSeverity.CRITICAL, additional_context=context or {})
        else:
            logger.info(f"Crash: {exception}")
            return None
    except Exception as e:
        logger.info(f"Error in report_crash: {e}")
        return None

def get_error_statistics() -> Dict[str, Any]:
    """Get current error statistics."""
    try:
        # Return basic statistics since we don't have a complex monitor
        return {
            "total_errors": 0,
            "error_rate": 0.0,
            "last_error": None,
            "status": "monitoring_not_available"
        }
    except Exception as e:
        return {"error": f"Failed to get statistics: {e}"}

def create_circuit_breaker(name: str, config: Optional[Dict[str, Any]] = None):
    """Create a circuit breaker with the specified configuration."""
    if CircuitBreaker and CircuitBreakerConfig:
        breaker_config = CircuitBreakerConfig(**(config or {}))
        return CircuitBreaker(name, breaker_config)
    else:
        logger.warning("Circuit breaker not available")
        return None

def register_recovery_strategy(error_type: type, strategy_func: Callable):
    """Register a custom error recovery strategy."""
    logger.info(f"Recovery strategy registered for {error_type.__name__}: {strategy_func.__name__}")
    _recovery_strategies[error_type] = strategy_func

# Error boundary context manager
class ErrorBoundary:
    """Context manager for error boundaries with automatic recovery."""

    def __init__(self, name: str, fallback_value=None, recovery_enabled: bool = True):
        self.name = name
        self.fallback_value = fallback_value
        self.recovery_enabled = recovery_enabled

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            # Handle the error
            error_context = handle_error(exc_val, {"boundary": self.name})

            # Attempt recovery if enabled
            if self.recovery_enabled:
                # Try to use registered recovery strategies
                strategy = _recovery_strategies.get(type(exc_val))
                if strategy:
                    try:
                        recovery_result = strategy(exc_val, error_context)
                        if recovery_result:
                            return True  # Suppress the exception
                    except Exception as recovery_error:
                        logger.error(f"Recovery strategy failed: {recovery_error}")

            # Use fallback value if provided
            if self.fallback_value is not None:
                return True  # Suppress the exception

        return False  # Let the exception propagate
