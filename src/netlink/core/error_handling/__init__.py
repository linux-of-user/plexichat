"""
NetLink Core Error Handling System - Unified Error Management

Consolidates all error handling components into a single, comprehensive module
with advanced error tracking, recovery mechanisms, and comprehensive logging.

This unified system replaces and consolidates:
- src/netlink/app/error_handling/
- src/netlink/app/core/error_handling/
- src/netlink/app/utils/monitoring/error_handler.py

Features:
- Comprehensive error classification and tracking
- Advanced error recovery mechanisms with circuit breakers
- Crash reporting with detailed context and analytics
- Standardized error codes with user-friendly messages
- Real-time error monitoring and alerting
- Error pattern analysis and prediction
- Integration with logging and monitoring systems
- Automatic error reporting to external services
- Error boundary management for fault isolation
"""

# Import existing error handling components (consolidated)
from ..app.core.error_handling.error_codes import ErrorCode, ErrorDetails, error_code_manager
from ..app.core.error_handling.exceptions import (
    BaseAPIException, ValidationError, AuthenticationError, AuthorizationError,
    DatabaseError, NetworkError, ExternalServiceError, FileError, RateLimitError
)
from ..app.core.error_handling.crash_reporter import CrashReporter, crash_reporter, CrashContext
from ..app.core.error_handling.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitState
from ..app.core.error_handling.enhanced_error_handler import EnhancedErrorHandler

# Import new unified components
from .error_manager import ErrorManager, error_manager
from .error_recovery import ErrorRecoveryManager, recovery_manager
from .error_monitor import ErrorMonitor, error_monitor
from .error_analytics import ErrorAnalytics, error_analytics
from .decorators import error_handler, crash_handler, circuit_breaker, retry
from .middleware import ErrorHandlingMiddleware
from .context import ErrorContext, ErrorBoundary
from .reporting import ErrorReporter, error_reporter

__version__ = "2.0.0"
__all__ = [
    # Core error management
    "ErrorManager",
    "error_manager",
    
    # Error codes and details
    "ErrorCode",
    "ErrorDetails", 
    "error_code_manager",
    
    # Exception classes
    "BaseAPIException",
    "ValidationError",
    "AuthenticationError",
    "AuthorizationError",
    "DatabaseError",
    "NetworkError",
    "ExternalServiceError",
    "FileError",
    "RateLimitError",
    
    # Crash reporting
    "CrashReporter",
    "crash_reporter",
    "CrashContext",
    
    # Circuit breaker
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitState",
    
    # Error recovery
    "ErrorRecoveryManager",
    "recovery_manager",
    
    # Error monitoring
    "ErrorMonitor",
    "error_monitor",
    
    # Error analytics
    "ErrorAnalytics",
    "error_analytics",
    
    # Error context and boundaries
    "ErrorContext",
    "ErrorBoundary",
    
    # Error reporting
    "ErrorReporter",
    "error_reporter",
    
    # Middleware
    "ErrorHandlingMiddleware",
    
    # Decorators
    "error_handler",
    "crash_handler", 
    "circuit_breaker",
    "retry"
]

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

async def initialize_error_handling_system(config: dict = None) -> bool:
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
        
        # Initialize core components
        await error_manager.initialize(system_config)
        await crash_reporter.initialize(system_config)
        await recovery_manager.initialize(system_config)
        await error_monitor.initialize(system_config)
        await error_analytics.initialize(system_config)
        await error_reporter.initialize(system_config)
        
        return True
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"❌ Failed to initialize error handling system: {e}")
        return False

async def shutdown_error_handling_system():
    """Gracefully shutdown the error handling system."""
    try:
        # Shutdown components in reverse order
        await error_reporter.shutdown()
        await error_analytics.shutdown()
        await error_monitor.shutdown()
        await recovery_manager.shutdown()
        await crash_reporter.shutdown()
        await error_manager.shutdown()
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"❌ Error during error handling system shutdown: {e}")

# Convenience functions for common operations
def handle_error(exception: Exception, context: dict = None, severity: str = "MEDIUM") -> ErrorContext:
    """Handle an error with comprehensive logging and recovery."""
    return error_manager.handle_error(exception, context, severity)

def report_crash(exception: Exception, context: dict = None) -> CrashContext:
    """Report a crash with detailed context."""
    return crash_reporter.report_crash(exception, context)

def get_error_statistics() -> dict:
    """Get current error statistics."""
    return error_monitor.get_statistics()

def create_circuit_breaker(name: str, config: dict = None) -> CircuitBreaker:
    """Create a circuit breaker with the specified configuration."""
    return error_manager.create_circuit_breaker(name, config)

def register_recovery_strategy(error_type: type, strategy_func: callable):
    """Register a custom error recovery strategy."""
    recovery_manager.register_strategy(error_type, strategy_func)

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
                recovery_result = recovery_manager.attempt_recovery(exc_val, error_context)
                if recovery_result:
                    return True  # Suppress the exception
            
            # Use fallback value if provided
            if self.fallback_value is not None:
                return True  # Suppress the exception
        
        return False  # Let the exception propagate
