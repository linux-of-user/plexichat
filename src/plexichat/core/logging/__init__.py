# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Core Logging System - SINGLE SOURCE OF TRUTH

Consolidates ALL logging components into a unified system:
- Unified Logging Management
- Structured JSON Logging
- Performance Monitoring
- Real-time Log Streaming
- Security and Audit Logging
- Colorized Console Output
- File Rotation and Compression
- Alert Integration

This module replaces and consolidates:
- core/logging.py - ENHANCED AND INTEGRATED
- core/logging_advanced/ - INTEGRATED
- infrastructure/utils/enhanced_logging.py - INTEGRATED
"""

import warnings
from typing import Optional, Dict, Any

# Import unified logging system (NEW SINGLE SOURCE OF TRUTH)
try:
    from .unified_logging import (
        # Main classes
        UnifiedLoggingManager,
        unified_logging_manager,
        UnifiedLogger,

        # Enums and data classes
        LogLevel,
        LogCategory,
        LogContext,
        LogEntry,

        # Formatters and utilities
        ColoredFormatter,
        StructuredFormatter,
        PerformanceTracker,
        LogBuffer,
        PerformanceTimer,

        # Main functions
        get_logger,
        get_logging_manager,
        setup_module_logging,

        # Backward compatibility functions
        log_performance,
        log_request,
        log_error,
        log_audit_event,
        timer,
        flush_logs,
    )

    # Backward compatibility aliases
    logging_manager = unified_logging_manager
    LoggingManager = UnifiedLoggingManager

except ImportError as e:
    # Fallback definitions if unified logging fails to import
    import logging

    warnings.warn(
        f"Failed to import unified logging system: {e}. Using fallback logging.",
        ImportWarning,
        stacklevel=2
    )

    class LogLevel:
        TRACE = 5
        DEBUG = 10
        INFO = 20
        WARNING = 30
        ERROR = 40
        CRITICAL = 50
        SECURITY = 60
        AUDIT = 70

    class LogCategory:
        SYSTEM = "system"
        SECURITY = "security"
        PERFORMANCE = "performance"
        API = "api"
        DATABASE = "database"

    class UnifiedLoggingManager:
        def get_logger(self, name: str):
            return logging.getLogger(name)

        def flush_logs(self):
            pass

        def shutdown(self):
            pass

    class UnifiedLogger:
        def __init__(self, name: str):
            self.logger = logging.getLogger(name)

        def info(self, message: str, **kwargs):
            self.logger.info(message)

        def error(self, message: str, **kwargs):
            self.logger.error(message)

        def warning(self, message: str, **kwargs):
            self.logger.warning(message)

        def debug(self, message: str, **kwargs):
            self.logger.debug(message)

    unified_logging_manager = UnifiedLoggingManager()
    logging_manager = unified_logging_manager
    LoggingManager = UnifiedLoggingManager

    def get_logger(name: str = "plexichat"):
        return logging.getLogger(name)

    def get_logging_manager():
        return unified_logging_manager

    def setup_module_logging(module_name: str, level: str = "INFO"):
        logger = logging.getLogger(module_name)
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        return logger

    def log_performance(operation: str, duration: float, **kwargs):
        logger = logging.getLogger("plexichat.performance")
        logger.info(f"Performance: {operation} took {duration:.3f}s")

    def log_request(method: str, path: str, status_code: int, duration: float, **kwargs):
        logger = logging.getLogger("plexichat.access")
        logger.info(f"{method} {path} {status_code} ({duration:.3f}s)")

    def log_error(error: Exception, context: str = "", **kwargs):
        logger = logging.getLogger("plexichat.error")
        logger.error(f"{context}: {str(error)}")

    def log_audit_event(event_type: str, user_id: Optional[str], details: Dict[str, Any]):
        logger = logging.getLogger("plexichat.audit")
        logger.info(f"Audit: {event_type} by user {user_id}")

    def timer(operation: str, **kwargs):
        def decorator(func):
            def wrapper(*args, **func_kwargs):
                import time
                start_time = time.time()
                try:
                    result = func(*args, **func_kwargs)
                    duration = time.time() - start_time
                    log_performance(operation, duration, **kwargs)
                    return result
                except Exception:
                    duration = time.time() - start_time
                    log_performance(f"{operation} (error)", duration, **kwargs)
                    raise
            return wrapper
        return decorator

    def flush_logs():
        pass

    # Fallback classes
    class LogContext:
        pass

    class LogEntry:
        pass

    class ColoredFormatter(logging.Formatter):
        pass

    class StructuredFormatter(logging.Formatter):
        pass

    class PerformanceTracker:
        pass

    class LogBuffer:
        pass

    class PerformanceTimer:
        pass

# Import legacy components for backward compatibility
try:
    from .performance_logger import get_performance_logger
except ImportError:
    def get_performance_logger():
        return None

try:
    from .security_logger import get_security_logger
except ImportError:
    def get_security_logger():
        return get_logger("plexichat.security")

# Setup commonly used loggers
audit_logger = get_logger("plexichat.audit")
security_logger = get_logger("plexichat.security")
performance_logger = get_logger("plexichat.performance")
access_logger = get_logger("plexichat.access")

# Export all the main classes and functions
__all__ = [
    # Unified logging system (NEW SINGLE SOURCE OF TRUTH)
    "UnifiedLoggingManager",
    "unified_logging_manager",
    "UnifiedLogger",

    # Enums and data classes
    "LogLevel",
    "LogCategory",
    "LogContext",
    "LogEntry",

    # Formatters and utilities
    "ColoredFormatter",
    "StructuredFormatter",
    "PerformanceTracker",
    "LogBuffer",
    "PerformanceTimer",

    # Main functions
    "get_logger",
    "get_logging_manager",
    "setup_module_logging",

    # Backward compatibility functions
    "log_performance",
    "log_request",
    "log_error",
    "log_audit_event",
    "timer",
    "flush_logs",

    # Backward compatibility aliases
    "logging_manager",
    "LoggingManager",

    # Legacy functions
    "get_performance_logger",
    "get_security_logger",

    # Common loggers
    "audit_logger",
    "security_logger",
    "performance_logger",
    "access_logger",
]

__version__ = "3.0.0"
