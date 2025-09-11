import json
import logging
import re
import sys
from enum import Enum
from logging.handlers import RotatingFileHandler
from typing import List, Optional

# Default PII patterns for redaction (consolidated from plan)
DEFAULT_PII_PATTERNS = [
    r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
    r"\b\d{16}\b",  # Credit card
    r"\b[A-Z]{2}\d{6}\b",  # Passport-like
]


class LogCategory(Enum):
    """Logging categories for structured logs."""

    GENERAL = "general"
    SECURITY = "security"
    PERFORMANCE = "performance"
    AUDIT = "audit"
    DATABASE = "database"
    ERROR = "error"


class ColoredFormatter(logging.Formatter):
    """Colored console formatter using ANSI codes."""

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m",
    }

    def __init__(self, fmt: str = None, datefmt: str = None, sanitize_func=None):
        self.sanitize_func = sanitize_func
        super().__init__(fmt=fmt, datefmt=datefmt)
        if self.sanitize_func is None:
            self.sanitize_func = lambda x: x

    def format(self, record):
        log_message = super().format(record)
        log_message = self.sanitize_func(log_message)
        color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
        return f"{color}{log_message}{self.COLORS['RESET']}"


class StructuredFormatter(logging.Formatter):
    """JSON structured formatter for logs."""

    def __init__(self, sanitize_func=None):
        self.sanitize_func = sanitize_func
        super().__init__(
            fmt="%(asctime)s %(levelname)s %(message)s %(module)s:%(lineno)d"
        )
        if self.sanitize_func is None:
            self.sanitize_func = lambda x: x

    def format(self, record):
        log_dict = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "message": self.sanitize_func(record.getMessage()),
            "module": record.module,
            "lineno": record.lineno,
            "exc_info": (
                self.formatException(record.exc_info) if record.exc_info else None
            ),
        }
        return json.dumps(log_dict)


def redact_pii(message: str, patterns: Optional[List[str]] = None) -> str:
    """Redact PII from message using regex patterns."""
    if patterns is None:
        patterns = DEFAULT_PII_PATTERNS
    for pattern in patterns:
        message = re.sub(pattern, "[REDACTED]", message)
    return message


def sanitize_for_logging(message: str) -> str:
    """Sanitize message for logging: handle Unicode and apply PII redaction."""
    # Handle Unicode: encode/decode with replacement for invalid chars
    try:
        message.encode("utf-8", errors="replace").decode("utf-8")
    except UnicodeError:
        message = message.encode("utf-8", errors="replace").decode("utf-8")
    # Chain with PII redaction
    return redact_pii(message)


def get_handler_factory(
    level: str = "INFO",
    format_type: str = "colored",
    rotation_max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    log_file: str = "app.log",
    sanitize_func=None,
) -> logging.Handler:
    """Factory for creating configured handlers."""
    handler = RotatingFileHandler(
        log_file, maxBytes=rotation_max_bytes, backupCount=backup_count
    )
    handler.setLevel(getattr(logging, level.upper()))

    if format_type == "colored":
        formatter = ColoredFormatter(sanitize_func=sanitize_func)
        handler.setFormatter(formatter)
    elif format_type == "structured":
        formatter = StructuredFormatter(sanitize_func=sanitize_func)
        handler.setFormatter(formatter)
    else:
        handler.setFormatter(logging.Formatter())

    # For console, add stream handler if format_type colored
    if format_type == "colored":
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, level.upper()))
        console_handler.setFormatter(ColoredFormatter(sanitize_func=sanitize_func))
        return [handler, console_handler]
    return handler


class EnhancedLogger:
    """Enhanced logger with security, audit, and other specialized methods."""
    
    def __init__(self, logger: logging.Logger):
        self._logger = logger
    
    def __getattr__(self, name):
        # Delegate all standard logging methods to the underlying logger
        return getattr(self._logger, name)
    
    def security(self, message: str, *args, **kwargs):
        """Log security-related messages."""
        self._logger.warning(f"[SECURITY] {message}", *args, **kwargs)
    
    def audit(self, message: str, *args, **kwargs):
        """Log audit-related messages."""  
        self._logger.info(f"[AUDIT] {message}", *args, **kwargs)


def get_logger(name: str = "plexichat", level: str = "INFO") -> EnhancedLogger:
    """Get configured logger with sanitization and enhanced methods."""
    logger = logging.getLogger(name)
    if not logger.handlers:  # Avoid duplicate handlers
        logger.setLevel(getattr(logging, level.upper()))

        # Default to structured file + colored console
        handlers = get_handler_factory(
            level=level, format_type="structured", sanitize_func=sanitize_for_logging
        )
        if isinstance(handlers, list):
            for h in handlers:
                logger.addHandler(h)
        else:
            logger.addHandler(handlers)

    # Return enhanced logger wrapper
    return EnhancedLogger(logger)


# Make utilities available at module level
__all__ = [
    "get_logger",
    "redact_pii",
    "sanitize_for_logging",
    "ColoredFormatter",
    "StructuredFormatter",
    "get_handler_factory",
    "LogCategory",
    "DEFAULT_PII_PATTERNS",
    "EnhancedLogger",
]


def get_logging_manager(name: str = "plexichat", level: str = "INFO") -> EnhancedLogger:
    """
    Get the unified logging manager instance for the application.
    Returns a configured logger with sanitization and handlers.
    """
    return get_logger(name, level)


__all__.append("get_logging_manager")