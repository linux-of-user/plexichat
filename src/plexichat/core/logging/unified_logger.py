from collections.abc import Callable
from enum import Enum
import json
import logging
from logging.handlers import RotatingFileHandler
import re
import sys
from typing import ClassVar

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


SanitizeFunc = Callable[[str], str]


class ColoredFormatter(logging.Formatter):
    """Colored console formatter using ANSI codes."""

    COLORS: ClassVar[dict[str, str]] = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m",
    }

    def __init__(
        self,
        fmt: str | None = None,
        datefmt: str | None = None,
        sanitize_func: SanitizeFunc | None = None,
    ) -> None:
        self.sanitize_func: SanitizeFunc = sanitize_func or (lambda x: x)
        super().__init__(fmt=fmt, datefmt=datefmt)

    def format(self, record: logging.LogRecord) -> str:
        log_message = super().format(record)
        log_message = self.sanitize_func(log_message)
        color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
        return f"{color}{log_message}{self.COLORS['RESET']}"


class StructuredFormatter(logging.Formatter):
    """JSON structured formatter for logs."""

    def __init__(self, sanitize_func: SanitizeFunc | None = None) -> None:
        self.sanitize_func: SanitizeFunc = sanitize_func or (lambda x: x)
        super().__init__(
            fmt="%(asctime)s %(levelname)s %(message)s %(module)s:%(lineno)d"
        )

    def format(self, record: logging.LogRecord) -> str:
        log_dict: dict[str, str | int | None] = {
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


def redact_pii(message: str, patterns: list[str] | None = None) -> str:
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
    sanitize_func: SanitizeFunc | None = None,
) -> logging.Handler | list[logging.Handler]:
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


def get_logger(name: str = "plexichat", level: str = "INFO") -> logging.Logger:
    """Get configured logger with sanitization."""
    logger = logging.getLogger(name)
    if logger.handlers:  # Avoid duplicate handlers
        return logger
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

    # For plugins, extensible: e.g., logger.addHandler(get_handler_factory(plugin_mode='analytics'))
    return logger


def get_logging_manager(name: str = "plexichat", level: str = "INFO") -> logging.Logger:
    """
    Get the unified logging manager instance for the application.
    Returns a configured logger with sanitization and handlers.
    """
    return get_logger(name, level)


# Make utilities available at module level
__all__ = [
    "ColoredFormatter",
    "DEFAULT_PII_PATTERNS",
    "LogCategory",
    "StructuredFormatter",
    "get_handler_factory",
    "get_logger",
    "get_logging_manager",
    "redact_pii",
    "sanitize_for_logging",
]