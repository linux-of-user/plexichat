"""
Unified Logger for PlexiChat

Implements unified logging with:
- LoggerAdapter for per-plugin contexts
- Colorized console output using raw ANSI escape codes
- Rotating file handler with per-plugin isolation
- DeduplicationFilter to collapse repeat messages
- Canonical logger tree with root: plexichat
"""

import logging
import logging.handlers
import os
import re
import sys
import threading
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# PII Redaction patterns and fields from pii_redaction.py
PII_PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "phone": re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"),
    "ssn": re.compile(r"\b\d{3}[-]?\d{2}[-]?\d{4}\b"),
    "credit_card": re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
    "ip_address": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    "api_key": re.compile(r"\b[A-Za-z0-9]{32,}\b"),
    "password": re.compile(
        r'(?i)(password|passwd|pwd)[\'"]?\s*[:=]\s*[\'"]([^\'"]+)[\'"]'
    ),
    "token": re.compile(r"\b[A-Za-z0-9+/=]{20,}\b"),
}

SENSITIVE_FIELDS = {
    "password",
    "passwd",
    "pwd",
    "token",
    "key",
    "secret",
    "private_key",
    "access_token",
    "refresh_token",
    "auth_token",
    "api_key",
    "api_secret",
    "database_url",
    "db_url",
    "connection_string",
    "credit_card",
    "cc_number",
    "ssn",
    "social_security",
    "phone",
    "email",
    "ip_address",
    "user_agent",
}


class DeduplicationFilter(logging.Filter):
    """Filter to collapse duplicate log messages."""

    def __init__(self, max_cache_size: int = 1000):
        super().__init__()
        self.cache: Dict[str, int] = {}
        self.max_cache_size = max_cache_size
        self.lock = threading.Lock()

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter out duplicate messages within a short time window."""
        # Create a key from message and level
        key = f"{record.levelno}:{record.getMessage()}"

        with self.lock:
            current_time = datetime.now().timestamp()

            # Clean old entries
            to_remove = []
            for k, timestamp in self.cache.items():
                if current_time - timestamp > 60:  # 60 seconds window
                    to_remove.append(k)

            for k in to_remove:
                del self.cache[k]

            # Check if this is a duplicate
            if key in self.cache:
                # It's a duplicate, suppress it
                return False

            # Add to cache
            self.cache[key] = current_time

            # Limit cache size
            if len(self.cache) > self.max_cache_size:
                # Remove oldest entries
                sorted_items = sorted(self.cache.items(), key=lambda x: x[1])
                for i in range(len(sorted_items) - self.max_cache_size):
                    del self.cache[sorted_items[i][0]]

        return True


class PluginContextAdapter(logging.LoggerAdapter):
    """LoggerAdapter for per-plugin contexts."""

    def __init__(self, logger: logging.Logger, plugin_name: str):
        super().__init__(logger, {"plugin": plugin_name})
        self.plugin_name = plugin_name

    def process(self, msg: str, kwargs: Any) -> tuple:
        """Process the logging record to add plugin context."""
        # Add plugin name to the message
        if self.plugin_name:
            msg = f"[{self.plugin_name}] {msg}"

        # Add plugin to extra data
        extra = kwargs.get("extra", {})
        extra["plugin"] = self.plugin_name
        kwargs["extra"] = extra

        return msg, kwargs


class ColorizedConsoleHandler(logging.StreamHandler):
    """Console handler with ANSI color support."""

    # ANSI escape codes for colors (no Unicode)
    COLORS = {
        logging.DEBUG: "\033[36m",  # Cyan
        logging.INFO: "\033[32m",  # Green
        logging.WARNING: "\033[33m",  # Yellow
        logging.ERROR: "\033[31m",  # Red
        logging.CRITICAL: "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def __init__(self, stream=None):
        super().__init__(stream or sys.stdout)
        self.setFormatter(
            logging.Formatter("[%(asctime)s] [%(levelname)-8s] %(name)s: %(message)s")
        )

    def format(self, record: logging.LogRecord) -> str:
        """Format the record with color."""
        # Get the original formatted message
        message = super().format(record)

        # Add color if supported
        if hasattr(record, "levelno") and record.levelno in self.COLORS:
            color = self.COLORS[record.levelno]
            # Color only the level name
            level_start = message.find(f"[{record.levelname}")
            if level_start != -1:
                level_end = message.find("]", level_start) + 1
                if level_end > level_start:
                    colored_level = (
                        f"{color}{message[level_start:level_end]}{self.RESET}"
                    )
                    message = (
                        message[:level_start] + colored_level + message[level_end:]
                    )

        return message


class PluginIsolatedRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Rotating file handler with per-plugin isolation."""

    def __init__(
        self,
        plugin_name: str,
        base_log_dir: str = "logs/plugins",
        maxBytes: int = 10 * 1024 * 1024,
        backupCount: int = 5,
    ):
        self.plugin_name = plugin_name
        self.base_log_dir = Path(base_log_dir)

        # Create plugin-specific directory
        plugin_dir = self.base_log_dir / plugin_name
        plugin_dir.mkdir(parents=True, exist_ok=True)

        # Plugin-specific log file
        log_file = plugin_dir / f"{plugin_name}.log"

        super().__init__(str(log_file), maxBytes=maxBytes, backupCount=backupCount)

        self.setFormatter(
            logging.Formatter(
                "[%(asctime)s] [%(levelname)-8s] [%(name)s:%(lineno)d] %(funcName)s() - %(message)s"
            )
        )


class SanitizationFilter(logging.Filter):
    """Sanitize log records: redact secrets/tokens and force ASCII-only output."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
            # Redact common sensitive patterns
            import re

            patterns = [
                (r"(?i)(password\s*[:=]\s*)([^\s,}]+)", r"\1***"),
                (r"(?i)(token\s*[:=]\s*)([^\s,}]+)", r"\1***"),
                (r"(?i)(api[_-]?key\s*[:=]\s*)([^\s,}]+)", r"\1***"),
                (r"(?i)(secret\s*[:=]\s*)([^\s,}]+)", r"\1***"),
            ]
            for pat, repl in patterns:
                msg = re.sub(pat, repl, msg)
            # Force ASCII-safe output
            msg_ascii = msg.encode("ascii", errors="replace").decode("ascii")
            record.msg = msg_ascii
        except Exception:
            pass
        return True


class UnifiedLogger:
    """Unified logger with all required features."""

    _instance: Optional["UnifiedLogger"] = None
    _lock = threading.Lock()

    def __init__(self):
        self.root_logger = logging.getLogger("plexichat")
        self.root_logger.setLevel(logging.DEBUG)

        # Remove existing handlers to avoid duplicates
        self.root_logger.handlers.clear()

        # Setup console handler with colors
        self.console_handler = ColorizedConsoleHandler()
        self.console_handler.setLevel(logging.INFO)
        self.root_logger.addHandler(self.console_handler)

        # Setup main file handler (latest.txt). Rotation handled by run.py on startup.
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        main_log_file = log_dir / "latest.txt"

        self.main_file_handler = logging.FileHandler(
            str(main_log_file), encoding="utf-8"
        )
        self.main_file_handler.setLevel(logging.DEBUG)
        self.main_file_handler.setFormatter(
            logging.Formatter(
                "[%(asctime)s] [%(levelname)-8s] [%(name)s:%(lineno)d] %(funcName)s() - %(message)s"
            )
        )
        self.root_logger.addHandler(self.main_file_handler)

        # Add sanitization filter (redaction + ASCII)
        self.sanitize_filter = SanitizationFilter()
        self.root_logger.addFilter(self.sanitize_filter)

        # Deduplication filter
        self.dedup_filter = DeduplicationFilter()
        self.root_logger.addFilter(self.dedup_filter)

        # Filter to suppress stack traces unless DEBUG level
        class StackTraceFilter(logging.Filter):
            def filter(self, record: logging.LogRecord) -> bool:
                try:
                    if (
                        hasattr(record, "exc_info")
                        and record.exc_info
                        and record.levelno > logging.DEBUG
                    ):
                        record.exc_info = None
                except Exception:
                    pass
                return True

        self.stacktrace_filter = StackTraceFilter()
        self.root_logger.addFilter(self.stacktrace_filter)

        # Plugin loggers cache
        self.plugin_loggers: Dict[str, logging.LoggerAdapter] = {}

    def get_plugin_logger(self, plugin_name: str) -> logging.LoggerAdapter:
        """Get a logger adapter for a specific plugin."""
        if plugin_name not in self.plugin_loggers:
            # Create plugin-specific logger
            plugin_logger = self.root_logger.getChild(f"plugins.{plugin_name}")

            # Create adapter
            adapter = PluginContextAdapter(plugin_logger, plugin_name)

            # Add plugin-specific file handler
            plugin_file_handler = PluginIsolatedRotatingFileHandler(plugin_name)
            plugin_logger.addHandler(plugin_file_handler)
            plugin_logger.setLevel(logging.DEBUG)

            self.plugin_loggers[plugin_name] = adapter

        return self.plugin_loggers[plugin_name]

    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger under the plexichat namespace."""
        return self.root_logger.getChild(name)

    def set_console_level(self, level: str):
        """Set console logging level."""
        self.console_handler.setLevel(getattr(logging, level.upper(), logging.INFO))

    def set_file_level(self, level: str):
        """Set file logging level."""
        self.main_file_handler.setLevel(getattr(logging, level.upper(), logging.DEBUG))

    def enable_deduplication(self, enabled: bool = True):
        """Enable or disable message deduplication."""
        if enabled:
            if self.dedup_filter not in self.root_logger.filters:
                self.root_logger.addFilter(self.dedup_filter)
        else:
            if self.dedup_filter in self.root_logger.filters:
                self.root_logger.removeFilter(self.dedup_filter)

    def get_handler_factory(self, level: str = "INFO", format_type: str = "standard") -> logging.Handler:
        """Create a logging handler based on type and level."""
        log_level = getattr(logging, level.upper(), logging.INFO)
        
        if format_type == "colored":
            handler = ColorizedConsoleHandler()
            handler.setLevel(log_level)
            handler.setFormatter(ColoredFormatter())
            return handler
        elif format_type == "structured":
            from logging.handlers import RotatingFileHandler
            log_dir = Path("logs")
            log_dir.mkdir(exist_ok=True)
            structured_file = log_dir / "structured.log"
            handler = RotatingFileHandler(structured_file, maxBytes=10*1024*1024, backupCount=5)
            handler.setLevel(log_level)
            handler.setFormatter(StructuredFormatter())
            return handler
        elif format_type == "file":
            log_dir = Path("logs")
            log_dir.mkdir(exist_ok=True)
            log_file = log_dir / "plexichat.log"
            handler = logging.FileHandler(log_file, encoding="utf-8")
            handler.setLevel(log_level)
            handler.setFormatter(logging.Formatter(
                "[%(asctime)s] [%(levelname)-8s] [%(name)s:%(lineno)d] %(funcName)s() - %(message)s"
            ))
            return handler
        else:
            # Default console handler
            handler = logging.StreamHandler()
            handler.setLevel(log_level)
            handler.setFormatter(logging.Formatter(
                "[%(asctime)s] [%(levelname)-8s] %(message)s"
            ))
            return handler

    @classmethod
    def get_instance(cls) -> "UnifiedLogger":
        """Get singleton instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance


def redact_pii(
    data: Union[str, Dict, List, Any], max_length: int = 1000
) -> Union[str, Dict, List, Any]:
    """
    Redact personally identifiable information from data.
    """
    if isinstance(data, str):
        return _redact_string(data, max_length)
    elif isinstance(data, dict):
        return _redact_dict(data)
    elif isinstance(data, list):
        return _redact_list(data)
    else:
        str_data = str(data)
        if len(str_data) > max_length:
            return f"[DATA_REDACTED_{len(str_data)}chars]"
        return _redact_string(str_data, max_length)


def _redact_string(text: str, max_length: int = 1000) -> str:
    if not text:
        return text
    if len(text) > max_length:
        return f"[DATA_REDACTED_{len(text)}chars]"
    redacted = text
    for pattern_name, pattern in PII_PATTERNS.items():
        redacted = pattern.sub("[REDACTED]", redacted)
    for field in SENSITIVE_FIELDS:
        field_pattern = re.compile(rf"(?i){re.escape(field)}\s*[:=]\s*([^\s,;\n]+)")
        redacted = field_pattern.sub(f"{field}: [REDACTED]", redacted)
    return redacted


def _redact_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    redacted = {}
    for key, value in data.items():
        key_lower = str(key).lower()
        if any(sensitive in key_lower for sensitive in SENSITIVE_FIELDS):
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = redact_pii(value)
    return redacted


def _redact_list(data: List[Any]) -> List[Any]:
    return [redact_pii(item) for item in data]


def sanitize_for_logging(text: Union[str, Any]) -> str:
    """
    Sanitize text for logging to ensure it's unicode-free and safe for Windows console output.
    """
    if not isinstance(text, str):
        text = str(text)
    replacements = {
        "\U0001f510": "[LOCK]",
        "\U0001f512": "[LOCK]",
        "\U0001f513": "[UNLOCK]",
        "\U0001f4a5": "[BOOM]",
        "\U0001f525": "[FIRE]",
        "\U0001f680": "[ROCKET]",
        "\U0001f44d": "[THUMBSUP]",
        "\U0001f44e": "[THUMBSDOWN]",
        "\U00002705": "[CHECK]",
        "\U0000274c": "[CROSS]",
        "\u26a0": "[WARNING]",
        "\U0001f6a8": "[ALERT]",
        "\u2713": "[OK]",
        "\u2717": "[X]",
        "\u2192": "->",
        "\u2190": "<-",
        "\u25b6": "[PLAY]",
        "\u25b7": "[PAUSE]",
        "\u23f8": "[STOP]",
        "\u2026": "...",
        "\u2013": "-",
        "\u2014": "--",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
    }
    for unicode_char, replacement in replacements.items():
        text = text.replace(unicode_char, replacement)
    try:
        encoded = text.encode("latin-1", errors="ignore")
        text = encoded.decode("latin-1")
    except (UnicodeEncodeError, UnicodeDecodeError):
        text = re.sub(r"[^\x00-\x7F]+", "[UNICODE]", text)
    return text


def sanitize_log_message(message: str, *args, **kwargs) -> tuple:
    """
    Sanitize a log message and its arguments for safe output.
    """
    sanitized_message = sanitize_for_logging(message)
    sanitized_args = tuple(sanitize_for_logging(arg) for arg in args)
    sanitized_kwargs = {}
    for key, value in kwargs.items():
        if isinstance(value, str):
            sanitized_kwargs[key] = sanitize_for_logging(value)
        else:
            sanitized_kwargs[key] = value
    return sanitized_message, sanitized_args, sanitized_kwargs


class ColoredFormatter(logging.Formatter):
    """Colored log formatter for console output."""

    COLORS = {
        logging.DEBUG: "\033[36m",  # Cyan
        logging.INFO: "\033[32m",  # Green
        logging.WARNING: "\033[33m",  # Yellow
        logging.ERROR: "\033[31m",  # Red
        logging.CRITICAL: "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record):
        message = super().format(record)
        if hasattr(record, "levelno") and record.levelno in self.COLORS:
            color = self.COLORS[record.levelno]
            level_start = message.find(f"[{record.levelname}")
            if level_start != -1:
                level_end = message.find("]", level_start) + 1
                if level_end > level_start:
                    colored_level = (
                        f"{color}{message[level_start:level_end]}{self.RESET}"
                    )
                    message = (
                        message[:level_start] + colored_level + message[level_end:]
                    )
        return message


class StructuredFormatter(logging.Formatter):
    """JSON structured log formatter."""

    import json
    from datetime import datetime

    def format(self, record):
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if hasattr(record, "context"):
            context = getattr(record, "context", None)
            if context:
                log_entry["context"] = context
        if hasattr(record, "category"):
            log_entry["category"] = getattr(record, "category", None)
        if hasattr(record, "extra_data"):
            log_entry["extra"] = getattr(record, "extra_data", None)
        return self.json.dumps(log_entry)


# Global instance
_unified_logger = UnifiedLogger.get_instance()


# Convenience functions
def get_plugin_logger(plugin_name: str) -> logging.LoggerAdapter:
    """Get a plugin-specific logger."""
    return _unified_logger.get_plugin_logger(plugin_name)


def get_logger(name: str) -> logging.Logger:
    """Get a logger under plexichat namespace."""
    return _unified_logger.get_logger(name)


def setup_logging(
    console_level: str = "INFO",
    file_level: str = "DEBUG",
    enable_deduplication: bool = True,
):
    """Setup unified logging system."""
    _unified_logger.set_console_level(console_level)
    _unified_logger.set_file_level(file_level)
    _unified_logger.enable_deduplication(enable_deduplication)


# Initialize on import
setup_logging()