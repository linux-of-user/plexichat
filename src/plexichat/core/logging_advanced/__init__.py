# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import gzip
import json
import logging
import logging.handlers
import os
import sys
import threading
import time
import traceback
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from ..unified_config import get_config
import enum
try:
    from .performance_logger import get_performance_logger
except ImportError:
    get_performance_logger = None

# Enhanced logging system exports
try:
    from .enhanced_logging_system import (
        get_enhanced_logging_system, get_logger, setup_module_logging,
        LogLevel, LogCategory, LogContext, PerformanceMetrics, SecurityMetrics,
        LogEntry, PerformanceTracker, track_performance
    )
except ImportError as e:
    print(f"Enhanced logging system import error: {e}")
    # Fallback to basic implementations
    import logging
    get_enhanced_logging_system = lambda: None
    get_logger = logging.getLogger
    setup_module_logging = lambda name=None, level="INFO": logging.getLogger(name or __name__)
    
    class LogLevel:
        TRACE = 5
        DEBUG = 10
        INFO = 20
        WARNING = 30
        ERROR = 40
        CRITICAL = 50
        SECURITY = 60
        AUDIT = 70
        PERFORMANCE = 80
    
    class LogCategory:
        SYSTEM = "system"
        SECURITY = "security"
        PERFORMANCE = "performance"
        API = "api"
        DATABASE = "database"
        BACKUP = "backup"
        AUTH = "auth"
        MESSAGING = "messaging"
        PLUGIN = "plugin"
        AUDIT = "audit"
        ERROR = "error"
        DEBUG = "debug"
        MONITORING = "monitoring"
        NETWORK = "network"
        FILE_SYSTEM = "file_system"
    
    LogContext = type('LogContext', (), {})
    PerformanceMetrics = type('PerformanceMetrics', (), {})
    SecurityMetrics = type('SecurityMetrics', (), {})
    LogEntry = type('LogEntry', (), {})
    PerformanceTracker = type('PerformanceTracker', (), {})
    track_performance = lambda op_name, logger=None: lambda func: func
# from .security_logger import get_security_logger

"""
PlexiChat Comprehensive Logging System

Unified logging architecture with structured logging, performance monitoring,
alerting, centralized log management, and enterprise-grade features.

Features:
- Structured JSON logging with context
- Performance monitoring and metrics
- Real-time log streaming
- Centralized log aggregation
- Security event logging
- Audit trail management
- Log rotation and compression
- Multi-level filtering
- Alert integration
- Dashboard visualization
"""

# Import configuration and utilities
# from ...services import get_service  # Commented out for now

# Log levels with custom additions
class LogLevel(Enum):
    """Extended log levels for comprehensive logging."""
    TRACE = 5
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    SECURITY = 60
    AUDIT = 70
    PERFORMANCE = 80

# Log categories for organization
class LogCategory(Enum):
    """Log categories for better organization."""
    SYSTEM = "system"
    SECURITY = "security"
    PERFORMANCE = "performance"
    API = "api"
    DATABASE = "database"
    BACKUP = "backup"
    AUTH = "auth"
    MESSAGING = "messaging"
    PLUGIN = "plugin"
    AUDIT = "audit"
    ERROR = "error"
    DEBUG = "debug"

@dataclass
class LogContext:
    """Log context information."""
    request_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    correlation_id: Optional[str] = None

@dataclass
class LogEntry:
    """Structured log entry."""
    timestamp: datetime
    level: LogLevel
    category: LogCategory
    message: str
    module: str
    function: str
    line: int
    context: LogContext = field(default_factory=LogContext)
    metadata: Dict[str, Any] = field(default_factory=dict)
    performance_data: Optional[Dict[str, float]] = None
    stack_trace: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert log entry to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.name,
            "category": self.category.value if hasattr(self.category, 'value') else str(self.category),
            "message": self.message,
            "module": self.module,
            "function": self.function,
            "line": self.line,
            "context": asdict(self.context) if self.context else {},
            "metadata": self.metadata,
            "performance_data": self.performance_data,
            "stack_trace": self.stack_trace
        }

class LogBuffer:
    """Thread-safe circular buffer for log entries."""

    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.buffer = deque(maxlen=max_size)
        self.lock = threading.RLock()
        self.subscribers = []

    def add_entry(self, entry: LogEntry):
        """Add log entry to buffer."""
        with self.lock:
            self.buffer.append(entry)
            # Notify subscribers
            for subscriber in self.subscribers:
                try:
                    subscriber(entry)
                except Exception:
                    pass  # Don't let subscriber errors affect logging

    def get_entries(self, count: Optional[int] = None, level_filter: Optional[LogLevel] = None, category_filter: Optional[LogCategory] = None) -> List[LogEntry]:
        """Get log entries with optional filtering."""
        with self.lock:
            entries = list(self.buffer)

            # Apply filters
            if level_filter:
                entries = [e for e in entries if e.level.value >= level_filter.value]
            if category_filter:
                entries = [e for e in entries if e.category == category_filter]

            # Limit count
            if count:
                entries = entries[-count:]

            return entries

    def subscribe(self, callback: Callable[[LogEntry], None]):
        """Subscribe to real-time log entries."""
        self.subscribers.append(callback)

    def clear(self):
        """Clear the buffer."""
        with self.lock:
            self.buffer.clear()

class PerformanceTracker:
    """Performance tracking for logging operations."""

    def __init__(self):
        self.metrics = defaultdict(list)
        self.lock = threading.RLock()

    def record_operation(self, operation: str, duration: float, metadata: Optional[Dict[str, Any]] = None):
        """Record operation performance."""
        with self.lock:
            self.metrics[operation].append({
                "duration": duration,
                "timestamp": datetime.now(timezone.utc),
                "metadata": metadata or {}
            })

            # Keep only last 1000 entries per operation
            if len(self.metrics[operation]) > 1000:
                self.metrics[operation] = self.metrics[operation][-1000:]

    def get_stats(self, operation: Optional[str] = None) -> Dict[str, Any]:
        """Get performance statistics."""
        with self.lock:
            if operation:
                if operation not in self.metrics:
                    return {}

                durations = [m["duration"] for m in self.metrics[operation]]
                return {
                    "count": len(durations),
                    "avg": sum(durations) / len(durations) if durations else 0,
                    "min": min(durations) if durations else 0,
                    "max": max(durations) if durations else 0,
                    "recent": durations[-10:] if durations else []
                }
            else:
                return {op: self.get_stats(op) for op in self.metrics.keys()}

class StructuredFormatter(logging.Formatter):
    """Structured JSON formatter with context."""

    def __init__(self, include_context: bool = True):
        super().__init__()
        self.include_context = include_context

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON."""
        # Extract context from record
        context = getattr(record, 'context', LogContext())
        # Create log entry
        entry = LogEntry(
            timestamp=datetime.fromtimestamp(record.created, tz=timezone.utc),
            level=self._get_log_level_from_name(record.levelname),
            category=getattr(record, 'category', LogCategory.SYSTEM),
            message=record.getMessage(),
            module=record.module if hasattr(record, 'module') else record.name,
            function=record.funcName,
            line=record.lineno,
            context=context if self.include_context else LogContext(),
            metadata=getattr(record, 'metadata', {}),
            performance_data=getattr(record, 'performance_data', None),
            stack_trace=self.formatException(record.exc_info) if record.exc_info else None
        )
        return json.dumps(entry.to_dict(), default=str, separators=(',', ':'))

    def _get_log_level_from_name(self, level_name: str) -> LogLevel:
        """Convert logging level name to LogLevel enum."""
        level_mapping = {
            'TRACE': LogLevel.TRACE,
            'DEBUG': LogLevel.DEBUG,
            'INFO': LogLevel.INFO,
            'WARNING': LogLevel.WARNING,
            'WARN': LogLevel.WARNING,
            'ERROR': LogLevel.ERROR,
            'CRITICAL': LogLevel.CRITICAL,
            'FATAL': LogLevel.CRITICAL,
            'SECURITY': LogLevel.SECURITY,
            'AUDIT': LogLevel.AUDIT,
            'PERFORMANCE': LogLevel.PERFORMANCE
        }
        return level_mapping.get(level_name.upper(), LogLevel.INFO)

class ColorizedFormatter(logging.Formatter):
    """Colorized console formatter."""

    COLORS = {
        'TRACE': '\033[90m',      # Dark gray
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'SECURITY': '\033[41m',   # Red background
        'AUDIT': '\033[44m',      # Blue background
        'RESET': '\033[0m'        # Reset
    }

    def __init__(self, fmt: str, datefmt: Optional[str] = None, use_colors: bool = True):
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors and sys.stdout.isatty()

    def format(self, record: logging.LogRecord) -> str:
        """Format with colors if enabled."""
        if self.use_colors:
            level_color = self.COLORS.get(record.levelname, '')
            reset_color = self.COLORS['RESET']

            # Colorize level name
            original_levelname = record.levelname
            record.levelname = f"{level_color}{record.levelname}{reset_color}"

            formatted = super().format(record)
            record.levelname = original_levelname  # Restore original

            return formatted
        else:
            return super().format(record)

class CompressingRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Rotating file handler with compression."""

    def doRollover(self):
        """Perform rollover with compression."""
        super().doRollover()

        # Compress the rotated file
        if self.backupCount > 0:
            for i in range(self.backupCount, 0, -1):
                sfn = f"{self.baseFilename}.{i}"
                if os.path.exists(sfn) and not sfn.endswith('.gz'):
                    # Compress the file
                    with open(sfn, 'rb') as f_in:
                        with gzip.open(f"{sfn}.gz", 'wb') as f_out:
                            f_out.writelines(f_in)
                    os.remove(sfn)

class LoggingManager:
    """Comprehensive logging manager for PlexiChat."""

    def __init__(self):
        self.config = get_config()
        # Safe config access with fallbacks
        buffer_size = getattr(self.config.logging, 'buffer_size', 10000) if hasattr(self.config, 'logging') else 10000
        self.log_buffer = LogBuffer(max_size=buffer_size)
        self.performance_tracker = PerformanceTracker()
        self.loggers: Dict[str, logging.Logger] = {}
        self.handlers: List[logging.Handler] = []
        self.alert_callbacks: List[Callable[[LogEntry], None]] = []

        # Setup logging system
        self._setup_logging_system()

    def _get_config(self, key: str, default: Optional[Any] = None) -> Any:
        """Safely get configuration value with fallback."""
        try:
            parts = key.split('.')
            value = self.config
            for part in parts:
                value = getattr(value, part, None)
                if value is None:
                    return default
            return value
        except (AttributeError, TypeError):
            return default

        # Setup performance monitoring
        self._setup_performance_monitoring()

        # Setup alert system
        self._setup_alert_system()

    def _setup_logging_system(self):
        """Setup the comprehensive logging system."""
        # Create log directory
        from pathlib import Path
        log_dir = Path(self._get_config("logging.directory", "logs"))
        log_dir.mkdir(exist_ok=True, parents=True)

        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.NOTSET)  # Let handlers control levels

        # Clear existing handlers
        root_logger.handlers.clear()

        # Setup console handler
        if self._get_config("logging.console_enabled", True):
            self._setup_console_handler(root_logger)

        # Setup file handlers
        if self._get_config("logging.file_enabled", True):
            self._setup_file_handlers(root_logger, log_dir)

        # Setup structured logging handler
        if self._get_config("logging.structured_enabled", True):
            self._setup_structured_handler(root_logger, log_dir)

        # Setup real-time streaming handler
        self._setup_streaming_handler(root_logger)

        # Setup security logging
        self._setup_security_logging(log_dir)

        # Setup audit logging
        self._setup_audit_logging(log_dir)

    def _setup_console_handler(self, logger: logging.Logger):
        """Setup colorized console handler."""
        console_handler = logging.StreamHandler(sys.stdout)
        console_level = getattr(logging, self._get_config("logging.console_level", "INFO"))
        console_handler.setLevel(console_level)

        formatter = ColorizedFormatter(
            fmt=self._get_config("logging.console_format", "[%(asctime)s] [%(levelname)-8s] %(name)s: %(message)s"),
            datefmt=self._get_config("logging.date_format", "%Y-%m-%d %H:%M:%S"),
            use_colors=self._get_config("logging.console_colors", True)
        )
        console_handler.setFormatter(formatter)

        logger.addHandler(console_handler)
        self.handlers.append(console_handler)

    def _setup_file_handlers(self, logger: logging.Logger, log_dir: Path):
        """Setup rotating file handlers."""
        # Main log file
        main_handler = CompressingRotatingFileHandler(
            filename=str(log_dir / "plexichat.log"),
            maxBytes=self._parse_size(self._get_config("logging.max_file_size", "10MB")),
            backupCount=self._get_config("logging.backup_count", 5),
            encoding="utf-8"
        )
        main_handler.setLevel(getattr(logging, self._get_config("logging.file_level", "INFO")))

        formatter = logging.Formatter(
            fmt=self._get_config("logging.file_format", "[%(asctime)s] [%(levelname)-8s] [%(name)s:%(lineno)d] %(funcName)s() - %(message)s"),
            datefmt=self._get_config("logging.date_format", "%Y-%m-%d %H:%M:%S")
        )
        main_handler.setFormatter(formatter)

        logger.addHandler(main_handler)
        self.handlers.append(main_handler)

        # Error-only log file
        error_handler = CompressingRotatingFileHandler(
            filename=str(log_dir / "plexichat_errors.log"),
            maxBytes=self._parse_size(self._get_config("logging.max_file_size", "10MB")),
            backupCount=self._get_config("logging.backup_count", 5),
            encoding="utf-8"
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)

        logger.addHandler(error_handler)
        self.handlers.append(error_handler)

    def _setup_structured_handler(self, logger: logging.Logger, log_dir: Path):
        """Setup structured JSON logging handler."""
        structured_handler = CompressingRotatingFileHandler(
            filename=str(log_dir / "plexichat_structured.jsonl"),
            maxBytes=self._parse_size(self._get_config("logging.max_file_size", "10MB")),
            backupCount=self._get_config("logging.backup_count", 5),
            encoding="utf-8"
        )
        structured_handler.setLevel(logging.DEBUG)

        formatter = StructuredFormatter(
            include_context=self._get_config("logging.include_context", True)
        )
        structured_handler.setFormatter(formatter)

        logger.addHandler(structured_handler)
        self.handlers.append(structured_handler)

    def _setup_streaming_handler(self, logger: logging.Logger):
        """Setup real-time streaming handler."""
        class StreamingHandler(logging.Handler):
            def __init__(self, log_buffer: LogBuffer):
                super().__init__()
                self.log_buffer = log_buffer

            def emit(self, record):
                try:
                    # Create log entry and add to buffer
                    formatter = logging.Formatter()
                    entry = LogEntry(
                        timestamp=datetime.fromtimestamp(record.created, tz=timezone.utc),
                        level=self._get_log_level_from_name(record.levelname),
                        category=getattr(record, 'category', LogCategory.SYSTEM),
                        message=record.getMessage(),
                        module=record.module if hasattr(record, 'module') else record.name,
                        function=record.funcName,
                        line=record.lineno,
                        context=getattr(record, 'context', LogContext()),
                        metadata=getattr(record, 'metadata', {}),
                        performance_data=getattr(record, 'performance_data', None),
                        stack_trace=formatter.formatException(record.exc_info) if record.exc_info else None
                    )
                    self.log_buffer.add_entry(entry)
                except Exception:
                    self.handleError(record)

            def _get_log_level_from_name(self, level_name: str) -> LogLevel:
                """Convert logging level name to LogLevel enum."""
                level_mapping = {
                    'TRACE': LogLevel.TRACE,
                    'DEBUG': LogLevel.DEBUG,
                    'INFO': LogLevel.INFO,
                    'WARNING': LogLevel.WARNING,
                    'WARN': LogLevel.WARNING,
                    'ERROR': LogLevel.ERROR,
                    'CRITICAL': LogLevel.CRITICAL,
                    'FATAL': LogLevel.CRITICAL,
                    'SECURITY': LogLevel.SECURITY,
                    'AUDIT': LogLevel.AUDIT,
                    'PERFORMANCE': LogLevel.PERFORMANCE
                }
                return level_mapping.get(level_name.upper(), LogLevel.INFO)

        streaming_handler = StreamingHandler(self.log_buffer)
        streaming_handler.setLevel(logging.DEBUG)

        logger.addHandler(streaming_handler)
        self.handlers.append(streaming_handler)

    def _setup_security_logging(self, log_dir: Path):
        """Setup security logging."""
        try:
            # if get_security_logger is not None: # Original line commented out
            #     self.security_logger = get_security_logger() # Original line commented out
            pass # Original line commented out
        except ImportError:
            # Security logger not available
            pass

    def _setup_audit_logging(self, log_dir: Path):
        """Setup audit logging."""
        audit_handler = CompressingRotatingFileHandler(
            filename=str(log_dir / "audit.log"),
            maxBytes=self._parse_size(self._get_config("logging.max_file_size", "10MB")),
            backupCount=self._get_config("logging.backup_count", 5),
            encoding="utf-8"
        )
        audit_handler.setLevel(logging.INFO)

        formatter = StructuredFormatter(include_context=True)
        audit_handler.setFormatter(formatter)

        audit_logger = logging.getLogger("plexichat.audit")
        audit_logger.addHandler(audit_handler)
        audit_logger.setLevel(logging.INFO)

        self.loggers["audit"] = audit_logger
        self.handlers.append(audit_handler)

    def _setup_performance_monitoring(self):
        """Setup performance monitoring."""
        try:
            if get_performance_logger is not None:
                self.performance_logger = get_performance_logger()
        except ImportError:
            # Performance logger not available
            pass

    def _setup_alert_system(self):
        """Setup alert system for critical log events."""
        def alert_handler(entry: LogEntry):
            if entry.level.value >= LogLevel.CRITICAL.value:
                self._send_alert(entry)

        self.log_buffer.subscribe(alert_handler)

    def _send_alert(self, entry: LogEntry):
        """Send alert for critical log entries."""
        # This would integrate with your alerting system
        # For now, just log the alert
        alert_logger = logging.getLogger("plexichat.alerts")
        alert_logger.critical(f"ALERT: {entry.message}")

    def _parse_size(self, size_input: Union[str, int]) -> int:
        """Parse size string or int to bytes."""
        if isinstance(size_input, int):
            return size_input

        size_str = str(size_input).upper()
        if size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)

    def get_log_entries(self, count: Optional[int] = None, level_filter: Optional[LogLevel] = None, category_filter: Optional[LogCategory] = None) -> List[LogEntry]:
        """Get log entries from buffer."""
        return self.log_buffer.get_entries(count, level_filter, category_filter)

    def subscribe_to_logs(self, callback: Callable[[LogEntry], None]):
        """Subscribe to real-time log entries."""
        self.log_buffer.subscribe(callback)

    def clear_logs(self):
        """Clear log buffer."""
        self.log_buffer.clear()

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary if available."""
        if hasattr(self, 'performance_logger'):
            return self.performance_logger.get_performance_summary()
        return {}

    def shutdown(self):
        """Shutdown logging system."""
        # Stop performance monitoring
        if hasattr(self, 'performance_logger'):
            self.performance_logger.stop_monitoring()

        # Close all handlers
        for handler in self.handlers:
            handler.close()

        # Clear loggers
        self.loggers.clear()
        self.handlers.clear()

# Global logging manager instance
_logging_manager = None

def get_logging_manager() -> LoggingManager:
    """Get the global logging manager instance."""
    global _logging_manager
    if _logging_manager is None:
        _logging_manager = LoggingManager()
    return _logging_manager

def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with PlexiChat configuration."""
    manager = get_logging_manager()

    if name not in manager.loggers:
        logger = logging.getLogger(name)
        manager.loggers[name] = logger

    return manager.loggers[name]


def setup_module_logging(module_name: str, level: str = "INFO") -> logging.Logger:
    """Setup logging for a specific module."""
    logger = get_logger(module_name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    return logger

# Export main components
__all__ = [
    "LogLevel", "LogCategory", "LogContext", "LogEntry", "LogBuffer",
    "PerformanceTracker", "StructuredFormatter", "ColorizedFormatter",
    "CompressingRotatingFileHandler", "LoggingManager", "get_logging_manager", "get_logger",
    "setup_module_logging"
]
