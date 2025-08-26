"""
PlexiChat Unified Logging System - SINGLE SOURCE OF TRUTH

Consolidates ALL logging functionality from:
- core/logging.py - INTEGRATED
- core/logging_advanced/ - INTEGRATED
- infrastructure/utils/enhanced_logging.py - INTEGRATED

Provides a single, unified interface for all logging operations.
"""

import gzip
import json
import logging
import logging.handlers
import os
import sys
import time
import threading
import shutil
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable
from enum import Enum
from dataclasses import dataclass, field, asdict
from pathlib import Path

# Core imports
try:
    from plexichat.core.config import get_config as _get_unified_config  # type: ignore

    def get_config() -> Any:
        """Wrapper to provide a config object without requiring a key parameter."""
        return type('Config', (), {
            'logging': type('Logging', (), {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'buffer_size': 10000,
                'max_file_size': '10MB',
                'backup_count': 5,
                'directory': 'logs',
                'console_enabled': True,
                'console_colors': True
            })()
        })()
except ImportError:
    def get_config() -> Any:
        class MockConfig:
            class logging:
                level = "INFO"
                directory = "logs"
                buffer_size = 10000
                console_enabled = True
                console_colors = True
                file_enabled = True
                structured_enabled = True
                performance_enabled = True
                security_enabled = True
                audit_enabled = True
        return MockConfig()

logger = logging.getLogger(__name__)


class CentralizedDirectoryManager:
    """
    Centralized directory manager for all PlexiChat storage needs.

    This class ensures all directories are created in a clean, organized structure
    and prevents the creation of excessive subdirectories.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        """Initialize the directory manager."""
        # Use project root as base directory
        if base_dir is None:
            # Find project root by looking for key files
            current_dir = Path(__file__).parent
            while current_dir.parent != current_dir:
                if (current_dir / "run.py").exists() or (current_dir / "src").exists():
                    base_dir = current_dir
                    break
                current_dir = current_dir.parent
            else:
                # Fallback to current working directory
                base_dir = Path.cwd()

        self.base_dir = Path(base_dir)
        self.data_dir = self.base_dir / "data"

        # Define all directory paths in one place
        self.directories = {
            # Logging directories
            "logs": self.data_dir / "logs",
            "logs_archive": self.data_dir / "logs" / "archive",
            "logs_structured": self.data_dir / "logs" / "structured",

            # Storage directories
            "storage": self.data_dir / "storage",
            "storage_temp": self.data_dir / "storage" / "temp",
            "storage_cache": self.data_dir / "storage" / "cache",

            # Backup directories (consolidated)
            "backups": self.data_dir / "backups",
            "backups_metadata": self.data_dir / "backups" / "metadata",
            "backups_versions": self.data_dir / "backups" / "versions",
            "backups_shards": self.data_dir / "backups" / "shards",

            # Config and runtime directories
            "config": self.data_dir / "config",
            "runtime": self.data_dir / "runtime",
            "uploads": self.data_dir / "uploads",
        }

        # Initialize directories
        self._initialize_directories()

    def _initialize_directories(self):
        """Create all necessary directories."""
        try:
            for name, path in self.directories.items():
                path.mkdir(parents=True, exist_ok=True)

            # Create .gitkeep files to preserve directory structure
            for name, path in self.directories.items():
                gitkeep_file = path / ".gitkeep"
                if not gitkeep_file.exists():
                    gitkeep_file.touch()

            logger.info(f"Initialized centralized directory structure at {self.base_dir}")

        except Exception as e:
            logger.error(f"Failed to initialize directories: {e}")
            raise

    def get_directory(self, name: str) -> Path:
        """Get a directory path by name."""
        if name not in self.directories:
            raise ValueError(f"Unknown directory: {name}. Available: {list(self.directories.keys())}")
        return self.directories[name]

    def get_log_directory(self) -> Path:
        """Get the main log directory."""
        return self.directories["logs"]

    def get_backup_directory(self) -> Path:
        """Get the main backup directory."""
        return self.directories["backups"]

    def get_storage_directory(self) -> Path:
        """Get the main storage directory."""
        return self.directories["storage"]

    def cleanup_old_directories(self):
        """Clean up old, unused directory structures."""
        try:
            # List of old directory patterns to clean up
            old_patterns = [
                "backup_storage",
                "logs_*",
                "**/backup_storage",
                "**/logs_*",
            ]

            cleaned_count = 0
            for pattern in old_patterns:
                for old_dir in self.base_dir.glob(pattern):
                    if old_dir.is_dir() and old_dir not in self.directories.values():
                        try:
                            # Move contents to new structure if needed
                            self._migrate_directory_contents(old_dir)

                            # Remove empty old directory
                            if not any(old_dir.iterdir()):
                                old_dir.rmdir()
                                cleaned_count += 1
                                logger.info(f"Cleaned up empty directory: {old_dir}")
                        except Exception as e:
                            logger.warning(f"Could not clean up directory {old_dir}: {e}")

            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} old directories")

        except Exception as e:
            logger.error(f"Error during directory cleanup: {e}")

    def _migrate_directory_contents(self, old_dir: Path):
        """Migrate contents from old directory structure to new structure."""
        try:
            # Determine target directory based on old directory name
            if "backup" in old_dir.name.lower():
                target_dir = self.directories["backups"]
            elif "log" in old_dir.name.lower():
                target_dir = self.directories["logs"]
            else:
                target_dir = self.directories["storage"]

            # Move files (not directories) to avoid nested structures
            for item in old_dir.iterdir():
                if item.is_file():
                    target_file = target_dir / item.name
                    if not target_file.exists():
                        shutil.move(str(item), str(target_file))
                        logger.info(f"Migrated file: {item} -> {target_file}")

        except Exception as e:
            logger.warning(f"Error migrating contents from {old_dir}: {e}")


class LogLevel(Enum):
    """Enhanced log levels."""
    TRACE = 5
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    SECURITY = 60
    AUDIT = 70


class LogCategory(Enum):
    """Log categories for organization."""
    SYSTEM = "system"
    SECURITY = "security"
    PERFORMANCE = "performance"
    API = "api"
    DATABASE = "database"
    AUTH = "auth"
    PLUGIN = "plugin"
    BACKUP = "backup"
    CLUSTERING = "clustering"
    MONITORING = "monitoring"
    USER = "user"
    AUDIT = "audit"


@dataclass
class LogContext:
    """Log context information."""
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    operation: Optional[str] = None
    component: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LogEntry:
    """Structured log entry."""
    timestamp: datetime
    level: LogLevel
    category: LogCategory
    message: str
    logger_name: str
    context: LogContext
    extra_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.name,
            "category": self.category.value,
            "message": self.message,
            "logger": self.logger_name,
            "context": {
                "user_id": self.context.user_id,
                "session_id": self.context.session_id,
                "request_id": self.context.request_id,
                "operation": self.context.operation,
                "component": self.context.component,
                "metadata": self.context.metadata,
            },
            "extra": self.extra_data,
        }


class ColoredFormatter(logging.Formatter):
    """Colored log formatter for console output."""

    COLORS = {
        'TRACE': '\033[90m',      # Dark gray
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'SECURITY': '\033[91m',   # Bright red
        'AUDIT': '\033[94m',      # Bright blue
    }
    RESET = '\033[0m'

    def format(self, record):
        if hasattr(record, 'levelname') and record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.RESET}"
        return super().format(record)


class StructuredFormatter(logging.Formatter):
    """JSON structured log formatter."""

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

        # Add extra fields
        if hasattr(record, 'context'):
            context = getattr(record, 'context', None)
            if context and hasattr(context, '__dataclass_fields__'):
                log_entry["context"] = asdict(context)  # type: ignore
            else:
                log_entry["context"] = context
        if hasattr(record, 'category'):
            log_entry["category"] = getattr(record, 'category', None)
        if hasattr(record, 'extra_data'):
            log_entry["extra"] = getattr(record, 'extra_data', None)

        return json.dumps(log_entry)


class PerformanceTracker:
    """Performance tracking and metrics."""

    def __init__(self):
        self.metrics: Dict[str, List[float]] = {}
        self.counters: Dict[str, int] = {}
        self.lock = threading.Lock()

    def record_timing(self, operation: str, duration: float):
        """Record timing metric."""
        with self.lock:
            if operation not in self.metrics:
                self.metrics[operation] = []
            self.metrics[operation].append(duration)

            # Keep only last 1000 entries
            if len(self.metrics[operation]) > 1000:
                self.metrics[operation] = self.metrics[operation][-1000:]

    def increment_counter(self, name: str, value: int = 1):
        """Increment counter metric."""
        with self.lock:
            self.counters[name] = self.counters.get(name, 0) + value

    def get_stats(self, operation: str) -> Dict[str, Any]:
        """Get statistics for an operation."""
        with self.lock:
            if operation not in self.metrics:
                return {}

            timings = self.metrics[operation]
            if not timings:
                return {}

            return {
                "count": len(timings),
                "avg": sum(timings) / len(timings),
                "min": min(timings),
                "max": max(timings),
                "total": sum(timings),
            }


class LogBuffer:
    """Thread-safe log buffer for real-time streaming."""

    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.entries: List[LogEntry] = []
        self.lock = threading.Lock()
        self.subscribers: List[Callable[[LogEntry], None]] = []

    def add_entry(self, entry: LogEntry):
        """Add log entry to buffer."""
        with self.lock:
            self.entries.append(entry)
            if len(self.entries) > self.max_size:
                self.entries = self.entries[-self.max_size:]

        # Notify subscribers
        for subscriber in self.subscribers:
            try:
                subscriber(entry)
            except Exception:
                # Don't let subscriber errors break logging
                pass

    def get_recent(self, count: int = 100) -> List[LogEntry]:
        """Get recent log entries."""
        with self.lock:
            return self.entries[-count:] if self.entries else []

    def subscribe(self, callback: Callable[[LogEntry], None]):
        """Subscribe to new log entries."""
        self.subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[LogEntry], None]):
        """Unsubscribe from log entries."""
        if callback in self.subscribers:
            self.subscribers.remove(callback)


class PerformanceTimer:
    """Context manager for performance timing."""

    def __init__(self, logger, operation: str, **kwargs):
        self.logger = logger
        self.operation = operation
        self.kwargs = kwargs
        self.start_time = None

    def __enter__(self):
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time is not None:
            duration = time.time() - self.start_time
            self.logger.log_performance(self.operation, duration, **self.kwargs)


class UnifiedLogger:
    """
    Unified Logger - SINGLE SOURCE OF TRUTH

    Consolidates all logging functionality from multiple systems.
    """

    def __init__(self, name: str, manager=None):
        self.name = name
        self.manager = manager
        self.logger = logging.getLogger(name)
        self.context = LogContext()

    def set_context(self, **kwargs):
        """Set logging context."""
        for key, value in kwargs.items():
            if hasattr(self.context, key):
                setattr(self.context, key, value)
            else:
                self.context.metadata[key] = value

    def clear_context(self):
        """Clear logging context."""
        self.context = LogContext()

    def _log(self, level: LogLevel, category: LogCategory, message: str, **kwargs):
        """Internal logging method."""
        entry = LogEntry(
            timestamp=datetime.now(),
            level=level,
            category=category,
            message=message,
            logger_name=self.name,
            context=self.context,
            extra_data=kwargs
        )

        # Add to buffer if manager exists
        if self.manager and hasattr(self.manager, 'log_buffer'):
            self.manager.log_buffer.add_entry(entry)

        # Log to standard logger
        log_level = getattr(logging, level.name, logging.INFO)
        extra = {
            'context': self.context,
            'category': category.value,
            'extra_data': kwargs
        }
        self.logger.log(log_level, message, extra=extra)

    def trace(self, message: str, category: LogCategory = LogCategory.SYSTEM, **kwargs):
        """Log trace message."""
        self._log(LogLevel.TRACE, category, message, **kwargs)

    def debug(self, message: str, category: LogCategory = LogCategory.SYSTEM, **kwargs):
        """Log debug message."""
        self._log(LogLevel.DEBUG, category, message, **kwargs)

    def info(self, message: str, category: LogCategory = LogCategory.SYSTEM, **kwargs):
        """Log info message."""
        self._log(LogLevel.INFO, category, message, **kwargs)

    def warning(self, message: str, category: LogCategory = LogCategory.SYSTEM, **kwargs):
        """Log warning message."""
        self._log(LogLevel.WARNING, category, message, **kwargs)

    def error(self, message: str, category: LogCategory = LogCategory.SYSTEM, **kwargs):
        """Log error message."""
        self._log(LogLevel.ERROR, category, message, **kwargs)

    def critical(self, message: str, category: LogCategory = LogCategory.SYSTEM, **kwargs):
        """Log critical message."""
        self._log(LogLevel.CRITICAL, category, message, **kwargs)

    def security(self, message: str, **kwargs):
        """Log security event."""
        self._log(LogLevel.SECURITY, LogCategory.SECURITY, message, **kwargs)

    def audit(self, message: str, **kwargs):
        """Log audit event."""
        self._log(LogLevel.AUDIT, LogCategory.AUDIT, message, **kwargs)

    def performance(self, operation: str, duration: float, **kwargs):
        """Log performance metric."""
        message = f"Performance: {operation} took {duration:.3f}s"
        self._log(LogLevel.INFO, LogCategory.PERFORMANCE, message, operation=operation, duration=duration, **kwargs)

        # Record in performance tracker
        if self.manager and hasattr(self.manager, 'performance_tracker'):
            self.manager.performance_tracker.record_timing(operation, duration)

    def request(self, method: str, path: str, status_code: int, duration: float, **kwargs):
        """Log HTTP request."""
        message = f"{method} {path} {status_code} ({duration:.3f}s)"
        self._log(LogLevel.INFO, LogCategory.API, message, method=method, path=path, status_code=status_code, duration=duration, **kwargs)

    def timer(self, operation: str, **kwargs):
        """Get performance timer context manager."""
        return PerformanceTimer(self, operation, **kwargs)

    def log_performance(self, operation: str, duration: float, **kwargs):
        """Log performance timing (for timer context manager)."""
        self.performance(operation, duration, **kwargs)


class CompressingRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Rotating file handler that compresses old log files and manages cleanup."""

    def __init__(self, filename, mode='a', maxBytes=0, backupCount=0, encoding=None, delay=False, log_dir=None):
        super().__init__(filename, mode, maxBytes, backupCount, encoding, delay)
        self.log_dir = Path(log_dir) if log_dir else Path(filename).parent

    def doRollover(self):
        """Perform rollover with compression."""
        if self.stream:
            self.stream.close()
            self.stream = None  # type: ignore

        if self.backupCount > 0:
            for i in range(self.backupCount - 1, 0, -1):
                sfn = f"{self.baseFilename}.{i}"
                dfn = f"{self.baseFilename}.{i+1}"
                if os.path.exists(sfn):
                    if os.path.exists(dfn):
                        os.remove(dfn)
                    os.rename(sfn, dfn)

            # Compress the current log file
            dfn = f"{self.baseFilename}.1"
            if os.path.exists(self.baseFilename):
                # Compress to .gz
                with open(self.baseFilename, 'rb') as f_in:
                    with gzip.open(f"{dfn}.gz", 'wb') as f_out:
                        f_out.writelines(f_in)
                os.remove(self.baseFilename)

                # Remove uncompressed backup if it exists
                if os.path.exists(dfn):
                    os.remove(dfn)

        if not self.delay:
            self.stream = self._open()


class UnifiedLoggingManager:
    """
    Unified Logging Manager - SINGLE SOURCE OF TRUTH

    Consolidates all logging management functionality.
    """

    def __init__(self):
        self.config = get_config()
        self.directory_manager = CentralizedDirectoryManager()
        self.loggers: Dict[str, UnifiedLogger] = {}
        self.log_buffer = LogBuffer(max_size=getattr(self.config.logging, 'buffer_size', 10000))
        self.performance_tracker = PerformanceTracker()
        self.handlers: List[logging.Handler] = []
        self.alert_callbacks: List[Callable[[LogEntry], None]] = []

        # Clean up old directories first
        self.directory_manager.cleanup_old_directories()

        # Setup logging system
        self._setup_logging_system()

    def _setup_logging_system(self):
        """Setup the unified logging system."""
        try:
            # Configure root logger
            root_logger = logging.getLogger()
            root_logger.setLevel(logging.NOTSET)  # Let handlers control levels
            root_logger.handlers.clear()

            # Setup console handler
            if getattr(self.config.logging, 'console_enabled', True):
                self._setup_console_handler()

            # Setup file handler
            if getattr(self.config.logging, 'file_enabled', True):
                self._setup_file_handler()

            # Setup structured logging handler
            if getattr(self.config.logging, 'structured_enabled', True):
                self._setup_structured_handler()

            # Configure third-party loggers
            self._configure_third_party_loggers()

            logger.info("Unified logging system initialized")

        except Exception as e:
            print(f"Error setting up logging system: {e}")

    def _setup_console_handler(self):
        """Setup console logging handler."""
        try:
            console_handler = logging.StreamHandler(sys.stdout)

            # Set level
            level_name = getattr(self.config.logging, 'console_level', 'INFO')
            level = getattr(logging, level_name.upper(), logging.INFO)
            console_handler.setLevel(level)

            # Set formatter
            if getattr(self.config.logging, 'console_colors', True):
                formatter = ColoredFormatter()
                formatter = logging.Formatter('[%(asctime)s] [%(levelname)-8s] %(name)s: %(message)s')
            else:
                formatter = logging.Formatter('[%(asctime)s] [%(levelname)-8s] %(name)s: %(message)s')

            console_handler.setFormatter(formatter)

            # Add to root logger
            logging.getLogger().addHandler(console_handler)
            self.handlers.append(console_handler)

        except Exception as e:
            print(f"Error setting up console handler: {e}")

    def _setup_file_handler(self):
        """Setup file logging handler with compression and cleanup."""
        try:
            # Use centralized directory manager
            log_dir = self.directory_manager.get_log_directory()
            log_file = log_dir / 'plexichat.log'

            # Use custom rotating file handler with compression
            max_file_size = getattr(self.config.logging, 'max_file_size', 10*1024*1024)
            backup_count = getattr(self.config.logging, 'backup_count', 5)

            # Ensure values are integers
            if isinstance(max_file_size, str):
                max_file_size = int(max_file_size) if max_file_size.isdigit() else 10*1024*1024
            if isinstance(backup_count, str):
                backup_count = int(backup_count) if backup_count.isdigit() else 5

            file_handler = CompressingRotatingFileHandler(
                log_file,
                maxBytes=max_file_size,
                backupCount=backup_count,
                log_dir=log_dir
            )

            # Set level
            level_name = getattr(self.config.logging, 'file_level', 'INFO')
            level = getattr(logging, level_name.upper(), logging.INFO)
            file_handler.setLevel(level)

            # Set formatter
            formatter = logging.Formatter('[%(asctime)s] [%(levelname)-8s] [%(name)s:%(lineno)d] %(funcName)s() - %(message)s')
            file_handler.setFormatter(formatter)

            # Add to root logger
            logging.getLogger().addHandler(file_handler)
            self.handlers.append(file_handler)

            # Schedule log cleanup
            self._schedule_log_cleanup(log_dir)

        except Exception as e:
            print(f"Error setting up file handler: {e}")

    def _schedule_log_cleanup(self, log_dir: Path):
        """Schedule periodic log cleanup."""
        try:
            import threading
            import time

            def cleanup_logs():
                while True:
                    try:
                        self._cleanup_old_logs(log_dir)
                        time.sleep(24 * 3600)  # Run daily
                    except Exception as e:
                        logger.error(f"Error in log cleanup: {e}")

            cleanup_thread = threading.Thread(target=cleanup_logs, daemon=True)
            cleanup_thread.start()

        except Exception as e:
            logger.error(f"Error scheduling log cleanup: {e}")

    def _cleanup_old_logs(self, log_dir: Path):
        """Clean up old log files."""
        try:
            # Get configuration values with fallbacks
            max_age_days = 30
            max_total_size_mb = 1000

            try:
                max_age_days = getattr(self.config.logging, 'max_age_days', 30)
                max_total_size_mb = getattr(self.config.logging, 'max_total_size_mb', 1000)
            except AttributeError:
                # Fallback to environment variables or defaults
                max_age_days = int(os.environ.get('LOG_MAX_AGE_DAYS', '30'))
                max_total_size_mb = int(os.environ.get('LOG_MAX_TOTAL_SIZE_MB', '1000'))

            current_time = time.time()
            cutoff_time = current_time - (max_age_days * 24 * 3600)

            log_files = []
            total_size = 0

            # Collect all log files with their info
            for log_file in log_dir.glob("*.log*"):
                if log_file.is_file():
                    stat = log_file.stat()
                    log_files.append({
                        'path': log_file,
                        'mtime': stat.st_mtime,
                        'size': stat.st_size
                    })
                    total_size += stat.st_size

            # Sort by modification time (oldest first)
            log_files.sort(key=lambda x: x['mtime'])

            # Remove files older than max_age_days
            for log_info in log_files[:]:
                if log_info['mtime'] < cutoff_time:
                    try:
                        log_info['path'].unlink()
                        total_size -= log_info['size']
                        log_files.remove(log_info)
                        logger.info(f"Deleted old log file: {log_info['path']}")
                    except Exception as e:
                        logger.error(f"Error deleting log file {log_info['path']}: {e}")

            # Remove files if total size exceeds limit
            max_total_size_bytes = max_total_size_mb * 1024 * 1024
            while total_size > max_total_size_bytes and log_files:
                oldest = log_files.pop(0)
                try:
                    oldest['path'].unlink()
                    total_size -= oldest['size']
                    logger.info(f"Deleted log file due to size limit: {oldest['path']}")
                except Exception as e:
                    logger.error(f"Error deleting log file {oldest['path']}: {e}")

        except Exception as e:
            logger.error(f"Error in log cleanup: {e}")

    def _setup_structured_handler(self):
        """Setup structured JSON logging handler."""
        try:
            # Use centralized directory manager
            log_dir = self.directory_manager.get_directory("logs_structured")
            structured_file = log_dir / 'plexichat-structured.log'

            from logging.handlers import RotatingFileHandler

            max_file_size = getattr(self.config.logging, 'max_file_size', 10*1024*1024)
            backup_count = getattr(self.config.logging, 'backup_count', 5)

            # Ensure values are integers
            if isinstance(max_file_size, str):
                max_file_size = int(max_file_size) if max_file_size.isdigit() else 10*1024*1024
            if isinstance(backup_count, str):
                backup_count = int(backup_count) if backup_count.isdigit() else 5

            structured_handler = RotatingFileHandler(
                structured_file,
                maxBytes=max_file_size,
                backupCount=backup_count
            )

            # Set level
            level_name = getattr(self.config.logging, 'structured_level', 'INFO')
            level = getattr(logging, level_name.upper(), logging.INFO)
            structured_handler.setLevel(level)

            # Set structured formatter
            structured_handler.setFormatter(StructuredFormatter())

            # Add to root logger
            logging.getLogger().addHandler(structured_handler)
            self.handlers.append(structured_handler)

        except Exception as e:
            print(f"Error setting up structured handler: {e}")

    def _configure_third_party_loggers(self):
        """Configure third-party library loggers."""
        try:
            third_party_loggers = [
                "urllib3", "requests", "asyncio", "websockets",
                "sqlalchemy", "uvicorn", "fastapi"
            ]

            level_name = getattr(self.config.logging, 'third_party_level', 'WARNING')
            level = getattr(logging, level_name.upper(), logging.WARNING)

            for logger_name in third_party_loggers:
                third_party_logger = logging.getLogger(logger_name)
                third_party_logger.setLevel(level)

        except Exception as e:
            print(f"Error configuring third-party loggers: {e}")

    def get_logger(self, name: str) -> UnifiedLogger:
        """Get a unified logger instance."""
        if name not in self.loggers:
            self.loggers[name] = UnifiedLogger(name, self)
        return self.loggers[name]

    def get_directory_manager(self) -> CentralizedDirectoryManager:
        """Get the centralized directory manager."""
        return self.directory_manager

    def add_alert_callback(self, callback: Callable[[LogEntry], None]):
        """Add alert callback for critical events."""
        self.alert_callbacks.append(callback)

    def remove_alert_callback(self, callback: Callable[[LogEntry], None]):
        """Remove alert callback."""
        if callback in self.alert_callbacks:
            self.alert_callbacks.remove(callback)

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        return {
            "operations": {
                op: self.performance_tracker.get_stats(op)
                for op in self.performance_tracker.metrics.keys()
            },
            "counters": dict(self.performance_tracker.counters)
        }

    def get_recent_logs(self, count: int = 100) -> List[Dict[str, Any]]:
        """Get recent log entries as dictionaries."""
        entries = self.log_buffer.get_recent(count)
        return [entry.to_dict() for entry in entries]

    def flush_logs(self):
        """Flush all log handlers."""
        for handler in self.handlers:
            try:
                handler.flush()
            except Exception as e:
                print(f"Error flushing handler: {e}")

    def shutdown(self):
        """Shutdown logging system."""
        try:
            self.flush_logs()

            # Close all handlers
            for handler in self.handlers:
                try:
                    handler.close()
                except Exception as e:
                    print(f"Error closing handler: {e}")

            # Clear handlers
            logging.getLogger().handlers.clear()
            self.handlers.clear()

            logger.info("Unified logging system shut down")

        except Exception as e:
            print(f"Error shutting down logging system: {e}")


# Global unified logging manager instance
unified_logging_manager = UnifiedLoggingManager()

# Backward compatibility functions
def get_logger(name: str = "plexichat") -> UnifiedLogger:
    """Get unified logger instance."""
    return unified_logging_manager.get_logger(name)

def get_logging_manager() -> UnifiedLoggingManager:
    """Get the global logging manager instance."""
    return unified_logging_manager

def get_directory_manager() -> CentralizedDirectoryManager:
    """Get the global directory manager instance."""
    return unified_logging_manager.get_directory_manager()

def setup_module_logging(module_name: str, level: str = "INFO") -> UnifiedLogger:
    """Setup logging for a specific module."""
    logger = get_logger(module_name)
    # Set level on underlying logger
    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.logger.setLevel(log_level)
    return logger

def log_performance(operation: str, duration: float, **kwargs):
    """Log performance metric (backward compatibility)."""
    logger = get_logger("plexichat.performance")
    logger.performance(operation, duration, **kwargs)

def log_request(method: str, path: str, status_code: int, duration: float, **kwargs):
    """Log HTTP request (backward compatibility)."""
    logger = get_logger("plexichat.access")
    logger.request(method, path, status_code, duration, **kwargs)

def log_error(error: Exception, context: str = "", **kwargs):
    """Log error with context (backward compatibility)."""
    logger = get_logger("plexichat.error")
    logger.error(f"{context}: {str(error)}", error_type=type(error).__name__, **kwargs)

def log_audit_event(event_type: str, user_id: Optional[str], details: Dict[str, Any]):
    """Log audit event (backward compatibility)."""
    logger = get_logger("plexichat.audit")
    logger.audit(f"Audit: {event_type}", user_id=user_id, event_type=event_type, details=details)

def timer(operation: str, **kwargs):
    """Decorator for performance timing (backward compatibility)."""
    def decorator(func):
        def wrapper(*args, **func_kwargs):
            logger = get_logger("plexichat.performance")
            with logger.timer(operation, **kwargs):
                return func(*args, **func_kwargs)
        return wrapper
    return decorator

def flush_logs():
    """Flush all logs (backward compatibility)."""
    unified_logging_manager.flush_logs()

# Backward compatibility aliases
logging_manager = unified_logging_manager
LoggingManager = UnifiedLoggingManager

__all__ = [
    # Main classes
    'UnifiedLoggingManager',
    'unified_logging_manager',
    'UnifiedLogger',
    'CentralizedDirectoryManager',

    # Enums and data classes
    'LogLevel',
    'LogCategory',
    'LogContext',
    'LogEntry',

    # Formatters and utilities
    'ColoredFormatter',
    'StructuredFormatter',
    'PerformanceTracker',
    'LogBuffer',
    'PerformanceTimer',

    # Main functions
    'get_logger',
    'get_logging_manager',
    'get_directory_manager',
    'setup_module_logging',

    # Backward compatibility functions
    'log_performance',
    'log_request',
    'log_error',
    'log_audit_event',
    'timer',
    'flush_logs',

    # Backward compatibility aliases
    'logging_manager',
    'LoggingManager',
]
