# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Unified Logging Manager

Advanced logging system with:
- Log level management
- Log rotation and compression
- Old log cleanup
- Performance monitoring
- Security audit logging
- Structured logging with JSON support
"""

import gzip
import json
import logging
import logging.handlers
import os
import shutil
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
import importlib

from ...core.unified_config import get_logs_dir
from ...shared.exceptions import LoggingError


class UnifiedLoggingManager:
    """Unified logging manager with advanced features."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # Merge provided config with defaults
        default_config = self._get_default_config()
        if config:
            default_config.update(config)
        self.config = default_config

        self.logs_dir = Path(get_logs_dir())
        self.loggers: Dict[str, logging.Logger] = {}
        self.handlers: Dict[str, logging.Handler] = {}

        # Create log directories
        self._create_log_directories()

        # Setup root logger
        self._setup_root_logger()

        # Setup specialized loggers
        self._setup_specialized_loggers()

        # Start log cleanup scheduler
        self._schedule_log_cleanup()

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default logging configuration."""
        return {
            "level": "INFO",
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "json_format": False,
            "max_file_size": "10MB",
            "backup_count": 5,
            "cleanup_days": 30,
            "compress_old_logs": True,
            "modules": {
                "plexichat.main": "INFO",
                "plexichat.api": "INFO",
                "plexichat.security": "DEBUG",
                "plexichat.performance": "INFO",
                "plexichat.database": "WARNING",
                "plexichat.auth": "INFO",
                "plexichat.messaging": "INFO",
                "plexichat.files": "INFO",
                "plexichat.tests": "DEBUG"
            },
            "specialized_logs": {
                "security": {"level": "DEBUG", "file": "security.log"},
                "performance": {"level": "INFO", "file": "performance.log"},
                "audit": {"level": "INFO", "file": "audit.log"},
                "errors": {"level": "ERROR", "file": "errors.log"},
                "tests": {"level": "DEBUG", "file": "tests.log"}
            }
        }

    def _create_log_directories(self):
        """Create all necessary log directories."""
        directories = [
            self.logs_dir,
            self.logs_dir / "security",
            self.logs_dir / "performance",
            self.logs_dir / "audit",
            self.logs_dir / "errors",
            self.logs_dir / "tests",
            self.logs_dir / "archived"
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def _setup_root_logger(self):
        """Setup the root logger."""
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, self.config["level"].upper()))

        # Clear existing handlers
        root_logger.handlers.clear()

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, self.config["level"].upper()))

        # Try to use colorlog for colorized output
        colorlog_spec = importlib.util.find_spec("colorlog")
        if colorlog_spec is not None:
            import colorlog
            formatter = colorlog.ColoredFormatter(
                fmt="%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
                log_colors={
                    'DEBUG':    'cyan',
                    'INFO':     'green',
                    'WARNING':  'yellow',
                    'ERROR':    'red',
                    'CRITICAL': 'bold_red',
                }
            )
            console_handler.setFormatter(formatter)
        elif self.config.get("json_format"):
            console_handler.setFormatter(self._get_json_formatter())
        else:
            console_handler.setFormatter(self._get_standard_formatter())

        root_logger.addHandler(console_handler)

        # Main log file handler with rotation
        main_log_file = self.logs_dir / "plexichat.log"
        file_handler = logging.handlers.RotatingFileHandler(
            main_log_file,
            maxBytes=self._parse_size(self.config["max_file_size"]),
            backupCount=self.config["backup_count"]
        )
        file_handler.setLevel(getattr(logging, self.config["level"].upper()))
        file_handler.setFormatter(self._get_standard_formatter())

        root_logger.addHandler(file_handler)
        self.handlers["main"] = file_handler

    def _setup_specialized_loggers(self):
        """Setup specialized loggers for different components."""
        for log_type, log_config in self.config["specialized_logs"].items():
            logger = logging.getLogger(f"plexichat.{log_type}")
            logger.setLevel(getattr(logging, log_config["level"].upper()))

            # Prevent propagation to avoid duplicate logs
            logger.propagate = False

            # File handler for specialized log
            log_file = self.logs_dir / log_type / log_config["file"]
            handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=self._parse_size(self.config["max_file_size"]),
                backupCount=self.config["backup_count"]
            )
            handler.setLevel(getattr(logging, log_config["level"].upper()))

            if log_type in ["audit", "security"]:
                handler.setFormatter(self._get_json_formatter())
            else:
                handler.setFormatter(self._get_standard_formatter())

            logger.addHandler(handler)
            self.loggers[log_type] = logger
            self.handlers[log_type] = handler

    def _get_standard_formatter(self) -> logging.Formatter:
        """Get standard text formatter."""
        return logging.Formatter(
            fmt=self.config["format"],
            datefmt="%Y-%m-%d %H:%M:%S"
        )

    def _get_json_formatter(self) -> logging.Formatter:
        """Get JSON formatter for structured logging."""
        class JsonFormatter(logging.Formatter):
            def format(self, record):
                log_entry = {
                    "timestamp": datetime.fromtimestamp(record.created).isoformat(),
                    "level": record.levelname,
                    "logger": record.name,
                    "message": record.getMessage(),
                    "module": record.module,
                    "function": record.funcName,
                    "line": record.lineno
                }

                if hasattr(record, "extra_data"):
                    log_entry.update(record.extra_data)

                return json.dumps(log_entry)

        return JsonFormatter()

    def _parse_size(self, size_str: str) -> int:
        """Parse size string like '10MB' to bytes."""
        size_str = size_str.upper()
        if size_str.endswith("KB"):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith("MB"):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith("GB"):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)

    def _schedule_log_cleanup(self):
        """Schedule periodic log cleanup."""
        # This would be called by a scheduler in a real implementation
        # For now, we'll call it manually
        pass

    def cleanup_old_logs(self):
        """Clean up old log files and compress them."""
        cutoff_date = datetime.now() - timedelta(days=self.config["cleanup_days"])
        archived_count = 0
        deleted_count = 0

        for log_file in self.logs_dir.rglob("*.log*"):
            if log_file.is_file():
                file_time = datetime.fromtimestamp(log_file.stat().st_mtime)

                if file_time < cutoff_date:
                    if self.config["compress_old_logs"] and not log_file.name.endswith(".gz"):
                        # Compress old log files
                        compressed_file = self.logs_dir / "archived" / f"{log_file.name}.gz"
                        with open(log_file, 'rb') as f_in:
                            with gzip.open(compressed_file, 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)

                        log_file.unlink()
                        archived_count += 1
                    else:
                        # Delete very old files
                        very_old_cutoff = datetime.now() - timedelta(days=self.config["cleanup_days"] * 2)
                        if file_time < very_old_cutoff:
                            log_file.unlink()
                            deleted_count += 1

        # Log cleanup results
        main_logger = logging.getLogger("plexichat.main")
        main_logger.info(f"Log cleanup completed: {archived_count} files archived, {deleted_count} files deleted")

    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger with proper configuration."""
        logger = logging.getLogger(name)

        # Set level based on module configuration
        for module_pattern, level in self.config["modules"].items():
            if name.startswith(module_pattern):
                logger.setLevel(getattr(logging, level.upper()))
                break

        return logger

    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log a security event with structured data."""
        security_logger = self.loggers.get("security")
        if security_logger:
            extra_data = {
                "event_type": event_type,
                "timestamp": datetime.now().isoformat(),
                **details
            }

            # Create a log record with extra data
            record = logging.LogRecord(
                name="plexichat.security",
                level=logging.INFO,
                pathname="",
                lineno=0,
                msg=f"Security event: {event_type}",
                args=(),
                exc_info=None
            )
            record.extra_data = extra_data

            security_logger.handle(record)

    def log_performance_metric(self, metric_name: str, value: float, unit: str = ""):
        """Log a performance metric."""
        performance_logger = self.loggers.get("performance")
        if performance_logger:
            performance_logger.info(f"Metric: {metric_name}={value}{unit}")

    def log_audit_event(self, user_id: str, action: str, resource: str, details: Dict[str, Any]):
        """Log an audit event."""
        audit_logger = self.loggers.get("audit")
        if audit_logger:
            extra_data = {
                "user_id": user_id,
                "action": action,
                "resource": resource,
                "timestamp": datetime.now().isoformat(),
                **details
            }

            record = logging.LogRecord(
                name="plexichat.audit",
                level=logging.INFO,
                pathname="",
                lineno=0,
                msg=f"Audit: {user_id} {action} {resource}",
                args=(),
                exc_info=None
            )
            record.extra_data = extra_data

            audit_logger.handle(record)


# Global logging manager instance
_logging_manager: Optional[UnifiedLoggingManager] = None


def initialize_logging(config: Optional[Dict[str, Any]] = None) -> UnifiedLoggingManager:
    """Initialize the unified logging system."""
    global _logging_manager

    if _logging_manager is None:
        _logging_manager = UnifiedLoggingManager(config)

    return _logging_manager


def get_logger(name: str) -> logging.Logger:
    """Get a properly configured logger."""
    if _logging_manager is None:
        initialize_logging()

    return _logging_manager.get_logger(name)


def cleanup_logs():
    """Clean up old log files."""
    if _logging_manager:
        _logging_manager.cleanup_old_logs()


def log_security_event(event_type: str, details: Dict[str, Any]):
    """Log a security event."""
    if _logging_manager:
        _logging_manager.log_security_event(event_type, details)


def log_performance_metric(metric_name: str, value: float, unit: str = ""):
    """Log a performance metric."""
    if _logging_manager:
        _logging_manager.log_performance_metric(metric_name, value, unit)


def log_audit_event(user_id: str, action: str, resource: str, details: Dict[str, Any]):
    """Log an audit event."""
    if _logging_manager:
        _logging_manager.log_audit_event(user_id, action, resource, details)
