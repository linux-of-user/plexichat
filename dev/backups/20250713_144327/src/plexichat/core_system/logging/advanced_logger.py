import json
import logging
import logging.handlers
import os
import sys
import threading
import time
import traceback
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

from datetime import datetime
from pathlib import Path

from datetime import datetime
from pathlib import Path

"""
PlexiChat Advanced Logging System

Comprehensive logging with configurable levels, structured output, crash handling,
performance monitoring, and real-time log streaming.
"""

logger = logging.getLogger(__name__)
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


@dataclass
class LogEntry:
    """Structured log entry."""
    timestamp: str
    level: str
    logger: str
    message: str
    module: str
    function: str
    line: int
    thread_id: int
    process_id: int
    extra: Optional[Dict[str, Any]] = None
    exception: Optional[str] = None
    performance: Optional[Dict[str, Any]] = None


class AdvancedFormatter(logging.Formatter):
    """Advanced formatter with structured output."""
    
    def __init__(self, format_type: str = "structured"):
        super().__init__()
        self.format_type = format_type
        
    def format(self, record):
        if self.format_type == "structured":
            return self._format_structured(record)
        elif self.format_type == "json":
            return self._format_json(record)
        else:
            return self._format_standard(record)
    
    def _format_structured(self, record):
        """Format as structured text."""
        timestamp = datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        # Build structured message
        parts = [
            f"[{timestamp}]",
            f"[{record.levelname:8}]",
            f"[{record.name}]",
            f"[{record.funcName}:{record.lineno}]",
            f"- {record.getMessage()}"
        ]
        
        # Add exception info if present
        if record.exc_info:
            parts.append(f"\nException: {self.formatException(record.exc_info)}")
            
        return " ".join(parts)
    
    def _format_json(self, record):
        """Format as JSON."""
        entry = LogEntry(
            timestamp=datetime.fromtimestamp(record.created).isoformat(),
            level=record.levelname,
            logger=record.name,
            message=record.getMessage(),
            module=record.module if hasattr(record, 'module') else record.filename,
            function=record.funcName,
            line=record.lineno,
            thread_id=record.thread,
            process_id=record.process,
            extra=getattr(record, 'extra', None),
            exception=self.formatException(record.exc_info) if record.exc_info else None,
            performance=getattr(record, 'performance', None)
        )
        return json.dumps(asdict(entry), default=str)
    
    def _format_standard(self, record):
        """Format as standard log format."""
        return f"{datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')} [{record.levelname}] {record.name}: {record.getMessage()}"


class CrashHandler:
    """Handle application crashes and generate crash reports."""
    
    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.crash_dir = log_dir / "crashes"
        self.crash_dir.mkdir(exist_ok=True)
        
    def handle_exception(self, exc_type, exc_value, exc_traceback):
        """Handle uncaught exceptions."""
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
            
        crash_id = from datetime import datetime
datetime.now().strftime("%Y%m%d_%H%M%S")
        crash_file = self.crash_dir / f"crash_{crash_id}.json"
        
        crash_report = {
            "crash_id": crash_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "exception_type": exc_type.__name__,
            "exception_message": str(exc_value),
            "traceback": traceback.format_exception(exc_type, exc_value, exc_traceback),
            "system_info": {
                "python_version": sys.version,
                "platform": sys.platform,
                "cwd": os.getcwd(),
                "pid": os.getpid()
            }
        }
        
        try:
            with open(crash_file, 'w') as f:
                json.dump(crash_report, f, indent=2)
            
            # Also log to main logger
            logger = logging.getLogger("plexichat.crash")
            logger.critical(f"Application crashed: {exc_type.__name__}: {exc_value}")
            logger.critical(f"Crash report saved to: {crash_file}")
            
        except Exception as e:
            logger.info(f"Failed to save crash report: {e}", file=sys.stderr)
        
        # Call original exception handler
        sys.__excepthook__(exc_type, exc_value, exc_traceback)


class PerformanceLogger:
    """Log performance metrics."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.start_times = {}
        
    def start_timer(self, operation: str):
        """Start timing an operation."""
        self.start_times[operation] = time.time()
        
    def end_timer(self, operation: str, extra_data: Optional[Dict[str, Any]] = None):
        """End timing and log performance."""
        if operation not in self.start_times:
            return
            
        duration = time.time() - self.start_times[operation]
        del self.start_times[operation]
        
        perf_data = {
            "operation": operation,
            "duration_ms": round(duration * 1000, 2),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        if extra_data is not None:
            perf_data.update(extra_data)
            
        # Create log record with performance data
        record = self.logger.makeRecord(
            self.logger.name, logging.INFO, __file__, 0,
            f"Performance: {operation} completed in {perf_data['duration_ms']}ms",
            (), None
        )
        record.performance = perf_data
        self.logger.handle(record)


class LogStreamer:
    """Stream logs in real-time."""
    
    def __init__(self, log_file: Path):
        self.log_file = log_file
        self.subscribers = []
        self.running = False
        self.thread = None
        
    def subscribe(self, callback):
        """Subscribe to log updates."""
        self.subscribers.append(callback)
        
    def start(self):
        """Start streaming logs."""
        if self.running:
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._stream_logs, daemon=True)
        self.thread.start()
        
    def stop(self):
        """Stop streaming logs."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
            
    def _stream_logs(self):
        """Stream log file changes."""
        if not self.log_file.exists():
            self.log_file.touch()
            
        with open(self.log_file, 'r') as f:
            # Go to end of file
            f.seek(0, 2)
            
            while self.running:
                line = f.readline()
                if line:
                    for callback in self.subscribers:
                        try:
                            callback(line.strip())
                        except Exception as e:
                            logger.info(f"Log subscriber error: {e}")
                else:
                    time.sleep(0.1)


class AdvancedLogger:
    """Advanced logging system manager."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        self.log_dir = from pathlib import Path
Path(self.config.get("log_directory", "logs"))
        self.log_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        (self.log_dir / "crashes").mkdir(exist_ok=True)
        (self.log_dir / "performance").mkdir(exist_ok=True)
        (self.log_dir / "security").mkdir(exist_ok=True)
        (self.log_dir / "audit").mkdir(exist_ok=True)
        
        self.crash_handler = CrashHandler(self.log_dir)
        self.performance_loggers = {}
        self.log_streamers = {}
        
        # Setup logging
        self._setup_logging()
        
        # Install crash handler
        sys.excepthook = self.crash_handler.handle_exception
        
    def _default_config(self):
        """Default logging configuration."""
        return {
            "log_directory": "logs",
            "log_level": "INFO",
            "console_enabled": True,
            "file_enabled": True,
            "structured_format": True,
            "json_format": False,
            "max_file_size": "10MB",
            "backup_count": 10,
            "performance_logging": True,
            "security_logging": True,
            "audit_logging": True
        }

    def _setup_logging(self):
        """Setup comprehensive logging system that consolidates all PlexiChat logging."""
        # Clear existing handlers to avoid conflicts with other logging systems
        root_logger = logging.getLogger()

        # Only clear handlers if we haven't already set them up
        if not hasattr(self, '_logging_setup_complete'):
            root_logger.handlers.clear()

        # Set root level
        log_level = getattr(logging, self.config["log_level"].upper(), logging.INFO)
        root_logger.setLevel(log_level)

        # Console handler
        if self.config["console_enabled"]:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(log_level)
            console_formatter = AdvancedFormatter("structured" if self.config["structured_format"] else "standard")
            console_handler.setFormatter(console_formatter)
            root_logger.addHandler(console_handler)

        # File handlers
        if self.config["file_enabled"]:
            self._setup_file_handlers(root_logger, log_level)

        # Performance logging
        if self.config["performance_logging"]:
            self._setup_performance_logging()

        # Security logging
        if self.config["security_logging"]:
            self._setup_security_logging()

        # Audit logging
        if self.config["audit_logging"]:
            self._setup_audit_logging()

        # Mark setup as complete to avoid conflicts
        self._logging_setup_complete = True

        # Generate initial log entries to ensure system is working
        logger = logging.getLogger("plexichat.logging.system")
        logger.info(" Advanced logging system initialized")
        logger.info(f" Log directory: {self.log_dir}")
        logger.info(f" Log level: {self.config['log_level']}")
        logger.debug(" Debug logging enabled")

        # Test all log levels
        logger.info(" INFO level logging active")
        logger.warning(" WARNING level logging active")
        logger.error(" ERROR level logging active")
        logger.critical(" CRITICAL level logging active")

    def _setup_file_handlers(self, root_logger, log_level):
        """Setup file-based logging handlers."""
        # Main log file
        main_log = self.log_dir / "plexichat.log"
        main_handler = logging.handlers.RotatingFileHandler(
            main_log,
            maxBytes=self._parse_size(self.config["max_file_size"]),
            backupCount=self.config["backup_count"],
            encoding='utf-8'
        )
        main_handler.setLevel(log_level)
        main_formatter = AdvancedFormatter("json" if self.config["json_format"] else "structured")
        main_handler.setFormatter(main_formatter)
        root_logger.addHandler(main_handler)

        # Error log file
        error_log = self.log_dir / "errors.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_log,
            maxBytes=self._parse_size(self.config["max_file_size"]),
            backupCount=self.config["backup_count"],
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(main_formatter)
        root_logger.addHandler(error_handler)

        # Latest log (for real-time monitoring)
        latest_log = self.log_dir / "latest.log"
        latest_handler = logging.FileHandler(latest_log, mode='w', encoding='utf-8')
        latest_handler.setLevel(log_level)
        latest_handler.setFormatter(AdvancedFormatter("standard"))
        root_logger.addHandler(latest_handler)

    def _setup_performance_logging(self):
        """Setup performance logging."""
        perf_logger = logging.getLogger("plexichat.performance")
        perf_log = self.log_dir / "performance" / "performance.log"

        perf_handler = logging.handlers.RotatingFileHandler(
            perf_log,
            maxBytes=self._parse_size("5MB"),
            backupCount=5,
            encoding='utf-8'
        )
        perf_handler.setFormatter(AdvancedFormatter("json"))
        perf_logger.addHandler(perf_handler)
        perf_logger.setLevel(logging.INFO)

    def _setup_security_logging(self):
        """Setup security logging."""
        sec_logger = logging.getLogger("plexichat.security")
        sec_log = self.log_dir / "security" / "security.log"

        sec_handler = logging.handlers.RotatingFileHandler(
            sec_log,
            maxBytes=self._parse_size("10MB"),
            backupCount=20,
            encoding='utf-8'
        )
        sec_handler.setFormatter(AdvancedFormatter("json"))
        sec_logger.addHandler(sec_handler)
        sec_logger.setLevel(logging.WARNING)

    def _setup_audit_logging(self):
        """Setup audit logging."""
        audit_logger = logging.getLogger("plexichat.audit")
        audit_log = self.log_dir / "audit" / "audit.log"

        audit_handler = logging.handlers.RotatingFileHandler(
            audit_log,
            maxBytes=self._parse_size("20MB"),
            backupCount=50,
            encoding='utf-8'
        )
        audit_handler.setFormatter(AdvancedFormatter("json"))
        audit_logger.addHandler(audit_handler)
        audit_logger.setLevel(logging.INFO)

    def _parse_size(self, size_str: str) -> int:
        """Parse size string to bytes."""
        size_str = size_str.upper()
        if size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)

    def get_performance_logger(self, name: str) -> PerformanceLogger:
        """Get performance logger for a component."""
        if name not in self.performance_loggers:
            logger = logging.getLogger(f"plexichat.performance.{name}")
            self.performance_loggers[name] = PerformanceLogger(logger)
        return self.performance_loggers[name]

    def get_log_streamer(self, log_type: str = "latest") -> LogStreamer:
        """Get log streamer for real-time monitoring."""
        if log_type not in self.log_streamers:
            log_file = self.log_dir / f"{log_type}.log"
            self.log_streamers[log_type] = LogStreamer(log_file)
        return self.log_streamers[log_type]

    def configure_module_logging(self, module_name: str, level: str = "INFO"):
        """Configure logging for a specific module."""
        logger = logging.getLogger(module_name)
        if level:
            logger.setLevel(getattr(logging, level.upper(), logging.INFO))

        # Add module-specific file handler if needed
        module_log = self.log_dir / f"{module_name.replace('.', '_')}.log"
        if not any(isinstance(h, logging.FileHandler) and h.baseFilename == str(module_log) for h in logger.handlers):
            handler = logging.handlers.RotatingFileHandler(
                module_log,
                maxBytes=self._parse_size("5MB"),
                backupCount=3,
                encoding='utf-8'
            )
            handler.setFormatter(AdvancedFormatter("structured"))
            logger.addHandler(handler)


# Global logger instance
_advanced_logger = None

def get_advanced_logger(config: Optional[Dict[str, Any]] = None) -> AdvancedLogger:
    """Get global advanced logger instance."""
    global _advanced_logger
    if _advanced_logger is None:
        _advanced_logger = AdvancedLogger(config)
    return _advanced_logger

def setup_module_logging(module_name: str, level: str = "INFO"):
    """Setup logging for a module."""
    logger = get_advanced_logger()
    logger.configure_module_logging(module_name, level)
    return logging.getLogger(module_name)
