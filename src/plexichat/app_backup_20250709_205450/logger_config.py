# app/logger_config.py
import os
import logging
import logging.handlers
import zipfile
import json
import threading
import queue
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from colorama import init, Fore, Style
from dotenv import load_dotenv

# load env - look for .env in app directory first, then project root
dotenv_path = Path(__file__).parent / ".env"
if not dotenv_path.exists():
    # Fallback to project root
    dotenv_path = Path(__file__).parent.parent / ".env"
load_dotenv(dotenv_path=dotenv_path)

# --- SETTINGS ---
class Settings:
    # Application Info
    APP_NAME = "NetLink"
    APP_VERSION = "1.0.0"
    APP_DESCRIPTION = "Modern distributed communication platform"
    APP_REPO = "linux-of-user/netlink"
    APP_GITHUB_URL = "https://github.com/linux-of-user/netlink"

    HOST   = os.getenv("HOST", "0.0.0.0")
    PORT   = int(os.getenv("PORT", "8000"))
    SECRET_KEY                 = os.getenv("SECRET_KEY", "supersecret")
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    WEBHOOK_SECRET             = os.getenv("WEBHOOK_SECRET", "your-webhook-secret")
    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        "postgresql://chatuser:chatpass@192.168.3.220:5432/chatdb"
    )
    DB_HOST   = os.getenv("DB_HOST", "")
    DB_PORT   = os.getenv("DB_PORT", "")
    BASE_URL  = os.getenv("BASE_URL", f"http://{HOST}:{PORT}")
    API_VERSION            = os.getenv("API_VERSION", "v1")
    LOG_LEVEL              = os.getenv("LOG_LEVEL", "DEBUG").upper()
    CONNECTIVITY_TIMEOUT   = float(os.getenv("CONNECTIVITY_TIMEOUT", "2.0"))
    TEST_USER,  TEST_PASS,  TEST_EMAIL,  TEST_DISPLAY  = (
        os.getenv("TEST_USER", "testuser"),
        os.getenv("TEST_PASS", "TestPass123!"),
        os.getenv("TEST_EMAIL", "testuser@example.com"),
        os.getenv("TEST_DISPLAY", "Test User"),
    )
    TEST_USER2, TEST_PASS2, TEST_EMAIL2, TEST_DISPLAY2 = (
        os.getenv("TEST_USER2", "testuser2"),
        os.getenv("TEST_PASS2", "TestPass123!"),
        os.getenv("TEST_EMAIL2", "testuser2@example.com"),
        os.getenv("TEST_DISPLAY2", "Test User 2"),
    )
    RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
    RATE_LIMIT_WINDOW   = int(os.getenv("RATE_LIMIT_WINDOW", "60"))

    # SSL Configuration
    SSL_KEYFILE  = os.getenv("SSL_KEYFILE", None)
    SSL_CERTFILE = os.getenv("SSL_CERTFILE", None)

    # Debug mode
    DEBUG = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes", "on")

    # Enhanced Logging Configuration
    LOG_TO_CONSOLE = os.getenv("LOG_TO_CONSOLE", "true").lower() in ("true", "1", "yes", "on")
    LOG_TO_FILE = os.getenv("LOG_TO_FILE", "true").lower() in ("true", "1", "yes", "on")
    LOG_CONSOLE_LEVEL = os.getenv("LOG_CONSOLE_LEVEL", "INFO").upper()
    LOG_FILE_LEVEL = os.getenv("LOG_FILE_LEVEL", "DEBUG").upper()
    LOG_DIR = os.getenv("LOG_DIR", "logs")
    LOG_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", "10485760"))  # 10MB
    LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", "30"))
    LOG_ROTATION_WHEN = os.getenv("LOG_ROTATION_WHEN", "midnight")
    LOG_ROTATION_INTERVAL = int(os.getenv("LOG_ROTATION_INTERVAL", "1"))
    LOG_COMPRESS_BACKUPS = os.getenv("LOG_COMPRESS_BACKUPS", "true").lower() in ("true", "1", "yes", "on")
    LOG_FORMAT_CONSOLE = os.getenv("LOG_FORMAT_CONSOLE", "[%(asctime)s] [%(levelname)-7s] %(name)s: %(message)s")
    LOG_FORMAT_FILE = os.getenv("LOG_FORMAT_FILE", "[%(asctime)s] [%(levelname)-7s] [%(name)s:%(lineno)d] %(funcName)s() - %(message)s")
    LOG_DATE_FORMAT = os.getenv("LOG_DATE_FORMAT", "%Y-%m-%d %H:%M:%S")
    LOG_CAPTURE_WARNINGS = os.getenv("LOG_CAPTURE_WARNINGS", "true").lower() in ("true", "1", "yes", "on")
    LOG_DISABLE_EXISTING_LOGGERS = os.getenv("LOG_DISABLE_EXISTING_LOGGERS", "false").lower() in ("true", "1", "yes", "on")

    # Advanced Logging Features
    LOG_JSON_FORMAT = os.getenv("LOG_JSON_FORMAT", "false").lower() in ("true", "1", "yes", "on")
    LOG_STRUCTURED = os.getenv("LOG_STRUCTURED", "true").lower() in ("true", "1", "yes", "on")
    LOG_INCLUDE_CONTEXT = os.getenv("LOG_INCLUDE_CONTEXT", "true").lower() in ("true", "1", "yes", "on")
    LOG_STREAM_ENABLED = os.getenv("LOG_STREAM_ENABLED", "true").lower() in ("true", "1", "yes", "on")
    LOG_STREAM_BUFFER_SIZE = int(os.getenv("LOG_STREAM_BUFFER_SIZE", "1000"))
    LOG_PERFORMANCE_TRACKING = os.getenv("LOG_PERFORMANCE_TRACKING", "true").lower() in ("true", "1", "yes", "on")
    LOG_REQUEST_ID_HEADER = os.getenv("LOG_REQUEST_ID_HEADER", "X-Request-ID")
    LOG_CORRELATION_ID_ENABLED = os.getenv("LOG_CORRELATION_ID_ENABLED", "true").lower() in ("true", "1", "yes", "on")

    # Self-Test Configuration
    SELFTEST_ENABLED = os.getenv("SELFTEST_ENABLED", "true").lower() in ("true", "1", "yes", "on")
    SELFTEST_INTERVAL_MINUTES = int(os.getenv("SELFTEST_INTERVAL_MINUTES", "5"))
    SELFTEST_INITIAL_DELAY_SECONDS = int(os.getenv("SELFTEST_INITIAL_DELAY_SECONDS", "15"))
    SELFTEST_TIMEOUT_SECONDS = int(os.getenv("SELFTEST_TIMEOUT_SECONDS", "30"))
    SELFTEST_RETRY_COUNT = int(os.getenv("SELFTEST_RETRY_COUNT", "3"))
    SELFTEST_RETRY_DELAY_SECONDS = int(os.getenv("SELFTEST_RETRY_DELAY_SECONDS", "5"))
    SELFTEST_LOG_RESULTS = os.getenv("SELFTEST_LOG_RESULTS", "true").lower() in ("true", "1", "yes", "on")
    SELFTEST_LOG_LEVEL = os.getenv("SELFTEST_LOG_LEVEL", "INFO").upper()
    SELFTEST_SAVE_RESULTS = os.getenv("SELFTEST_SAVE_RESULTS", "true").lower() in ("true", "1", "yes", "on")
    SELFTEST_RESULTS_DIR = os.getenv("SELFTEST_RESULTS_DIR", "logs/selftest")
    SELFTEST_ALERT_ON_FAILURE = os.getenv("SELFTEST_ALERT_ON_FAILURE", "true").lower() in ("true", "1", "yes", "on")
    SELFTEST_FAILURE_THRESHOLD = int(os.getenv("SELFTEST_FAILURE_THRESHOLD", "3"))

    # Monitoring Configuration
    MONITORING_ENABLED = os.getenv("MONITORING_ENABLED", "true").lower() in ("true", "1", "yes", "on")
    MONITORING_LOG_PERFORMANCE = os.getenv("MONITORING_LOG_PERFORMANCE", "true").lower() in ("true", "1", "yes", "on")
    MONITORING_LOG_MEMORY_USAGE = os.getenv("MONITORING_LOG_MEMORY_USAGE", "false").lower() in ("true", "1", "yes", "on")
    MONITORING_LOG_DISK_USAGE = os.getenv("MONITORING_LOG_DISK_USAGE", "false").lower() in ("true", "1", "yes", "on")

settings = Settings()

# --- TRACE LEVEL ---
TRACE_LEVEL = 5
logging.addLevelName(TRACE_LEVEL, "TRACE")
def trace(self, msg, *args, **kwargs):
    if self.isEnabledFor(TRACE_LEVEL):
        self._log(TRACE_LEVEL, msg, args, **kwargs)
logging.Logger.trace = trace

# --- ENHANCED LOGGER SETUP ---
init(autoreset=True)

class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def __init__(self, include_context=True):
        super().__init__()
        self.include_context = include_context

    def format(self, record):
        try:
            log_entry = {
                "timestamp": datetime.fromtimestamp(record.created).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "module": record.module,
                "function": record.funcName,
                "line": record.lineno,
            }

            if self.include_context:
                log_entry.update({
                    "thread": record.thread,
                    "thread_name": record.threadName,
                    "process": record.process,
                    "process_name": getattr(record, 'processName', 'MainProcess'),
                })

            # Add exception info if present
            if record.exc_info:
                log_entry["exception"] = self.formatException(record.exc_info)

            # Add extra fields
            for key, value in record.__dict__.items():
                if key not in ('name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                              'filename', 'module', 'lineno', 'funcName', 'created',
                              'msecs', 'relativeCreated', 'thread', 'threadName',
                              'processName', 'process', 'exc_info', 'exc_text', 'stack_info'):
                    log_entry[key] = value

            return json.dumps(log_entry, default=str)
        except Exception as e:
            return json.dumps({
                "timestamp": datetime.now().isoformat(),
                "level": "ERROR",
                "logger": "logging_system",
                "message": f"JSON formatting error: {e}",
                "original_message": str(record.getMessage())
            })

class ColourizedFormatter(logging.Formatter):
    """Enhanced colorized formatter with better formatting and error handling."""
    COLORS = {
        logging.DEBUG:    Fore.CYAN,
        logging.INFO:     Fore.GREEN,
        logging.WARNING:  Fore.YELLOW,
        logging.ERROR:    Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
        TRACE_LEVEL:      Fore.MAGENTA,
    }

    def __init__(self, fmt=None, datefmt=None, show_colors=True, structured=False):
        super().__init__(fmt, datefmt)
        self.show_colors = show_colors
        self.structured = structured

    def format(self, record):
        try:
            if self.structured:
                return self._format_structured(record)
            elif self.show_colors:
                col = self.COLORS.get(record.levelno, "")
                # Create a copy of the record to avoid modifying the original
                record_copy = logging.makeLogRecord(record.__dict__)
                record_copy.levelname = f"{col}{record.levelname:<7}{Style.RESET_ALL}"
                return super().format(record_copy)
            else:
                return super().format(record)
        except Exception as e:
            # Fallback formatting if colorization fails
            return f"[LOGGING ERROR] {record.getMessage()} (Format error: {e})"

    def _format_structured(self, record):
        """Format with structured information."""
        try:
            base_format = super().format(record)

            # Add context information if available
            context_parts = []
            if hasattr(record, 'request_id'):
                context_parts.append(f"req_id={record.request_id}")
            if hasattr(record, 'user_id'):
                context_parts.append(f"user={record.user_id}")
            if hasattr(record, 'endpoint'):
                context_parts.append(f"endpoint={record.endpoint}")
            if hasattr(record, 'duration'):
                context_parts.append(f"duration={record.duration}ms")

            if context_parts:
                context_str = " [" + " | ".join(context_parts) + "]"
                return base_format + context_str

            return base_format
        except Exception as e:
            return f"[STRUCTURED FORMAT ERROR] {record.getMessage()} (Error: {e})"

class LogStreamHandler(logging.Handler):
    """Handler that streams log records to a buffer for real-time access."""

    def __init__(self, buffer_size=1000):
        super().__init__()
        self.buffer_size = buffer_size
        self.buffer = queue.deque(maxlen=buffer_size)
        self.subscribers = set()
        self.lock = threading.Lock()

    def emit(self, record):
        try:
            formatted = self.format(record)
            log_entry = {
                'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                'level': record.levelname,
                'logger': record.name,
                'message': record.getMessage(),
                'formatted': formatted,
                'module': record.module,
                'function': record.funcName,
                'line': record.lineno
            }

            with self.lock:
                self.buffer.append(log_entry)
                # Notify subscribers
                for subscriber in self.subscribers.copy():
                    try:
                        subscriber.put_nowait(log_entry)
                    except queue.Full:
                        # Remove full subscribers
                        self.subscribers.discard(subscriber)
                    except Exception:
                        # Remove broken subscribers
                        self.subscribers.discard(subscriber)
        except Exception:
            self.handleError(record)

    def get_recent_logs(self, count=None):
        """Get recent log entries."""
        with self.lock:
            if count is None:
                return list(self.buffer)
            else:
                return list(self.buffer)[-count:]

    def subscribe(self, subscriber_queue):
        """Subscribe to real-time log updates."""
        with self.lock:
            self.subscribers.add(subscriber_queue)

    def unsubscribe(self, subscriber_queue):
        """Unsubscribe from real-time log updates."""
        with self.lock:
            self.subscribers.discard(subscriber_queue)

class CompressingTimedRotatingFileHandler(logging.handlers.TimedRotatingFileHandler):
    """Enhanced rotating file handler with compression and better error handling."""

    def __init__(self, *args, compress_backups=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.compress_backups = compress_backups

    def doRollover(self):
        try:
            super().doRollover()
            if self.compress_backups:
                self._compress_old_logs()
        except Exception as e:
            # Log the error but don't crash the application
            print(f"[LOGGING ERROR] Failed to rotate log file: {e}")

    def _compress_old_logs(self):
        """Compress rotated log files."""
        try:
            log_dir = Path(self.baseFilename).parent
            base_name = Path(self.baseFilename).name

            # Find uncompressed backup files
            for log_file in log_dir.glob(f"{base_name}.*"):
                if log_file.suffix not in ('.zip', '.gz') and log_file.name != base_name:
                    try:
                        zip_path = log_file.with_suffix(log_file.suffix + '.zip')
                        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                            zf.write(log_file, log_file.name)
                        log_file.unlink()  # Remove original file
                    except Exception as e:
                        print(f"[LOGGING ERROR] Failed to compress {log_file}: {e}")
        except Exception as e:
            print(f"[LOGGING ERROR] Failed to compress old logs: {e}")

class LoggingManager:
    """Centralized logging management with comprehensive configuration."""

    def __init__(self, settings):
        self.settings = settings
        self.loggers = {}
        self.handlers = []
        self.stream_handler = None
        self.performance_tracker = {}
        self._setup_logging()

    def _setup_logging(self):
        """Setup comprehensive logging system."""
        try:
            # Configure root logging
            if self.settings.LOG_CAPTURE_WARNINGS:
                logging.captureWarnings(True)

            # Create log directory
            log_dir = Path(self.settings.LOG_DIR)
            log_dir.mkdir(exist_ok=True)

            # Create selftest results directory
            if self.settings.SELFTEST_SAVE_RESULTS:
                selftest_dir = Path(self.settings.SELFTEST_RESULTS_DIR)
                selftest_dir.mkdir(parents=True, exist_ok=True)

            # Setup main application logger
            self._setup_main_logger()

            # Setup specialized loggers
            self._setup_selftest_logger()
            self._setup_monitoring_logger()

            # Silence noisy third-party loggers
            self._configure_third_party_loggers()

        except Exception as e:
            print(f"[LOGGING ERROR] Failed to setup logging: {e}")
            # Fallback to basic console logging
            logging.basicConfig(level=logging.INFO)

    def _setup_main_logger(self):
        """Setup the main application logger."""
        logger = logging.getLogger("chat_server")
        logger.setLevel(TRACE_LEVEL)
        logger.handlers.clear()  # Clear any existing handlers

        # Console handler
        if self.settings.LOG_TO_CONSOLE:
            console_handler = logging.StreamHandler()
            console_level = getattr(logging, self.settings.LOG_CONSOLE_LEVEL, logging.INFO)
            console_handler.setLevel(console_level)

            if self.settings.LOG_JSON_FORMAT:
                console_formatter = JSONFormatter(include_context=self.settings.LOG_INCLUDE_CONTEXT)
            else:
                console_formatter = ColourizedFormatter(
                    self.settings.LOG_FORMAT_CONSOLE,
                    self.settings.LOG_DATE_FORMAT,
                    show_colors=True,
                    structured=self.settings.LOG_STRUCTURED
                )
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)
            self.handlers.append(console_handler)

        # Stream handler for real-time log access
        if self.settings.LOG_STREAM_ENABLED:
            self.stream_handler = LogStreamHandler(buffer_size=self.settings.LOG_STREAM_BUFFER_SIZE)
            self.stream_handler.setLevel(logging.DEBUG)

            if self.settings.LOG_JSON_FORMAT:
                stream_formatter = JSONFormatter(include_context=self.settings.LOG_INCLUDE_CONTEXT)
            else:
                stream_formatter = ColourizedFormatter(
                    self.settings.LOG_FORMAT_FILE,
                    self.settings.LOG_DATE_FORMAT,
                    show_colors=False,
                    structured=self.settings.LOG_STRUCTURED
                )
            self.stream_handler.setFormatter(stream_formatter)
            logger.addHandler(self.stream_handler)
            self.handlers.append(self.stream_handler)

        # File handlers
        if self.settings.LOG_TO_FILE:
            self._add_file_handlers(logger)

        self.loggers['main'] = logger
        return logger

    def _add_file_handlers(self, logger):
        """Add file handlers to logger."""
        try:
            log_dir = Path(self.settings.LOG_DIR)
            file_level = getattr(logging, self.settings.LOG_FILE_LEVEL, logging.DEBUG)

            # Latest log file (always current)
            latest_handler = logging.FileHandler(
                log_dir / "latest.log",
                mode="w",
                encoding="utf-8"
            )
            latest_handler.setLevel(file_level)
            latest_formatter = logging.Formatter(
                self.settings.LOG_FORMAT_FILE,
                self.settings.LOG_DATE_FORMAT
            )
            latest_handler.setFormatter(latest_formatter)
            logger.addHandler(latest_handler)
            self.handlers.append(latest_handler)

            # Rotating log file
            rotating_handler = CompressingTimedRotatingFileHandler(
                filename=log_dir / "chatapi.log",
                when=self.settings.LOG_ROTATION_WHEN,
                interval=self.settings.LOG_ROTATION_INTERVAL,
                backupCount=self.settings.LOG_BACKUP_COUNT,
                encoding="utf-8",
                compress_backups=self.settings.LOG_COMPRESS_BACKUPS
            )
            rotating_handler.setLevel(file_level)
            rotating_handler.setFormatter(latest_formatter)
            logger.addHandler(rotating_handler)
            self.handlers.append(rotating_handler)

        except Exception as e:
            print(f"[LOGGING ERROR] Failed to setup file handlers: {e}")

    def _setup_selftest_logger(self):
        """Setup specialized logger for self-tests."""
        if not self.settings.SELFTEST_ENABLED:
            return

        logger = logging.getLogger("selftest")
        logger.setLevel(getattr(logging, self.settings.SELFTEST_LOG_LEVEL, logging.INFO))
        logger.handlers.clear()

        if self.settings.SELFTEST_SAVE_RESULTS:
            try:
                results_dir = Path(self.settings.SELFTEST_RESULTS_DIR)

                # Selftest results file
                selftest_handler = CompressingTimedRotatingFileHandler(
                    filename=results_dir / "selftest_results.log",
                    when="midnight",
                    interval=1,
                    backupCount=7,
                    encoding="utf-8",
                    compress_backups=True
                )
                selftest_handler.setLevel(logging.INFO)
                selftest_formatter = logging.Formatter(
                    "[%(asctime)s] [%(levelname)-7s] %(message)s",
                    "%Y-%m-%d %H:%M:%S"
                )
                selftest_handler.setFormatter(selftest_formatter)
                logger.addHandler(selftest_handler)
                self.handlers.append(selftest_handler)

            except Exception as e:
                print(f"[LOGGING ERROR] Failed to setup selftest logger: {e}")

        self.loggers['selftest'] = logger
        return logger

    def _setup_monitoring_logger(self):
        """Setup specialized logger for monitoring."""
        if not self.settings.MONITORING_ENABLED:
            return

        logger = logging.getLogger("monitoring")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()

        try:
            log_dir = Path(self.settings.LOG_DIR)

            # Monitoring log file
            monitoring_handler = CompressingTimedRotatingFileHandler(
                filename=log_dir / "monitoring.log",
                when="midnight",
                interval=1,
                backupCount=7,
                encoding="utf-8",
                compress_backups=True
            )
            monitoring_handler.setLevel(logging.INFO)
            monitoring_formatter = logging.Formatter(
                "[%(asctime)s] [MONITORING] %(message)s",
                "%Y-%m-%d %H:%M:%S"
            )
            monitoring_handler.setFormatter(monitoring_formatter)
            logger.addHandler(monitoring_handler)
            self.handlers.append(monitoring_handler)

        except Exception as e:
            print(f"[LOGGING ERROR] Failed to setup monitoring logger: {e}")

        self.loggers['monitoring'] = logger
        return logger

    def _configure_third_party_loggers(self):
        """Configure third-party library loggers."""
        # Silence noisy loggers
        logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
        logging.getLogger("sqlalchemy.pool").setLevel(logging.WARNING)
        logging.getLogger("sqlalchemy.dialects").setLevel(logging.WARNING)
        logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
        logging.getLogger("requests.packages.urllib3").setLevel(logging.WARNING)
        logging.getLogger("asyncio").setLevel(logging.WARNING)

        # Configure uvicorn loggers
        logging.getLogger("uvicorn.access").setLevel(logging.INFO)
        logging.getLogger("uvicorn.error").setLevel(logging.INFO)

    def get_logger(self, name="main"):
        """Get a configured logger by name."""
        return self.loggers.get(name, self.loggers.get('main'))

    def get_stream_handler(self):
        """Get the log stream handler for real-time access."""
        return self.stream_handler

    def get_recent_logs(self, count=None):
        """Get recent log entries from the stream handler."""
        if self.stream_handler:
            return self.stream_handler.get_recent_logs(count)
        return []

    def subscribe_to_logs(self, subscriber_queue):
        """Subscribe to real-time log updates."""
        if self.stream_handler:
            self.stream_handler.subscribe(subscriber_queue)

    def unsubscribe_from_logs(self, subscriber_queue):
        """Unsubscribe from real-time log updates."""
        if self.stream_handler:
            self.stream_handler.unsubscribe(subscriber_queue)

    def start_performance_tracking(self, operation_id: str):
        """Start tracking performance for an operation."""
        if self.settings.LOG_PERFORMANCE_TRACKING:
            self.performance_tracker[operation_id] = time.time()

    def end_performance_tracking(self, operation_id: str, logger_name="main", extra_context=None):
        """End performance tracking and log the result."""
        if self.settings.LOG_PERFORMANCE_TRACKING and operation_id in self.performance_tracker:
            duration = (time.time() - self.performance_tracker.pop(operation_id)) * 1000
            logger = self.get_logger(logger_name)

            context = {"operation": operation_id, "duration": f"{duration:.2f}ms"}
            if extra_context:
                context.update(extra_context)

            logger.info("Performance: %s completed in %.2fms", operation_id, duration, extra=context)
            return duration
        return None

    def log_with_context(self, logger_name="main", level=logging.INFO, message="", **context):
        """Log a message with additional context."""
        logger = self.get_logger(logger_name)
        logger.log(level, message, extra=context)

    def shutdown(self):
        """Properly shutdown all logging handlers."""
        for handler in self.handlers:
            try:
                handler.close()
            except Exception as e:
                print(f"[LOGGING ERROR] Failed to close handler: {e}")

# Context management for request tracking
_context_storage = threading.local()

def set_log_context(**context):
    """Set logging context for the current thread."""
    if not hasattr(_context_storage, 'context'):
        _context_storage.context = {}
    _context_storage.context.update(context)

def get_log_context():
    """Get current logging context."""
    return getattr(_context_storage, 'context', {})

def clear_log_context():
    """Clear current logging context."""
    if hasattr(_context_storage, 'context'):
        _context_storage.context.clear()

# Enhanced logging filter to add context
class ContextFilter(logging.Filter):
    """Filter to add context information to log records."""

    def filter(self, record):
        context = get_log_context()
        for key, value in context.items():
            setattr(record, key, value)
        return True

# Initialize logging system
logging_manager = LoggingManager(settings)
logger = logging_manager.get_logger("main")
selftest_logger = logging_manager.get_logger("selftest")
monitoring_logger = logging_manager.get_logger("monitoring")

# Add context filter to main logger
context_filter = ContextFilter()
logger.addFilter(context_filter)

# Enhanced performance and metrics tracking
class PerformanceLogger:
    """Enhanced performance logging with detailed metrics."""

    def __init__(self, logger):
        self.logger = logger
        self.active_operations = {}
        self.metrics = {
            'requests_total': 0,
            'requests_success': 0,
            'requests_error': 0,
            'avg_response_time': 0,
            'peak_memory_usage': 0,
            'active_connections': 0
        }
        self.lock = threading.Lock()

    def start_operation(self, operation_id: str, operation_type: str = "request", **context):
        """Start tracking an operation with enhanced context."""
        with self.lock:
            self.active_operations[operation_id] = {
                'start_time': time.time(),
                'type': operation_type,
                'context': context
            }
            self.metrics['requests_total'] += 1

        self.logger.debug(f"Started {operation_type}: {operation_id}",
                         extra={'operation_id': operation_id, 'operation_type': operation_type, **context})

    def end_operation(self, operation_id: str, success: bool = True, **result_context):
        """End operation tracking with success/failure metrics."""
        with self.lock:
            if operation_id not in self.active_operations:
                self.logger.warning(f"Attempted to end unknown operation: {operation_id}")
                return None

            operation = self.active_operations.pop(operation_id)
            duration = (time.time() - operation['start_time']) * 1000

            # Update metrics
            if success:
                self.metrics['requests_success'] += 1
            else:
                self.metrics['requests_error'] += 1

            # Update average response time
            total_requests = self.metrics['requests_success'] + self.metrics['requests_error']
            if total_requests > 0:
                self.metrics['avg_response_time'] = (
                    (self.metrics['avg_response_time'] * (total_requests - 1) + duration) / total_requests
                )

        # Log completion
        log_level = logging.INFO if success else logging.ERROR
        status = "completed" if success else "failed"

        self.logger.log(log_level, f"Operation {status}: {operation_id} in {duration:.2f}ms",
                       extra={
                           'operation_id': operation_id,
                           'operation_type': operation['type'],
                           'duration_ms': duration,
                           'success': success,
                           **operation['context'],
                           **result_context
                       })

        return duration

    def get_metrics(self):
        """Get current performance metrics."""
        with self.lock:
            return {
                **self.metrics,
                'active_operations': len(self.active_operations),
                'timestamp': datetime.now().isoformat()
            }

    def log_metrics(self):
        """Log current metrics."""
        metrics = self.get_metrics()
        self.logger.info("Performance Metrics", extra={'metrics': metrics})

# Enhanced system monitoring
class SystemMonitor:
    """Enhanced system monitoring with resource tracking."""

    def __init__(self, logger):
        self.logger = logger
        self.monitoring_active = False
        self.monitor_thread = None

    def start_monitoring(self, interval: int = 60):
        """Start system monitoring."""
        if self.monitoring_active:
            return

        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, args=(interval,), daemon=True)
        self.monitor_thread.start()
        self.logger.info("System monitoring started", extra={'interval': interval})

    def stop_monitoring(self):
        """Stop system monitoring."""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info("System monitoring stopped")

    def _monitor_loop(self, interval):
        """Main monitoring loop."""
        import psutil

        while self.monitoring_active:
            try:
                # Collect system metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')

                # Network stats
                network = psutil.net_io_counters()

                metrics = {
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'memory_used_mb': memory.used // (1024 * 1024),
                    'memory_available_mb': memory.available // (1024 * 1024),
                    'disk_percent': disk.percent,
                    'disk_used_gb': disk.used // (1024 * 1024 * 1024),
                    'disk_free_gb': disk.free // (1024 * 1024 * 1024),
                    'network_bytes_sent': network.bytes_sent,
                    'network_bytes_recv': network.bytes_recv,
                    'timestamp': datetime.now().isoformat()
                }

                self.logger.info("System metrics", extra={'system_metrics': metrics})

                # Alert on high resource usage
                if cpu_percent > 80:
                    self.logger.warning(f"High CPU usage: {cpu_percent}%", extra={'cpu_percent': cpu_percent})
                if memory.percent > 85:
                    self.logger.warning(f"High memory usage: {memory.percent}%", extra={'memory_percent': memory.percent})
                if disk.percent > 90:
                    self.logger.warning(f"High disk usage: {disk.percent}%", extra={'disk_percent': disk.percent})

                time.sleep(interval)

            except Exception as e:
                self.logger.error(f"System monitoring error: {e}", exc_info=True)
                time.sleep(interval)

# Initialize enhanced components
performance_logger = PerformanceLogger(logger)
system_monitor = SystemMonitor(monitoring_logger)

# Log successful initialization
logger.info("Enhanced logging system initialized successfully")
logger.info("Configuration: Console=%s, File=%s, JSON=%s, Stream=%s, Level=%s/%s",
           settings.LOG_TO_CONSOLE, settings.LOG_TO_FILE, settings.LOG_JSON_FORMAT,
           settings.LOG_STREAM_ENABLED, settings.LOG_CONSOLE_LEVEL, settings.LOG_FILE_LEVEL)

# System monitoring can be started manually to avoid import-time hanging
# if settings.MONITORING_ENABLED:
#     system_monitor.start_monitoring()

def start_system_monitoring():
    """Start system monitoring manually to avoid import-time issues."""
    if settings.MONITORING_ENABLED and not system_monitor.monitoring_active:
        system_monitor.start_monitoring()
