"""
Enhanced Logging System for PlexiChat
Provides comprehensive logging with structured output, contextual information, and monitoring.
"""

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
import uuid
import inspect

# Core imports
try:
    from ..unified_config import get_config as _get_unified_config
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
        return type('Config', (), {'logging': type('Logging', (), {})()})()


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
    PERFORMANCE = 80


class LogCategory(Enum):
    """Log categories for organization."""
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


@dataclass
class LogContext:
    """Context information for logs."""
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
    tenant_id: Optional[str] = None
    component: Optional[str] = None
    version: Optional[str] = None


@dataclass
class PerformanceMetrics:
    """Performance metrics for logging."""
    duration_ms: Optional[float] = None
    memory_usage_mb: Optional[float] = None
    cpu_usage_percent: Optional[float] = None
    disk_io_mb: Optional[float] = None
    network_io_mb: Optional[float] = None
    database_queries: Optional[int] = None
    cache_hits: Optional[int] = None
    cache_misses: Optional[int] = None


@dataclass
class SecurityMetrics:
    """Security-related metrics."""
    threat_score: Optional[float] = None
    blocked_attempts: Optional[int] = None
    failed_authentications: Optional[int] = None
    privilege_escalations: Optional[int] = None
    suspicious_activities: Optional[int] = None


@dataclass
class LogEntry:
    """Enhanced structured log entry."""
    timestamp: datetime
    level: LogLevel
    category: LogCategory
    message: str
    module: str
    function: str
    line: int
    thread_id: str
    process_id: int
    hostname: str
    context: LogContext = field(default_factory=LogContext)
    metadata: Dict[str, Any] = field(default_factory=dict)
    performance: Optional[PerformanceMetrics] = None
    security: Optional[SecurityMetrics] = None
    stack_trace: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.name,
            "category": self.category.value if hasattr(self.category, 'value') else str(self.category),
            "message": self.message,
            "module": self.module,
            "function": self.function,
            "line": self.line,
            "thread_id": self.thread_id,
            "process_id": self.process_id,
            "hostname": self.hostname,
            "context": asdict(self.context) if self.context else {},
            "metadata": self.metadata,
            "tags": self.tags
        }
        
        if self.performance:
            data["performance"] = asdict(self.performance)
        
        if self.security:
            data["security"] = asdict(self.security)
        
        if self.stack_trace:
            data["stack_trace"] = self.stack_trace
        
        return data
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str, separators=(',', ':'))


class LogBuffer:
    """Thread-safe circular buffer for log entries."""
    
    def __init__(self, max_size: int = 50000):
        self.max_size = max_size
        self.buffer = deque(maxlen=max_size)
        self.lock = threading.RLock()
        self.subscribers = []
        self.stats = {
            "total_entries": 0,
            "entries_by_level": defaultdict(int),
            "entries_by_category": defaultdict(int),
            "buffer_overflows": 0
        }
    
    def add_entry(self, entry: LogEntry):
        """Add log entry to buffer."""
        with self.lock:
            if len(self.buffer) == self.max_size:
                self.stats["buffer_overflows"] += 1
            
            self.buffer.append(entry)
            self.stats["total_entries"] += 1
            self.stats["entries_by_level"][entry.level.name] += 1
            category_key = entry.category.value if hasattr(entry.category, 'value') else str(entry.category)
            self.stats["entries_by_category"][category_key] += 1
            
            # Notify subscribers asynchronously
            for subscriber in self.subscribers[:]:  # Copy list to avoid modification during iteration
                try:
                    if asyncio.iscoroutinefunction(subscriber):
                        asyncio.create_task(subscriber(entry))
                    else:
                        subscriber(entry)
                except Exception as e:
                    # Remove failed subscribers
                    try:
                        self.subscribers.remove(subscriber)
                    except ValueError:
                        pass
    
    def get_entries(self, 
                   count: Optional[int] = None,
                   level_filter: Optional[LogLevel] = None,
                   category_filter: Optional[LogCategory] = None,
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None,
                   tags: Optional[List[str]] = None) -> List[LogEntry]:
        """Get filtered log entries."""
        with self.lock:
            entries = list(self.buffer)
            
            # Apply filters
            if level_filter:
                entries = [e for e in entries if e.level.value >= level_filter.value]
            
            if category_filter:
                entries = [e for e in entries if e.category == category_filter]
            
            if start_time:
                entries = [e for e in entries if e.timestamp >= start_time]
            
            if end_time:
                entries = [e for e in entries if e.timestamp <= end_time]
            
            if tags:
                entries = [e for e in entries if any(tag in e.tags for tag in tags)]
            
            # Sort by timestamp (most recent first)
            entries.sort(key=lambda x: x.timestamp, reverse=True)
            
            # Limit count
            if count:
                entries = entries[:count]
            
            return entries
    
    def subscribe(self, callback: Callable[[LogEntry], None]):
        """Subscribe to real-time log entries."""
        with self.lock:
            self.subscribers.append(callback)
    
    def unsubscribe(self, callback: Callable[[LogEntry], None]):
        """Unsubscribe from log entries."""
        with self.lock:
            try:
                self.subscribers.remove(callback)
            except ValueError:
                pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get buffer statistics."""
        with self.lock:
            return {
                "buffer_size": len(self.buffer),
                "max_size": self.max_size,
                "stats": dict(self.stats),
                "subscribers": len(self.subscribers)
            }
    
    def clear(self):
        """Clear the buffer."""
        with self.lock:
            self.buffer.clear()
            self.stats = {
                "total_entries": 0,
                "entries_by_level": defaultdict(int),
                "entries_by_category": defaultdict(int),
                "buffer_overflows": 0
            }


class PerformanceTracker:
    """Performance tracking for operations."""
    
    def __init__(self):
        self.operations = defaultdict(list)
        self.lock = threading.RLock()
    
    def track_operation(self, operation: str, duration: float, metadata: Optional[Dict] = None):
        """Track operation performance."""
        with self.lock:
            self.operations[operation].append({
                "duration": duration,
                "timestamp": datetime.now(timezone.utc),
                "metadata": metadata or {}
            })
            
            # Keep only last 1000 entries per operation
            if len(self.operations[operation]) > 1000:
                self.operations[operation] = self.operations[operation][-1000:]
    
    def get_stats(self, operation: Optional[str] = None) -> Dict[str, Any]:
        """Get performance statistics."""
        with self.lock:
            if operation:
                if operation not in self.operations:
                    return {}
                
                durations = [op["duration"] for op in self.operations[operation]]
                return {
                    "operation": operation,
                    "count": len(durations),
                    "avg_duration": sum(durations) / len(durations) if durations else 0,
                    "min_duration": min(durations) if durations else 0,
                    "max_duration": max(durations) if durations else 0,
                    "recent_durations": durations[-10:] if durations else [],
                    "p95": self._percentile(durations, 95) if durations else 0,
                    "p99": self._percentile(durations, 99) if durations else 0
                }
            else:
                return {op: self.get_stats(op) for op in self.operations.keys()}
    
    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile value."""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        index = int((percentile / 100) * len(sorted_data))
        return sorted_data[min(index, len(sorted_data) - 1)]


class StructuredFormatter(logging.Formatter):
    """Enhanced structured JSON formatter."""
    
    def __init__(self, include_context: bool = True, include_performance: bool = True):
        super().__init__()
        self.include_context = include_context
        self.include_performance = include_performance
        self.hostname = os.uname().nodename if hasattr(os, 'uname') else 'unknown'
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON."""
        # Get caller information
        frame = inspect.currentframe()
        try:
            # Walk up the stack to find the actual calling code
            while frame and (
                frame.f_code.co_filename.endswith('logging/__init__.py') or
                frame.f_code.co_filename.endswith('enhanced_logging_system.py')
            ):
                frame = frame.f_back
            
            if frame:
                caller_filename = frame.f_code.co_filename
                caller_function = frame.f_code.co_name
                caller_lineno = frame.f_lineno
            else:
                caller_filename = record.pathname
                caller_function = record.funcName
                caller_lineno = record.lineno
        finally:
            del frame
        
        # Extract context and metadata
        context = getattr(record, 'context', LogContext())
        metadata = getattr(record, 'metadata', {})
        performance = getattr(record, 'performance', None)
        security = getattr(record, 'security', None)
        tags = getattr(record, 'tags', [])
        
        # Create log entry
        entry = LogEntry(
            timestamp=datetime.fromtimestamp(record.created, tz=timezone.utc),
            level=self._get_log_level(record.levelname),
            category=getattr(record, 'category', LogCategory.SYSTEM),
            message=record.getMessage(),
            module=os.path.basename(caller_filename).replace('.py', ''),
            function=caller_function,
            line=caller_lineno,
            thread_id=str(threading.current_thread().ident),
            process_id=os.getpid(),
            hostname=self.hostname,
            context=context if self.include_context else LogContext(),
            metadata=metadata,
            performance=performance if self.include_performance else None,
            security=security,
            stack_trace=self.formatException(record.exc_info) if record.exc_info else None,
            tags=tags
        )
        
        return entry.to_json()
    
    def _get_log_level(self, level_name: str) -> LogLevel:
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


class ColorizedConsoleFormatter(logging.Formatter):
    """Colorized console formatter for better readability."""
    
    COLORS = {
        'TRACE': '\033[90m',      # Dark gray
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'SECURITY': '\033[41m',   # Red background
        'AUDIT': '\033[44m',      # Blue background
        'PERFORMANCE': '\033[43m', # Yellow background
        'RESET': '\033[0m'        # Reset
    }
    
    def __init__(self, fmt: str = None, datefmt: str = None, use_colors: bool = True):
        if fmt is None:
            fmt = '[%(asctime)s] %(levelname)-8s [%(name)s:%(lineno)d] %(message)s'
        if datefmt is None:
            datefmt = '%Y-%m-%d %H:%M:%S'
        
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors and sys.stdout.isatty()
    
    def format(self, record: logging.LogRecord) -> str:
        """Format with colors if enabled."""
        if self.use_colors:
            level_color = self.COLORS.get(record.levelname, '')
            reset_color = self.COLORS['RESET']
            
            # Colorize level name
            original_levelname = record.levelname
            record.levelname = f"{level_color}{record.levelname:<8}{reset_color}"
            
            # Colorize message based on level
            original_msg = record.getMessage()
            if record.levelno >= logging.ERROR:
                record.msg = f"{self.COLORS['ERROR']}{original_msg}{reset_color}"
            elif record.levelno >= logging.WARNING:
                record.msg = f"{self.COLORS['WARNING']}{original_msg}{reset_color}"
            
            formatted = super().format(record)
            
            # Restore original values
            record.levelname = original_levelname
            record.msg = original_msg
            
            return formatted
        else:
            return super().format(record)


class CompressingRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Rotating file handler with automatic compression."""
    
    def doRollover(self):
        """Perform rollover with compression."""
        super().doRollover()
        
        # Compress rotated files
        if self.backupCount > 0:
            for i in range(self.backupCount, 0, -1):
                sfn = f"{self.baseFilename}.{i}"
                if os.path.exists(sfn) and not sfn.endswith('.gz'):
                    try:
                        with open(sfn, 'rb') as f_in:
                            with gzip.open(f"{sfn}.gz", 'wb') as f_out:
                                f_out.writelines(f_in)
                        os.remove(sfn)
                    except Exception as e:
                        # Log compression error but don't fail
                        print(f"Warning: Failed to compress log file {sfn}: {e}")


class AsyncLogHandler(logging.Handler):
    """Asynchronous log handler to prevent I/O blocking."""
    
    def __init__(self, target_handler: logging.Handler, queue_size: int = 10000):
        super().__init__()
        self.target_handler = target_handler
        self.queue = asyncio.Queue(maxsize=queue_size)
        self.running = True
        self.task = None
    
    def emit(self, record: logging.LogRecord):
        """Queue log record for asynchronous processing."""
        try:
            if self.running and not self.queue.full():
                # Try to put immediately, don't block
                try:
                    self.queue.put_nowait(record)
                except asyncio.QueueFull:
                    # Queue is full, drop the record
                    pass
        except Exception:
            self.handleError(record)
    
    async def start_processing(self):
        """Start the asynchronous processing task."""
        self.task = asyncio.create_task(self._process_queue())
    
    async def _process_queue(self):
        """Process queued log records."""
        while self.running:
            try:
                record = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                self.target_handler.emit(record)
                self.queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f"Error processing log record: {e}")
    
    def close(self):
        """Close the handler and stop processing."""
        self.running = False
        if self.task:
            self.task.cancel()
        self.target_handler.close()
        super().close()


class EnhancedLoggingSystem:
    """Enhanced logging system with comprehensive features."""
    
    def __init__(self):
        self.config = get_config()
        self.log_buffer = LogBuffer()
        self.performance_stats = {}
        self.loggers = {}
        self.handlers = []
        self.context_stack = threading.local()
        
        # Setup logging system
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup the enhanced logging system."""
        # Create logs directory
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.NOTSET)
        root_logger.handlers.clear()
        
        # Setup console handler
        self._setup_console_handler(root_logger)
        
        # Setup file handlers
        self._setup_file_handlers(root_logger, log_dir)
        
        # Setup structured logging
        self._setup_structured_handler(root_logger, log_dir)
        
        # Setup buffer handler
        self._setup_buffer_handler(root_logger)
        
        # Setup custom log levels
        self._setup_custom_levels()
    
    def _setup_console_handler(self, logger: logging.Logger):
        """Setup colorized console handler."""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = ColorizedConsoleFormatter()
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        self.handlers.append(console_handler)
    
    def _setup_file_handlers(self, logger: logging.Logger, log_dir: Path):
        """Setup rotating file handlers."""
        # General log file
        general_handler = CompressingRotatingFileHandler(
            log_dir / "plexichat.log",
            maxBytes=100 * 1024 * 1024,  # 100MB
            backupCount=10
        )
        general_handler.setLevel(logging.INFO)
        general_formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)-8s [%(name)s:%(lineno)d] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        general_handler.setFormatter(general_formatter)
        logger.addHandler(general_handler)
        self.handlers.append(general_handler)
        
        # Error log file
        error_handler = CompressingRotatingFileHandler(
            log_dir / "errors.log",
            maxBytes=50 * 1024 * 1024,  # 50MB
            backupCount=5
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(general_formatter)
        logger.addHandler(error_handler)
        self.handlers.append(error_handler)
        
        # Security log file
        security_handler = CompressingRotatingFileHandler(
            log_dir / "security.log",
            maxBytes=50 * 1024 * 1024,  # 50MB
            backupCount=10
        )
        security_handler.setLevel(logging.WARNING)
        security_handler.addFilter(lambda record: getattr(record, 'category', None) == LogCategory.SECURITY)
        security_handler.setFormatter(general_formatter)
        logger.addHandler(security_handler)
        self.handlers.append(security_handler)
        
        # Performance log file
        performance_handler = CompressingRotatingFileHandler(
            log_dir / "performance.log",
            maxBytes=50 * 1024 * 1024,  # 50MB
            backupCount=5
        )
        performance_handler.setLevel(logging.INFO)
        performance_handler.addFilter(lambda record: getattr(record, 'category', None) == LogCategory.PERFORMANCE)
        performance_handler.setFormatter(general_formatter)
        logger.addHandler(performance_handler)
        self.handlers.append(performance_handler)
    
    def _setup_structured_handler(self, logger: logging.Logger, log_dir: Path):
        """Setup structured JSON logging handler."""
        structured_handler = CompressingRotatingFileHandler(
            log_dir / "structured.jsonl",
            maxBytes=200 * 1024 * 1024,  # 200MB
            backupCount=10
        )
        structured_handler.setLevel(logging.DEBUG)
        structured_formatter = StructuredFormatter()
        structured_handler.setFormatter(structured_formatter)
        logger.addHandler(structured_handler)
        self.handlers.append(structured_handler)
    
    def _setup_buffer_handler(self, logger: logging.Logger):
        """Setup in-memory buffer handler."""
        class BufferHandler(logging.Handler):
            def __init__(self, log_buffer: LogBuffer):
                super().__init__()
                self.log_buffer = log_buffer
                self.formatter = StructuredFormatter()
            
            def emit(self, record: logging.LogRecord):
                try:
                    # Create structured entry and add to buffer
                    formatted = self.formatter.format(record)
                    entry_dict = json.loads(formatted)
                    
                    # Convert back to LogEntry for buffer
                    entry = LogEntry(
                        timestamp=datetime.fromisoformat(entry_dict['timestamp']),
                        level=LogLevel[entry_dict['level']],
                        category=LogCategory(entry_dict['category']),
                        message=entry_dict['message'],
                        module=entry_dict['module'],
                        function=entry_dict['function'],
                        line=entry_dict['line'],
                        thread_id=entry_dict['thread_id'],
                        process_id=entry_dict['process_id'],
                        hostname=entry_dict['hostname'],
                        context=LogContext(**entry_dict.get('context', {})),
                        metadata=entry_dict.get('metadata', {}),
                        tags=entry_dict.get('tags', [])
                    )
                    
                    if 'performance' in entry_dict and entry_dict['performance']:
                        entry.performance = PerformanceMetrics(**entry_dict['performance'])
                    
                    if 'security' in entry_dict and entry_dict['security']:
                        entry.security = SecurityMetrics(**entry_dict['security'])
                    
                    if 'stack_trace' in entry_dict:
                        entry.stack_trace = entry_dict['stack_trace']
                    
                    self.log_buffer.add_entry(entry)
                except Exception as e:
                    # Don't let buffer errors break logging
                    pass
        
        buffer_handler = BufferHandler(self.log_buffer)
        buffer_handler.setLevel(logging.DEBUG)
        logger.addHandler(buffer_handler)
        self.handlers.append(buffer_handler)
    
    def _setup_custom_levels(self):
        """Setup custom log levels."""
        # Add custom levels to logging module
        logging.addLevelName(LogLevel.TRACE.value, 'TRACE')
        logging.addLevelName(LogLevel.SECURITY.value, 'SECURITY')
        logging.addLevelName(LogLevel.AUDIT.value, 'AUDIT')
        logging.addLevelName(LogLevel.PERFORMANCE.value, 'PERFORMANCE')
        
        # Add methods to Logger class
        def trace(self, message, *args, **kwargs):
            if self.isEnabledFor(LogLevel.TRACE.value):
                self._log(LogLevel.TRACE.value, message, args, **kwargs)
        
        def security(self, message, *args, **kwargs):
            if self.isEnabledFor(LogLevel.SECURITY.value):
                kwargs.setdefault('extra', {})['category'] = LogCategory.SECURITY
                self._log(LogLevel.SECURITY.value, message, args, **kwargs)
        
        def audit(self, message, *args, **kwargs):
            if self.isEnabledFor(LogLevel.AUDIT.value):
                kwargs.setdefault('extra', {})['category'] = LogCategory.AUDIT
                self._log(LogLevel.AUDIT.value, message, args, **kwargs)
        
        def performance(self, message, *args, **kwargs):
            if self.isEnabledFor(LogLevel.PERFORMANCE.value):
                kwargs.setdefault('extra', {})['category'] = LogCategory.PERFORMANCE
                self._log(LogLevel.PERFORMANCE.value, message, args, **kwargs)
        
        logging.Logger.trace = trace
        logging.Logger.security = security
        logging.Logger.audit = audit
        logging.Logger.performance = performance
    
    def get_logger(self, name: str = None) -> logging.Logger:
        """Get enhanced logger instance."""
        if name is None:
            name = self._get_caller_module()
        
        if name not in self.loggers:
            logger = logging.getLogger(name)
            self.loggers[name] = logger
        
        return self.loggers[name]
    
    def _get_caller_module(self) -> str:
        """Get the module name of the caller."""
        frame = inspect.currentframe()
        try:
            # Walk up the stack to find the calling module
            while frame:
                frame = frame.f_back
                if frame and not frame.f_code.co_filename.endswith('enhanced_logging_system.py'):
                    module_name = inspect.getmodulename(frame.f_code.co_filename)
                    return module_name or 'unknown'
        finally:
            del frame
        return 'unknown'
    
    def set_context(self, **kwargs):
        """Set logging context for current thread."""
        if not hasattr(self.context_stack, 'context'):
            self.context_stack.context = LogContext()
        
        for key, value in kwargs.items():
            if hasattr(self.context_stack.context, key):
                setattr(self.context_stack.context, key, value)
    
    def get_context(self) -> LogContext:
        """Get current logging context."""
        if not hasattr(self.context_stack, 'context'):
            self.context_stack.context = LogContext()
        return self.context_stack.context
    
    def clear_context(self):
        """Clear logging context for current thread."""
        if hasattr(self.context_stack, 'context'):
            self.context_stack.context = LogContext()
    
    def log_with_context(self, level: int, message: str, 
                        category: LogCategory = LogCategory.SYSTEM,
                        context: Optional[LogContext] = None,
                        metadata: Optional[Dict] = None,
                        performance: Optional[PerformanceMetrics] = None,
                        security: Optional[SecurityMetrics] = None,
                        tags: Optional[List[str]] = None):
        """Log message with full context."""
        logger = self.get_logger()
        
        extra = {
            'category': category,
            'context': context or self.get_context(),
            'metadata': metadata or {},
            'tags': tags or []
        }
        
        if performance:
            extra['performance'] = performance
        
        if security:
            extra['security'] = security
        
        logger.log(level, message, extra=extra)
    
    def get_buffer_stats(self) -> Dict[str, Any]:
        """Get logging buffer statistics."""
        return self.log_buffer.get_stats()
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance tracking statistics."""
        return self.performance_stats
    
    def get_performance_tracker(self, operation_name: str, logger_name: Optional[str] = None):
        """Get a performance tracker instance."""
        logger = self.get_logger(logger_name) if logger_name else self.get_logger()
        return PerformanceTracker(operation_name, logger)
    
    def track_operation(self, operation_name: str, duration: float, metadata: Dict[str, Any] = None):
        """Track an operation's performance."""
        if operation_name not in self.performance_stats:
            self.performance_stats[operation_name] = {
                'count': 0,
                'total_duration': 0.0,
                'avg_duration': 0.0,
                'min_duration': float('inf'),
                'max_duration': 0.0
            }
        
        stats = self.performance_stats[operation_name]
        stats['count'] += 1
        stats['total_duration'] += duration
        stats['avg_duration'] = stats['total_duration'] / stats['count']
        stats['min_duration'] = min(stats['min_duration'], duration)
        stats['max_duration'] = max(stats['max_duration'], duration)
    
    def search_logs(self, query: str, 
                   level: Optional[LogLevel] = None,
                   category: Optional[LogCategory] = None,
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None,
                   limit: int = 100) -> List[LogEntry]:
        """Search logs with filters."""
        entries = self.log_buffer.get_entries(
            count=limit * 2,  # Get more entries to filter
            level_filter=level,
            category_filter=category,
            start_time=start_time,
            end_time=end_time
        )
        
        # Filter by query string
        if query:
            query_lower = query.lower()
            filtered_entries = []
            for entry in entries:
                if (query_lower in entry.message.lower() or
                    query_lower in entry.module.lower() or
                    query_lower in entry.function.lower() or
                    any(query_lower in str(v).lower() for v in entry.metadata.values())):
                    filtered_entries.append(entry)
                    if len(filtered_entries) >= limit:
                        break
            return filtered_entries
        
        return entries[:limit]
    
    def export_logs(self, 
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None,
                   format: str = 'json') -> str:
        """Export logs in specified format."""
        entries = self.log_buffer.get_entries(
            start_time=start_time,
            end_time=end_time
        )
        
        if format.lower() == 'json':
            return json.dumps([entry.to_dict() for entry in entries], 
                            default=str, indent=2)
        elif format.lower() == 'csv':
            # Implement CSV export
            import csv
            import io
            
            output = io.StringIO()
            if entries:
                fieldnames = ['timestamp', 'level', 'category', 'message', 'module', 'function']
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                
                for entry in entries:
                    writer.writerow({
                        'timestamp': entry.timestamp.isoformat(),
                        'level': entry.level.name,
                        'category': entry.category.value if hasattr(entry.category, 'value') else str(entry.category),
                        'message': entry.message,
                        'module': entry.module,
                        'function': entry.function
                    })
            
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def shutdown(self):
        """Shutdown the logging system."""
        for handler in self.handlers:
            handler.close()
        self.handlers.clear()


# Global instance
_logging_system = None

def get_enhanced_logging_system() -> EnhancedLoggingSystem:
    """Get global enhanced logging system instance."""
    global _logging_system
    if _logging_system is None:
        _logging_system = EnhancedLoggingSystem()
    return _logging_system


def get_logger(name: str = None) -> logging.Logger:
    """Get enhanced logger instance."""
    return get_enhanced_logging_system().get_logger(name)


def setup_module_logging(name: str = None, level: str = "INFO") -> logging.Logger:
    """Setup logging for a module."""
    logger = get_logger(name)
    level_obj = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(level_obj)
    return logger


# Context manager for performance tracking
class PerformanceTracker:
    """Context manager for tracking operation performance."""
    
    def __init__(self, operation_name: str, logger: logging.Logger = None):
        self.operation_name = operation_name
        self.logger = logger or get_logger()
        self.start_time = None
        self.metadata = {}
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = (time.time() - self.start_time) * 1000  # milliseconds
            
            # Track in performance system
            logging_system = get_enhanced_logging_system()
            if logging_system:
                logging_system.track_operation(
                    self.operation_name, duration, self.metadata
                )
            
            # Log performance
            performance_metrics = PerformanceMetrics(duration_ms=duration)
            
            extra = {
                'category': LogCategory.PERFORMANCE,
                'performance': performance_metrics,
                'metadata': {'operation': self.operation_name, **self.metadata}
            }
            
            self.logger.log(LogLevel.PERFORMANCE.value, 
                          f"Operation '{self.operation_name}' completed in {duration:.2f}ms",
                          extra=extra)
    
    def add_metadata(self, **kwargs):
        """Add metadata to the performance tracking."""
        self.metadata.update(kwargs)


def track_performance(operation_name: str, logger: logging.Logger = None):
    """Decorator for tracking function performance."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            with PerformanceTracker(operation_name, logger):
                return func(*args, **kwargs)
        return wrapper
    return decorator