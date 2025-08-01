"""
Enhanced Logging System - Enterprise-Grade Logging and Monitoring
================================================================

This module provides enterprise-grade logging with:
- Structured logging with JSON format
- Multiple output destinations (file, database, remote)
- Log aggregation and centralization
- Security event logging and SIEM integration
- Performance monitoring and metrics
- Log rotation and archival
- Real-time log streaming
- Compliance and audit logging
"""

import asyncio
import json
import logging
import logging.handlers
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import threading
import queue
import gzip
import hashlib

# Additional imports for enhanced features
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False

try:
    import elasticsearch
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False

from ..security.enhanced_security_manager import enhanced_security_manager

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

class LogDestination(Enum):
    """Log output destinations."""
    CONSOLE = "console"
    FILE = "file"
    DATABASE = "database"
    ELASTICSEARCH = "elasticsearch"
    SYSLOG = "syslog"
    REMOTE = "remote"

class LogFormat(Enum):
    """Log output formats."""
    TEXT = "text"
    JSON = "json"
    STRUCTURED = "structured"
    CEF = "cef"  # Common Event Format
    SYSLOG = "syslog"

@dataclass
class LogEntry:
    """Structured log entry."""
    timestamp: datetime
    level: LogLevel
    logger_name: str
    message: str
    module: str
    function: str
    line_number: int
    thread_id: int
    process_id: int
    
    # Additional context
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    source_ip: Optional[str] = None
    
    # Structured data
    extra_data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    
    # Security context
    security_event: bool = False
    threat_level: Optional[str] = None
    
    # Performance metrics
    execution_time: Optional[float] = None
    memory_usage: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert log entry to dictionary."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['level'] = self.level.name
        return data
    
    def to_json(self) -> str:
        """Convert log entry to JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)

class EnhancedLogHandler:
    """Enhanced log handler with multiple destinations."""
    
    def __init__(self, destination: LogDestination, config: Dict[str, Any]):
        self.destination = destination
        self.config = config
        self.handler = None
        self.formatter = None
        self.is_active = False
        
        self._initialize_handler()
    
    def _initialize_handler(self):
        """Initialize the appropriate handler based on destination."""
        try:
            if self.destination == LogDestination.CONSOLE:
                self.handler = logging.StreamHandler(sys.stdout)
                
            elif self.destination == LogDestination.FILE:
                log_file = self.config.get('file_path', 'plexichat.log')
                max_bytes = self.config.get('max_bytes', 10 * 1024 * 1024)  # 10MB
                backup_count = self.config.get('backup_count', 5)
                
                self.handler = logging.handlers.RotatingFileHandler(
                    log_file, maxBytes=max_bytes, backupCount=backup_count
                )
                
            elif self.destination == LogDestination.SYSLOG:
                address = self.config.get('address', '/dev/log')
                facility = self.config.get('facility', logging.handlers.SysLogHandler.LOG_USER)
                
                self.handler = logging.handlers.SysLogHandler(address=address, facility=facility)
                
            elif self.destination == LogDestination.DATABASE:
                # Custom database handler would be implemented here
                self.handler = DatabaseLogHandler(self.config)
                
            elif self.destination == LogDestination.ELASTICSEARCH:
                # Custom Elasticsearch handler would be implemented here
                self.handler = ElasticsearchLogHandler(self.config)
                
            else:
                raise ValueError(f"Unsupported log destination: {self.destination}")
            
            # Set formatter
            log_format = self.config.get('format', LogFormat.JSON)
            self.formatter = self._create_formatter(log_format)
            
            if self.handler and self.formatter:
                self.handler.setFormatter(self.formatter)
                self.is_active = True
                
        except Exception as e:
            print(f"Failed to initialize log handler for {self.destination}: {e}")
            self.is_active = False
    
    def _create_formatter(self, log_format: LogFormat) -> logging.Formatter:
        """Create appropriate formatter."""
        if log_format == LogFormat.JSON:
            return JSONFormatter()
        elif log_format == LogFormat.STRUCTURED:
            return StructuredFormatter()
        elif log_format == LogFormat.CEF:
            return CEFFormatter()
        else:
            # Default text formatter
            format_string = (
                '%(asctime)s - %(name)s - %(levelname)s - '
                '%(filename)s:%(lineno)d - %(message)s'
            )
            return logging.Formatter(format_string)
    
    def emit(self, log_entry: LogEntry):
        """Emit log entry to handler."""
        if not self.is_active or not self.handler:
            return
        
        try:
            # Convert LogEntry to LogRecord for compatibility
            record = logging.LogRecord(
                name=log_entry.logger_name,
                level=log_entry.level.value,
                pathname=log_entry.module,
                lineno=log_entry.line_number,
                msg=log_entry.message,
                args=(),
                exc_info=None
            )
            
            # Add extra attributes
            record.user_id = log_entry.user_id
            record.session_id = log_entry.session_id
            record.request_id = log_entry.request_id
            record.source_ip = log_entry.source_ip
            record.extra_data = log_entry.extra_data
            record.tags = log_entry.tags
            record.security_event = log_entry.security_event
            record.threat_level = log_entry.threat_level
            record.execution_time = log_entry.execution_time
            record.memory_usage = log_entry.memory_usage
            
            self.handler.emit(record)
            
        except Exception as e:
            print(f"Error emitting log to {self.destination}: {e}")

class JSONFormatter(logging.Formatter):
    """JSON log formatter."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.pathname,
            'function': record.funcName,
            'line': record.lineno,
            'thread': record.thread,
            'process': record.process,
        }
        
        # Add extra attributes if present
        for attr in ['user_id', 'session_id', 'request_id', 'source_ip', 
                     'extra_data', 'tags', 'security_event', 'threat_level',
                     'execution_time', 'memory_usage']:
            if hasattr(record, attr):
                value = getattr(record, attr)
                if value is not None:
                    log_data[attr] = value
        
        return json.dumps(log_data, ensure_ascii=False)

class StructuredFormatter(logging.Formatter):
    """Structured log formatter using structlog if available."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with structured logging."""
        if STRUCTLOG_AVAILABLE:
            # Use structlog for structured formatting
            return super().format(record)
        else:
            # Fallback to JSON formatter
            return JSONFormatter().format(record)

class CEFFormatter(logging.Formatter):
    """Common Event Format (CEF) formatter for SIEM integration."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record in CEF format."""
        # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
        
        severity = self._map_severity(record.levelno)
        device_event_class_id = getattr(record, 'security_event', False) and 'SECURITY' or 'INFO'
        
        cef_header = f"CEF:0|PlexiChat|PlexiChat|1.0|{device_event_class_id}|{record.getMessage()}|{severity}"
        
        # Add extensions
        extensions = []
        if hasattr(record, 'source_ip') and record.source_ip:
            extensions.append(f"src={record.source_ip}")
        if hasattr(record, 'user_id') and record.user_id:
            extensions.append(f"suser={record.user_id}")
        if hasattr(record, 'request_id') and record.request_id:
            extensions.append(f"requestId={record.request_id}")
        
        if extensions:
            return f"{cef_header}|{' '.join(extensions)}"
        else:
            return cef_header
    
    def _map_severity(self, level: int) -> int:
        """Map Python log level to CEF severity."""
        if level >= 50:  # CRITICAL
            return 10
        elif level >= 40:  # ERROR
            return 8
        elif level >= 30:  # WARNING
            return 6
        elif level >= 20:  # INFO
            return 4
        else:  # DEBUG
            return 2

class DatabaseLogHandler(logging.Handler):
    """Custom database log handler."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__()
        self.config = config
        self.buffer = []
        self.buffer_size = config.get('buffer_size', 100)
        self.flush_interval = config.get('flush_interval', 60)  # seconds
        
        # Start background flush task
        self._start_flush_task()
    
    def emit(self, record: logging.LogRecord):
        """Add record to buffer."""
        self.buffer.append(record)
        
        if len(self.buffer) >= self.buffer_size:
            asyncio.create_task(self._flush_buffer())
    
    async def _flush_buffer(self):
        """Flush buffer to database."""
        if not self.buffer:
            return
        
        try:
            # This would integrate with the enhanced database manager
            # For now, just clear the buffer
            records_to_flush = self.buffer.copy()
            self.buffer.clear()
            
            # TODO: Implement actual database insertion
            print(f"Flushing {len(records_to_flush)} log records to database")
            
        except Exception as e:
            print(f"Failed to flush logs to database: {e}")
    
    def _start_flush_task(self):
        """Start background task to flush buffer periodically."""
        async def flush_periodically():
            while True:
                await asyncio.sleep(self.flush_interval)
                await self._flush_buffer()
        
        try:
            asyncio.create_task(flush_periodically())
        except RuntimeError:
            # No event loop running, skip periodic flushing
            pass

class ElasticsearchLogHandler(logging.Handler):
    """Custom Elasticsearch log handler."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__()
        self.config = config
        self.client = None
        self.index_name = config.get('index', 'plexichat-logs')
        
        if ELASTICSEARCH_AVAILABLE:
            try:
                self.client = elasticsearch.Elasticsearch(
                    hosts=config.get('hosts', ['localhost:9200']),
                    http_auth=config.get('auth'),
                    use_ssl=config.get('ssl', False)
                )
            except Exception as e:
                print(f"Failed to initialize Elasticsearch client: {e}")
    
    def emit(self, record: logging.LogRecord):
        """Send record to Elasticsearch."""
        if not self.client:
            return
        
        try:
            doc = {
                'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                'level': record.levelname,
                'logger': record.name,
                'message': record.getMessage(),
                'module': record.pathname,
                'function': record.funcName,
                'line': record.lineno,
            }
            
            # Add extra fields
            for attr in ['user_id', 'session_id', 'request_id', 'source_ip']:
                if hasattr(record, attr):
                    value = getattr(record, attr)
                    if value:
                        doc[attr] = value
            
            self.client.index(index=self.index_name, body=doc)
            
        except Exception as e:
            print(f"Failed to send log to Elasticsearch: {e}")

class EnhancedLogger:
    """Enhanced Logger with enterprise-grade features."""

    def __init__(self, name: str = "plexichat"):
        self.name = name
        self.handlers: List[EnhancedLogHandler] = []
        self.log_queue = queue.Queue()
        self.is_running = False

        # Performance tracking
        self.log_counts = {level: 0 for level in LogLevel}
        self.start_time = datetime.now()

        # Security integration
        self.security_logging = True
        self.audit_logging = True

        # Context tracking
        self.context_stack = threading.local()

        # Initialize default configuration
        self._initialize_default_config()

        # Start log processing thread
        self._start_log_processor()

    def _initialize_default_config(self):
        """Initialize default logging configuration."""
        # Console handler
        console_config = {
            'format': LogFormat.JSON,
            'level': LogLevel.INFO
        }
        console_handler = EnhancedLogHandler(LogDestination.CONSOLE, console_config)
        self.handlers.append(console_handler)

        # File handler
        log_dir = Path("./logs")
        log_dir.mkdir(exist_ok=True)

        file_config = {
            'file_path': log_dir / 'plexichat.log',
            'format': LogFormat.JSON,
            'level': LogLevel.DEBUG,
            'max_bytes': 50 * 1024 * 1024,  # 50MB
            'backup_count': 10
        }
        file_handler = EnhancedLogHandler(LogDestination.FILE, file_config)
        self.handlers.append(file_handler)

        # Security log file
        security_config = {
            'file_path': log_dir / 'security.log',
            'format': LogFormat.CEF,
            'level': LogLevel.SECURITY,
            'max_bytes': 100 * 1024 * 1024,  # 100MB
            'backup_count': 20
        }
        security_handler = EnhancedLogHandler(LogDestination.FILE, security_config)
        self.handlers.append(security_handler)

    def _start_log_processor(self):
        """Start background log processing thread."""
        def process_logs():
            self.is_running = True
            while self.is_running:
                try:
                    # Get log entry from queue (with timeout)
                    log_entry = self.log_queue.get(timeout=1.0)

                    # Process log entry through all handlers
                    for handler in self.handlers:
                        if handler.is_active:
                            handler.emit(log_entry)

                    # Mark task as done
                    self.log_queue.task_done()

                except queue.Empty:
                    continue
                except Exception as e:
                    print(f"Error processing log entry: {e}")

        # Start processing thread
        processor_thread = threading.Thread(target=process_logs, daemon=True)
        processor_thread.start()

    def _create_log_entry(self, level: LogLevel, message: str, **kwargs) -> LogEntry:
        """Create a structured log entry."""
        import inspect
        import threading
        import os

        # Get caller information
        frame = inspect.currentframe()
        try:
            # Go up the stack to find the actual caller
            caller_frame = frame.f_back.f_back
            module = caller_frame.f_code.co_filename
            function = caller_frame.f_code.co_name
            line_number = caller_frame.f_lineno
        finally:
            del frame

        # Get context information
        context = getattr(self.context_stack, 'context', {})

        # Create log entry
        log_entry = LogEntry(
            timestamp=datetime.now(),
            level=level,
            logger_name=self.name,
            message=message,
            module=module,
            function=function,
            line_number=line_number,
            thread_id=threading.get_ident(),
            process_id=os.getpid(),
            user_id=context.get('user_id') or kwargs.get('user_id'),
            session_id=context.get('session_id') or kwargs.get('session_id'),
            request_id=context.get('request_id') or kwargs.get('request_id'),
            source_ip=context.get('source_ip') or kwargs.get('source_ip'),
            extra_data=kwargs.get('extra_data', {}),
            tags=kwargs.get('tags', []),
            security_event=kwargs.get('security_event', False),
            threat_level=kwargs.get('threat_level'),
            execution_time=kwargs.get('execution_time'),
            memory_usage=kwargs.get('memory_usage')
        )

        return log_entry

    def set_context(self, **context):
        """Set logging context for current thread."""
        if not hasattr(self.context_stack, 'context'):
            self.context_stack.context = {}
        self.context_stack.context.update(context)

    def clear_context(self):
        """Clear logging context for current thread."""
        if hasattr(self.context_stack, 'context'):
            self.context_stack.context.clear()

    def log(self, level: LogLevel, message: str, **kwargs):
        """Log a message at the specified level."""
        try:
            log_entry = self._create_log_entry(level, message, **kwargs)

            # Update counters
            self.log_counts[level] += 1

            # Add to queue for processing
            self.log_queue.put(log_entry)

            # If this is a security event, also log to security manager
            if kwargs.get('security_event') or level == LogLevel.SECURITY:
                asyncio.create_task(self._log_security_event(log_entry))

        except Exception as e:
            print(f"Error creating log entry: {e}")

    async def _log_security_event(self, log_entry: LogEntry):
        """Log security event to security manager."""
        try:
            # Map log level to threat level
            threat_level_map = {
                LogLevel.CRITICAL: enhanced_security_manager.ThreatLevel.CRITICAL,
                LogLevel.ERROR: enhanced_security_manager.ThreatLevel.HIGH,
                LogLevel.WARNING: enhanced_security_manager.ThreatLevel.MEDIUM,
                LogLevel.SECURITY: enhanced_security_manager.ThreatLevel.HIGH,
                LogLevel.AUDIT: enhanced_security_manager.ThreatLevel.LOW,
            }

            threat_level = threat_level_map.get(log_entry.level, enhanced_security_manager.ThreatLevel.LOW)

            await enhanced_security_manager._log_security_event(
                enhanced_security_manager.SecurityEventType.SUSPICIOUS_ACTIVITY,
                log_entry.source_ip or "unknown",
                log_entry.user_id,
                threat_level,
                {
                    'log_level': log_entry.level.name,
                    'message': log_entry.message,
                    'module': log_entry.module,
                    'function': log_entry.function,
                    'extra_data': log_entry.extra_data
                }
            )
        except Exception as e:
            print(f"Failed to log security event: {e}")

    # Convenience methods for different log levels
    def trace(self, message: str, **kwargs):
        """Log trace message."""
        self.log(LogLevel.TRACE, message, **kwargs)

    def debug(self, message: str, **kwargs):
        """Log debug message."""
        self.log(LogLevel.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs):
        """Log info message."""
        self.log(LogLevel.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message."""
        self.log(LogLevel.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs):
        """Log error message."""
        self.log(LogLevel.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs):
        """Log critical message."""
        self.log(LogLevel.CRITICAL, message, **kwargs)

    def security(self, message: str, **kwargs):
        """Log security event."""
        kwargs['security_event'] = True
        self.log(LogLevel.SECURITY, message, **kwargs)

    def audit(self, message: str, **kwargs):
        """Log audit event."""
        self.log(LogLevel.AUDIT, message, **kwargs)

    def performance(self, message: str, execution_time: float, **kwargs):
        """Log performance metric."""
        kwargs['execution_time'] = execution_time
        kwargs['tags'] = kwargs.get('tags', []) + ['performance']
        self.log(LogLevel.INFO, message, **kwargs)

    def add_handler(self, destination: LogDestination, config: Dict[str, Any]):
        """Add a new log handler."""
        handler = EnhancedLogHandler(destination, config)
        if handler.is_active:
            self.handlers.append(handler)
            return True
        return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get logging statistics."""
        uptime = (datetime.now() - self.start_time).total_seconds()
        total_logs = sum(self.log_counts.values())

        return {
            'uptime_seconds': uptime,
            'total_logs': total_logs,
            'logs_per_second': total_logs / max(uptime, 1),
            'log_counts_by_level': {level.name: count for level, count in self.log_counts.items()},
            'active_handlers': len([h for h in self.handlers if h.is_active]),
            'queue_size': self.log_queue.qsize()
        }

    def shutdown(self):
        """Shutdown the logger gracefully."""
        self.is_running = False

        # Wait for queue to be processed
        self.log_queue.join()

        # Close all handlers
        for handler in self.handlers:
            if hasattr(handler.handler, 'close'):
                handler.handler.close()

# Global enhanced logger instance
enhanced_logger = EnhancedLogger("plexichat")

# Convenience functions for global usage
def trace(message: str, **kwargs):
    enhanced_logger.trace(message, **kwargs)

def debug(message: str, **kwargs):
    enhanced_logger.debug(message, **kwargs)

def info(message: str, **kwargs):
    enhanced_logger.info(message, **kwargs)

def warning(message: str, **kwargs):
    enhanced_logger.warning(message, **kwargs)

def error(message: str, **kwargs):
    enhanced_logger.error(message, **kwargs)

def critical(message: str, **kwargs):
    enhanced_logger.critical(message, **kwargs)

def security(message: str, **kwargs):
    enhanced_logger.security(message, **kwargs)

def audit(message: str, **kwargs):
    enhanced_logger.audit(message, **kwargs)

def performance(message: str, execution_time: float, **kwargs):
    enhanced_logger.performance(message, execution_time, **kwargs)

def set_context(**context):
    enhanced_logger.set_context(**context)

def clear_context():
    enhanced_logger.clear_context()
