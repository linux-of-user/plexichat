"""
Advanced logging system with beautiful formatting, real-time console output,
and split-screen interface support.
"""

import asyncio
import json
import time
import sys
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import threading
import queue
from collections import deque
import gzip
import shutil

from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
import logging
import logging.handlers

from app.core.config.settings import settings

class LogLevel(str, Enum):
    """Log levels with colors."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class LogEntry:
    """Individual log entry."""
    timestamp: datetime
    level: LogLevel
    message: str
    module: str
    function: str
    line: int
    extra: Dict[str, Any] = field(default_factory=dict)
    request_id: Optional[str] = None
    user_id: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'level': self.level,
            'message': self.message,
            'module': self.module,
            'function': self.function,
            'line': self.line,
            'extra': self.extra,
            'request_id': self.request_id,
            'user_id': self.user_id
        }

class LogBuffer:
    """Thread-safe log buffer for real-time display."""
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.entries = deque(maxlen=max_size)
        self.lock = threading.Lock()
        self.subscribers = []
    
    def add_entry(self, entry: LogEntry):
        """Add a log entry to the buffer."""
        with self.lock:
            self.entries.append(entry)
            # Notify subscribers
            for callback in self.subscribers:
                try:
                    callback(entry)
                except Exception:
                    pass  # Don't let subscriber errors break logging
    
    def get_recent(self, count: int = 50) -> List[LogEntry]:
        """Get recent log entries."""
        with self.lock:
            return list(self.entries)[-count:]
    
    def subscribe(self, callback: Callable[[LogEntry], None]):
        """Subscribe to new log entries."""
        self.subscribers.append(callback)
    
    def clear(self):
        """Clear the buffer."""
        with self.lock:
            self.entries.clear()

class AdvancedLogger:
    """Advanced logging system with beautiful formatting and real-time display."""
    
    def __init__(self):
        self.console = Console()
        self.log_buffer = LogBuffer()
        self.log_dir = Path(getattr(settings, 'LOG_DIR', './logs'))
        self.log_dir.mkdir(exist_ok=True)
        
        # Configuration
        self.log_level = getattr(settings, 'LOG_LEVEL', 'INFO')
        self.log_to_file = getattr(settings, 'LOG_TO_FILE', True)
        self.log_to_console = getattr(settings, 'LOG_TO_CONSOLE', True)
        self.json_format = getattr(settings, 'LOG_JSON_FORMAT', False)
        self.max_file_size = getattr(settings, 'LOG_MAX_FILE_SIZE', 10 * 1024 * 1024)  # 10MB
        self.backup_count = getattr(settings, 'LOG_BACKUP_COUNT', 5)
        self.compress_backups = getattr(settings, 'LOG_COMPRESS_BACKUPS', True)
        
        # Real-time display
        self.live_display = None
        self.display_active = False
        self.stats = {
            'total_logs': 0,
            'errors': 0,
            'warnings': 0,
            'requests': 0,
            'start_time': datetime.now()
        }
        
        self._setup_logging()
        self._setup_file_handlers()
        
    def _setup_logging(self):
        """Setup the logging configuration."""
        # Create custom logger
        self.logger = logging.getLogger('chatapi')
        self.logger.setLevel(getattr(logging, self.log_level.upper()))
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler with Rich
        if self.log_to_console:
            console_handler = RichHandler(
                console=self.console,
                show_time=True,
                show_level=True,
                show_path=True,
                rich_tracebacks=True,
                tracebacks_show_locals=True
            )
            console_handler.setLevel(getattr(logging, self.log_level.upper()))
            self.logger.addHandler(console_handler)
        
        # Custom handler for buffer
        buffer_handler = BufferHandler(self.log_buffer, self.stats)
        buffer_handler.setLevel(logging.DEBUG)  # Capture all levels for buffer
        self.logger.addHandler(buffer_handler)
    
    def _setup_file_handlers(self):
        """Setup file logging handlers."""
        if not self.log_to_file:
            return
        
        # Main log file with rotation
        main_log_file = self.log_dir / 'chatapi.log'
        file_handler = logging.handlers.RotatingFileHandler(
            main_log_file,
            maxBytes=self.max_file_size,
            backupCount=self.backup_count
        )
        
        if self.json_format:
            file_handler.setFormatter(JSONFormatter())
        else:
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            ))
        
        file_handler.setLevel(getattr(logging, self.log_level.upper()))
        self.logger.addHandler(file_handler)
        
        # Error log file
        error_log_file = self.log_dir / 'errors.log'
        error_handler = logging.handlers.RotatingFileHandler(
            error_log_file,
            maxBytes=self.max_file_size,
            backupCount=self.backup_count
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        ))
        self.logger.addHandler(error_handler)
        
        # Access log file for requests
        access_log_file = self.log_dir / 'access.log'
        self.access_logger = logging.getLogger('chatapi.access')
        access_handler = logging.handlers.RotatingFileHandler(
            access_log_file,
            maxBytes=self.max_file_size,
            backupCount=self.backup_count
        )
        access_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(message)s'
        ))
        self.access_logger.addHandler(access_handler)
        self.access_logger.setLevel(logging.INFO)
    
    def start_live_display(self):
        """Start the live display for split-screen interface."""
        if self.display_active:
            return
        
        self.display_active = True
        layout = self._create_layout()
        
        self.live_display = Live(
            layout,
            console=self.console,
            refresh_per_second=4,
            screen=True
        )
        
        # Start the display in a separate thread
        display_thread = threading.Thread(target=self._run_live_display, daemon=True)
        display_thread.start()
    
    def _create_layout(self) -> Layout:
        """Create the split-screen layout."""
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        layout["main"].split_row(
            Layout(name="logs", ratio=2),
            Layout(name="stats", ratio=1)
        )
        
        return layout
    
    def _run_live_display(self):
        """Run the live display."""
        try:
            with self.live_display:
                while self.display_active:
                    self._update_display()
                    time.sleep(0.25)
        except KeyboardInterrupt:
            self.display_active = False
    
    def _update_display(self):
        """Update the live display content."""
        if not self.live_display:
            return
        
        layout = self.live_display.renderable
        
        # Header
        layout["header"].update(Panel(
            f"[bold blue]Chat API - Advanced Logging System[/bold blue] | "
            f"Uptime: {self._get_uptime()} | "
            f"Logs: {self.stats['total_logs']} | "
            f"Errors: {self.stats['errors']}",
            style="blue"
        ))
        
        # Recent logs
        recent_logs = self.log_buffer.get_recent(20)
        log_table = Table(show_header=True, header_style="bold magenta")
        log_table.add_column("Time", style="dim", width=12)
        log_table.add_column("Level", width=8)
        log_table.add_column("Module", width=15)
        log_table.add_column("Message", ratio=1)
        
        for entry in recent_logs[-10:]:  # Show last 10 logs
            level_style = self._get_level_style(entry.level)
            log_table.add_row(
                entry.timestamp.strftime("%H:%M:%S"),
                f"[{level_style}]{entry.level.upper()}[/{level_style}]",
                entry.module,
                entry.message[:80] + "..." if len(entry.message) > 80 else entry.message
            )
        
        layout["logs"].update(Panel(log_table, title="Recent Logs", border_style="green"))
        
        # Statistics
        stats_table = Table(show_header=False)
        stats_table.add_column("Metric", style="bold")
        stats_table.add_column("Value", style="green")
        
        stats_table.add_row("Total Logs", str(self.stats['total_logs']))
        stats_table.add_row("Errors", str(self.stats['errors']))
        stats_table.add_row("Warnings", str(self.stats['warnings']))
        stats_table.add_row("Requests", str(self.stats['requests']))
        stats_table.add_row("Log Level", self.log_level)
        stats_table.add_row("File Logging", "✓" if self.log_to_file else "✗")
        
        layout["stats"].update(Panel(stats_table, title="Statistics", border_style="yellow"))
        
        # Footer
        layout["footer"].update(Panel(
            "[dim]Press Ctrl+C to exit | Logs stored in ./logs/ | Real-time updates every 250ms[/dim]",
            style="dim"
        ))
    
    def _get_level_style(self, level: LogLevel) -> str:
        """Get Rich style for log level."""
        styles = {
            LogLevel.DEBUG: "dim",
            LogLevel.INFO: "blue",
            LogLevel.WARNING: "yellow",
            LogLevel.ERROR: "red",
            LogLevel.CRITICAL: "bold red"
        }
        return styles.get(level, "white")
    
    def _get_uptime(self) -> str:
        """Get formatted uptime."""
        uptime = datetime.now() - self.stats['start_time']
        hours, remainder = divmod(int(uptime.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    def stop_live_display(self):
        """Stop the live display."""
        self.display_active = False
        if self.live_display:
            self.live_display.stop()
    
    def log_request(self, method: str, path: str, status_code: int, 
                   duration: float, user_id: Optional[int] = None):
        """Log an HTTP request."""
        self.stats['requests'] += 1
        
        message = f"{method} {path} {status_code} {duration:.3f}s"
        if user_id:
            message += f" user:{user_id}"
        
        self.access_logger.info(message)
        
        # Also log to main logger for display
        level = LogLevel.ERROR if status_code >= 400 else LogLevel.INFO
        self.logger.log(
            getattr(logging, level.upper()),
            f"HTTP {status_code} {method} {path} ({duration:.3f}s)",
            extra={'request_duration': duration, 'status_code': status_code}
        )
    
    def log_websocket_event(self, event: str, user_id: Optional[int] = None, **kwargs):
        """Log a WebSocket event."""
        message = f"WebSocket {event}"
        if user_id:
            message += f" user:{user_id}"
        
        self.logger.info(message, extra={'websocket_event': event, **kwargs})
    
    def log_database_operation(self, operation: str, table: str, duration: float, **kwargs):
        """Log a database operation."""
        self.logger.debug(
            f"DB {operation} {table} ({duration:.3f}s)",
            extra={'db_operation': operation, 'table': table, 'duration': duration, **kwargs}
        )
    
    def log_backup_operation(self, operation: str, backup_id: str, **kwargs):
        """Log a backup operation."""
        self.logger.info(
            f"Backup {operation} {backup_id}",
            extra={'backup_operation': operation, 'backup_id': backup_id, **kwargs}
        )
    
    def log_security_event(self, event: str, user_id: Optional[int] = None, 
                          ip_address: Optional[str] = None, **kwargs):
        """Log a security event."""
        message = f"Security {event}"
        if user_id:
            message += f" user:{user_id}"
        if ip_address:
            message += f" ip:{ip_address}"
        
        self.logger.warning(
            message,
            extra={'security_event': event, 'user_id': user_id, 'ip_address': ip_address, **kwargs}
        )
    
    def get_log_stats(self) -> Dict[str, Any]:
        """Get logging statistics."""
        return {
            **self.stats,
            'uptime_seconds': (datetime.now() - self.stats['start_time']).total_seconds(),
            'log_files': [
                {
                    'name': f.name,
                    'size': f.stat().st_size,
                    'modified': datetime.fromtimestamp(f.stat().st_mtime).isoformat()
                }
                for f in self.log_dir.glob('*.log')
            ],
            'buffer_size': len(self.log_buffer.entries)
        }
    
    def compress_old_logs(self):
        """Compress old log files."""
        if not self.compress_backups:
            return
        
        for log_file in self.log_dir.glob('*.log.*'):
            if not log_file.name.endswith('.gz'):
                compressed_file = log_file.with_suffix(log_file.suffix + '.gz')
                with open(log_file, 'rb') as f_in:
                    with gzip.open(compressed_file, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                log_file.unlink()
                self.logger.info(f"Compressed log file: {compressed_file}")

class BufferHandler(logging.Handler):
    """Custom logging handler that adds entries to the log buffer."""
    
    def __init__(self, log_buffer: LogBuffer, stats: Dict[str, Any]):
        super().__init__()
        self.log_buffer = log_buffer
        self.stats = stats
    
    def emit(self, record):
        """Emit a log record to the buffer."""
        try:
            entry = LogEntry(
                timestamp=datetime.fromtimestamp(record.created),
                level=LogLevel(record.levelname.lower()),
                message=record.getMessage(),
                module=record.module,
                function=record.funcName,
                line=record.lineno,
                extra=getattr(record, '__dict__', {}),
                request_id=getattr(record, 'request_id', None),
                user_id=getattr(record, 'user_id', None)
            )
            
            self.log_buffer.add_entry(entry)
            
            # Update stats
            self.stats['total_logs'] += 1
            if entry.level == LogLevel.ERROR:
                self.stats['errors'] += 1
            elif entry.level == LogLevel.WARNING:
                self.stats['warnings'] += 1
                
        except Exception:
            self.handleError(record)

class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def format(self, record):
        """Format the record as JSON."""
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'process': record.process,
            'thread': record.thread
        }
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'lineno', 'funcName', 'created',
                          'msecs', 'relativeCreated', 'thread', 'threadName',
                          'processName', 'process', 'getMessage', 'exc_info',
                          'exc_text', 'stack_info']:
                log_entry[key] = value
        
        return json.dumps(log_entry)

# Enhanced logging functionality
class EnhancedLoggingManager:
    """Enhanced logging manager with periodic status reporting."""

    def __init__(self):
        self.logger = advanced_logger
        self.periodic_tasks_started = False

    async def start_periodic_tasks(self):
        """Start periodic background tasks."""
        if self.periodic_tasks_started:
            return

        import asyncio

        # Start periodic status logging
        asyncio.create_task(self._periodic_status_task())
        asyncio.create_task(self._endpoint_stats_task())
        asyncio.create_task(self._self_test_status_task())

        self.periodic_tasks_started = True
        self.logger.info("📊 Periodic logging tasks started")

    async def _periodic_status_task(self):
        """Periodically log system status."""
        while True:
            try:
                await asyncio.sleep(300)  # Every 5 minutes

                # Get system metrics
                import psutil
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()

                status_msg = (
                    f"📊 System Status - "
                    f"CPU: {cpu_percent:.1f}%, "
                    f"Memory: {memory.percent:.1f}%, "
                    f"Logs: {len(self.logger.log_buffer)}"
                )

                self.logger.info(status_msg)

            except Exception as e:
                self.logger.error(f"Periodic status task error: {e}")
                await asyncio.sleep(60)

    async def _endpoint_stats_task(self):
        """Periodically log endpoint statistics."""
        while True:
            try:
                await asyncio.sleep(600)  # Every 10 minutes

                # Get endpoint statistics from analytics if available
                try:
                    from app.core.analytics.analytics_engine import analytics_engine

                    endpoint_analytics = analytics_engine.collector.get_endpoint_analytics(5)

                    if endpoint_analytics:
                        stats_msg = "🌐 Top Endpoints:\n"
                        for i, endpoint_data in enumerate(endpoint_analytics, 1):
                            stats_msg += (
                                f"  {i}. {endpoint_data['endpoint']}: "
                                f"{endpoint_data['request_count']} requests"
                            )
                            if i < len(endpoint_analytics):
                                stats_msg += "\n"

                        self.logger.info(stats_msg)

                except ImportError:
                    self.logger.debug("Analytics engine not available")

            except Exception as e:
                self.logger.error(f"Endpoint stats task error: {e}")
                await asyncio.sleep(60)

    async def _self_test_status_task(self):
        """Periodically log self-test results."""
        while True:
            try:
                await asyncio.sleep(900)  # Every 15 minutes

                try:
                    from app.testing.comprehensive_test_suite import test_framework

                    # Run health check
                    health_results = await test_framework.run_suite("api_health")

                    if health_results:
                        passed = sum(1 for r in health_results if r.passed)
                        total = len(health_results)

                        if passed == total:
                            self.logger.info(f"✅ Self-tests: {passed}/{total} passed")
                        else:
                            failed = total - passed
                            self.logger.warning(f"⚠️ Self-tests: {passed}/{total} passed, {failed} failed")

                except ImportError:
                    self.logger.debug("Testing framework not available")
                except Exception as test_error:
                    self.logger.error(f"Self-test failed: {test_error}")

            except Exception as e:
                self.logger.error(f"Self-test status task error: {e}")
                await asyncio.sleep(300)

# Global logger instance
advanced_logger = AdvancedLogger()

# Enhanced logging manager
enhanced_logging_manager = EnhancedLoggingManager()
