#!/usr/bin/env python3
"""
Unified Logging System for PlexiChat

ASCII-only logging system with comprehensive coverage.
No unicode characters, proper formatting, and structured logging.


import logging
import logging.handlers
import sys
import os
import time
import json
import traceback
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum

class LogLevel(Enum):
    """Log levels for the system."""
        DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class LogCategory(Enum):
    """Log categories for better organization."""
    SYSTEM = "SYSTEM"
    SECURITY = "SECURITY"
    PERFORMANCE = "PERFORMANCE"
    API = "API"
    DATABASE = "DATABASE"
    RATE_LIMIT = "RATE_LIMIT"
    DDOS = "DDOS"
    AUTH = "AUTH"
    CONFIG = "CONFIG"
    STARTUP = "STARTUP"

class ASCIIFormatter(logging.Formatter):
    """Custom formatter that ensures ASCII-only output.
        def __init__(self, include_colors=False):
        self.include_colors = include_colors
        super().__init__()
    
    def format(self, record):
        """Format log record with ASCII-only characters."""
        # Get timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')
        
        # Get level with padding
        level = record.levelname.ljust(8)
        
        # Get category if available
        category = getattr(record, 'category', 'GENERAL').ljust(12)
        
        # Get module name
        module = record.name.split('.')[-1].ljust(15)
        
        # Clean message (remove unicode)
        message = str(record.getMessage())
        # Replace common unicode characters with ASCII equivalents
        message = message.encode('ascii', errors='replace').decode('ascii')
        message = message.replace('?', '?')  # Replace replacement character
        
        # Format the log line
        log_line = f"{timestamp} | {level} | {category} | {module} | {message}"
        
        # Add exception info if present
        if record.exc_info:
            exc_text = self.formatException(record.exc_info)
            # Clean exception text
            exc_text = exc_text.encode('ascii', errors='replace').decode('ascii')
            log_line += f"\n{exc_text}"
        
        return log_line

class UnifiedLogger:
    """Unified logging system for PlexiChat."""
        def __init__(self, name: str = "plexichat"):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Prevent duplicate handlers
        if self.logger.handlers:
            self.logger.handlers.clear()
        
        # Setup handlers
        self._setup_handlers()
        
        # Statistics
        self.stats = {
            "total_logs": 0,
            "logs_by_level": {level.value: 0 for level in LogLevel},
            "logs_by_category": {cat.value: 0 for cat in LogCategory},
            "errors_count": 0,
            "warnings_count": 0
        }
    
    def _setup_handlers(self):
        """Setup log handlers."""
        # Create logs directory
        log_dir = Path("data/logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = ASCIIFormatter(include_colors=True)
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler for all logs
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / "plexichat.log",
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='ascii',
            errors='replace'
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = ASCIIFormatter()
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Error-only handler
        error_handler = logging.handlers.RotatingFileHandler(
            log_dir / "errors.log",
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3,
            encoding='ascii',
            errors='replace'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(file_formatter)
        self.logger.addHandler(error_handler)
        
        # Security logs handler
        security_handler = logging.handlers.RotatingFileHandler(
            log_dir / "security.log",
            maxBytes=5*1024*1024,  # 5MB
            backupCount=10,  # Keep more security logs
            encoding='ascii',
            errors='replace'
        )
        security_handler.setLevel(logging.INFO)
        security_handler.setFormatter(file_formatter)
        security_handler.addFilter(lambda record: getattr(record, 'category', '') == 'SECURITY')
        self.logger.addHandler(security_handler)
    
    def _log(self, level: LogLevel, message: str, category: LogCategory = LogCategory.SYSTEM, 
            extra_data: Optional[Dict[str, Any]] = None, exc_info: bool = False):
        """Internal logging method."""
        try:
            # Update statistics
            self.stats["total_logs"] += 1
            self.stats["logs_by_level"][level.value] += 1
            self.stats["logs_by_category"][category.value] += 1
            
            if level in [LogLevel.ERROR, LogLevel.CRITICAL]:
                self.stats["errors_count"] += 1
            elif level == LogLevel.WARNING:
                self.stats["warnings_count"] += 1
            
            # Create log record
            extra = {"category": category.value}
            if extra_data:
                # Convert extra data to ASCII-safe string
                extra_str = json.dumps(extra_data, ensure_ascii=True, default=str)
                message += f" | Data: {extra_str}"
            
            # Log the message
            log_method = getattr(self.logger, level.value.lower())
            log_method(message, extra=extra, exc_info=exc_info)
            
        except Exception as e:
            # Fallback logging to stderr
            print(f"LOGGING ERROR: {e}", file=sys.stderr)
            print(f"Original message: {message}", file=sys.stderr)
    
    def debug(self, message: str, category: LogCategory = LogCategory.SYSTEM, 
            extra_data: Optional[Dict[str, Any]] = None):
        """Log debug message.
        self._log(LogLevel.DEBUG, message, category, extra_data)
    
    def info(self, message: str, category: LogCategory = LogCategory.SYSTEM, 
            extra_data: Optional[Dict[str, Any]] = None):
        """Log info message."""
        self._log(LogLevel.INFO, message, category, extra_data)
    
    def warning(self, message: str, category: LogCategory = LogCategory.SYSTEM, 
                extra_data: Optional[Dict[str, Any]] = None):
        Log warning message."""
        self._log(LogLevel.WARNING, message, category, extra_data)
    
    def error(self, message: str, category: LogCategory = LogCategory.SYSTEM, 
            extra_data: Optional[Dict[str, Any]] = None, exc_info: bool = True):
        """Log error message.
        self._log(LogLevel.ERROR, message, category, extra_data, exc_info)
    
    def critical(self, message: str, category: LogCategory = LogCategory.SYSTEM, 
                extra_data: Optional[Dict[str, Any]] = None, exc_info: bool = True):
        """Log critical message."""
        self._log(LogLevel.CRITICAL, message, category, extra_data, exc_info)
    
    def log_startup(self, component: str, status: str, details: Optional[str] = None):
        Log startup information."""
        message = f"STARTUP: {component} - {status}"
        if details:
            message += f" - {details}"
        self.info(message, LogCategory.STARTUP)
    
    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log security event."""
        message = f"SECURITY EVENT: {event_type}"
        self.warning(message, LogCategory.SECURITY, details)
    
    def log_rate_limit_violation(self, client_id: str, strategy: str, limit: int, current: int):
        """Log rate limit violation."""
        message = f"RATE LIMIT VIOLATION: {strategy} - Client: {client_id} - {current}/{limit}"
        self.warning(message, LogCategory.RATE_LIMIT, {
            "client_id": client_id,
            "strategy": strategy,
            "limit": limit,
            "current": current
        })
    
    def log_ddos_event(self, ip: str, threat_level: str, action: str):
        """Log DDoS event."""
        message = f"DDOS EVENT: IP {ip} - Threat: {threat_level} - Action: {action}"
        self.warning(message, LogCategory.DDOS, {
            "ip": ip,
            "threat_level": threat_level,
            "action": action
        })
    
    def log_api_request(self, method: str, path: str, status_code: int, 
                    response_time: float, client_ip: str):
        """Log API request."""
        message = f"API: {method} {path} - {status_code} - {response_time:.3f}ms - {client_ip}"
        level = LogLevel.INFO if status_code < 400 else LogLevel.WARNING
        self._log(level, message, LogCategory.API, {
            "method": method,
            "path": path,
            "status_code": status_code,
            "response_time": response_time,
            "client_ip": client_ip
        })
    
    def log_performance_metric(self, metric_name: str, value: float, unit: str = ""):
        """Log performance metric."""
        message = f"PERFORMANCE: {metric_name} = {value}{unit}"
        self.debug(message, LogCategory.PERFORMANCE, {
            "metric": metric_name,
            "value": value,
            "unit": unit
        })
    
    def get_stats(self) -> Dict[str, Any]:
        """Get logging statistics.
        return self.stats.copy()
    
    def flush(self):
        """Flush all handlers."""
        for handler in self.logger.handlers:
            handler.flush()

# Global logger instance
_global_logger: Optional[UnifiedLogger] = None

def get_logger(name: str = "plexichat") -> UnifiedLogger:
    """Get the global logger instance."""
    global _global_logger
    if _global_logger is None:
        _global_logger = UnifiedLogger(name)
    return _global_logger

def setup_logging(log_level: str = "INFO", log_dir: str = "data/logs"):
    """Setup logging system."""
    # Create log directory
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    # Initialize global logger
    logger = get_logger()
    logger.info("Logging system initialized", LogCategory.STARTUP, {
        "log_level": log_level,
        "log_dir": log_dir
    })
    
    return logger
