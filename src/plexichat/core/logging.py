"""
PlexiChat Core Logging System

Enhanced logging with comprehensive configuration and performance optimization.
Uses EXISTING performance optimization systems.
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

# Configuration imports
try:
    from plexichat.core.config import settings
except ImportError:
    class MockSettings:
        LOG_LEVEL = "INFO"
        LOG_FILE = None
        LOG_MAX_SIZE = 10 * 1024 * 1024
        LOG_BACKUP_COUNT = 5
        DEBUG = False
    settings = MockSettings()

class ColoredFormatter(logging.Formatter):
    """Colored log formatter for console output."""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record):
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.RESET}"
        return super().format(record)

class PerformanceFilter(logging.Filter):
    """Filter to add performance metrics to log records."""
    
    def __init__(self):
        super().__init__()
        self.performance_logger = get_performance_logger() if get_performance_logger else None
    
    def filter(self, record):
        # Add performance context if available
        if self.performance_logger:
            try:
                # Add current performance metrics to record
                record.memory_usage = self.performance_logger.get_current_memory_usage()
                record.cpu_usage = self.performance_logger.get_current_cpu_usage()
            except Exception:
                pass
        return True

class LoggingManager:
    """Enhanced logging manager with performance optimization."""
    
    def __init__(self):
        self.loggers: Dict[str, logging.Logger] = {}
        self.performance_logger = get_performance_logger() if get_performance_logger else None
        self._setup_root_logger()
    
    def _setup_root_logger(self):
        """Setup root logger configuration."""
        try:
            # Get log level
            log_level = getattr(settings, 'LOG_LEVEL', 'INFO')
            level = getattr(logging, log_level.upper(), logging.INFO)
            
            # Configure root logger
            root_logger = logging.getLogger()
            root_logger.setLevel(level)
            
            # Clear existing handlers
            root_logger.handlers.clear()
            
            # Console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(level)
            
            # Console formatter
            if getattr(settings, 'DEBUG', False):
                console_format = '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
                console_formatter = ColoredFormatter(console_format)
            else:
                console_format = '%(asctime)s - %(levelname)s - %(message)s'
                console_formatter = ColoredFormatter(console_format)
            
            console_handler.setFormatter(console_formatter)
            console_handler.addFilter(PerformanceFilter())
            root_logger.addHandler(console_handler)
            
            # File handler (if configured)
            log_file = getattr(settings, 'LOG_FILE', None)
            if log_file:
                self._setup_file_handler(root_logger, log_file, level)
            
            # Performance logging
            if self.performance_logger:
                self.performance_logger.record_metric("logging_system_initialized", 1, "count")
            
        except Exception as e:
            print(f"Error setting up logging: {e}")
    
    def _setup_file_handler(self, logger: logging.Logger, log_file: str, level: int):
        """Setup file handler with rotation."""
        try:
            # Create log directory if it doesn't exist
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Rotating file handler
            max_size = getattr(settings, 'LOG_MAX_SIZE', 10 * 1024 * 1024)
            backup_count = getattr(settings, 'LOG_BACKUP_COUNT', 5)
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_size,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(level)
            
            # File formatter (more detailed)
            file_format = '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s - %(message)s'
            file_formatter = logging.Formatter(file_format)
            file_handler.setFormatter(file_formatter)
            file_handler.addFilter(PerformanceFilter())
            
            logger.addHandler(file_handler)
            
        except Exception as e:
            print(f"Error setting up file handler: {e}")
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get or create logger with performance optimization."""
        if name not in self.loggers:
            logger = logging.getLogger(name)
            
            # Add performance context
            if self.performance_logger:
                logger.addFilter(PerformanceFilter())
            
            self.loggers[name] = logger
            
            # Performance tracking
            if self.performance_logger:
                self.performance_logger.record_metric("loggers_created", 1, "count")
        
        return self.loggers[name]
    
    def set_level(self, level: str):
        """Set logging level for all loggers."""
        try:
            log_level = getattr(logging, level.upper(), logging.INFO)
            
            # Update root logger
            root_logger = logging.getLogger()
            root_logger.setLevel(log_level)
            
            # Update all handlers
            for handler in root_logger.handlers:
                handler.setLevel(log_level)
            
            # Update all custom loggers
            for logger in self.loggers.values():
                logger.setLevel(log_level)
            
        except Exception as e:
            print(f"Error setting log level: {e}")
    
    def add_handler(self, handler: logging.Handler, logger_name: Optional[str] = None):
        """Add handler to logger."""
        try:
            if logger_name:
                logger = self.get_logger(logger_name)
            else:
                logger = logging.getLogger()
            
            handler.addFilter(PerformanceFilter())
            logger.addHandler(handler)
            
        except Exception as e:
            print(f"Error adding handler: {e}")
    
    def remove_handler(self, handler: logging.Handler, logger_name: Optional[str] = None):
        """Remove handler from logger."""
        try:
            if logger_name:
                logger = self.get_logger(logger_name)
            else:
                logger = logging.getLogger()
            
            logger.removeHandler(handler)
            
        except Exception as e:
            print(f"Error removing handler: {e}")
    
    def get_log_stats(self) -> Dict[str, Any]:
        """Get logging statistics."""
        try:
            stats = {
                "total_loggers": len(self.loggers),
                "root_level": logging.getLogger().level,
                "handlers_count": len(logging.getLogger().handlers),
                "timestamp": datetime.now().isoformat()
            }
            
            # Add performance metrics if available
            if self.performance_logger:
                stats.update({
                    "memory_usage": self.performance_logger.get_current_memory_usage(),
                    "cpu_usage": self.performance_logger.get_current_cpu_usage()
                })
            
            return stats
            
        except Exception as e:
            return {"error": str(e), "timestamp": datetime.now().isoformat()}
    
    def flush_logs(self):
        """Flush all log handlers."""
        try:
            for handler in logging.getLogger().handlers:
                if hasattr(handler, 'flush'):
                    handler.flush()
            
            for logger in self.loggers.values():
                for handler in logger.handlers:
                    if hasattr(handler, 'flush'):
                        handler.flush()
                        
        except Exception as e:
            print(f"Error flushing logs: {e}")

# Global logging manager
logging_manager = LoggingManager()

# Convenience functions
def get_logger(name: str) -> logging.Logger:
    """Get logger instance."""
    return logging_manager.get_logger(name)

def set_log_level(level: str):
    """Set global log level."""
    logging_manager.set_level(level)

def get_log_stats() -> Dict[str, Any]:
    """Get logging statistics."""
    return logging_manager.get_log_stats()

def flush_logs():
    """Flush all logs."""
    logging_manager.flush_logs()

# Setup audit logger
audit_logger = get_logger("plexichat.audit")

def log_audit_event(event_type: str, user_id: Optional[int], details: Dict[str, Any]):
    """Log audit event."""
    try:
        audit_data = {
            "event_type": event_type,
            "user_id": user_id,
            "timestamp": datetime.now().isoformat(),
            "details": details
        }
        audit_logger.info(f"AUDIT: {audit_data}")
        
        # Performance tracking
        if logging_manager.performance_logger:
            logging_manager.performance_logger.record_metric("audit_events", 1, "count")
            
    except Exception as e:
        logging.getLogger(__name__).error(f"Error logging audit event: {e}")

# Setup security logger
security_logger = get_logger("plexichat.security")

def log_security_event(event_type: str, severity: str, details: Dict[str, Any]):
    """Log security event."""
    try:
        security_data = {
            "event_type": event_type,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
            "details": details
        }
        
        if severity.upper() == "CRITICAL":
            security_logger.critical(f"SECURITY: {security_data}")
        elif severity.upper() == "HIGH":
            security_logger.error(f"SECURITY: {security_data}")
        elif severity.upper() == "MEDIUM":
            security_logger.warning(f"SECURITY: {security_data}")
        else:
            security_logger.info(f"SECURITY: {security_data}")
        
        # Performance tracking
        if logging_manager.performance_logger:
            logging_manager.performance_logger.record_metric("security_events", 1, "count")
            
    except Exception as e:
        logging.getLogger(__name__).error(f"Error logging security event: {e}")
