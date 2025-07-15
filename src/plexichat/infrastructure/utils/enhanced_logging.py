import json
import logging
import logging.handlers
import platform
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import psutil
except ImportError: Optional[psutil] = None

"""
Enhanced Logging System for PlexiChat
Provides comprehensive logging with structured output, performance tracking, and error handling.
"""

class EnhancedLogger:
    """Enhanced logging system with structured output and performance tracking."""
    
    def __init__(self, name: str = "plexichat", log_dir: str = "logs"):
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Performance tracking
        self.performance_data = {}
        self.request_times = []
        
        # Setup logging
        self.setup_enhanced_logging()
        
        # Get logger instance
        self.logger = logging.getLogger(name)
        
    def setup_enhanced_logging(self):
        """Setup comprehensive logging system."""
        # Create timestamp for log files
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Main log file
        main_log = self.log_dir / f"plexichat_{timestamp}.log"
        
        # Error log file
        error_log = self.log_dir / f"plexichat_errors_{datetime.now().strftime('%Y%m%d')}.log"
        
        # Performance log file
        perf_log = self.log_dir / f"plexichat_performance_{datetime.now().strftime('%Y%m%d')}.log"
        
        # Access log file
        access_log = self.log_dir / f"plexichat_access_{datetime.now().strftime('%Y%m%d')}.log"
        
        # Setup formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)8s] %(name)s [%(filename)s:%(lineno)d] %(funcName)s(): %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        simple_formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)7s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        json_formatter = JsonFormatter()
        
        # Main file handler
        main_handler = logging.handlers.RotatingFileHandler(
            main_log,
            maxBytes=20*1024*1024,  # 20MB
            backupCount=10,
            encoding='utf-8'
        )
        main_handler.setFormatter(detailed_formatter)
        main_handler.setLevel(logging.DEBUG)
        
        # Error file handler
        error_handler = logging.handlers.RotatingFileHandler(
            error_log,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        error_handler.setFormatter(detailed_formatter)
        error_handler.setLevel(logging.ERROR)
        
        # Performance file handler
        perf_handler = logging.handlers.RotatingFileHandler(
            perf_log,
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3,
            encoding='utf-8'
        )
        perf_handler.setFormatter(json_formatter)
        perf_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(simple_formatter)
        console_handler.setLevel(logging.INFO)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Add handlers
        root_logger.addHandler(main_handler)
        root_logger.addHandler(error_handler)
        root_logger.addHandler(console_handler)
        
        # Configure performance logger
        perf_logger = logging.getLogger("plexichat.performance")
        perf_logger.addHandler(perf_handler)
        perf_logger.setLevel(logging.INFO)
        perf_logger.propagate = False
        
        # Configure access logger
        access_handler = logging.handlers.RotatingFileHandler(
            access_log,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        access_handler.setFormatter(simple_formatter)
        
        access_logger = logging.getLogger("plexichat.access")
        access_logger.addHandler(access_handler)
        access_logger.setLevel(logging.INFO)
        access_logger.propagate = False
        
        # Configure specific loggers
        self.configure_component_loggers()
        
        # Log initialization
        logger = logging.getLogger(self.name)
        logger.info("Enhanced logging system initialized")
        logger.info(f"Main log: {main_log}")
        logger.info(f"Error log: {error_log}")
        logger.info(f"Performance log: {perf_log}")
        logger.info(f"Access log: {access_log}")
        
        # Log system information
        self.log_system_info()
    
    def configure_component_loggers(self):
        """Configure loggers for different components."""
        # Uvicorn logger
        uvicorn_logger = logging.getLogger("uvicorn")
        uvicorn_logger.setLevel(logging.INFO)
        
        # FastAPI logger
        fastapi_logger = logging.getLogger("fastapi")
        fastapi_logger.setLevel(logging.INFO)
        
        # SQLAlchemy logger
        sqlalchemy_logger = logging.getLogger("sqlalchemy")
        sqlalchemy_logger.setLevel(logging.WARNING)
        
        # Requests logger
        requests_logger = logging.getLogger("urllib3")
        requests_logger.setLevel(logging.WARNING)
        
        # PlexiChat component loggers
        components = [
            "plexichat.app.auth",
            "plexichat.app.security",
            "plexichat.app.clustering",
            "plexichat.app.backup",
            "plexichat.app.core",
            "plexichat.gui",
            "plexichat.cli"
        ]
        
        for component in components:
            comp_logger = logging.getLogger(component)
            comp_logger.setLevel(logging.DEBUG)
    
    def log_system_info(self):
        """Log system information at startup."""
        logger = logging.getLogger(self.name)
        
        try:
            logger.info(f"System: {platform.system()} {platform.release()}")
            logger.info(f"Python: {platform.python_version()}")
            if psutil:
                logger.info(f"CPU Cores: {psutil.cpu_count()}")
                logger.info(f"Memory: {psutil.virtual_memory().total / (1024**3):.1f} GB")
                logger.info(f"Disk Space: {psutil.disk_usage('/').total / (1024**3):.1f} GB")
            else:
                logger.warning("psutil not available - system info limited")
            
        except Exception as e:
            logger.error(f"Error logging system info: {e}")
    
    def log_performance(self, operation: str, duration: float, **kwargs):
        """Log performance metrics."""
        perf_logger = logging.getLogger("plexichat.performance")
        
        perf_data = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "duration_ms": round(duration * 1000, 2),
            "thread_id": threading.get_ident(),
            **kwargs
        }
        
        perf_logger.info(json.dumps(perf_data))
        
        # Store for statistics
        self.performance_data[operation] = self.performance_data.get(operation, [])
        self.performance_data[operation].append(duration)
        
        # Keep only last 1000 entries per operation
        if len(self.performance_data[operation]) > 1000:
            self.performance_data[operation] = self.performance_data[operation][-1000:]
    
    def log_request(self, method: str, path: str, status_code: int, duration: float, **kwargs):
        """Log HTTP request."""
        access_logger = logging.getLogger("plexichat.access")
        
        request_data = {
            "timestamp": datetime.now().isoformat(),
            "method": method,
            "path": path,
            "status_code": status_code,
            "duration_ms": round(duration * 1000, 2),
            "thread_id": threading.get_ident(),
            **kwargs
        }
        
        access_logger.info(json.dumps(request_data))
        
        # Store for statistics
        self.request_times.append(duration)
        if len(self.request_times) > 10000:
            self.request_times = self.request_times[-10000:]
    
    def log_error(self, error: Exception, context: str = "", **kwargs):
        """Log error with context."""
        logger = logging.getLogger(self.name)
        
        error_data = {
            "timestamp": datetime.now().isoformat(),
            "error_type": type(error).__name__,
            "error_message": str(error),
            "context": context,
            "thread_id": threading.get_ident(),
            **kwargs
        }
        
        logger.error(json.dumps(error_data))
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        stats = {}
        
        # Overall performance stats
        if self.request_times:
            stats["requests"] = {
                "total": len(self.request_times),
                "avg_duration": sum(self.request_times) / len(self.request_times),
                "min_duration": min(self.request_times),
                "max_duration": max(self.request_times),
                "p95_duration": sorted(self.request_times)[int(len(self.request_times) * 0.95)]
            }
        
        # Operation-specific stats
        for operation, durations in self.performance_data.items():
            if durations:
                stats[operation] = {
                    "count": len(durations),
                    "avg_duration": sum(durations) / len(durations),
                    "min_duration": min(durations),
                    "max_duration": max(durations),
                    "p95_duration": sorted(durations)[int(len(durations) * 0.95)]
                }
        
        return stats

class JsonFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
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
        
        if hasattr(record, 'thread_id'):
            log_entry["thread_id"] = record.thread_id
        
        return json.dumps(log_entry)

class PerformanceTimer:
    """Context manager for performance timing."""
    
    def __init__(self, logger: EnhancedLogger, operation: str, **kwargs):
        self.logger = logger
        self.operation = operation
        self.kwargs = kwargs
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        self.logger.log_performance(self.operation, duration, **self.kwargs)

def get_logger(name: str = "plexichat") -> logging.Logger:
    """Get logger instance."""
    return logging.getLogger(name)

def log_performance(operation: str, duration: float, **kwargs):
    """Log performance metric."""
    perf_logger = logging.getLogger("plexichat.performance")
    perf_logger.info(json.dumps({
        "timestamp": datetime.now().isoformat(),
        "operation": operation,
        "duration_ms": round(duration * 1000, 2),
        **kwargs
    }))

def log_request(method: str, path: str, status_code: int, duration: float, **kwargs):
    """Log HTTP request."""
    access_logger = logging.getLogger("plexichat.access")
    access_logger.info(json.dumps({
        "timestamp": datetime.now().isoformat(),
        "method": method,
        "path": path,
        "status_code": status_code,
        "duration_ms": round(duration * 1000, 2),
        **kwargs
    }))

def log_error(error: Exception, context: str = "", **kwargs):
    """Log error with context."""
    logger = logging.getLogger("plexichat")
    logger.error(json.dumps({
        "timestamp": datetime.now().isoformat(),
        "error_type": type(error).__name__,
        "error_message": str(error),
        "context": context,
        **kwargs
    }))

def timer(operation: str, **kwargs):
    """Decorator for performance timing."""
    def decorator(func):
        def wrapper(*args, **func_kwargs):
            start_time = time.time()
            try:
                result = func(*args, **func_kwargs)
                duration = time.time() - start_time
                log_performance(operation, duration, **kwargs)
                return result
            except Exception as e:
                duration = time.time() - start_time
                log_performance(f"{operation} (error)", duration, **kwargs)
                raise
        return wrapper
    return decorator

def get_performance_stats() -> Dict[str, Any]:
    """Get performance statistics."""
    # This would need to be implemented based on your logging setup
    return {}

# Global enhanced logger instance
enhanced_logger = EnhancedLogger()

def setup_logging(name: str = "plexichat", log_dir: str = "logs"):
    """Setup enhanced logging system."""
    global enhanced_logger
    enhanced_logger = EnhancedLogger(name, log_dir)
    return enhanced_logger
