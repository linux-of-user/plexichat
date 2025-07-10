"""
NetLink Logging Service Module

Small modular service for centralized logging with advanced features.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from pathlib import Path
import gzip
import threading
from collections import deque

# Service metadata
SERVICE_METADATA = {
    "module_id": "logging_service",
    "name": "Centralized Logging Service",
    "description": "Advanced logging service with rotation, compression, and filtering",
    "version": "1.0.0",
    "service_type": "core",
    "dependencies": [],
    "provides": ["logging", "log_rotation", "log_filtering"],
    "config": {
        "log_level": "INFO",
        "max_file_size": "10MB",
        "backup_count": 5,
        "compression": True,
        "structured_logging": True
    },
    "auto_start": True,
    "hot_reload": True
}


class LoggingService:
    """Centralized logging service."""
    
    def __init__(self):
        self.config = SERVICE_METADATA["config"]
        self.log_queue = deque(maxlen=10000)
        self.log_handlers = {}
        self.filters = []
        self.stats = {
            "total_logs": 0,
            "error_logs": 0,
            "warning_logs": 0,
            "info_logs": 0,
            "debug_logs": 0
        }
        
        # Thread-safe logging
        self.lock = threading.Lock()
        
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self) -> bool:
        """Initialize the logging service."""
        try:
            # Setup log directory
            self.log_dir = Path("logs")
            self.log_dir.mkdir(exist_ok=True)
            
            # Setup rotating file handler
            self._setup_file_handler()
            
            # Setup structured logging
            if self.config.get("structured_logging", True):
                self._setup_structured_logging()
            
            self.logger.info("Logging service initialized")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize logging service: {e}")
            return False
    
    async def start(self) -> bool:
        """Start the logging service."""
        try:
            # Start log processing task
            asyncio.create_task(self._process_log_queue())
            
            self.logger.info("Logging service started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start logging service: {e}")
            return False
    
    async def stop(self) -> bool:
        """Stop the logging service."""
        try:
            # Flush remaining logs
            await self._flush_logs()
            
            self.logger.info("Logging service stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop logging service: {e}")
            return False
    
    def _setup_file_handler(self):
        """Setup rotating file handler."""
        from logging.handlers import RotatingFileHandler
        
        log_file = self.log_dir / "netlink.log"
        max_bytes = self._parse_size(self.config.get("max_file_size", "10MB"))
        backup_count = self.config.get("backup_count", 5)
        
        handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        
        # Custom formatter for structured logging
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        
        # Add to root logger
        root_logger = logging.getLogger()
        root_logger.addHandler(handler)
        root_logger.setLevel(getattr(logging, self.config.get("log_level", "INFO")))
    
    def _setup_structured_logging(self):
        """Setup structured logging with JSON format."""
        class StructuredFormatter(logging.Formatter):
            def format(self, record):
                log_entry = {
                    "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
                    "level": record.levelname,
                    "logger": record.name,
                    "message": record.getMessage(),
                    "module": record.module,
                    "function": record.funcName,
                    "line": record.lineno
                }
                
                if record.exc_info:
                    log_entry["exception"] = self.formatException(record.exc_info)
                
                return json.dumps(log_entry)
        
        # Add structured handler
        structured_file = self.log_dir / "netlink_structured.log"
        structured_handler = logging.FileHandler(structured_file)
        structured_handler.setFormatter(StructuredFormatter())
        
        root_logger = logging.getLogger()
        root_logger.addHandler(structured_handler)
    
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
    
    async def _process_log_queue(self):
        """Process queued log entries."""
        while True:
            try:
                if self.log_queue:
                    with self.lock:
                        log_entry = self.log_queue.popleft()
                    
                    await self._process_log_entry(log_entry)
                
                await asyncio.sleep(0.1)
                
            except Exception as e:
                self.logger.error(f"Error processing log queue: {e}")
    
    async def _process_log_entry(self, log_entry: Dict[str, Any]):
        """Process a single log entry."""
        try:
            # Apply filters
            if not self._should_log(log_entry):
                return
            
            # Update statistics
            self._update_stats(log_entry)
            
            # Additional processing (e.g., send to external systems)
            await self._send_to_external_systems(log_entry)
            
        except Exception as e:
            self.logger.error(f"Error processing log entry: {e}")
    
    def _should_log(self, log_entry: Dict[str, Any]) -> bool:
        """Check if log entry should be processed based on filters."""
        for filter_func in self.filters:
            if not filter_func(log_entry):
                return False
        return True
    
    def _update_stats(self, log_entry: Dict[str, Any]):
        """Update logging statistics."""
        self.stats["total_logs"] += 1
        
        level = log_entry.get("level", "INFO").lower()
        if level == "error":
            self.stats["error_logs"] += 1
        elif level == "warning":
            self.stats["warning_logs"] += 1
        elif level == "info":
            self.stats["info_logs"] += 1
        elif level == "debug":
            self.stats["debug_logs"] += 1
    
    async def _send_to_external_systems(self, log_entry: Dict[str, Any]):
        """Send log entry to external logging systems."""
        # Placeholder for external integrations
        # Could send to ELK stack, Splunk, etc.
        pass
    
    async def _flush_logs(self):
        """Flush remaining logs."""
        while self.log_queue:
            with self.lock:
                if self.log_queue:
                    log_entry = self.log_queue.popleft()
                    await self._process_log_entry(log_entry)
    
    def add_log_filter(self, filter_func):
        """Add a log filter function."""
        self.filters.append(filter_func)
    
    def remove_log_filter(self, filter_func):
        """Remove a log filter function."""
        if filter_func in self.filters:
            self.filters.remove(filter_func)
    
    def get_log_stats(self) -> Dict[str, Any]:
        """Get logging statistics."""
        return self.stats.copy()
    
    async def rotate_logs(self):
        """Manually rotate log files."""
        try:
            # Compress old logs if enabled
            if self.config.get("compression", True):
                await self._compress_old_logs()
            
            self.logger.info("Log rotation completed")
            
        except Exception as e:
            self.logger.error(f"Failed to rotate logs: {e}")
    
    async def _compress_old_logs(self):
        """Compress old log files."""
        for log_file in self.log_dir.glob("*.log.*"):
            if not log_file.name.endswith('.gz'):
                compressed_file = log_file.with_suffix(log_file.suffix + '.gz')
                
                with open(log_file, 'rb') as f_in:
                    with gzip.open(compressed_file, 'wb') as f_out:
                        f_out.writelines(f_in)
                
                log_file.unlink()  # Remove original file
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check."""
        try:
            # Check log directory
            log_dir_writable = self.log_dir.exists() and self.log_dir.is_dir()
            
            # Check queue size
            queue_size = len(self.log_queue)
            queue_healthy = queue_size < 8000  # 80% of max capacity
            
            # Check disk space
            disk_space = self._get_disk_space()
            disk_healthy = disk_space > 100 * 1024 * 1024  # 100MB minimum
            
            overall_health = log_dir_writable and queue_healthy and disk_healthy
            
            return {
                "status": "healthy" if overall_health else "unhealthy",
                "log_directory_writable": log_dir_writable,
                "queue_size": queue_size,
                "queue_healthy": queue_healthy,
                "disk_space_mb": disk_space / (1024 * 1024),
                "disk_healthy": disk_healthy,
                "statistics": self.stats
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    def _get_disk_space(self) -> int:
        """Get available disk space in bytes."""
        try:
            import shutil
            return shutil.disk_usage(self.log_dir).free
        except Exception:
            return 0


# Create service instance
def create_service():
    """Create logging service instance."""
    return LoggingService()


# Module-level functions for backward compatibility
async def initialize():
    """Initialize the logging service."""
    service = create_service()
    return await service.initialize()


async def start():
    """Start the logging service."""
    service = create_service()
    return await service.start()


async def health_check():
    """Perform health check."""
    service = create_service()
    return await service.health_check()
