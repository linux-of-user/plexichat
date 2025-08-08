"""
Advanced Logging System

Enhanced logging with categorization, performance tracking, and advanced features.
"""

import logging
import time
import asyncio
from typing import Any, Dict, Optional, List
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class LogLevel(Enum):
    """Enhanced log levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    AUDIT = "audit"
    SECURITY = "security"
    PERFORMANCE = "performance"


class LogCategory(Enum):
    """Log categories for better organization."""
    GENERAL = "general"
    API = "api"
    SECURITY = "security"
    PERFORMANCE = "performance"
    AUDIT = "audit"
    SYSTEM = "system"
    DATABASE = "database"
    NETWORK = "network"
    MONITORING = "monitoring"


@dataclass
class LogEntry:
    """Enhanced log entry with metadata."""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    level: LogLevel = LogLevel.INFO
    category: LogCategory = LogCategory.GENERAL
    message: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    performance_data: Optional[Dict[str, Any]] = None


class PerformanceTracker:
    """Performance tracking context manager."""
    
    def __init__(self, operation: str, logger_instance: Optional['AdvancedLogger'] = None):
        self.operation = operation
        self.logger = logger_instance
        self.start_time = None
        self.end_time = None
    
    def __enter__(self):
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.perf_counter()
        duration = self.end_time - (self.start_time or 0)
        
        if self.logger:
            self.logger.log_performance(
                f"Operation '{self.operation}' completed",
                duration=duration,
                operation=self.operation,
                success=exc_type is None
            )


class AdvancedLogger:
    """Advanced logger with enhanced features."""
    
    def __init__(self, name: str = "advanced_logger"):
        self.name = name
        self.logger = logging.getLogger(name)
        self.entries: List[LogEntry] = []
        self.performance_metrics: Dict[str, List[float]] = {}
    
    def log(
        self,
        level: LogLevel,
        message: str,
        category: LogCategory = LogCategory.GENERAL,
        context: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        **kwargs
    ):
        """Log a message with enhanced metadata."""
        entry = LogEntry(
            level=level,
            category=category,
            message=message,
            context=context or {},
            user_id=user_id,
            session_id=session_id,
            request_id=request_id
        )
        
        # Add any additional context from kwargs
        entry.context.update(kwargs)
        
        # Store entry
        self.entries.append(entry)
        
        # Log to standard logger
        log_method = getattr(self.logger, level.value.lower(), self.logger.info)
        log_method(f"[{category.value.upper()}] {message}", extra=entry.context)
    
    def log_performance(
        self,
        message: str,
        duration: float,
        operation: str,
        success: bool = True,
        **kwargs
    ):
        """Log performance metrics."""
        # Track metrics
        if operation not in self.performance_metrics:
            self.performance_metrics[operation] = []
        self.performance_metrics[operation].append(duration)
        
        # Create performance context
        perf_context = {
            "duration_ms": duration * 1000,
            "operation": operation,
            "success": success,
            **kwargs
        }
        
        self.log(
            LogLevel.PERFORMANCE,
            message,
            LogCategory.PERFORMANCE,
            context=perf_context
        )
    
    def log_security(
        self,
        message: str,
        event_type: str,
        severity: str = "medium",
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        **kwargs
    ):
        """Log security events."""
        security_context = {
            "event_type": event_type,
            "severity": severity,
            "ip_address": ip_address,
            **kwargs
        }
        
        self.log(
            LogLevel.SECURITY,
            message,
            LogCategory.SECURITY,
            context=security_context,
            user_id=user_id
        )
    
    def log_audit(
        self,
        message: str,
        action: str,
        resource: str,
        user_id: Optional[str] = None,
        success: bool = True,
        **kwargs
    ):
        """Log audit events."""
        audit_context = {
            "action": action,
            "resource": resource,
            "success": success,
            **kwargs
        }
        
        self.log(
            LogLevel.AUDIT,
            message,
            LogCategory.AUDIT,
            context=audit_context,
            user_id=user_id
        )
    
    def log_api(
        self,
        message: str,
        method: str,
        endpoint: str,
        status_code: int,
        duration: Optional[float] = None,
        user_id: Optional[str] = None,
        **kwargs
    ):
        """Log API requests."""
        api_context = {
            "method": method,
            "endpoint": endpoint,
            "status_code": status_code,
            "duration_ms": duration * 1000 if duration else None,
            **kwargs
        }
        
        level = LogLevel.INFO if 200 <= status_code < 400 else LogLevel.WARNING
        
        self.log(
            level,
            message,
            LogCategory.API,
            context=api_context,
            user_id=user_id
        )
    
    def log_system(
        self,
        message: str,
        component: str,
        level: LogLevel = LogLevel.INFO,
        **kwargs
    ):
        """Log system events."""
        system_context = {
            "component": component,
            **kwargs
        }
        
        self.log(
            level,
            message,
            LogCategory.SYSTEM,
            context=system_context
        )
    
    def log_monitoring(
        self,
        message: str,
        metric_name: str,
        metric_value: Any,
        unit: str = "",
        **kwargs
    ):
        """Log monitoring metrics."""
        monitoring_context = {
            "metric_name": metric_name,
            "metric_value": metric_value,
            "unit": unit,
            **kwargs
        }
        
        self.log(
            LogLevel.INFO,
            message,
            LogCategory.MONITORING,
            context=monitoring_context
        )
    
    def track_performance(self, operation: str) -> PerformanceTracker:
        """Create a performance tracker context manager."""
        return PerformanceTracker(operation, self)
    
    def get_performance_stats(self, operation: str) -> Dict[str, float]:
        """Get performance statistics for an operation."""
        if operation not in self.performance_metrics:
            return {}
        
        durations = self.performance_metrics[operation]
        return {
            "count": len(durations),
            "avg_ms": (sum(durations) / len(durations)) * 1000,
            "min_ms": min(durations) * 1000,
            "max_ms": max(durations) * 1000,
            "total_ms": sum(durations) * 1000
        }
    
    def get_recent_entries(
        self,
        limit: int = 100,
        level: Optional[LogLevel] = None,
        category: Optional[LogCategory] = None
    ) -> List[LogEntry]:
        """Get recent log entries with optional filtering."""
        entries = self.entries[-limit:]
        
        if level:
            entries = [e for e in entries if e.level == level]
        
        if category:
            entries = [e for e in entries if e.category == category]
        
        return entries


# Global advanced logger instance
advanced_logger = AdvancedLogger("plexichat_advanced")


# Convenience functions
def log_performance(message: str, duration: float, operation: str, **kwargs):
    """Log performance metrics."""
    advanced_logger.log_performance(message, duration, operation, **kwargs)


def log_security(message: str, event_type: str, **kwargs):
    """Log security events."""
    advanced_logger.log_security(message, event_type, **kwargs)


def log_audit(message: str, action: str, resource: str, **kwargs):
    """Log audit events."""
    advanced_logger.log_audit(message, action, resource, **kwargs)


def log_api(message: str, method: str, endpoint: str, status_code: int, **kwargs):
    """Log API requests."""
    advanced_logger.log_api(message, method, endpoint, status_code, **kwargs)


def log_system(message: str, component: str, **kwargs):
    """Log system events."""
    advanced_logger.log_system(message, component, **kwargs)


def log_monitoring(message: str, metric_name: str, metric_value: Any, **kwargs):
    """Log monitoring metrics."""
    advanced_logger.log_monitoring(message, metric_name, metric_value, **kwargs)


# Export all components
__all__ = [
    # Enums
    "LogLevel",
    "LogCategory",

    # Classes
    "LogEntry",
    "PerformanceTracker",
    "AdvancedLogger",

    # Global instance
    "advanced_logger",

    # Convenience functions
    "log_performance",
    "log_security",
    "log_audit",
    "log_api",
    "log_system",
    "log_monitoring",
]
