"""
Enhanced Logging System

Advanced logging with context management and metrics.
"""

import logging
import time
from typing import Any, Dict, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timezone
from contextlib import contextmanager

logger = logging.getLogger(__name__)


@dataclass
class LogContext:
    """Logging context for enhanced tracking."""
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    component: Optional[str] = None
    operation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LogMetrics:
    """Logging metrics and statistics."""
    total_logs: int = 0
    error_count: int = 0
    warning_count: int = 0
    performance_logs: int = 0
    security_logs: int = 0
    audit_logs: int = 0
    avg_log_rate: float = 0.0
    last_reset: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class EnhancedLogger:
    """Enhanced logger with context and metrics."""
    
    def __init__(self, name: str = "enhanced_logger"):
        self.name = name
        self.logger = logging.getLogger(name)
        self.context = LogContext()
        self.metrics = LogMetrics()
        self._start_time = time.time()
    
    def set_context(self, **kwargs):
        """Set logging context."""
        for key, value in kwargs.items():
            if hasattr(self.context, key):
                setattr(self.context, key, value)
            else:
                self.context.metadata[key] = value
    
    def clear_context(self):
        """Clear logging context."""
        self.context = LogContext()
    
    @contextmanager
    def context_manager(self, **kwargs):
        """Context manager for temporary context."""
        old_context = LogContext(**self.context.__dict__)
        try:
            self.set_context(**kwargs)
            yield
        finally:
            self.context = old_context
    
    def _format_message(self, message: str, extra: Optional[Dict[str, Any]] = None) -> str:
        """Format message with context."""
        parts = []
        
        if self.context.request_id:
            parts.append(f"[req:{self.context.request_id[:8]}]")
        
        if self.context.user_id:
            parts.append(f"[user:{self.context.user_id}]")
        
        if self.context.component:
            parts.append(f"[{self.context.component}]")
        
        if self.context.operation:
            parts.append(f"[{self.context.operation}]")
        
        prefix = " ".join(parts)
        return f"{prefix} {message}" if prefix else message
    
    def _update_metrics(self, level: str):
        """Update logging metrics."""
        self.metrics.total_logs += 1
        
        if level.lower() == 'error':
            self.metrics.error_count += 1
        elif level.lower() == 'warning':
            self.metrics.warning_count += 1
        
        # Update average log rate
        elapsed = time.time() - self._start_time
        if elapsed > 0:
            self.metrics.avg_log_rate = self.metrics.total_logs / elapsed
    
    def debug(self, message: str, **kwargs):
        """Log debug message."""
        formatted_msg = self._format_message(message, kwargs)
        self.logger.debug(formatted_msg, extra=kwargs)
        self._update_metrics('debug')
    
    def info(self, message: str, **kwargs):
        """Log info message."""
        formatted_msg = self._format_message(message, kwargs)
        self.logger.info(formatted_msg, extra=kwargs)
        self._update_metrics('info')
    
    def warning(self, message: str, **kwargs):
        """Log warning message."""
        formatted_msg = self._format_message(message, kwargs)
        self.logger.warning(formatted_msg, extra=kwargs)
        self._update_metrics('warning')
    
    def error(self, message: str, **kwargs):
        """Log error message."""
        formatted_msg = self._format_message(message, kwargs)
        self.logger.error(formatted_msg, extra=kwargs)
        self._update_metrics('error')
    
    def critical(self, message: str, **kwargs):
        """Log critical message."""
        formatted_msg = self._format_message(message, kwargs)
        self.logger.critical(formatted_msg, extra=kwargs)
        self._update_metrics('critical')
    
    def performance(self, message: str, duration: float, **kwargs):
        """Log performance message."""
        kwargs['duration_ms'] = duration * 1000
        formatted_msg = self._format_message(f"PERF: {message}", kwargs)
        self.logger.info(formatted_msg, extra=kwargs)
        self.metrics.performance_logs += 1
        self._update_metrics('performance')
    
    def security(self, message: str, event_type: str, severity: str = "medium", **kwargs):
        """Log security message."""
        kwargs.update({
            'event_type': event_type,
            'severity': severity,
            'category': 'security'
        })
        formatted_msg = self._format_message(f"SECURITY: {message}", kwargs)
        self.logger.warning(formatted_msg, extra=kwargs)
        self.metrics.security_logs += 1
        self._update_metrics('security')
    
    def audit(self, message: str, action: str, resource: str, success: bool = True, **kwargs):
        """Log audit message."""
        kwargs.update({
            'action': action,
            'resource': resource,
            'success': success,
            'category': 'audit'
        })
        formatted_msg = self._format_message(f"AUDIT: {message}", kwargs)
        self.logger.info(formatted_msg, extra=kwargs)
        self.metrics.audit_logs += 1
        self._update_metrics('audit')
    
    def api(self, message: str, method: str, endpoint: str, status_code: int, **kwargs):
        """Log API message."""
        kwargs.update({
            'method': method,
            'endpoint': endpoint,
            'status_code': status_code,
            'category': 'api'
        })
        
        level_method = self.info if 200 <= status_code < 400 else self.warning
        formatted_msg = self._format_message(f"API: {message}", kwargs)
        level_method(formatted_msg, **kwargs)
    
    def system(self, message: str, component: str, **kwargs):
        """Log system message."""
        kwargs.update({
            'component': component,
            'category': 'system'
        })
        formatted_msg = self._format_message(f"SYSTEM: {message}", kwargs)
        self.logger.info(formatted_msg, extra=kwargs)
        self._update_metrics('system')
    
    def get_metrics(self) -> LogMetrics:
        """Get current logging metrics."""
        return self.metrics
    
    def reset_metrics(self):
        """Reset logging metrics."""
        self.metrics = LogMetrics()
        self._start_time = time.time()
    
    @contextmanager
    def performance_timer(self, operation: str):
        """Context manager for performance timing."""
        start_time = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start_time
            self.performance(f"Operation '{operation}' completed", duration, operation=operation)


# Global enhanced logger instance
enhanced_logger = EnhancedLogger("plexichat_enhanced")


# Export all components
__all__ = [
    "LogContext",
    "LogMetrics",
    "EnhancedLogger",
    "enhanced_logger",
]
