# app/utils/monitoring/__init__.py
"""
Monitoring and error handling package for Chat API.
Provides comprehensive system monitoring, error handling, and alerting.
"""

from .error_handler import (
    ErrorHandler, SystemMonitor, ErrorSeverity,
    error_handler, system_monitor,
    error_handler_decorator, monitor_performance
)

__all__ = [
    "ErrorHandler", "SystemMonitor", "ErrorSeverity",
    "error_handler", "system_monitor", 
    "error_handler_decorator", "monitor_performance"
]
