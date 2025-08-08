"""
PlexiChat Unified Logger System

Single source of truth for all logging functionality.
Consolidates logging/, logging_advanced/, and logging.py into one clean system.
"""

from typing import Any, Dict, List, Optional, Callable
import logging
import sys
from pathlib import Path

# Lazy import to avoid circular dependencies
def _get_unified_logger():
    from .unified_logger import (
        UnifiedLoggingManager, UnifiedLogger, LogLevel, LogCategory,
        LogContext, LogEntry, PerformanceTimer, CentralizedDirectoryManager,
        get_logger, get_logging_manager, get_directory_manager, setup_module_logging,
        log_performance, log_request, log_error, log_audit_event, timer, flush_logs
    )
    return {
        'UnifiedLoggingManager': UnifiedLoggingManager,
        'UnifiedLogger': UnifiedLogger,
        'LogLevel': LogLevel,
        'LogCategory': LogCategory,
        'LogContext': LogContext,
        'LogEntry': LogEntry,
        'PerformanceTimer': PerformanceTimer,
        'CentralizedDirectoryManager': CentralizedDirectoryManager,
        'get_logger': get_logger,
        'get_logging_manager': get_logging_manager,
        'get_directory_manager': get_directory_manager,
        'setup_module_logging': setup_module_logging,
        'log_performance': log_performance,
        'log_request': log_request,
        'log_error': log_error,
        'log_audit_event': log_audit_event,
        'timer': timer,
        'flush_logs': flush_logs,
    }

# Global variables for lazy loading
_logger_components = None

def get_logger(name: str = "plexichat"):
    """Get a logger instance."""
    global _logger_components
    if _logger_components is None:
        _logger_components = _get_unified_logger()
    return _logger_components['get_logger'](name)

def get_logging_manager():
    """Get the logging manager."""
    global _logger_components
    if _logger_components is None:
        _logger_components = _get_unified_logger()
    return _logger_components['get_logging_manager']()

def get_directory_manager():
    """Get the directory manager."""
    global _logger_components
    if _logger_components is None:
        _logger_components = _get_unified_logger()
    return _logger_components['get_directory_manager']()

def initialize_logging(config: Optional[Dict[str, Any]] = None):
    """Initialize the logging system with optional configuration."""
    global _logger_components
    if _logger_components is None:
        _logger_components = _get_unified_logger()

    # Get the logging manager to trigger initialization
    manager = _logger_components['get_logging_manager']()

    # Apply any custom configuration
    if config:
        # Update configuration if needed
        pass

    return manager

# Export all the main functions
__all__ = [
    "get_logger",
    "get_logging_manager",
    "get_directory_manager",
    "initialize_logging",
]
