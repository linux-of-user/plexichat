"""
Compatibility shim for logging system.

This module re-exports logging functions from the unified logger to maintain
backward compatibility and fix import path issues throughout the codebase.
"""

from src.plexichat.core.logging.unified_logger import (
    flush_logs,
    get_directory_manager,
    get_logger,
    get_logging_manager,
    log_audit_event,
    log_error,
    log_performance,
    log_request,
    setup_module_logging,
    timer,
)

# Re-export all logging functions for compatibility
__all__ = [
    "flush_logs",
    "get_directory_manager",
    "get_logger",
    "get_logging_manager",
    "log_audit_event",
    "log_error",
    "log_performance",
    "log_request",
    "setup_module_logging",
    "timer",
]
