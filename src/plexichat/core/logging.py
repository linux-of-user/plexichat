"""
Compatibility shim for logging system.

This module re-exports logging functions from the unified logger to maintain
backward compatibility and fix import path issues throughout the codebase.
"""

from plexichat.core.logging import (
    get_logger,
    get_logging_manager,
    get_directory_manager,
    setup_module_logging,
    log_performance,
    log_request,
    log_error,
    log_audit_event,
    timer,
    flush_logs
)

# Re-export all logging functions for compatibility
__all__ = [
    "get_logger",
    "get_logging_manager", 
    "get_directory_manager",
    "setup_module_logging",
    "log_performance",
    "log_request",
    "log_error",
    "log_audit_event",
    "timer",
    "flush_logs"
]
