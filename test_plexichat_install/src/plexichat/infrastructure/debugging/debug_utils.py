# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
Debug Utilities

Utility functions and decorators for debugging PlexiChat components.
"""

import asyncio
import functools
import inspect
import json
import logging
import time
import traceback
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Callable, Union
from pathlib import Path

from .debug_manager import get_debug_manager, DebugLevel, ProfilerType

logger = logging.getLogger(__name__)


def debug_trace(level: DebugLevel = DebugLevel.DEBUG, ):
               include_args: bool = True,
               include_result: bool = True,
               profile: bool = False):
    """Decorator to trace function calls with debugging information."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            debug_manager = get_debug_manager()
            function_name = f"{func.__module__}.{func.__qualname__}"

            # Prepare context
            context = {"function": function_name}

            if include_args:
                try:
                    # Get function signature
                    sig = inspect.signature(func)
                    bound_args = sig.bind(*args, **kwargs)
                    bound_args.apply_defaults()

                    # Sanitize arguments (avoid logging sensitive data)
                    sanitized_args = {}
                    for name, value in bound_args.arguments.items():
                        if isinstance(value, (str, int, float, bool, list, dict)):
                            if name.lower() in ['password', 'token', 'secret', 'key']:
                                sanitized_args[name] = "[REDACTED]"
                            else:
                                sanitized_args[name] = str(value)[:100]  # Limit length
                        else:
                            sanitized_args[name] = f"<{type(value).__name__}>"

                    context["arguments"] = sanitized_args
                except Exception as e:
                    context["arguments_error"] = str(e)

            # Log function entry
            debug_manager.log_event()
                level,
                function_name,
                f"Function called: {function_name}",
                context
            )

            start_time = time.time()

            try:
                # Execute function with optional profiling
                if profile:
                    with debug_manager.profile_function(function_name):
                        result = func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)

                duration = time.time() - start_time

                # Log successful completion
                result_context = {
                    "function": function_name,
                    "duration": duration,
                    "success": True
                }

                if include_result and result is not None:
                    try:
                        if isinstance(result, (str, int, float, bool, list, dict)):
                            result_context["result"] = str(result)[:200]  # Limit length
                        else:
                            result_context["result_type"] = type(result).__name__
                    except Exception:
                        result_context["result_type"] = "unknown"

                debug_manager.log_event()
                    DebugLevel.DEBUG,
                    function_name,
                    f"Function completed: {function_name} ({duration:.4f}s)",
                    result_context
                )

                return result

            except Exception as e:
                duration = time.time() - start_time

                # Log error
                error_context = {
                    "function": function_name,
                    "duration": duration,
                    "success": False,
                    "error_type": type(e).__name__
                }

                debug_manager.log_error(function_name, e, error_context)
                raise

        return wrapper
    return decorator


def async_debug_trace(level: DebugLevel = DebugLevel.DEBUG,
                     include_args: bool = True,
                     include_result: bool = True,
                     profile: bool = False):
    """Decorator to trace async function calls with debugging information."""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            debug_manager = get_debug_manager()
            function_name = f"{func.__module__}.{func.__qualname__}"

            # Prepare context
            context = {"function": function_name, "async": True}

            if include_args:
                try:
                    sig = inspect.signature(func)
                    bound_args = sig.bind(*args, **kwargs)
                    bound_args.apply_defaults()

                    sanitized_args = {}
                    for name, value in bound_args.arguments.items():
                        if isinstance(value, (str, int, float, bool, list, dict)):
                            if name.lower() in ['password', 'token', 'secret', 'key']:
                                sanitized_args[name] = "[REDACTED]"
                            else:
                                sanitized_args[name] = str(value)[:100]
                        else:
                            sanitized_args[name] = f"<{type(value).__name__}>"

                    context["arguments"] = sanitized_args
                except Exception as e:
                    context["arguments_error"] = str(e)

            # Log function entry
            debug_manager.log_event()
                level,
                function_name,
                f"Async function called: {function_name}",
                context
            )

            start_time = time.time()

            try:
                # Execute async function with optional profiling
                if profile:
                    with debug_manager.profile_function(function_name):
                        result = await func(*args, **kwargs)
                else:
                    result = await func(*args, **kwargs)

                duration = time.time() - start_time

                # Log successful completion
                result_context = {
                    "function": function_name,
                    "duration": duration,
                    "success": True,
                    "async": True
                }

                if include_result and result is not None:
                    try:
                        if isinstance(result, (str, int, float, bool, list, dict)):
                            result_context["result"] = str(result)[:200]
                        else:
                            result_context["result_type"] = type(result).__name__
                    except Exception:
                        result_context["result_type"] = "unknown"

                debug_manager.log_event()
                    DebugLevel.DEBUG,
                    function_name,
                    f"Async function completed: {function_name} ({duration:.4f}s)",
                    result_context
                )

                return result

            except Exception as e:
                duration = time.time() - start_time

                error_context = {
                    "function": function_name,
                    "duration": duration,
                    "success": False,
                    "error_type": type(e).__name__,
                    "async": True
                }

                debug_manager.log_error(function_name, e, error_context)
                raise

        return wrapper
    return decorator


@contextmanager
def debug_context(name: str, metadata: Optional[Dict[str, Any]] = None):
    """Context manager for creating debug sessions."""
    debug_manager = get_debug_manager()
    session_id = debug_manager.create_debug_session(name, metadata)

    try:
        debug_manager.log_event()
            DebugLevel.INFO,
            "debug_context",
            f"Debug context started: {name}",
            {"session_id": session_id},
            session_id
        )

        yield session_id

    except Exception as e:
        debug_manager.log_error("debug_context", e, {"session_id": session_id}, session_id)
        raise

    finally:
        debug_manager.log_event()
            DebugLevel.INFO,
            "debug_context",
            f"Debug context ended: {name}",
            {"session_id": session_id},
            session_id
        )

        if session_id in debug_manager.debug_sessions:
            debug_manager.debug_sessions[session_id].end_session()


def log_debug(message: str, context: Optional[Dict[str, Any]] = None,
              level: DebugLevel = DebugLevel.DEBUG):
    """Quick debug logging function."""
    debug_manager = get_debug_manager()

    # Get caller information
    frame = inspect.currentframe().f_back
    source = f"{frame.f_globals.get('__name__', 'unknown')}.{frame.f_code.co_name}"

    debug_manager.log_event(level, source, message, context)


def log_error(error: Exception, context: Optional[Dict[str, Any]] = None):
    """Quick error logging function."""
    debug_manager = get_debug_manager()

    # Get caller information
    frame = inspect.currentframe().f_back
    source = f"{frame.f_globals.get('__name__', 'unknown')}.{frame.f_code.co_name}"

    debug_manager.log_error(source, error, context)


def memory_snapshot(label: str = ""):
    """Take a memory snapshot."""
    debug_manager = get_debug_manager()

    # Get caller information
    frame = inspect.currentframe().f_back
    caller_info = f"{frame.f_globals.get('__name__', 'unknown')}.{frame.f_code.co_name}"

    full_label = f"{caller_info}: {label}" if label else caller_info
    debug_manager.take_memory_snapshot(full_label)


def profile_function(profiler_type: ProfilerType = ProfilerType.CPU):
    """Decorator for profiling functions."""
    debug_manager = get_debug_manager()
    return debug_manager.profile_decorator(profiler_type)


def async_profile_function(profiler_type: ProfilerType = ProfilerType.CPU):
    """Decorator for profiling async functions."""
    debug_manager = get_debug_manager()
    return debug_manager.async_profile_decorator(profiler_type)


class DebugTimer:
    """Context manager for timing operations."""

    def __init__(self, name: str, log_result: bool = True):
        self.name = name
        self.log_result = log_result
        self.start_time = None
        self.end_time = None
        self.duration = None

    def __enter__(self):
        self.start_time = time.time()
        log_debug(f"Timer started: {self.name}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time

        if self.log_result:
            if exc_type is None:
                log_debug(f"Timer completed: {self.name} ({self.duration:.4f}s)")
            else:
                log_debug(f"Timer failed: {self.name} ({self.duration:.4f}s) - {exc_type.__name__}")


def debug_api_call(endpoint: str, method: str = "GET"):
    """Decorator for debugging API calls."""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            debug_manager = get_debug_manager()

            context = {
                "endpoint": endpoint,
                "method": method,
                "function": func.__name__
            }

            debug_manager.log_event()
                DebugLevel.DEBUG,
                "api_call",
                f"API call started: {method} {endpoint}",
                context
            )

            start_time = time.time()

            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time

                result_context = context.copy()
                result_context.update({)
                    "duration": duration,
                    "success": True
                })

                if hasattr(result, 'status_code'):
                    result_context["status_code"] = result.status_code

                debug_manager.log_event()
                    DebugLevel.DEBUG,
                    "api_call",
                    f"API call completed: {method} {endpoint} ({duration:.4f}s)",
                    result_context
                )

                return result

            except Exception as e:
                duration = time.time() - start_time

                error_context = context.copy()
                error_context.update({)
                    "duration": duration,
                    "success": False
                })

                debug_manager.log_error("api_call", e, error_context)
                raise

        return wrapper
    return decorator


def debug_plugin_operation(plugin_name: str, operation: str):
    """Decorator for debugging plugin operations."""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            debug_manager = get_debug_manager()

            context = {
                "plugin_name": plugin_name,
                "operation": operation,
                "function": func.__name__
            }

            debug_manager.log_event()
                DebugLevel.DEBUG,
                f"plugin.{plugin_name}",
                f"Plugin operation started: {operation}",
                context
            )

            start_time = time.time()

            try:
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)

                duration = time.time() - start_time

                result_context = context.copy()
                result_context.update({
                    "duration": duration,
                    "success": True
                })

                debug_manager.log_event(
                    DebugLevel.DEBUG,
                    f"plugin.{plugin_name}",
                    f"Plugin operation completed: {operation} ({duration:.4f}s)",
                    result_context
                )

                return result

            except Exception as e:
                duration = time.time() - start_time

                error_context = context.copy()
                error_context.update({
                    "duration": duration,
                    "success": False
                })

                debug_manager.log_error(f"plugin.{plugin_name}", e, error_context)
                raise

        return wrapper
    return decorator


def create_debug_dump(filename: Optional[str] = None) -> str:
    """Create a comprehensive debug dump."""
    debug_manager = get_debug_manager()

    if filename is None:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"debug_dump_{timestamp}.json"

    try:
        debug_data = debug_manager.export_debug_data()

        dump_path = Path("logs/debug") / filename
        dump_path.parent.mkdir(parents=True, exist_ok=True)

        with open(dump_path, 'w') as f:
            json.dump(debug_data, f, indent=2, default=str)

        log_debug(f"Debug dump created: {dump_path}")
        return str(dump_path)

    except Exception as e:
        log_error(e, {"operation": "create_debug_dump", "filename": filename})
        return ""


def analyze_performance_bottlenecks() -> Dict[str, Any]:
    """Analyze performance bottlenecks from debug data."""
    debug_manager = get_debug_manager()

    try:
        performance_summary = debug_manager.get_performance_summary()

        # Find slowest functions
        slow_functions = []
        for func_name, stats in performance_summary.items():
            if stats["avg_duration"] > 1.0:  # Functions taking more than 1 second on average
                slow_functions.append({
                    "function": func_name,
                    "avg_duration": stats["avg_duration"],
                    "max_duration": stats["max_duration"],
                    "call_count": stats["count"],
                    "total_time": stats["total_duration"]
                })

        # Sort by total time impact
        slow_functions.sort(key=lambda x: x["total_time"], reverse=True)

        # Find frequently called functions
        frequent_functions = []
        for func_name, stats in performance_summary.items():
            if stats["count"] > 100:  # Functions called more than 100 times
                frequent_functions.append({
                    "function": func_name,
                    "call_count": stats["count"],
                    "avg_duration": stats["avg_duration"],
                    "total_time": stats["total_duration"]
                })

        frequent_functions.sort(key=lambda x: x["call_count"], reverse=True)

        return {
            "slow_functions": slow_functions[:10],  # Top 10 slowest
            "frequent_functions": frequent_functions[:10],  # Top 10 most frequent
            "total_functions_analyzed": len(performance_summary),
            "analysis_timestamp": time.time()
        }

    except Exception as e:
        log_error(e, {"operation": "analyze_performance_bottlenecks"})
        return {}
