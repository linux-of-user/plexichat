# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
Debug Manager

Comprehensive debugging system for PlexiChat with advanced logging, profiling,
error tracking, and debugging tools.


import asyncio
import functools
import inspect
import json
import logging
import sys
import time
import traceback
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
import cProfile
import pstats
import io
import psutil
import gc

logger = logging.getLogger(__name__)


class DebugLevel(Enum):
    """Debug levels for different types of debugging."""
        TRACE = "trace"
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ProfilerType(Enum):
    """Types of profiling available."""
    CPU = "cpu"
    MEMORY = "memory"
    IO = "io"
    NETWORK = "network"


@dataclass
class DebugEvent:
    """Debug event data structure.
        timestamp: str
    level: DebugLevel
    source: str
    message: str
    context: Dict[str, Any] = field(default_factory=dict)
    stack_trace: Optional[str] = None
    performance_data: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class ProfileData:
    """Profiling data structure."""
        profiler_type: ProfilerType
    start_time: float
    end_time: float
    duration: float
    data: Dict[str, Any]
    function_name: str
    module_name: str


class DebugSession:
    Debug session for tracking debugging activities."""
        def __init__(self, session_id: str, name: str):
        self.session_id = session_id
        self.name = name
        self.start_time = time.time()
        self.events: List[DebugEvent] = []
        self.profiling_data: List[ProfileData] = []
        self.active = True
        self.metadata: Dict[str, Any] = {}

    def add_event(self, event: DebugEvent):
        """Add a debug event to the session.
        if self.active:
            self.events.append(event)

    def add_profile_data(self, profile_data: ProfileData):
        """Add profiling data to the session."""
        if self.active:
            self.profiling_data.append(profile_data)

    def end_session(self):
        End the debug session."""
        self.active = False
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time


class DebugManager:
    """Comprehensive debugging manager."""
        def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.debug_enabled = self.config.get("debug_enabled", True)
        self.log_level = DebugLevel(self.config.get("log_level", "debug"))
        self.max_events = self.config.get("max_events", 10000)
        self.max_sessions = self.config.get("max_sessions", 100)

        # Storage
        self.debug_events: List[DebugEvent] = []
        self.debug_sessions: Dict[str, DebugSession] = {}
        self.error_counts: Dict[str, int] = {}
        self.performance_metrics: Dict[str, List[float]] = {}

        # Profiling
        self.active_profilers: Dict[str, cProfile.Profile] = {}
        self.profiling_enabled = self.config.get("profiling_enabled", True)

        # File logging
        self.log_directory = Path(self.config.get("log_directory", "logs/debug"))
        self.log_directory.mkdir(parents=True, exist_ok=True)

        # Setup file handler
        self._setup_file_logging()

        # Thread safety
        self._lock = threading.RLock()

        # Memory tracking
        self.memory_snapshots: List[Dict[str, Any]] = []
        self.memory_tracking_enabled = self.config.get("memory_tracking", True)

        logger.info("Debug Manager initialized")

    def _setup_file_logging(self):
        """Setup file logging for debug events."""
        try:
            log_file = self.log_directory / f"debug_{datetime.now().strftime('%Y%m%d')}.log"

            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)

            formatter = logging.Formatter()
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)

            # Add to root logger
            root_logger = logging.getLogger()
            root_logger.addHandler(file_handler)

        except Exception as e:
            logger.error(f"Failed to setup file logging: {e}")

    def create_debug_session(self, name: str, metadata: Optional[Dict[str, Any]] = None) -> str:
        """Create a new debug session."""
        try:
            session_id = f"debug_session_{int(time.time())}_{len(self.debug_sessions)}"

            session = DebugSession(session_id, name)
            if metadata:
                session.metadata = metadata

            with self._lock:
                self.debug_sessions[session_id] = session

                # Limit number of sessions
                if len(self.debug_sessions) > self.max_sessions:
                    oldest_session = min()
                        self.debug_sessions.keys(),
                        key=lambda k: self.debug_sessions[k].start_time
                    )
                    del self.debug_sessions[oldest_session]

            logger.info(f"Created debug session: {session_id} - {name}")
            return session_id

        except Exception as e:
            logger.error(f"Error creating debug session: {e}")
            return ""

    def log_event(self, level: DebugLevel, source: str, message: str, ):
                context: Optional[Dict[str, Any]] = None,
                session_id: Optional[str] = None,
                include_stack: bool = False):
        """Log a debug event."""
        try:
            if not self.debug_enabled:
                return

            # Create debug event
            event = DebugEvent()
                timestamp=datetime.now().isoformat(),
                level=level,
                source=source,
                message=message,
                context=context or {}
            )

            # Add stack trace if requested
            if include_stack:
                event.stack_trace = traceback.format_stack()

            # Add performance data if available
            if self.memory_tracking_enabled:
                event.performance_data = self._get_current_performance_data()

            with self._lock:
                # Add to global events
                self.debug_events.append(event)

                # Limit events
                if len(self.debug_events) > self.max_events:
                    self.debug_events = self.debug_events[-self.max_events:]

                # Add to session if specified
                if session_id and session_id in self.debug_sessions:
                    self.debug_sessions[session_id].add_event(event)

            # Log to standard logger
            log_level = getattr(logging, level.value.upper())
            logger.log(log_level, f"[{source}] {message}")

        except Exception as e:
            logger.error(f"Error logging debug event: {e}")

    def log_error(self, source: str, error: Exception, ):
                context: Optional[Dict[str, Any]] = None,
                session_id: Optional[str] = None):
        """Log an error with full traceback."""
        try:
            error_message = f"{type(error).__name__}: {str(error)}"

            # Track error counts
            error_key = f"{source}:{type(error).__name__}"
            with self._lock:
                self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1

            # Create enhanced context
            enhanced_context = context or {}
            enhanced_context.update({)
                "error_type": type(error).__name__,
                "error_count": self.error_counts[error_key],
                "traceback": traceback.format_exc()
            })

            self.log_event()
                DebugLevel.ERROR,
                source,
                error_message,
                enhanced_context,
                session_id,
                include_stack=True
            )

        except Exception as e:
            logger.error(f"Error logging error: {e}")

    @contextmanager
    def profile_function(self, function_name: str, profiler_type: ProfilerType = ProfilerType.CPU):
        """Context manager for profiling function execution."""
        if not self.profiling_enabled:
            yield
            return

        profiler_id = f"{function_name}_{int(time.time())}"
        start_time = time.time()

        try:
            if profiler_type == ProfilerType.CPU:
                profiler = cProfile.Profile()
                profiler.enable()

                with self._lock:
                    self.active_profilers[profiler_id] = profiler

            # Memory snapshot before
            memory_before = self._get_memory_usage() if profiler_type == ProfilerType.MEMORY else None

            yield

        finally:
            end_time = time.time()
            duration = end_time - start_time

            try:
                profile_data = {}

                if profiler_type == ProfilerType.CPU and profiler_id in self.active_profilers:
                    profiler = self.active_profilers[profiler_id]
                    profiler.disable()

                    # Get profiling stats
                    stats_stream = io.StringIO()
                    stats = pstats.Stats(profiler, stream=stats_stream)
                    stats.sort_stats('cumulative')
                    stats.print_stats(20)  # Top 20 functions

                    profile_data = {
                        "stats": stats_stream.getvalue(),
                        "total_calls": stats.total_calls,
                        "total_time": stats.total_tt
                    }

                    del self.active_profilers[profiler_id]

                elif profiler_type == ProfilerType.MEMORY:
                    memory_after = self._get_memory_usage()
                    profile_data = {
                        "memory_before": memory_before,
                        "memory_after": memory_after,
                        "memory_delta": memory_after - memory_before if memory_before else 0
                    }

                # Create profile data object
                profile_obj = ProfileData()
                    profiler_type=profiler_type,
                    start_time=start_time,
                    end_time=end_time,
                    duration=duration,
                    data=profile_data,
                    function_name=function_name,
                    module_name=inspect.getmodule(inspect.currentframe().f_back).__name__
                )

                # Store performance metrics
                with self._lock:
                    if function_name not in self.performance_metrics:
                        self.performance_metrics[function_name] = []
                    self.performance_metrics[function_name].append(duration)

                    # Limit metrics
                    if len(self.performance_metrics[function_name]) > 1000:
                        self.performance_metrics[function_name] = self.performance_metrics[function_name][-1000:]

                logger.debug(f"Profiled {function_name}: {duration:.4f}s")

            except Exception as e:
                logger.error(f"Error processing profile data: {e}")

    def profile_decorator(self, profiler_type: ProfilerType = ProfilerType.CPU):
        """Decorator for profiling functions.
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                with self.profile_function(func.__name__, profiler_type):
                    return func(*args, **kwargs)
            return wrapper
        return decorator

    def async_profile_decorator(self, profiler_type: ProfilerType = ProfilerType.CPU):
        """Decorator for profiling async functions."""
        def decorator(func):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                with self.profile_function(func.__name__, profiler_type):
                    return await func(*args, **kwargs)
            return wrapper
        return decorator

    def _get_current_performance_data(self) -> Dict[str, Any]:
        Get current performance data."""
        try:
            process = psutil.Process()

            return {
                "cpu_percent": process.cpu_percent(),
                "memory_mb": process.memory_info().rss / 1024 / 1024,
                "memory_percent": process.memory_percent(),
                "num_threads": process.num_threads(),
                "num_fds": process.num_fds() if hasattr(process, 'num_fds') else 0,
                "timestamp": time.time()
            }}

        except Exception as e:
            logger.error(f"Error getting performance data: {e}")
            return {}}

    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024
        except Exception:
            return 0.0

    def take_memory_snapshot(self, label: str = ""):
        """Take a memory snapshot for analysis."""
        try:
            if not self.memory_tracking_enabled:
                return

            snapshot = {
                "timestamp": datetime.now().isoformat(),
                "label": label,
                "memory_usage": self._get_memory_usage(),
                "gc_stats": {
                    "collected": gc.get_stats(),
                    "count": gc.get_count()
                },
                "process_info": self._get_current_performance_data()
            }

            with self._lock:
                self.memory_snapshots.append(snapshot)

                # Limit snapshots
                if len(self.memory_snapshots) > 1000:
                    self.memory_snapshots = self.memory_snapshots[-1000:]

            logger.debug(f"Memory snapshot taken: {label}")

        except Exception as e:
            logger.error(f"Error taking memory snapshot: {e}")

    def get_debug_events(self, level: Optional[DebugLevel] = None,):
                        source: Optional[str] = None,
                        limit: int = 100) -> List[DebugEvent]:
        """Get debug events with optional filtering."""
        try:
            with self._lock:
                events = self.debug_events.copy()

            # Filter by level
            if level:
                events = [e for e in events if e.level == level]

            # Filter by source
            if source:
                events = [e for e in events if source.lower() in e.source.lower()]

            # Return most recent events
            return events[-limit:]

        except Exception as e:
            logger.error(f"Error getting debug events: {e}")
            return []

    def get_error_summary(self) -> Dict[str, Any]:
        """Get error summary statistics."""
        try:
            with self._lock:
                error_counts = self.error_counts.copy()

            total_errors = sum(error_counts.values())

            # Get top errors
            top_errors = sorted()
                error_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]

            return {
                "total_errors": total_errors,
                "unique_errors": len(error_counts),
                "top_errors": top_errors,
                "error_rate": total_errors / len(self.debug_events) if self.debug_events else 0
            }}

        except Exception as e:
            logger.error(f"Error getting error summary: {e}")
            return {}}

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary statistics."""
        try:
            with self._lock:
                metrics = self.performance_metrics.copy()

            summary = {}

            for function_name, durations in metrics.items():
                if durations:
                    summary[function_name] = {
                        "count": len(durations),
                        "avg_duration": sum(durations) / len(durations),
                        "min_duration": min(durations),
                        "max_duration": max(durations),
                        "total_duration": sum(durations)
                    }

            return summary

        except Exception as e:
            logger.error(f"Error getting performance summary: {e}")
            return {}}

    def export_debug_data(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Export debug data for analysis."""
        try:
            with self._lock:
                if session_id and session_id in self.debug_sessions:
                    session = self.debug_sessions[session_id]
                    return {
                        "session_id": session_id,
                        "session_name": session.name,
                        "start_time": session.start_time,
                        "duration": getattr(session, 'duration', time.time() - session.start_time),
                        "events": [
                            {
                                "timestamp": event.timestamp,
                                "level": event.level.value,
                                "source": event.source,
                                "message": event.message,
                                "context": event.context
                            }}
                            for event in session.events
                        ],
                        "profiling_data": [
                            {
                                "function_name": profile.function_name,
                                "duration": profile.duration,
                                "profiler_type": profile.profiler_type.value,
                                "data": profile.data
                            }
                            for profile in session.profiling_data
                        ]
                    }
                else:
                    return {
                        "all_events": [
                            {
                                "timestamp": event.timestamp,
                                "level": event.level.value,
                                "source": event.source,
                                "message": event.message,
                                "context": event.context
                            }}
                            for event in self.debug_events
                        ],
                        "error_summary": self.get_error_summary(),
                        "performance_summary": self.get_performance_summary(),
                        "memory_snapshots": self.memory_snapshots
                    }

        except Exception as e:
            logger.error(f"Error exporting debug data: {e}")
            return {}}

    def clear_debug_data(self, session_id: Optional[str] = None):
        """Clear debug data."""
        try:
            with self._lock:
                if session_id and session_id in self.debug_sessions:
                    del self.debug_sessions[session_id]
                else:
                    self.debug_events.clear()
                    self.error_counts.clear()
                    self.performance_metrics.clear()
                    self.memory_snapshots.clear()

            logger.info("Debug data cleared")

        except Exception as e:
            logger.error(f"Error clearing debug data: {e}")


# Global debug manager instance
_debug_manager = None


def get_debug_manager(config: Optional[Dict[str, Any]] = None) -> DebugManager:
    """Get the global debug manager instance."""
    global _debug_manager
    if _debug_manager is None:
        _debug_manager = DebugManager(config)
    return _debug_manager
