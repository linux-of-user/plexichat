"""
Debug Manager

Comprehensive debugging system for PlexiChat with advanced logging, profiling,
error tracking, and debugging tools.
"""

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

try:
    import cProfile
    import pstats
    import io
    import psutil
    import gc
except ImportError:
    cProfile = None
    pstats = None
    io = None
    psutil = None
    gc = None

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
    TIME = "time"
    NETWORK = "network"


@dataclass
class DebugSession:
    """Debug session information."""
    id: str
    name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    level: DebugLevel = DebugLevel.DEBUG
    profiler_type: Optional[ProfilerType] = None
    data: Dict[str, Any] = field(default_factory=dict)
    logs: List[str] = field(default_factory=list)


@dataclass
class PerformanceMetric:
    """Performance metric data."""
    name: str
    value: float
    unit: str
    timestamp: datetime
    context: Dict[str, Any] = field(default_factory=dict)


class DebugManager:
    """Comprehensive debug manager for PlexiChat."""
    
    def __init__(self):
        self.sessions: Dict[str, DebugSession] = {}
        self.active_profilers: Dict[str, Any] = {}
        self.performance_metrics: List[PerformanceMetric] = []
        self.error_history: List[Dict[str, Any]] = []
        self.debug_enabled = True
        self.max_history_size = 1000
        self._lock = threading.RLock()
        
        # Setup debug logging
        self._setup_debug_logging()
    
    def _setup_debug_logging(self):
        """Setup debug logging configuration."""
        debug_logger = logging.getLogger('plexichat.debug')
        debug_logger.setLevel(logging.DEBUG)
        
        # Create debug handler if it doesn't exist
        if not debug_logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            debug_logger.addHandler(handler)
    
    def start_debug_session(self, name: str, level: DebugLevel = DebugLevel.DEBUG,
                          profiler_type: Optional[ProfilerType] = None) -> str:
        """Start a new debug session."""
        session_id = f"debug_{int(time.time())}_{len(self.sessions)}"
        
        session = DebugSession(
            id=session_id,
            name=name,
            start_time=datetime.now(),
            level=level,
            profiler_type=profiler_type
        )
        
        with self._lock:
            self.sessions[session_id] = session
            
            # Start profiler if requested
            if profiler_type and cProfile:
                if profiler_type == ProfilerType.CPU:
                    profiler = cProfile.Profile()
                    profiler.enable()
                    self.active_profilers[session_id] = profiler
        
        logger.info(f"Started debug session: {name} ({session_id})")
        return session_id
    
    def end_debug_session(self, session_id: str) -> Optional[DebugSession]:
        """End a debug session."""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                return None
            
            session.end_time = datetime.now()
            
            # Stop profiler if active
            if session_id in self.active_profilers:
                profiler = self.active_profilers.pop(session_id)
                if hasattr(profiler, 'disable'):
                    profiler.disable()
                    
                    # Generate profiler stats
                    if pstats and io:
                        stats_stream = io.StringIO()
                        stats = pstats.Stats(profiler, stream=stats_stream)
                        stats.sort_stats('cumulative')
                        stats.print_stats(20)  # Top 20 functions
                        session.data['profiler_stats'] = stats_stream.getvalue()
        
        logger.info(f"Ended debug session: {session.name} ({session_id})")
        return session
    
    def log_debug(self, session_id: str, message: str, level: DebugLevel = DebugLevel.DEBUG,
                 context: Optional[Dict[str, Any]] = None):
        """Log a debug message to a session."""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                return
            
            timestamp = datetime.now().isoformat()
            log_entry = f"[{timestamp}] [{level.value.upper()}] {message}"
            
            if context:
                log_entry += f" | Context: {json.dumps(context, default=str)}"
            
            session.logs.append(log_entry)
            
            # Also log to standard logger
            log_level = getattr(logging, level.value.upper(), logging.DEBUG)
            logger.log(log_level, f"[{session.name}] {message}")
    
    def record_performance_metric(self, name: str, value: float, unit: str,
                                context: Optional[Dict[str, Any]] = None):
        """Record a performance metric."""
        metric = PerformanceMetric(
            name=name,
            value=value,
            unit=unit,
            timestamp=datetime.now(),
            context=context or {}
        )
        
        with self._lock:
            self.performance_metrics.append(metric)
            
            # Limit history size
            if len(self.performance_metrics) > self.max_history_size:
                self.performance_metrics = self.performance_metrics[-self.max_history_size:]
        
        logger.debug(f"Performance metric: {name} = {value} {unit}")
    
    def record_error(self, error: Exception, context: Optional[Dict[str, Any]] = None):
        """Record an error with full traceback."""
        error_data = {
            'timestamp': datetime.now().isoformat(),
            'type': type(error).__name__,
            'message': str(error),
            'traceback': traceback.format_exc(),
            'context': context or {}
        }
        
        with self._lock:
            self.error_history.append(error_data)
            
            # Limit history size
            if len(self.error_history) > self.max_history_size:
                self.error_history = self.error_history[-self.max_history_size:]
        
        logger.error(f"Error recorded: {type(error).__name__}: {error}")
    
    @contextmanager
    def debug_context(self, name: str, level: DebugLevel = DebugLevel.DEBUG):
        """Context manager for debug sessions."""
        session_id = self.start_debug_session(name, level)
        try:
            yield session_id
        except Exception as e:
            self.record_error(e, {'session': name})
            raise
        finally:
            self.end_debug_session(session_id)
    
    def debug_decorator(self, name: Optional[str] = None, level: DebugLevel = DebugLevel.DEBUG):
        """Decorator for debugging functions."""
        def decorator(func: Callable) -> Callable:
            debug_name = name or f"{func.__module__}.{func.__name__}"
            
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                with self.debug_context(debug_name, level) as session_id:
                    self.log_debug(session_id, f"Calling {debug_name}")
                    start_time = time.time()
                    
                    try:
                        result = func(*args, **kwargs)
                        execution_time = time.time() - start_time
                        self.record_performance_metric(
                            f"{debug_name}_execution_time",
                            execution_time,
                            "seconds"
                        )
                        self.log_debug(session_id, f"Completed {debug_name} in {execution_time:.4f}s")
                        return result
                    except Exception as e:
                        execution_time = time.time() - start_time
                        self.log_debug(session_id, f"Error in {debug_name} after {execution_time:.4f}s: {e}")
                        raise
            
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                with self.debug_context(debug_name, level) as session_id:
                    self.log_debug(session_id, f"Calling async {debug_name}")
                    start_time = time.time()
                    
                    try:
                        result = await func(*args, **kwargs)
                        execution_time = time.time() - start_time
                        self.record_performance_metric(
                            f"{debug_name}_execution_time",
                            execution_time,
                            "seconds"
                        )
                        self.log_debug(session_id, f"Completed async {debug_name} in {execution_time:.4f}s")
                        return result
                    except Exception as e:
                        execution_time = time.time() - start_time
                        self.log_debug(session_id, f"Error in async {debug_name} after {execution_time:.4f}s: {e}")
                        raise
            
            return async_wrapper if asyncio.iscoroutinefunction(func) else wrapper
        return decorator
    
    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a debug session."""
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        return {
            'id': session.id,
            'name': session.name,
            'start_time': session.start_time.isoformat(),
            'end_time': session.end_time.isoformat() if session.end_time else None,
            'level': session.level.value,
            'profiler_type': session.profiler_type.value if session.profiler_type else None,
            'log_count': len(session.logs),
            'data': session.data
        }
    
    def get_performance_summary(self, metric_name: Optional[str] = None,
                              time_range: Optional[timedelta] = None) -> Dict[str, Any]:
        """Get performance metrics summary."""
        cutoff_time = datetime.now() - (time_range or timedelta(hours=1))
        
        filtered_metrics = [
            m for m in self.performance_metrics
            if m.timestamp >= cutoff_time and (not metric_name or m.name == metric_name)
        ]
        
        if not filtered_metrics:
            return {}
        
        values = [m.value for m in filtered_metrics]
        return {
            'count': len(values),
            'min': min(values),
            'max': max(values),
            'avg': sum(values) / len(values),
            'latest': values[-1] if values else 0,
            'unit': filtered_metrics[0].unit if filtered_metrics else ''
        }
    
    def get_error_summary(self, time_range: Optional[timedelta] = None) -> Dict[str, Any]:
        """Get error summary."""
        cutoff_time = datetime.now() - (time_range or timedelta(hours=1))
        
        recent_errors = [
            e for e in self.error_history
            if datetime.fromisoformat(e['timestamp']) >= cutoff_time
        ]
        
        error_types = {}
        for error in recent_errors:
            error_type = error['type']
            error_types[error_type] = error_types.get(error_type, 0) + 1
        
        return {
            'total_errors': len(recent_errors),
            'error_types': error_types,
            'latest_error': recent_errors[-1] if recent_errors else None
        }
    
    def export_debug_data(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Export debug data for analysis."""
        if session_id:
            session = self.sessions.get(session_id)
            if not session:
                return {}
            
            return {
                'session': self.get_session_info(session_id),
                'logs': session.logs,
                'data': session.data
            }
        else:
            return {
                'sessions': [self.get_session_info(sid) for sid in self.sessions.keys()],
                'performance_metrics': [
                    {
                        'name': m.name,
                        'value': m.value,
                        'unit': m.unit,
                        'timestamp': m.timestamp.isoformat(),
                        'context': m.context
                    }
                    for m in self.performance_metrics
                ],
                'error_history': self.error_history
            }
    
    def clear_history(self):
        """Clear debug history."""
        with self._lock:
            self.sessions.clear()
            self.performance_metrics.clear()
            self.error_history.clear()
            self.active_profilers.clear()
        
        logger.info("Debug history cleared")


# Global debug manager instance
debug_manager = DebugManager()


# Convenience functions
def start_debug(name: str, level: DebugLevel = DebugLevel.DEBUG) -> str:
    """Start a debug session."""
    return debug_manager.start_debug_session(name, level)


def end_debug(session_id: str) -> Optional[DebugSession]:
    """End a debug session."""
    return debug_manager.end_debug_session(session_id)


def debug_log(session_id: str, message: str, level: DebugLevel = DebugLevel.DEBUG):
    """Log a debug message."""
    debug_manager.log_debug(session_id, message, level)


def record_metric(name: str, value: float, unit: str):
    """Record a performance metric."""
    debug_manager.record_performance_metric(name, value, unit)


def record_error(error: Exception, context: Optional[Dict[str, Any]] = None):
    """Record an error."""
    debug_manager.record_error(error, context)


def debug_function(name: Optional[str] = None, level: DebugLevel = DebugLevel.DEBUG):
    """Decorator for debugging functions."""
    return debug_manager.debug_decorator(name, level)
