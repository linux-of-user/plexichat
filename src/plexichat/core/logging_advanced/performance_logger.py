"""
Performance Logger

Specialized logging for performance metrics and timing.
"""

import logging
import time
import asyncio
from typing import Any, Dict, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from contextlib import contextmanager
from functools import wraps

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetric:
    """Performance metric data."""
    operation: str
    duration: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    success: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


class PerformanceLogger:
    """Specialized performance logger."""
    
    def __init__(self, name: str = "performance_logger"):
        self.name = name
        self.logger = logging.getLogger(name)
        self.metrics: List[PerformanceMetric] = []
        self.operation_stats: Dict[str, List[float]] = {}
    
    def log_timing(
        self,
        operation: str,
        duration: float,
        success: bool = True,
        **metadata
    ):
        """Log a timing measurement."""
        metric = PerformanceMetric(
            operation=operation,
            duration=duration,
            success=success,
            metadata=metadata
        )
        
        self.metrics.append(metric)
        
        # Update operation stats
        if operation not in self.operation_stats:
            self.operation_stats[operation] = []
        self.operation_stats[operation].append(duration)
        
        # Log the metric
        self.logger.info(
            f"PERF: {operation} completed in {duration*1000:.2f}ms",
            extra={
                'operation': operation,
                'duration_ms': duration * 1000,
                'success': success,
                **metadata
            }
        )
    
    @contextmanager
    def track_performance(self, operation: str, **metadata):
        """Context manager for tracking performance."""
        start_time = time.perf_counter()
        success = True
        try:
            yield
        except Exception as e:
            success = False
            metadata['error'] = str(e)
            raise
        finally:
            duration = time.perf_counter() - start_time
            self.log_timing(operation, duration, success, **metadata)
    
    def track_async_performance(self, operation: str, **metadata):
        """Decorator for tracking async function performance."""
        def decorator(func: Callable):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                start_time = time.perf_counter()
                success = True
                try:
                    result = await func(*args, **kwargs)
                    return result
                except Exception as e:
                    success = False
                    metadata['error'] = str(e)
                    raise
                finally:
                    duration = time.perf_counter() - start_time
                    self.log_timing(operation, duration, success, **metadata)
            return wrapper
        return decorator
    
    def track_sync_performance(self, operation: str, **metadata):
        """Decorator for tracking sync function performance."""
        def decorator(func: Callable):
            @wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.perf_counter()
                success = True
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as e:
                    success = False
                    metadata['error'] = str(e)
                    raise
                finally:
                    duration = time.perf_counter() - start_time
                    self.log_timing(operation, duration, success, **metadata)
            return wrapper
        return decorator
    
    def get_operation_stats(self, operation: str) -> Dict[str, float]:
        """Get statistics for a specific operation."""
        if operation not in self.operation_stats:
            return {}
        
        durations = self.operation_stats[operation]
        return {
            'count': len(durations),
            'avg_ms': (sum(durations) / len(durations)) * 1000,
            'min_ms': min(durations) * 1000,
            'max_ms': max(durations) * 1000,
            'total_ms': sum(durations) * 1000,
            'p50_ms': self._percentile(durations, 50) * 1000,
            'p95_ms': self._percentile(durations, 95) * 1000,
            'p99_ms': self._percentile(durations, 99) * 1000,
        }
    
    def get_all_stats(self) -> Dict[str, Dict[str, float]]:
        """Get statistics for all operations."""
        return {
            operation: self.get_operation_stats(operation)
            for operation in self.operation_stats.keys()
        }
    
    def get_recent_metrics(self, limit: int = 100) -> List[PerformanceMetric]:
        """Get recent performance metrics."""
        return self.metrics[-limit:]
    
    def get_slow_operations(self, threshold_ms: float = 1000) -> List[PerformanceMetric]:
        """Get operations that exceeded the threshold."""
        threshold_s = threshold_ms / 1000
        return [
            metric for metric in self.metrics
            if metric.duration > threshold_s
        ]
    
    def clear_metrics(self):
        """Clear stored metrics."""
        self.metrics.clear()
        self.operation_stats.clear()
    
    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile of data."""
        if not data:
            return 0.0
        
        sorted_data = sorted(data)
        index = (percentile / 100) * (len(sorted_data) - 1)
        
        if index.is_integer():
            return sorted_data[int(index)]
        else:
            lower = sorted_data[int(index)]
            upper = sorted_data[int(index) + 1]
            return lower + (upper - lower) * (index - int(index))


# Global performance logger instance
performance_logger = PerformanceLogger("plexichat_performance")


# Convenience functions
def track_performance(operation: str, **metadata):
    """Track performance context manager."""
    return performance_logger.track_performance(operation, **metadata)


def log_timing(operation: str, duration: float, **metadata):
    """Log a timing measurement."""
    performance_logger.log_timing(operation, duration, **metadata)


# Decorators
def track_async(operation: str, **metadata):
    """Decorator for tracking async function performance."""
    return performance_logger.track_async_performance(operation, **metadata)


def track_sync(operation: str, **metadata):
    """Decorator for tracking sync function performance."""
    return performance_logger.track_sync_performance(operation, **metadata)


# Export all components
__all__ = [
    "PerformanceMetric",
    "PerformanceLogger",
    "performance_logger",
    "track_performance",
    "log_timing",
    "track_async",
    "track_sync",
]
