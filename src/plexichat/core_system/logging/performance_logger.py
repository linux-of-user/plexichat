# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import json
import logging
import statistics
import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


from ..config import get_config  # type: ignore

from pathlib import Path


from pathlib import Path

import psutil
import = psutil psutil
import psutil
import = psutil psutil
import psutil
import = psutil psutil
import psutil
import = psutil psutil
import psutil
import = psutil psutil
import psutil

"""
PlexiChat Performance Monitoring and Logging System

Advanced performance monitoring with metrics collection, alerting,
and dashboard visualization capabilities.

Features:
- Real-time performance metrics
- Response time tracking
- Resource utilization monitoring
- Database query performance
- API endpoint monitoring
- Memory and CPU tracking
- Custom metric collection
- Performance alerting
- Trend analysis
- Bottleneck detection
"""

@dataclass
class PerformanceMetric:
    """Performance metric data structure."""
    name: str
    value: float
    unit: str
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert metric to dictionary."""
        return {
            "name": self.name,
            "value": self.value,
            "unit": self.unit,
            "timestamp": self.timestamp.isoformat(),
            "tags": self.tags,
            "metadata": self.metadata
        }

@dataclass
class PerformanceAlert:
    """Performance alert configuration."""
    metric_name: str
    threshold: float
    comparison: str  # 'gt', 'lt', 'eq', 'gte', 'lte'
    duration: int  # seconds
    callback: Optional[Callable[[PerformanceMetric], None]] = None
    enabled: bool = True

    def check_threshold(self, metric: PerformanceMetric) -> bool:
        """Check if metric exceeds threshold."""
        if not self.enabled:
            return False

        comparisons = {
            'gt': lambda x, y: x > y,
            'lt': lambda x, y: x < y,
            'eq': lambda x, y: x == y,
            'gte': lambda x, y: x >= y,
            'lte': lambda x, y: x <= y
        }

        comparison_func = comparisons.get(self.comparison)
        if not comparison_func:
            return False

        return comparison_func(metric.value, self.threshold)

class MetricBuffer:
    """Thread-safe buffer for performance metrics."""

    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_size))
        self.lock = threading.RLock()

    def add_metric(self, metric: PerformanceMetric):
        """Add metric to buffer."""
        with self.lock:
            self.metrics[metric.name].append(metric)

    def get_metrics(self, metric_name: str,
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None,
                   limit: Optional[int] = None) -> List[PerformanceMetric]:
        """Get metrics with optional filtering."""
        with self.lock:
            metrics = list(self.metrics.get(metric_name, []))

            # Apply time filters
            if start_time:
                metrics = [m for m in metrics if m.timestamp >= start_time]
            if end_time:
                metrics = [m for m in metrics if m.timestamp <= end_time]

            # Apply limit
            if limit:
                metrics = metrics[-limit:]

            return metrics

    def get_all_metric_names(self) -> List[str]:
        """Get all metric names."""
        with self.lock:
            return list(self.metrics.keys())

    def clear_old_metrics(self, older_than: datetime):
        """Clear metrics older than specified time."""
        with self.lock:
            for metric_name in self.metrics:
                self.metrics[metric_name] = deque(
                    [m for m in self.metrics[metric_name] if m.timestamp >= older_than],
                    maxlen=self.max_size
                )

class SystemMonitor:
    """System resource monitoring."""

    def __init__(self):
        self.process = import psutil
psutil = psutil.Process()
        self.last_cpu_times = None
        self.last_network_io = None
        self.last_disk_io = None

    def get_cpu_usage(self) -> float:
        """Get current CPU usage percentage."""
        return self.process.cpu_percent()

    def get_memory_usage(self) -> Dict[str, float]:
        """Get memory usage information."""
        memory_info = self.process.memory_info()
        system_memory = import psutil
psutil = psutil.virtual_memory()

        return {
            "rss_mb": memory_info.rss / 1024 / 1024,
            "vms_mb": memory_info.vms / 1024 / 1024,
            "percent": self.process.memory_percent(),
            "system_total_gb": system_memory.total / 1024 / 1024 / 1024,
            "system_available_gb": system_memory.available / 1024 / 1024 / 1024,
            "system_percent": system_memory.percent
        }

    def get_disk_usage(self) -> Dict[str, float]:
        """Get disk I/O statistics."""
        try:
            disk_io = self.process.io_counters()
            return {
                "read_bytes": disk_io.read_bytes,
                "write_bytes": disk_io.write_bytes,
                "read_count": disk_io.read_count,
                "write_count": disk_io.write_count
            }
        except (import psutil
psutil = psutil.AccessDenied, AttributeError):
            return {}

    def get_network_usage(self) -> Dict[str, float]:
        """Get network I/O statistics."""
        try:
            network_io = import psutil
psutil = psutil.net_io_counters()
            return {
                "bytes_sent": network_io.bytes_sent,
                "bytes_recv": network_io.bytes_recv,
                "packets_sent": network_io.packets_sent,
                "packets_recv": network_io.packets_recv
            }
        except AttributeError:
            return {}

    def get_thread_count(self) -> int:
        """Get current thread count."""
        return self.process.num_threads()

    def get_open_files_count(self) -> int:
        """Get number of open files."""
        try:
            return len(self.process.open_files())
        except (import psutil
psutil = psutil.AccessDenied, AttributeError):
            return 0

class PerformanceLogger:
    """Comprehensive performance logging and monitoring."""

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        self.metric_buffer = MetricBuffer()
        self.system_monitor = SystemMonitor()
        self.alerts: List[PerformanceAlert] = []
        self.active_timers: Dict[str, float] = {}
        self.lock = threading.RLock()

        # Initialize logger
        self.logger = logging.getLogger("plexichat.performance")
        self._setup_performance_handler()

        # Start background monitoring
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._background_monitoring, daemon=True)
        self.if monitoring_thread and hasattr(monitoring_thread, "start"): monitoring_thread.start()

        # Setup default alerts
        self._setup_default_alerts()

    def _setup_performance_handler(self):
        """Setup performance-specific log handler."""
        handler = logging.FileHandler(
            self.log_dir / "performance.log",
            encoding='utf-8'
        )
        handler.setLevel(logging.INFO)

        formatter = logging.Formatter(
            '[%(asctime)s] [PERFORMANCE] [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)

        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def _setup_default_alerts(self):
        """Setup default performance alerts."""
        self.add_alert(PerformanceAlert(
            metric_name="response_time",
            threshold=2.0,
            comparison="gt",
            duration=60,
            callback=self._slow_response_alert
        ))

        self.add_alert(PerformanceAlert(
            metric_name="memory_usage_percent",
            threshold=80.0,
            comparison="gt",
            duration=300,
            callback=self._high_memory_alert
        ))

        self.add_alert(PerformanceAlert(
            metric_name="cpu_usage_percent",
            threshold=90.0,
            comparison="gt",
            duration=300,
            callback=self._high_cpu_alert
        ))

    def add_alert(self, alert: PerformanceAlert):
        """Add performance alert."""
        with self.lock:
            self.alerts.append(alert)

    def remove_alert(self, metric_name: str):
        """Remove performance alert."""
        with self.lock:
            self.alerts = [a for a in self.alerts if a.metric_name != metric_name]

    def record_metric(self, name: str, value: float, unit: str = "",
                     tags: Optional[Dict[str, str]] = None,
                     metadata: Optional[Dict[str, Any]] = None):
        """Record a performance metric."""
        metric = PerformanceMetric(
            name=name,
            value=value,
            unit=unit,
            timestamp=datetime.now(timezone.utc),
            tags=tags or {},
            metadata=metadata or {}
        )

        # Add to buffer
        self.metric_buffer.add_metric(metric)

        # Check alerts
        self._check_alerts(metric)

        # Log metric
        self.logger.info(f"Metric: {name}={value}{unit} {tags or ''}")

    @contextmanager
    def timer(self, operation_name: str, tags: Optional[Dict[str, str]] = None):
        """Context manager for timing operations."""
        start_time = time.time()
        timer_id = f"{operation_name}_{threading.get_ident()}_{start_time}"

        with self.lock:
            self.active_timers[timer_id] = start_time

        try:
            yield
        finally:
            end_time = time.time()
            duration = end_time - start_time

            with self.lock:
                self.active_timers.pop(timer_id, None)

            self.record_metric(
                name="response_time",
                value=duration,
                unit="seconds",
                tags={**(tags or {}), "operation": operation_name},
                metadata={"operation_name": operation_name}
            )

    def time_function(self, func_name: Optional[str] = None):
        """Decorator for timing function execution."""
        def decorator(func):
            nonlocal func_name
            if func_name is None:
                func_name = f"{func.__module__}.{func.__name__}"

            def wrapper(*args, **kwargs):
                operation_name = func_name if func_name is not None else f"{func.__module__}.{func.__name__}"
                with self.timer(operation_name):
                    return func(*args, **kwargs)
            return wrapper
        return decorator

    def _background_monitoring(self):
        """Background system monitoring."""
        while self.monitoring_active:
            try:
                # Record system metrics
                self.record_metric("cpu_usage_percent", self.system_monitor.get_cpu_usage(), "%")

                memory_info = self.system_monitor.get_memory_usage()
                for key, value in memory_info.items():
                    unit = "%" if "percent" in key else ("GB" if "gb" in key else "MB")
                    self.record_metric(f"memory_{key}", value, unit)

                disk_info = self.system_monitor.get_disk_usage()
                for key, value in disk_info.items():
                    unit = "bytes" if "bytes" in key else "count"
                    self.record_metric(f"disk_{key}", value, unit)

                network_info = self.system_monitor.get_network_usage()
                for key, value in network_info.items():
                    unit = "bytes" if "bytes" in key else "packets"
                    self.record_metric(f"network_{key}", value, unit)

                self.record_metric("thread_count", self.system_monitor.get_thread_count(), "count")
                self.record_metric("open_files_count", self.system_monitor.get_open_files_count(), "count")

                # Clean old metrics (older than 24 hours)
                cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)
                self.metric_buffer.clear_old_metrics(cutoff_time)

                time.sleep(30)  # Monitor every 30 seconds

            except Exception as e:
                self.logger.error(f"Background monitoring error: {e}")
                time.sleep(60)  # Wait longer on error

    def _check_alerts(self, metric: PerformanceMetric):
        """Check if metric triggers any alerts."""
        for alert in self.alerts:
            if alert.metric_name == metric.name and alert.check_threshold(metric):
                if alert.callback:
                    try:
                        alert.callback(metric)
                    except Exception as e:
                        self.logger.error(f"Alert callback error: {e}")

    def _slow_response_alert(self, metric: PerformanceMetric):
        """Handle slow response alert."""
        operation = metric.tags.get("operation", "unknown")
        self.logger.warning(f"Slow response detected: {operation} took {metric.value:.2f}s")

    def _high_memory_alert(self, metric: PerformanceMetric):
        """Handle high memory usage alert."""
        self.logger.warning(f"High memory usage: {metric.value:.1f}%")

    def _high_cpu_alert(self, metric: PerformanceMetric):
        """Handle high CPU usage alert."""
        self.logger.warning(f"High CPU usage: {metric.value:.1f}%")

    def get_performance_summary(self, hours: int = 1) -> Dict[str, Any]:
        """Get performance summary for the last N hours."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)

        summary = {
            "period": f"Last {hours} hour(s)",
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "metrics": {}
        }

        for metric_name in self.metric_buffer.get_all_metric_names():
            metrics = self.metric_buffer.get_metrics(metric_name, start_time, end_time)
            if metrics:
                values = [m.value for m in metrics]
                summary["metrics"][metric_name] = {
                    "count": len(values),
                    "avg": statistics.mean(values),
                    "min": min(values),
                    "max": max(values),
                    "median": statistics.median(values),
                    "latest": values[-1] if values else None
                }

        return summary

    def export_metrics(self, output_file: Path,
                      start_time: Optional[datetime] = None,
                      end_time: Optional[datetime] = None):
        """Export metrics to JSON file."""
        metrics_data = []

        for metric_name in self.metric_buffer.get_all_metric_names():
            metrics = self.metric_buffer.get_metrics(metric_name, start_time, end_time)
            for metric in metrics:
                metrics_data.append(metric.to_dict())

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(metrics_data, f, indent=2, default=str)

    def stop_monitoring(self):
        """Stop background monitoring."""
        self.monitoring_active = False
        if self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)

# Global performance logger instance
_performance_logger = None

def get_performance_logger() -> PerformanceLogger:
    """Get the global performance logger instance."""
    global _performance_logger
    if _performance_logger is None:
        config = get_config()
        from pathlib import Path
log_dir = Path
Path(getattr(config.logging, "directory", "logs")) / "performance"
        _performance_logger = PerformanceLogger(log_dir)
    return _performance_logger

# Convenience functions
def record_metric(name: str, value: float, unit: str = "", **kwargs):
    """Record a performance metric."""
    get_performance_logger().record_metric(name, value, unit, **kwargs)

def timer(operation_name: str, **kwargs):
    """Timer context manager."""
    return get_performance_logger().timer(operation_name, **kwargs)

def time_function(func_name: Optional[str] = None):
    """Function timing decorator."""
    return get_performance_logger().time_function(func_name)

# Export main components
__all__ = [
    "PerformanceMetric", "PerformanceAlert", "MetricBuffer", "SystemMonitor",
    "PerformanceLogger", "get_performance_logger", "record_metric", "timer", "time_function"
]
