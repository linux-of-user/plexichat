import asyncio
from plexichat.core.logging import get_logger
import statistics
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union
import psutil
import gc

logger = get_logger(__name__)


class MetricType(Enum):
    """Types of performance metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"
    RATE = "rate"


class AlertLevel(Enum):
    """Performance alert levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class PerformanceMetric:
    """Performance metric data structure."""
    name: str
    metric_type: MetricType
    value: Union[int, float]
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    unit: str = ""
    description: str = ""


@dataclass
class PerformanceAlert:
    """Performance alert data structure."""
    metric_name: str
    alert_level: AlertLevel
    threshold_value: Union[int, float]
    current_value: Union[int, float]
    message: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SystemMetrics:
    """System-level performance metrics."""
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_available_mb: float
    disk_usage_percent: float
    network_bytes_sent: int
    network_bytes_recv: int
    active_threads: int
    open_files: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class EnterprisePerformanceLogger:
    """Enterprise-grade performance logging and monitoring system.
    
    Features:
    - Real-time performance metrics collection
    - System resource monitoring
    - Custom metric tracking
    - Performance alerting
    - Statistical analysis
    - Memory leak detection
    - Bottleneck identification
    """
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self.counters: Dict[str, int] = defaultdict(int)
        self.gauges: Dict[str, float] = defaultdict(float)
        self.timers: Dict[str, List[float]] = defaultdict(list)
        self.system_metrics_history: deque = deque(maxlen=1000)
        self.alert_callbacks: List[Callable[[PerformanceAlert], None]] = []
        self.thresholds: Dict[str, Dict[str, Union[int, float]]] = {}
        self._lock = threading.RLock()
        self._running = False
        self._monitoring_task: Optional[asyncio.Task] = None
        self._collection_interval = self.config.get("collection_interval_seconds", 30)
        self._alert_cooldown = self.config.get("alert_cooldown_seconds", 300)  # 5 minutes
        self._last_alerts: Dict[str, datetime] = {}
        
        # Performance tracking
        self._operation_timers: Dict[str, float] = {}
        self._gc_stats = {"collections": 0, "collected": 0, "uncollectable": 0}
        
        # Initialize default thresholds
        self._initialize_default_thresholds()
        
    def _initialize_default_thresholds(self):
        """Initialize default performance thresholds."""
        self.thresholds = {
            "cpu_percent": {"warning": 80.0, "critical": 95.0},
            "memory_percent": {"warning": 85.0, "critical": 95.0},
            "response_time": {"warning": 1.0, "critical": 5.0},
            "error_rate": {"warning": 0.05, "critical": 0.10},
            "active_threads": {"warning": 100, "critical": 200},
            "open_files": {"warning": 500, "critical": 900}
        }
    
    async def initialize(self):
        """Initialize the performance logger."""
        self._running = True
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Enterprise Performance Logger initialized")
    
    async def shutdown(self):
        """Shutdown the performance logger."""
        self._running = False
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
        logger.info("Enterprise Performance Logger shutdown complete")
    
    def record_metric(self, name: str, value: Union[int, float], 
                     metric_type: MetricType = MetricType.GAUGE,
                     tags: Optional[Dict[str, str]] = None,
                     unit: str = "",
                     description: str = ""):
        """Record a performance metric."""
        metric = PerformanceMetric(
            name=name,
            metric_type=metric_type,
            value=value,
            timestamp=datetime.now(timezone.utc),
            tags=tags or {},
            unit=unit,
            description=description
        )
        
        with self._lock:
            self.metrics[name].append(metric)
            
            # Update type-specific storage
            if metric_type == MetricType.COUNTER:
                self.counters[name] += value
            elif metric_type == MetricType.GAUGE:
                self.gauges[name] = value
            elif metric_type == MetricType.TIMER:
                self.timers[name].append(value)
                # Keep only recent timer values
                max_timers = self.config.get("max_timer_values", 1000)
                if len(self.timers[name]) > max_timers:
                    self.timers[name] = self.timers[name][-max_timers:]
        
        # Check for alerts
        self._check_alert_thresholds(name, value)
        
        logger.debug(f"Recorded {metric_type.value} metric '{name}': {value} {unit}")
    
    def increment_counter(self, name: str, value: int = 1, 
                         tags: Optional[Dict[str, str]] = None):
        """Increment a counter metric."""
        self.record_metric(name, value, MetricType.COUNTER, tags)
    
    def set_gauge(self, name: str, value: Union[int, float], 
                 tags: Optional[Dict[str, str]] = None,
                 unit: str = ""):
        """Set a gauge metric."""
        self.record_metric(name, value, MetricType.GAUGE, tags, unit)
    
    def record_timer(self, name: str, duration: float, 
                    tags: Optional[Dict[str, str]] = None):
        """Record a timer metric."""
        self.record_metric(name, duration, MetricType.TIMER, tags, "seconds")
    
    def start_timer(self, operation_name: str) -> str:
        """Start timing an operation."""
        timer_id = f"{operation_name}_{time.time()}"
        self._operation_timers[timer_id] = time.time()
        return timer_id
    
    def end_timer(self, timer_id: str, tags: Optional[Dict[str, str]] = None):
        """End timing an operation."""
        if timer_id in self._operation_timers:
            start_time = self._operation_timers.pop(timer_id)
            duration = time.time() - start_time
            operation_name = timer_id.rsplit('_', 1)[0]
            self.record_timer(operation_name, duration, tags)
            return duration
        return None
    
    def collect_system_metrics(self) -> SystemMetrics:
        """Collect current system performance metrics."""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            
            # Memory metrics
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_used_mb = memory.used / (1024 * 1024)
            memory_available_mb = memory.available / (1024 * 1024)
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            disk_usage_percent = disk.percent
            
            # Network metrics
            network = psutil.net_io_counters()
            network_bytes_sent = network.bytes_sent
            network_bytes_recv = network.bytes_recv
            
            # Process metrics
            process = psutil.Process()
            active_threads = process.num_threads()
            open_files = len(process.open_files())
            
            metrics = SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                memory_used_mb=memory_used_mb,
                memory_available_mb=memory_available_mb,
                disk_usage_percent=disk_usage_percent,
                network_bytes_sent=network_bytes_sent,
                network_bytes_recv=network_bytes_recv,
                active_threads=active_threads,
                open_files=open_files
            )
            
            # Store in history
            with self._lock:
                self.system_metrics_history.append(metrics)
            
            # Record as individual metrics
            self.set_gauge("cpu_percent", cpu_percent, unit="%")
            self.set_gauge("memory_percent", memory_percent, unit="%")
            self.set_gauge("memory_used_mb", memory_used_mb, unit="MB")
            self.set_gauge("disk_usage_percent", disk_usage_percent, unit="%")
            self.set_gauge("active_threads", active_threads)
            self.set_gauge("open_files", open_files)
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return SystemMetrics(0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    def get_metric_statistics(self, metric_name: str, 
                            time_window: Optional[timedelta] = None) -> Dict[str, Any]:
        """Get statistical analysis of a metric."""
        with self._lock:
            if metric_name not in self.metrics:
                return {"error": f"Metric '{metric_name}' not found"}
            
            metrics = list(self.metrics[metric_name])
            
            # Filter by time window if specified
            if time_window:
                cutoff_time = datetime.now(timezone.utc) - time_window
                metrics = [m for m in metrics if m.timestamp >= cutoff_time]
            
            if not metrics:
                return {"error": "No data points in specified time window"}
            
            values = [m.value for m in metrics]
            
            stats = {
                "count": len(values),
                "min": min(values),
                "max": max(values),
                "mean": statistics.mean(values),
                "median": statistics.median(values),
                "std_dev": statistics.stdev(values) if len(values) > 1 else 0,
                "first_timestamp": metrics[0].timestamp.isoformat(),
                "last_timestamp": metrics[-1].timestamp.isoformat()
            }
            
            # Add percentiles for larger datasets
            if len(values) >= 10:
                sorted_values = sorted(values)
                stats["p50"] = statistics.median(sorted_values)
                stats["p90"] = sorted_values[int(0.9 * len(sorted_values))]
                stats["p95"] = sorted_values[int(0.95 * len(sorted_values))]
                stats["p99"] = sorted_values[int(0.99 * len(sorted_values))]
            
            return stats
    
    def set_alert_threshold(self, metric_name: str, warning_threshold: Union[int, float],
                          critical_threshold: Union[int, float]):
        """Set alert thresholds for a metric."""
        self.thresholds[metric_name] = {
            "warning": warning_threshold,
            "critical": critical_threshold
        }
        logger.info(f"Set thresholds for {metric_name}: warning={warning_threshold}, critical={critical_threshold}")
    
    def _check_alert_thresholds(self, metric_name: str, value: Union[int, float]):
        """Check if metric value exceeds alert thresholds."""
        if metric_name not in self.thresholds:
            return
        
        thresholds = self.thresholds[metric_name]
        current_time = datetime.now(timezone.utc)
        
        # Check cooldown period
        if metric_name in self._last_alerts:
            time_since_last = current_time - self._last_alerts[metric_name]
            if time_since_last.total_seconds() < self._alert_cooldown:
                return
        
        alert_level = None
        threshold_value = None
        
        if value >= thresholds.get("critical", float('inf')):
            alert_level = AlertLevel.CRITICAL
            threshold_value = thresholds["critical"]
        elif value >= thresholds.get("warning", float('inf')):
            alert_level = AlertLevel.WARNING
            threshold_value = thresholds["warning"]
        
        if alert_level:
            alert = PerformanceAlert(
                metric_name=metric_name,
                alert_level=alert_level,
                threshold_value=threshold_value,
                current_value=value,
                message=f"Metric '{metric_name}' exceeded {alert_level.value} threshold: {value} >= {threshold_value}",
                timestamp=current_time
            )
            
            self._last_alerts[metric_name] = current_time
            
            # Notify alert callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
            
            logger.warning(f"PERFORMANCE ALERT: {alert.message}")
    
    def add_alert_callback(self, callback: Callable[[PerformanceAlert], None]):
        """Add a callback for performance alerts."""
        self.alert_callbacks.append(callback)
    
    def remove_alert_callback(self, callback: Callable[[PerformanceAlert], None]):
        """Remove an alert callback."""
        if callback in self.alert_callbacks:
            self.alert_callbacks.remove(callback)
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get a comprehensive performance summary."""
        with self._lock:
            summary = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metrics_count": sum(len(metrics) for metrics in self.metrics.values()),
                "active_metrics": len(self.metrics),
                "counters": dict(self.counters),
                "gauges": dict(self.gauges),
                "system_metrics": None,
                "gc_stats": self._gc_stats.copy(),
                "active_timers": len(self._operation_timers)
            }
            
            # Add latest system metrics
            if self.system_metrics_history:
                latest_system = self.system_metrics_history[-1]
                summary["system_metrics"] = {
                    "cpu_percent": latest_system.cpu_percent,
                    "memory_percent": latest_system.memory_percent,
                    "memory_used_mb": latest_system.memory_used_mb,
                    "disk_usage_percent": latest_system.disk_usage_percent,
                    "active_threads": latest_system.active_threads,
                    "open_files": latest_system.open_files,
                    "timestamp": latest_system.timestamp.isoformat()
                }
            
            # Add timer statistics
            timer_stats = {}
            for name, times in self.timers.items():
                if times:
                    timer_stats[name] = {
                        "count": len(times),
                        "avg": statistics.mean(times),
                        "min": min(times),
                        "max": max(times)
                    }
            summary["timer_stats"] = timer_stats
            
            return summary
    
    async def _monitoring_loop(self):
        """Background monitoring loop."""
        while self._running:
            try:
                # Collect system metrics
                self.collect_system_metrics()
                
                # Collect garbage collection stats
                self._collect_gc_stats()
                
                # Sleep until next collection
                await asyncio.sleep(self._collection_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in performance monitoring loop: {e}")
    
    def _collect_gc_stats(self):
        """Collect garbage collection statistics."""
        try:
            gc_stats = gc.get_stats()
            if gc_stats:
                total_collections = sum(stat.get('collections', 0) for stat in gc_stats)
                total_collected = sum(stat.get('collected', 0) for stat in gc_stats)
                total_uncollectable = sum(stat.get('uncollectable', 0) for stat in gc_stats)
                
                self._gc_stats = {
                    "collections": total_collections,
                    "collected": total_collected,
                    "uncollectable": total_uncollectable
                }
                
                self.set_gauge("gc_collections", total_collections)
                self.set_gauge("gc_collected", total_collected)
                self.set_gauge("gc_uncollectable", total_uncollectable)
                
        except Exception as e:
            logger.error(f"Error collecting GC stats: {e}")


class PerformanceTimer:
    """Context manager for timing operations."""
    
    def __init__(self, logger: EnterprisePerformanceLogger, operation_name: str,
                 tags: Optional[Dict[str, str]] = None):
        self.logger = logger
        self.operation_name = operation_name
        self.tags = tags
        self.start_time: Optional[float] = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = time.time() - self.start_time
            self.logger.record_timer(self.operation_name, duration, self.tags)


# Global performance logger instance
_performance_logger: Optional[EnterprisePerformanceLogger] = None


def get_performance_logger() -> EnterprisePerformanceLogger:
    """Get the global performance logger instance."""
    global _performance_logger
    if _performance_logger is None:
        _performance_logger = EnterprisePerformanceLogger()
    return _performance_logger


async def initialize_performance_logger(config: Optional[Dict[str, Any]] = None) -> EnterprisePerformanceLogger:
    """Initialize and return the performance logger."""
    perf_logger = get_performance_logger()
    if config:
        perf_logger.config.update(config)
    await perf_logger.initialize()
    return perf_logger


def time_operation(operation_name: str, tags: Optional[Dict[str, str]] = None) -> PerformanceTimer:
    """Create a performance timer context manager."""
    return PerformanceTimer(get_performance_logger(), operation_name, tags)
