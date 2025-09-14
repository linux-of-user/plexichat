# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import statistics
import threading
from typing import Any, Optional

from ..ai.core.analytics_engine import analytics_engine
from ..app.performance.optimization import PerformanceOptimizer
from ..clustering.core.performance_monitor import PerformanceMonitor
from ..core.config import get_config
from ..core.logging.performance_logger import get_performance_logger
from .base_service import BaseService

"""
import logging
import time
PlexiChat Unified Performance Monitoring Service

Centralized performance monitoring service that consolidates all performance
monitoring capabilities across the PlexiChat system into a single, comprehensive
service with real-time metrics, alerting, and dashboard visualization.

Features:
- Real-time system metrics collection
- Application performance monitoring
- Database performance tracking
- API endpoint monitoring
- Cluster performance metrics
- AI service performance tracking
- Custom metric collection
- Performance alerting
- Dashboard data aggregation
- Historical trend analysis
"""


@dataclass
class SystemMetrics:
    """System-level performance metrics."""

    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_io: dict[str, float]
    thread_count: int
    open_files: int
    load_average: list[float] = field(default_factory=list)


@dataclass
class ApplicationMetrics:
    """Application-level performance metrics."""

    timestamp: datetime
    active_connections: int
    request_rate: float
    response_time_avg: float
    response_time_p95: float
    response_time_p99: float
    error_rate: float
    success_rate: float
    throughput: float


@dataclass
class DatabaseMetrics:
    """Database performance metrics."""

    timestamp: datetime
    connection_pool_size: int
    active_connections: int
    query_rate: float
    avg_query_time: float
    slow_queries: int
    cache_hit_rate: float
    deadlocks: int


@dataclass
class ClusterMetrics:
    """Cluster performance metrics."""

    timestamp: datetime
    total_nodes: int
    active_nodes: int
    cluster_cpu_avg: float
    cluster_memory_avg: float
    cluster_load_balance: float
    inter_node_latency: float
    failover_count: int


@dataclass
class AIMetrics:
    """AI service performance metrics."""

    timestamp: datetime
    requests_per_minute: float
    avg_response_time: float
    model_accuracy: float
    token_usage: int
    cost_per_request: float
    error_rate: float
    provider_availability: dict[str, bool]


class PerformanceAggregator:
    """Aggregates performance data from multiple sources."""

    def __init__(self):
        self.system_metrics: deque = deque(maxlen=1000)
        self.app_metrics: deque = deque(maxlen=1000)
        self.db_metrics: deque = deque(maxlen=1000)
        self.cluster_metrics: deque = deque(maxlen=1000)
        self.ai_metrics: deque = deque(maxlen=1000)
        self.custom_metrics: dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.lock = threading.RLock()

    def add_system_metrics(self, metrics: SystemMetrics):
        """Add system metrics."""
        with self.lock:
            self.system_metrics.append(metrics)

    def add_application_metrics(self, metrics: ApplicationMetrics):
        """Add application metrics."""
        with self.lock:
            self.app_metrics.append(metrics)

    def add_database_metrics(self, metrics: DatabaseMetrics):
        """Add database metrics."""
        with self.lock:
            self.db_metrics.append(metrics)

    def add_ai_metrics(self, metrics: AIMetrics):
        """Add AI metrics."""
        with self.lock:
            self.ai_metrics.append(metrics)

    def add_cluster_metrics(self, metrics: ClusterMetrics):
        """Add cluster metrics."""
        with self.lock:
            self.cluster_metrics.append(metrics)

    def add_custom_metric(
        self, name: str, value: Any, timestamp: datetime | None = None
    ):
        """Add custom metric."""
        if timestamp is None:
            timestamp = datetime.now(UTC)

        with self.lock:
            self.custom_metrics[name].append({"timestamp": timestamp, "value": value})

    def get_latest_metrics(self) -> dict[str, Any]:
        """Get latest metrics from all sources."""
        with self.lock:
            return {
                "system": (
                    self.system_metrics[-1].__dict__ if self.system_metrics else None
                ),
                "application": (
                    self.app_metrics[-1].__dict__ if self.app_metrics else None
                ),
                "database": self.db_metrics[-1].__dict__ if self.db_metrics else None,
                "cluster": (
                    self.cluster_metrics[-1].__dict__ if self.cluster_metrics else None
                ),
                "ai": self.ai_metrics[-1].__dict__ if self.ai_metrics else None,
                "custom": {
                    name: list(metrics)[-1] if metrics else None
                    for name, metrics in self.custom_metrics.items()
                },
            }

    def get_historical_data(self, hours: int = 1) -> dict[str, list[dict[str, Any]]]:
        """Get historical metrics data."""
        cutoff_time = datetime.now(UTC) - timedelta(hours=hours)

        with self.lock:
            return {
                "system": [
                    m.__dict__
                    for m in self.system_metrics
                    if m.timestamp >= cutoff_time
                ],
                "application": [
                    m.__dict__ for m in self.app_metrics if m.timestamp >= cutoff_time
                ],
                "database": [
                    m.__dict__ for m in self.db_metrics if m.timestamp >= cutoff_time
                ],
                "cluster": [
                    m.__dict__
                    for m in self.cluster_metrics
                    if m.timestamp >= cutoff_time
                ],
                "ai": [
                    m.__dict__ for m in self.ai_metrics if m.timestamp >= cutoff_time
                ],
                "custom": {
                    name: [m for m in metrics if m["timestamp"] >= cutoff_time]
                    for name, metrics in self.custom_metrics.items()
                },
            }


class PerformanceService(BaseService):
    """Unified performance monitoring service."""

    def __init__(self):
        super().__init__("performance")
        self.config = get_config()
        self.performance_logger = get_performance_logger()
        self.aggregator = PerformanceAggregator()

        # Monitoring configuration
        self.monitoring_interval = self.config.get(
            "performance.monitoring_interval", 30
        )
        self.alert_thresholds = self.config.get("performance.alert_thresholds", {})
        self.dashboard_enabled = self.config.get("performance.dashboard_enabled", True)

        # Monitoring state
        self.monitoring_active = False
        self.monitoring_tasks: list[asyncio.Task] = []
        self.alert_callbacks: list[Callable] = []

        # Performance baselines for anomaly detection
        self.baselines = {
            "cpu_usage": 50.0,
            "memory_usage": 70.0,
            "response_time": 200.0,
            "error_rate": 1.0,
        }

        # Initialize collectors
        self._initialize_collectors()

    async def start(self):
        """Start the performance monitoring service."""
        await super().start()
        self.monitoring_active = True

        # Start monitoring tasks
        self.monitoring_tasks = [
            asyncio.create_task(self._system_monitoring_loop()),
            asyncio.create_task(self._application_monitoring_loop()),
            asyncio.create_task(self._database_monitoring_loop()),
            asyncio.create_task(self._cluster_monitoring_loop()),
            asyncio.create_task(self._ai_monitoring_loop()),
            asyncio.create_task(self._alert_monitoring_loop()),
        ]

        self.logger.info("Performance monitoring service started")

    async def stop(self):
        """Stop the performance monitoring service."""
        self.monitoring_active = False

        # Cancel monitoring tasks
        for task in self.monitoring_tasks:
            task.cancel()

        # Wait for tasks to complete
        await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)

        await super().stop()
        self.logger.info("Performance monitoring service stopped")

    def _initialize_collectors(self):
        """Initialize performance data collectors."""
        # Import collectors based on availability
        try:
            self.perf_optimizer = PerformanceOptimizer()
        except ImportError:
            Optional[self.perf_optimizer] = None

        try:
            self.cluster_monitor = PerformanceMonitor()
        except ImportError:
            Optional[self.cluster_monitor] = None

        try:
            self.ai_analytics = analytics_engine
        except ImportError:
            Optional[self.ai_analytics] = None

    async def _system_monitoring_loop(self):
        """System metrics monitoring loop."""
        while self.monitoring_active:
            try:
                # Collect system metrics using the performance logger
                system_metrics = SystemMetrics(
                    timestamp=datetime.now(UTC),
                    cpu_usage=self.performance_logger.system_monitor.get_cpu_usage(),
                    memory_usage=self.performance_logger.system_monitor.get_memory_usage()[
                        "percent"
                    ],
                    disk_usage=0.0,  # Will be calculated from disk I/O
                    network_io=self.performance_logger.system_monitor.get_network_usage(),
                    thread_count=self.performance_logger.system_monitor.get_thread_count(),
                    open_files=self.performance_logger.system_monitor.get_open_files_count(),
                )

                self.aggregator.add_system_metrics(system_metrics)

                # Record individual metrics
                self.performance_logger.record_metric(
                    "system_cpu_usage", system_metrics.cpu_usage, "%"
                )
                self.performance_logger.record_metric(
                    "system_memory_usage", system_metrics.memory_usage, "%"
                )
                self.performance_logger.record_metric(
                    "system_thread_count", system_metrics.thread_count, "count"
                )

                await asyncio.sleep(self.monitoring_interval)

            except Exception as e:
                self.logger.error(f"System monitoring error: {e}")
                await asyncio.sleep(60)

    async def _application_monitoring_loop(self):
        """Application metrics monitoring loop."""
        while self.monitoring_active:
            try:
                # Collect application metrics from various sources
                app_metrics = ApplicationMetrics(
                    timestamp=datetime.now(UTC),
                    active_connections=self._get_active_connections(),
                    request_rate=self._get_request_rate(),
                    response_time_avg=self._get_avg_response_time(),
                    response_time_p95=self._get_p95_response_time(),
                    response_time_p99=self._get_p99_response_time(),
                    error_rate=self._get_error_rate(),
                    success_rate=self._get_success_rate(),
                    throughput=self._get_throughput(),
                )

                self.aggregator.add_application_metrics(app_metrics)

                # Record individual metrics
                self.performance_logger.record_metric(
                    "app_active_connections", app_metrics.active_connections, "count"
                )
                self.performance_logger.record_metric(
                    "app_request_rate", app_metrics.request_rate, "req/s"
                )
                self.performance_logger.record_metric(
                    "app_response_time_avg", app_metrics.response_time_avg, "ms"
                )
                self.performance_logger.record_metric(
                    "app_error_rate", app_metrics.error_rate, "%"
                )

                await asyncio.sleep(self.monitoring_interval)

            except Exception as e:
                self.logger.error(f"Application monitoring error: {e}")
                await asyncio.sleep(60)

    async def _database_monitoring_loop(self):
        """Database metrics monitoring loop."""
        while self.monitoring_active:
            try:
                # Collect database metrics
                db_metrics = DatabaseMetrics(
                    timestamp=datetime.now(UTC),
                    connection_pool_size=self._get_db_pool_size(),
                    active_connections=self._get_db_active_connections(),
                    query_rate=self._get_db_query_rate(),
                    avg_query_time=self._get_db_avg_query_time(),
                    slow_queries=self._get_db_slow_queries(),
                    cache_hit_rate=self._get_db_cache_hit_rate(),
                    deadlocks=self._get_db_deadlocks(),
                )

                self.aggregator.add_database_metrics(db_metrics)

                # Record individual metrics
                self.performance_logger.record_metric(
                    "db_connection_pool_size", db_metrics.connection_pool_size, "count"
                )
                self.performance_logger.record_metric(
                    "db_query_rate", db_metrics.query_rate, "queries/s"
                )
                self.performance_logger.record_metric(
                    "db_avg_query_time", db_metrics.avg_query_time, "ms"
                )
                self.performance_logger.record_metric(
                    "db_cache_hit_rate", db_metrics.cache_hit_rate, "%"
                )

                await asyncio.sleep(
                    self.monitoring_interval * 2
                )  # Less frequent DB monitoring

            except Exception as e:
                self.logger.error(f"Database monitoring error: {e}")
                await asyncio.sleep(120)

    async def _cluster_monitoring_loop(self):
        """Cluster metrics monitoring loop."""
        if not self.cluster_monitor:
            return

        while self.monitoring_active:
            try:
                # Collect cluster metrics if clustering is enabled
                cluster_data = await self.cluster_monitor.collect_cluster_metrics()

                cluster_metrics = ClusterMetrics(
                    timestamp=datetime.now(UTC),
                    total_nodes=cluster_data.get("total_nodes", 1),
                    active_nodes=cluster_data.get("active_nodes", 1),
                    cluster_cpu_avg=cluster_data.get("cluster_cpu_usage", 0.0),
                    cluster_memory_avg=cluster_data.get("cluster_memory_usage", 0.0),
                    cluster_load_balance=cluster_data.get(
                        "performance_gain_factor", 1.0
                    ),
                    inter_node_latency=cluster_data.get(
                        "average_response_time_ms", 0.0
                    ),
                    failover_count=0,  # Would be tracked separately
                )

                self.aggregator.add_cluster_metrics(cluster_metrics)

                # Record individual metrics
                self.performance_logger.record_metric(
                    "cluster_total_nodes", cluster_metrics.total_nodes, "count"
                )
                self.performance_logger.record_metric(
                    "cluster_active_nodes", cluster_metrics.active_nodes, "count"
                )
                self.performance_logger.record_metric(
                    "cluster_cpu_avg", cluster_metrics.cluster_cpu_avg, "%"
                )
                self.performance_logger.record_metric(
                    "cluster_memory_avg", cluster_metrics.cluster_memory_avg, "%"
                )

                await asyncio.sleep(
                    self.monitoring_interval * 3
                )  # Less frequent cluster monitoring

            except Exception as e:
                self.logger.error(f"Cluster monitoring error: {e}")
                await asyncio.sleep(180)

    async def _ai_monitoring_loop(self):
        """AI service metrics monitoring loop."""
        if not self.ai_analytics:
            return

        while self.monitoring_active:
            try:
                # Collect AI service metrics
                recent_metrics = list(self.ai_analytics.performance_buffer)[
                    -100:
                ]  # Last 100 requests

                if recent_metrics:
                    ai_metrics = AIMetrics(
                        timestamp=datetime.now(UTC),
                        requests_per_minute=len(
                            [
                                m
                                for m in recent_metrics
                                if m.timestamp
                                >= datetime.now(UTC) - timedelta(minutes=1)
                            ]
                        ),
                        avg_response_time=statistics.mean(
                            [m.latency_ms for m in recent_metrics]
                        ),
                        model_accuracy=95.0,  # Would be calculated from actual model performance
                        token_usage=sum(
                            [getattr(m, "tokens_used", 0) for m in recent_metrics]
                        ),
                        cost_per_request=statistics.mean(
                            [getattr(m, "cost", 0.0) for m in recent_metrics]
                        ),
                        error_rate=len([m for m in recent_metrics if not m.success])
                        / len(recent_metrics)
                        * 100,
                        provider_availability={},  # Would be populated from provider health checks
                    )

                    self.aggregator.add_ai_metrics(ai_metrics)

                    # Record individual metrics
                    self.performance_logger.record_metric(
                        "ai_requests_per_minute",
                        ai_metrics.requests_per_minute,
                        "req/min",
                    )
                    self.performance_logger.record_metric(
                        "ai_avg_response_time", ai_metrics.avg_response_time, "ms"
                    )
                    self.performance_logger.record_metric(
                        "ai_error_rate", ai_metrics.error_rate, "%"
                    )
                    self.performance_logger.record_metric(
                        "ai_token_usage", ai_metrics.token_usage, "tokens"
                    )

                await asyncio.sleep(
                    self.monitoring_interval * 2
                )  # Less frequent AI monitoring

            except Exception as e:
                self.logger.error(f"AI monitoring error: {e}")
                await asyncio.sleep(120)

    async def _alert_monitoring_loop(self):
        """Alert monitoring loop."""
        while self.monitoring_active:
            try:
                # Check for performance anomalies and trigger alerts
                latest_metrics = self.aggregator.get_latest_metrics()

                # Check system alerts
                if latest_metrics["system"]:
                    system = latest_metrics["system"]
                    if system["cpu_usage"] > self.alert_thresholds.get("cpu_usage", 90):
                        await self._trigger_alert("high_cpu_usage", system["cpu_usage"])
                    if system["memory_usage"] > self.alert_thresholds.get(
                        "memory_usage", 85
                    ):
                        await self._trigger_alert(
                            "high_memory_usage", system["memory_usage"]
                        )

                # Check application alerts
                if latest_metrics["application"]:
                    app = latest_metrics["application"]
                    if app["error_rate"] > self.alert_thresholds.get("error_rate", 5):
                        await self._trigger_alert("high_error_rate", app["error_rate"])
                    if app["response_time_avg"] > self.alert_thresholds.get(
                        "response_time", 1000
                    ):
                        await self._trigger_alert(
                            "slow_response_time", app["response_time_avg"]
                        )

                await asyncio.sleep(60)  # Check alerts every minute

            except Exception as e:
                self.logger.error(f"Alert monitoring error: {e}")
                await asyncio.sleep(60)

    async def _trigger_alert(self, alert_type: str, value: float):
        """Trigger performance alert."""
        alert_data = {
            "type": alert_type,
            "value": value,
            "timestamp": datetime.now(UTC).isoformat(),
            "severity": (
                "high"
                if value
                > self.baselines.get(
                    alert_type.replace("high_", "").replace("slow_", ""), 0
                )
                else "medium"
            ),
        }

        self.logger.warning(f"Performance alert: {alert_type} = {value}")

        # Call alert callbacks
        for callback in self.alert_callbacks:
            try:
                await callback(alert_data)
            except Exception as e:
                self.logger.error(f"Alert callback error: {e}")

    # Helper methods for collecting metrics
    def _get_active_connections(self) -> int:
        """Get active connection count."""
        # This would integrate with actual connection tracking
        return 50  # Placeholder

    def _get_request_rate(self) -> float:
        """Get current request rate."""
        # This would integrate with actual request tracking
        return 10.5  # Placeholder

    def _get_avg_response_time(self) -> float:
        """Get average response time."""
        # This would integrate with actual response time tracking
        return 150.0  # Placeholder

    def _get_p95_response_time(self) -> float:
        """Get response time at 95th percentile."""
        return 300.0  # Placeholder

    def _get_p99_response_time(self) -> float:
        """Get response time at 99th percentile."""
        return 500.0  # Placeholder

    def _get_error_rate(self) -> float:
        """Get current error rate."""
        return 2.5  # Placeholder

    def _get_success_rate(self) -> float:
        """Get current success rate."""
        return 97.5  # Placeholder

    def _get_throughput(self) -> float:
        """Get current throughput."""
        return 1000.0  # Placeholder

    def _get_db_pool_size(self) -> int:
        """Get database connection pool size."""
        return 20  # Placeholder

    def _get_db_active_connections(self) -> int:
        """Get active database connections."""
        return 5  # Placeholder

    def _get_db_query_rate(self) -> float:
        """Get database query rate."""
        return 25.0  # Placeholder

    def _get_db_avg_query_time(self) -> float:
        """Get average database query time."""
        return 50.0  # Placeholder

    def _get_db_slow_queries(self) -> int:
        """Get slow query count."""
        return 2  # Placeholder

    def _get_db_cache_hit_rate(self) -> float:
        """Get database cache hit rate."""
        return 85.0  # Placeholder

    def _get_db_deadlocks(self) -> int:
        """Get database deadlock count."""
        return 0  # Placeholder

    # Public API methods
    def get_current_metrics(self) -> dict[str, Any]:
        """Get current performance metrics."""
        return self.aggregator.get_latest_metrics()

    def get_historical_metrics(self, hours: int = 1) -> dict[str, Any]:
        """Get historical performance metrics."""
        return self.aggregator.get_historical_data(hours)

    def add_custom_metric(self, name: str, value: Any):
        """Add custom performance metric."""
        self.aggregator.add_custom_metric(name, value)
        self.performance_logger.record_metric(
            f"custom_{name}",
            float(value) if isinstance(value, (int, float)) else 0.0,
            "custom",
        )

    def add_alert_callback(self, callback: Callable):
        """Add alert callback function."""
        self.alert_callbacks.append(callback)

    def get_performance_summary(self) -> dict[str, Any]:
        """Get comprehensive performance summary."""
        latest = self.aggregator.get_latest_metrics()
        historical = self.aggregator.get_historical_data(24)  # Last 24 hours

        return {
            "timestamp": datetime.now(UTC).isoformat(),
            "current": latest,
            "trends": self._calculate_trends(historical),
            "alerts": self._get_active_alerts(),
            "health_score": self._calculate_health_score(latest),
        }

    def _calculate_trends(self, historical_data: dict[str, Any]) -> dict[str, str]:
        """Calculate performance trends."""
        # This would implement trend analysis
        return {
            "cpu_usage": "stable",
            "memory_usage": "increasing",
            "response_time": "improving",
            "error_rate": "stable",
        }

    def _get_active_alerts(self) -> list[dict[str, Any]]:
        """Get currently active alerts."""
        # This would return actual active alerts
        return []

    def _calculate_health_score(self, metrics: dict[str, Any]) -> float:
        """Calculate overall system health score (0-100)."""
        # This would implement a comprehensive health scoring algorithm
        return 85.0  # Placeholder


# Global performance service instance
_performance_service = None


async def get_performance_service() -> PerformanceService:
    """Get the global performance service instance."""
    global _performance_service
    if _performance_service is None:
        _performance_service = PerformanceService()
        if _performance_service and hasattr(_performance_service, "start"):
            await _performance_service.start()
    return _performance_service


# Export main components
__all__ = [
    "AIMetrics",
    "ApplicationMetrics",
    "ClusterMetrics",
    "DatabaseMetrics",
    "PerformanceAggregator",
    "PerformanceService",
    "SystemMetrics",
    "get_performance_service",
]
