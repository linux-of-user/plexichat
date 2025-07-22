"""
PlexiChat Unified Monitoring & Analytics System - SINGLE SOURCE OF TRUTH

Consolidates ALL monitoring and analytics functionality from:
- core/monitoring/system_monitor.py - INTEGRATED
- core/analytics/analytics_manager.py - INTEGRATED
- infrastructure/analytics/ (all modules) - INTEGRATED
- Feature-specific monitoring components - INTEGRATED

Provides a single, unified interface for all monitoring and analytics operations.
"""

import asyncio
import json
import logging
import psutil
import time
import threading
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Callable, Union
from enum import Enum
from dataclasses import dataclass, field
from uuid import uuid4

# Core imports
try:
    from ..database.manager import database_manager
    from ..exceptions import MonitoringError, AnalyticsError
    from ..config import get_config
except ImportError:
    database_manager = None

    class MonitoringError(Exception):
        pass

    class AnalyticsError(Exception):
        pass

    def get_config():
        class MockConfig:
            class monitoring:
                enabled = True
                collection_interval = 60
                retention_days = 30
            class analytics:
                enabled = True
                batch_size = 100
                real_time = True
        return MockConfig()

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Metric types."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"
    SET = "set"


class EventType(Enum):
    """Analytics event types."""
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_REGISTER = "user_register"
    MESSAGE_SENT = "message_sent"
    MESSAGE_RECEIVED = "message_received"
    FILE_UPLOAD = "file_upload"
    FILE_DOWNLOAD = "file_download"
    API_REQUEST = "api_request"
    ERROR_OCCURRED = "error_occurred"
    SYSTEM_EVENT = "system_event"
    SECURITY_EVENT = "security_event"
    PERFORMANCE_EVENT = "performance_event"


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class HealthStatus(Enum):
    """Health status levels."""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class Metric:
    """Metric data structure."""
    name: str
    value: Union[int, float]
    metric_type: MetricType
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalyticsEvent:
    """Analytics event data structure."""
    event_id: str
    event_type: EventType
    timestamp: datetime
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    properties: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    duration_ms: Optional[float] = None


@dataclass
class SystemMetrics:
    """System metrics data structure."""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    network_bytes_sent: int
    network_bytes_recv: int
    process_count: int
    load_average: List[float]
    uptime_seconds: float


@dataclass
class ApplicationMetrics:
    """Application metrics data structure."""
    timestamp: datetime
    active_connections: int
    request_count: int
    error_count: int
    response_time_avg: float
    memory_usage_mb: float
    cpu_usage_percent: float
    database_connections: int
    cache_hit_rate: float


@dataclass
class Alert:
    """Alert data structure."""
    alert_id: str
    name: str
    severity: AlertSeverity
    message: str
    timestamp: datetime
    source: str
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class MetricsCollector:
    """Metrics collection and storage."""

    def __init__(self):
        self.metrics: Dict[str, List[Metric]] = defaultdict(list)
        self.retention_days = 30
        self.max_metrics_per_name = 10000
        self.lock = threading.Lock()

    def record_metric(self, name: str, value: Union[int, float], metric_type: MetricType = MetricType.GAUGE, tags: Optional[Dict[str, str]] = None, metadata: Optional[Dict[str, Any]] = None):
        """Record a metric."""
        try:
            with self.lock:
                metric = Metric(
                    name=name,
                    value=value,
                    metric_type=metric_type,
                    timestamp=datetime.now(timezone.utc),
                    tags=tags or {},
                    metadata=metadata or {}
                )

                self.metrics[name].append(metric)

                # Limit metrics per name
                if len(self.metrics[name]) > self.max_metrics_per_name:
                    self.metrics[name] = self.metrics[name][-self.max_metrics_per_name:]

        except Exception as e:
            logger.error(f"Error recording metric {name}: {e}")

    def get_metrics(self, name: str, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None) -> List[Metric]:
        """Get metrics by name and time range."""
        try:
            with self.lock:
                metrics = self.metrics.get(name, [])

                if start_time or end_time:
                    filtered_metrics = []
                    for metric in metrics:
                        if start_time and metric.timestamp < start_time:
                            continue
                        if end_time and metric.timestamp > end_time:
                            continue
                        filtered_metrics.append(metric)
                    return filtered_metrics

                return metrics.copy()

        except Exception as e:
            logger.error(f"Error getting metrics {name}: {e}")
            return []

    def get_latest_metric(self, name: str) -> Optional[Metric]:
        """Get the latest metric value."""
        try:
            with self.lock:
                metrics = self.metrics.get(name, [])
                return metrics[-1] if metrics else None
        except Exception as e:
            logger.error(f"Error getting latest metric {name}: {e}")
            return None

    def cleanup_old_metrics(self):
        """Clean up old metrics based on retention policy."""
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(days=self.retention_days)

            with self.lock:
                for name in list(self.metrics.keys()):
                    self.metrics[name] = [
                        metric for metric in self.metrics[name]
                        if metric.timestamp > cutoff_time
                    ]

                    # Remove empty metric lists
                    if not self.metrics[name]:
                        del self.metrics[name]

        except Exception as e:
            logger.error(f"Error cleaning up metrics: {e}")


class AnalyticsCollector:
    """Analytics event collection and processing."""

    def __init__(self):
        self.events: deque = deque(maxlen=100000)
        self.event_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self.processing = False
        self.events_processed = 0
        self.events_failed = 0
        self.lock = threading.Lock()

    async def track_event(self, event: AnalyticsEvent):
        """Track an analytics event."""
        try:
            await self.event_queue.put(event)
        except Exception as e:
            logger.error(f"Error tracking event: {e}")
            self.events_failed += 1

    async def process_events(self):
        """Process events from the queue."""
        self.processing = True

        try:
            while self.processing:
                try:
                    # Get event with timeout
                    event = await asyncio.wait_for(
                        self.event_queue.get(),
                        timeout=1.0
                    )

                    # Store event
                    with self.lock:
                        self.events.append(event)

                    # Process event
                    await self._process_single_event(event)

                    self.events_processed += 1

                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logger.error(f"Error processing event: {e}")
                    self.events_failed += 1

        except Exception as e:
            logger.error(f"Event processing error: {e}")
        finally:
            self.processing = False

    async def _process_single_event(self, event: AnalyticsEvent):
        """Process a single event."""
        try:
            # Store in database if available
            if database_manager:
                await self._store_event_in_database(event)

            # Update real-time metrics
            self._update_real_time_metrics(event)

        except Exception as e:
            logger.error(f"Error processing single event: {e}")

    async def _store_event_in_database(self, event: AnalyticsEvent):
        """Store event in database."""
        # This would store the event in the database
        pass

    def _update_real_time_metrics(self, event: AnalyticsEvent):
        """Update real-time metrics based on event."""
        # This would update real-time counters and metrics
        pass

    def get_events(self, event_type: Optional[EventType] = None, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None) -> List[AnalyticsEvent]:
        """Get events by type and time range."""
        try:
            with self.lock:
                events = list(self.events)

                # Filter by event type
                if event_type:
                    events = [e for e in events if e.event_type == event_type]

                # Filter by time range
                if start_time:
                    events = [e for e in events if e.timestamp >= start_time]
                if end_time:
                    events = [e for e in events if e.timestamp <= end_time]

                return events

        except Exception as e:
            logger.error(f"Error getting events: {e}")
            return []


class SystemMonitor:
    """System monitoring component."""

    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics_collector = metrics_collector
        self.monitoring_active = False
        self.collection_interval = 60  # seconds
        self.monitor_task: Optional[asyncio.Task] = None

    async def start_monitoring(self):
        """Start system monitoring."""
        if self.monitoring_active:
            return

        self.monitoring_active = True
        self.monitor_task = asyncio.create_task(self._monitoring_loop())
        logger.info("System monitoring started")

    async def stop_monitoring(self):
        """Stop system monitoring."""
        self.monitoring_active = False

        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass

        logger.info("System monitoring stopped")

    async def _monitoring_loop(self):
        """Main monitoring loop."""
        while self.monitoring_active:
            try:
                # Collect system metrics
                system_metrics = await self._collect_system_metrics()

                # Record metrics
                self._record_system_metrics(system_metrics)

                # Collect application metrics
                app_metrics = await self._collect_application_metrics()

                # Record application metrics
                self._record_application_metrics(app_metrics)

                await asyncio.sleep(self.collection_interval)

            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(self.collection_interval)

    async def _collect_system_metrics(self) -> SystemMetrics:
        """Collect system metrics."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)

            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent

            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100

            # Network I/O
            network = psutil.net_io_counters()

            # Process count
            process_count = len(psutil.pids())

            # Load average
            load_average = list(psutil.getloadavg()) if hasattr(psutil, 'getloadavg') else [0.0, 0.0, 0.0]

            # Uptime
            boot_time = psutil.boot_time()
            uptime_seconds = time.time() - boot_time

            return SystemMetrics(
                timestamp=datetime.now(timezone.utc),
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                disk_percent=disk_percent,
                network_bytes_sent=network.bytes_sent,
                network_bytes_recv=network.bytes_recv,
                process_count=process_count,
                load_average=load_average,
                uptime_seconds=uptime_seconds
            )

        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return SystemMetrics(
                timestamp=datetime.now(timezone.utc),
                cpu_percent=0.0,
                memory_percent=0.0,
                disk_percent=0.0,
                network_bytes_sent=0,
                network_bytes_recv=0,
                process_count=0,
                load_average=[0.0, 0.0, 0.0],
                uptime_seconds=0.0
            )

    async def _collect_application_metrics(self) -> ApplicationMetrics:
        """Collect application-specific metrics."""
        try:
            # Get current process
            process = psutil.Process()

            # Memory usage
            memory_info = process.memory_info()
            memory_usage_mb = memory_info.rss / 1024 / 1024

            # CPU usage
            cpu_usage_percent = process.cpu_percent()

            # Placeholder values for application-specific metrics
            # These would be collected from the actual application
            active_connections = 0
            request_count = 0
            error_count = 0
            response_time_avg = 0.0
            database_connections = 0
            cache_hit_rate = 0.0

            return ApplicationMetrics(
                timestamp=datetime.now(timezone.utc),
                active_connections=active_connections,
                request_count=request_count,
                error_count=error_count,
                response_time_avg=response_time_avg,
                memory_usage_mb=memory_usage_mb,
                cpu_usage_percent=cpu_usage_percent,
                database_connections=database_connections,
                cache_hit_rate=cache_hit_rate
            )

        except Exception as e:
            logger.error(f"Error collecting application metrics: {e}")
            return ApplicationMetrics(
                timestamp=datetime.now(timezone.utc),
                active_connections=0,
                request_count=0,
                error_count=0,
                response_time_avg=0.0,
                memory_usage_mb=0.0,
                cpu_usage_percent=0.0,
                database_connections=0,
                cache_hit_rate=0.0
            )

    def _record_system_metrics(self, metrics: SystemMetrics):
        """Record system metrics."""
        try:
            self.metrics_collector.record_metric("system.cpu_percent", metrics.cpu_percent)
            self.metrics_collector.record_metric("system.memory_percent", metrics.memory_percent)
            self.metrics_collector.record_metric("system.disk_percent", metrics.disk_percent)
            self.metrics_collector.record_metric("system.network_bytes_sent", metrics.network_bytes_sent, MetricType.COUNTER)
            self.metrics_collector.record_metric("system.network_bytes_recv", metrics.network_bytes_recv, MetricType.COUNTER)
            self.metrics_collector.record_metric("system.process_count", metrics.process_count)
            self.metrics_collector.record_metric("system.uptime_seconds", metrics.uptime_seconds)

            if metrics.load_average:
                self.metrics_collector.record_metric("system.load_1min", metrics.load_average[0])
                self.metrics_collector.record_metric("system.load_5min", metrics.load_average[1])
                self.metrics_collector.record_metric("system.load_15min", metrics.load_average[2])

        except Exception as e:
            logger.error(f"Error recording system metrics: {e}")

    def _record_application_metrics(self, metrics: ApplicationMetrics):
        """Record application metrics."""
        try:
            self.metrics_collector.record_metric("app.active_connections", metrics.active_connections)
            self.metrics_collector.record_metric("app.request_count", metrics.request_count, MetricType.COUNTER)
            self.metrics_collector.record_metric("app.error_count", metrics.error_count, MetricType.COUNTER)
            self.metrics_collector.record_metric("app.response_time_avg", metrics.response_time_avg)
            self.metrics_collector.record_metric("app.memory_usage_mb", metrics.memory_usage_mb)
            self.metrics_collector.record_metric("app.cpu_usage_percent", metrics.cpu_usage_percent)
            self.metrics_collector.record_metric("app.database_connections", metrics.database_connections)
            self.metrics_collector.record_metric("app.cache_hit_rate", metrics.cache_hit_rate)

        except Exception as e:
            logger.error(f"Error recording application metrics: {e}")


class AlertManager:
    """Alert management and notification."""

    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics_collector = metrics_collector
        self.alerts: Dict[str, Alert] = {}
        self.alert_rules: List[Dict[str, Any]] = []
        self.alert_callbacks: List[Callable[[Alert], None]] = []
        self.check_interval = 60  # seconds
        self.checking_active = False
        self.check_task: Optional[asyncio.Task] = None

        # Initialize default alert rules
        self._initialize_default_rules()

    def _initialize_default_rules(self):
        """Initialize default alert rules."""
        self.alert_rules = [
            {
                "name": "high_cpu_usage",
                "metric": "system.cpu_percent",
                "condition": "greater_than",
                "threshold": 80.0,
                "severity": AlertSeverity.WARNING,
                "message": "High CPU usage detected: {value}%"
            },
            {
                "name": "high_memory_usage",
                "metric": "system.memory_percent",
                "condition": "greater_than",
                "threshold": 85.0,
                "severity": AlertSeverity.WARNING,
                "message": "High memory usage detected: {value}%"
            },
            {
                "name": "high_disk_usage",
                "metric": "system.disk_percent",
                "condition": "greater_than",
                "threshold": 90.0,
                "severity": AlertSeverity.CRITICAL,
                "message": "High disk usage detected: {value}%"
            },
            {
                "name": "high_error_rate",
                "metric": "app.error_count",
                "condition": "rate_increase",
                "threshold": 10.0,
                "severity": AlertSeverity.ERROR,
                "message": "High error rate detected"
            }
        ]

    async def start_checking(self):
        """Start alert checking."""
        if self.checking_active:
            return

        self.checking_active = True
        self.check_task = asyncio.create_task(self._checking_loop())
        logger.info("Alert checking started")

    async def stop_checking(self):
        """Stop alert checking."""
        self.checking_active = False

        if self.check_task:
            self.check_task.cancel()
            try:
                await self.check_task
            except asyncio.CancelledError:
                pass

        logger.info("Alert checking stopped")

    async def _checking_loop(self):
        """Main alert checking loop."""
        while self.checking_active:
            try:
                await self._check_all_rules()
                await asyncio.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Alert checking error: {e}")
                await asyncio.sleep(self.check_interval)

    async def _check_all_rules(self):
        """Check all alert rules."""
        for rule in self.alert_rules:
            try:
                await self._check_rule(rule)
            except Exception as e:
                logger.error(f"Error checking rule {rule.get('name', 'unknown')}: {e}")

    async def _check_rule(self, rule: Dict[str, Any]):
        """Check a single alert rule."""
        try:
            metric_name = rule["metric"]
            condition = rule["condition"]
            threshold = rule["threshold"]

            # Get latest metric
            latest_metric = self.metrics_collector.get_latest_metric(metric_name)
            if not latest_metric:
                return

            # Check condition
            triggered = False

            if condition == "greater_than":
                triggered = latest_metric.value > threshold
            elif condition == "less_than":
                triggered = latest_metric.value < threshold
            elif condition == "equals":
                triggered = latest_metric.value == threshold
            elif condition == "rate_increase":
                # Check rate of increase over time
                recent_metrics = self.metrics_collector.get_metrics(
                    metric_name,
                    start_time=datetime.now(timezone.utc) - timedelta(minutes=5)
                )
                if len(recent_metrics) >= 2:
                    rate = (recent_metrics[-1].value - recent_metrics[0].value) / len(recent_metrics)
                    triggered = rate > threshold

            # Handle alert
            alert_id = f"{rule['name']}_{metric_name}"

            if triggered:
                if alert_id not in self.alerts or self.alerts[alert_id].resolved:
                    # Create new alert
                    alert = Alert(
                        alert_id=alert_id,
                        name=rule["name"],
                        severity=rule["severity"],
                        message=rule["message"].format(value=latest_metric.value),
                        timestamp=datetime.now(timezone.utc),
                        source="monitoring_system",
                        metadata={"metric": metric_name, "value": latest_metric.value}
                    )

                    self.alerts[alert_id] = alert
                    await self._notify_alert(alert)
            else:
                # Resolve alert if it exists
                if alert_id in self.alerts and not self.alerts[alert_id].resolved:
                    self.alerts[alert_id].resolved = True
                    self.alerts[alert_id].resolved_at = datetime.now(timezone.utc)
                    await self._notify_alert_resolved(self.alerts[alert_id])

        except Exception as e:
            logger.error(f"Error checking rule: {e}")

    async def _notify_alert(self, alert: Alert):
        """Notify about new alert."""
        logger.warning(f"ALERT: {alert.name} - {alert.message}")

        # Call registered callbacks
        for callback in self.alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert)
                else:
                    callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")

    async def _notify_alert_resolved(self, alert: Alert):
        """Notify about resolved alert."""
        logger.info(f"RESOLVED: {alert.name}")

    def add_alert_callback(self, callback: Callable[[Alert], None]):
        """Add alert notification callback."""
        self.alert_callbacks.append(callback)

    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts."""
        return [alert for alert in self.alerts.values() if not alert.resolved]

    def get_all_alerts(self) -> List[Alert]:
        """Get all alerts."""
        return list(self.alerts.values())


class UnifiedMonitoringManager:
    """
    Unified Monitoring & Analytics Manager - SINGLE SOURCE OF TRUTH

    Consolidates all monitoring and analytics functionality.
    """

    def __init__(self):
        self.config = get_config()

        # Initialize components
        self.metrics_collector = MetricsCollector()
        self.analytics_collector = AnalyticsCollector()
        self.system_monitor = SystemMonitor(self.metrics_collector)
        self.alert_manager = AlertManager(self.metrics_collector)

        # State
        self.initialized = False
        self.running = False

        # Background tasks
        self.background_tasks: List[asyncio.Task] = []

    async def initialize(self) -> bool:
        """Initialize the monitoring system."""
        try:
            if self.initialized:
                return True

            logger.info("Initializing unified monitoring system")

            # Start analytics event processing
            analytics_task = asyncio.create_task(self.analytics_collector.process_events())
            self.background_tasks.append(analytics_task)

            # Start system monitoring
            await self.system_monitor.start_monitoring()

            # Start alert checking
            await self.alert_manager.start_checking()

            # Start cleanup task
            cleanup_task = asyncio.create_task(self._cleanup_loop())
            self.background_tasks.append(cleanup_task)

            self.initialized = True
            self.running = True

            logger.info("Unified monitoring system initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize monitoring system: {e}")
            return False

    async def shutdown(self):
        """Shutdown the monitoring system."""
        try:
            logger.info("Shutting down unified monitoring system")

            self.running = False

            # Stop monitoring components
            await self.system_monitor.stop_monitoring()
            await self.alert_manager.stop_checking()

            # Stop analytics processing
            self.analytics_collector.processing = False

            # Cancel background tasks
            for task in self.background_tasks:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            self.background_tasks.clear()
            self.initialized = False

            logger.info("Unified monitoring system shut down successfully")

        except Exception as e:
            logger.error(f"Error shutting down monitoring system: {e}")

    async def _cleanup_loop(self):
        """Background cleanup loop."""
        while self.running:
            try:
                # Clean up old metrics
                self.metrics_collector.cleanup_old_metrics()

                # Sleep for 1 hour
                await asyncio.sleep(3600)

            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")
                await asyncio.sleep(3600)

    # Metrics methods
    def record_metric(self, name: str, value: Union[int, float], metric_type: MetricType = MetricType.GAUGE, tags: Optional[Dict[str, str]] = None, metadata: Optional[Dict[str, Any]] = None):
        """Record a metric."""
        self.metrics_collector.record_metric(name, value, metric_type, tags, metadata)

    def get_metrics(self, name: str, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None) -> List[Metric]:
        """Get metrics by name and time range."""
        return self.metrics_collector.get_metrics(name, start_time, end_time)

    def get_latest_metric(self, name: str) -> Optional[Metric]:
        """Get the latest metric value."""
        return self.metrics_collector.get_latest_metric(name)

    # Analytics methods
    async def track_event(self, event_type: EventType, user_id: Optional[str] = None, session_id: Optional[str] = None, properties: Optional[Dict[str, Any]] = None, context: Optional[Dict[str, Any]] = None, duration_ms: Optional[float] = None):
        """Track an analytics event."""
        event = AnalyticsEvent(
            event_id=str(uuid4()),
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            session_id=session_id,
            properties=properties or {},
            context=context or {},
            duration_ms=duration_ms
        )

        await self.analytics_collector.track_event(event)

    def get_events(self, event_type: Optional[EventType] = None, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None) -> List[AnalyticsEvent]:
        """Get events by type and time range."""
        return self.analytics_collector.get_events(event_type, start_time, end_time)

    # Alert methods
    def add_alert_callback(self, callback: Callable[[Alert], None]):
        """Add alert notification callback."""
        self.alert_manager.add_alert_callback(callback)

    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts."""
        return self.alert_manager.get_active_alerts()

    def get_all_alerts(self) -> List[Alert]:
        """Get all alerts."""
        return self.alert_manager.get_all_alerts()

    # Dashboard and reporting methods
    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health."""
        try:
            # Get latest system metrics
            cpu_metric = self.get_latest_metric("system.cpu_percent")
            memory_metric = self.get_latest_metric("system.memory_percent")
            disk_metric = self.get_latest_metric("system.disk_percent")

            # Determine health status
            health_status = HealthStatus.HEALTHY

            if cpu_metric and cpu_metric.value > 80:
                health_status = HealthStatus.WARNING
            if memory_metric and memory_metric.value > 85:
                health_status = HealthStatus.WARNING
            if disk_metric and disk_metric.value > 90:
                health_status = HealthStatus.CRITICAL

            # Check for active alerts
            active_alerts = self.get_active_alerts()
            if any(alert.severity == AlertSeverity.CRITICAL for alert in active_alerts):
                health_status = HealthStatus.CRITICAL
            elif any(alert.severity == AlertSeverity.ERROR for alert in active_alerts):
                health_status = HealthStatus.WARNING

            return {
                "status": health_status.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metrics": {
                    "cpu_percent": cpu_metric.value if cpu_metric else 0,
                    "memory_percent": memory_metric.value if memory_metric else 0,
                    "disk_percent": disk_metric.value if disk_metric else 0,
                },
                "active_alerts": len(active_alerts),
                "critical_alerts": len([a for a in active_alerts if a.severity == AlertSeverity.CRITICAL])
            }

        except Exception as e:
            logger.error(f"Error getting system health: {e}")
            return {
                "status": HealthStatus.UNKNOWN.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": str(e)
            }

    def get_analytics_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get analytics summary for the specified time period."""
        try:
            start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
            events = self.get_events(start_time=start_time)

            # Count events by type
            event_counts = defaultdict(int)
            user_events = defaultdict(int)

            for event in events:
                event_counts[event.event_type.value] += 1
                if event.user_id:
                    user_events[event.user_id] += 1

            return {
                "period_hours": hours,
                "total_events": len(events),
                "event_types": dict(event_counts),
                "unique_users": len(user_events),
                "most_active_users": sorted(
                    user_events.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10],
                "events_per_hour": len(events) / hours if hours > 0 else 0
            }

        except Exception as e:
            logger.error(f"Error getting analytics summary: {e}")
            return {"error": str(e)}

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics summary."""
        try:
            # Get recent metrics (last hour)
            start_time = datetime.now(timezone.utc) - timedelta(hours=1)

            cpu_metrics = self.get_metrics("system.cpu_percent", start_time)
            memory_metrics = self.get_metrics("system.memory_percent", start_time)
            response_time_metrics = self.get_metrics("app.response_time_avg", start_time)

            def calculate_stats(metrics):
                if not metrics:
                    return {"avg": 0, "min": 0, "max": 0, "current": 0}

                values = [m.value for m in metrics]
                return {
                    "avg": sum(values) / len(values),
                    "min": min(values),
                    "max": max(values),
                    "current": values[-1] if values else 0
                }

            return {
                "cpu": calculate_stats(cpu_metrics),
                "memory": calculate_stats(memory_metrics),
                "response_time": calculate_stats(response_time_metrics),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            logger.error(f"Error getting performance metrics: {e}")
            return {"error": str(e)}


# Global unified monitoring manager instance
unified_monitoring_manager = UnifiedMonitoringManager()

# Backward compatibility functions
async def start_monitoring():
    """Start monitoring using global manager."""
    return await unified_monitoring_manager.initialize()

async def stop_monitoring():
    """Stop monitoring using global manager."""
    await unified_monitoring_manager.shutdown()

def record_metric(name: str, value: Union[int, float], metric_type: str = "gauge", **kwargs):
    """Record metric using global manager."""
    mt = MetricType.GAUGE
    if metric_type.lower() == "counter":
        mt = MetricType.COUNTER
    elif metric_type.lower() == "histogram":
        mt = MetricType.HISTOGRAM
    elif metric_type.lower() == "timer":
        mt = MetricType.TIMER

    unified_monitoring_manager.record_metric(name, value, mt, **kwargs)

async def track_event(event_type: str, **kwargs):
    """Track event using global manager."""
    et = EventType.SYSTEM_EVENT
    try:
        et = EventType(event_type.lower())
    except ValueError:
        pass

    await unified_monitoring_manager.track_event(et, **kwargs)

def get_system_metrics() -> Dict[str, Any]:
    """Get system metrics using global manager."""
    return unified_monitoring_manager.get_system_health()

def get_metrics_history(metric_name: str, hours: int = 24) -> List[Dict[str, Any]]:
    """Get metrics history using global manager."""
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
    metrics = unified_monitoring_manager.get_metrics(metric_name, start_time)

    return [
        {
            "timestamp": m.timestamp.isoformat(),
            "value": m.value,
            "tags": m.tags,
            "metadata": m.metadata
        }
        for m in metrics
    ]

def get_analytics_metrics(**kwargs) -> Dict[str, Any]:
    """Get analytics metrics using global manager."""
    return unified_monitoring_manager.get_analytics_summary(**kwargs)

# Backward compatibility aliases
system_monitor = unified_monitoring_manager
monitoring_manager = unified_monitoring_manager
analytics_manager = unified_monitoring_manager
SystemMonitor = UnifiedMonitoringManager
AnalyticsManager = UnifiedMonitoringManager

__all__ = [
    # Main classes
    'UnifiedMonitoringManager',
    'unified_monitoring_manager',
    'MetricsCollector',
    'AnalyticsCollector',
    'SystemMonitor',
    'AlertManager',

    # Data classes
    'Metric',
    'AnalyticsEvent',
    'SystemMetrics',
    'ApplicationMetrics',
    'Alert',
    'MetricType',
    'EventType',
    'AlertSeverity',
    'HealthStatus',

    # Main functions
    'start_monitoring',
    'stop_monitoring',
    'record_metric',
    'track_event',
    'get_system_metrics',
    'get_metrics_history',
    'get_analytics_metrics',

    # Backward compatibility aliases
    'system_monitor',
    'monitoring_manager',
    'analytics_manager',
    'SystemMonitor',
    'AnalyticsManager',

    # Exceptions
    'MonitoringError',
    'AnalyticsError',
]
