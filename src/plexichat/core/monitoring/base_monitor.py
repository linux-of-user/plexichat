"""
Base Monitor Class for Shared Monitoring Logic

Provides common functionality for monitoring components including
collection loops, alert checking, and database persistence.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional

from plexichat.core.database.manager import database_manager

logger = logging.getLogger(__name__)


@dataclass
class AlertRule:
    """Alert rule configuration."""

    name: str
    metric: str
    threshold: float
    operator: str  # >, <, >=, <=, ==, !=
    enabled: bool = True
    cooldown: int = 300  # seconds
    severity: str = "warning"  # info, warning, error, critical
    description: str = ""
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    time_window: int = 0  # Time window for trend analysis (seconds)
    trend_type: str = "instant"  # instant, average, trend_up, trend_down
    notification_channels: List[str] = field(default_factory=lambda: ["log"])
    escalation_policy: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Initialize default values."""
        if not self.conditions:
            self.conditions = []
        if not self.notification_channels:
            self.notification_channels = ["log"]
        if not self.escalation_policy:
            self.escalation_policy = {}


@dataclass
class MetricData:
    """Metric data structure."""

    name: str
    value: float
    unit: str
    timestamp: datetime = field(default_factory=datetime.now)
    tags: Dict[str, str] = field(default_factory=dict)


class MonitorBase(ABC):
    """Base class for all monitoring components with shared functionality."""

    def __init__(
        self, interval_seconds: int = 60, config: Optional[Dict[str, Any]] = None
    ):
        self.interval_seconds = interval_seconds
        self.config = config or {}
        self.running = False
        self.task: Optional[asyncio.Task] = None
        self.metrics: Dict[str, List[MetricData]] = {}
        self.alert_rules: Dict[str, AlertRule] = {}
        self.last_alerts: Dict[str, datetime] = {}
        self.initialized = False

        # Setup default alerts
        self._setup_default_alerts()

        logger.info(f"{self.__class__.__name__} initialized")

    def initialize(self) -> bool:
        """Initialize the monitor."""
        try:
            self.initialized = True
            logger.info(f"{self.__class__.__name__} initialization complete")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize {self.__class__.__name__}: {e}")
            return False

    def _setup_default_alerts(self):
        """Set up default alert rules."""
        default_rules = [
            AlertRule("high_cpu", "cpu_usage_percent", 90.0, ">"),
            AlertRule("high_memory", "memory_percent", 85.0, ">"),
            AlertRule("low_disk", "disk_free_percent", 10.0, "<"),
            AlertRule("high_error_rate", "error_rate", 5.0, ">"),
        ]
        for rule in default_rules:
            self.alert_rules[rule.name] = rule

    async def start(self):
        """Start the monitoring service."""
        if self.running:
            logger.warning(f"{self.__class__.__name__} is already running")
            return

        self.running = True
        self.task = asyncio.create_task(self._collection_loop())
        logger.info(f"{self.__class__.__name__} started")

    async def stop(self):
        """Stop the monitoring service."""
        if not self.running:
            return

        self.running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass

        logger.info(f"{self.__class__.__name__} stopped")

    async def _collection_loop(self):
        """Generic collection loop calling abstract _collect_metrics."""
        while self.running:
            try:
                await self._collect_metrics()
            except Exception as e:
                logger.error(f"Error in collection loop: {e}")

            await asyncio.sleep(self.interval_seconds)

    @abstractmethod
    async def _collect_metrics(self):
        """Abstract method to be overridden by subclasses for specific metric collection."""
        pass

    async def _save_metric_to_db(self, metric: MetricData):
        """Save a metric to the database."""
        try:
            data = {
                "metric_name": metric.name,
                "metric_value": metric.value,
                "unit": metric.unit,
                "timestamp": metric.timestamp.isoformat(),
                "tags": str(metric.tags),
                "source": "system",
                "retention_days": 30,
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
                "metadata": "{}",
            }

            async with database_manager.get_session() as session:
                await session.insert("performance_metrics", data)
                await session.commit()

        except Exception as e:
            logger.error(f"Failed to save metric to database: {e}")

    def _check_alerts(self, metric: MetricData):
        """Check if metric triggers any alerts."""
        for rule_name, rule in self.alert_rules.items():
            if not rule.enabled or rule.metric != metric.name:
                continue

            # Check cooldown
            if rule_name in self.last_alerts:
                time_since_last = datetime.now() - self.last_alerts[rule_name]
                if time_since_last.total_seconds() < rule.cooldown:
                    continue

            # Check threshold
            triggered = False
            if rule.operator == ">":
                triggered = metric.value > rule.threshold
            elif rule.operator == "<":
                triggered = metric.value < rule.threshold
            elif rule.operator == ">=":
                triggered = metric.value >= rule.threshold
            elif rule.operator == "<=":
                triggered = metric.value <= rule.threshold
            elif rule.operator == "==":
                triggered = metric.value == rule.threshold
            elif rule.operator == "!=":
                triggered = metric.value != rule.threshold

            if triggered:
                self._trigger_alert(rule, metric)

    def _trigger_alert(self, rule: AlertRule, metric: MetricData):
        """Trigger an alert."""
        self.last_alerts[rule.name] = datetime.now()
        message = f"ALERT: {rule.name} - {metric.name} {rule.operator} {rule.threshold} (current: {metric.value})"
        logger.warning(message)

        # Save alert to database asynchronously
        asyncio.create_task(self._save_alert_to_db(rule, metric, message))

    async def _save_alert_to_db(
        self, rule: AlertRule, metric: MetricData, message: str
    ):
        """Save an alert to the database."""
        try:
            data = {
                "rule_id": rule.name,
                "rule_name": rule.name,
                "metric_name": metric.name,
                "metric_value": metric.value,
                "threshold": rule.threshold,
                "operator": rule.operator,
                "severity": getattr(rule, "severity", "warning"),
                "message": message,
                "status": "active",
                "acknowledged": False,
                "notification_sent": False,
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
                "metadata": "{}",
            }

            async with database_manager.get_session() as session:
                await session.insert("alerts", data)
                await session.commit()

        except Exception as e:
            logger.error(f"Failed to save alert to database: {e}")

    def record_metric(
        self,
        name: str,
        value: float,
        unit: str = "",
        tags: Optional[Dict[str, str]] = None,
    ):
        """Record a metric value."""
        metric = MetricData(name=name, value=value, unit=unit, tags=tags or {})

        if name not in self.metrics:
            self.metrics[name] = []

        self.metrics[name].append(metric)

        # Keep only last 1000 metrics per name
        if len(self.metrics[name]) > 1000:
            self.metrics[name] = self.metrics[name][-1000:]

        # Save to database asynchronously
        asyncio.create_task(self._save_metric_to_db(metric))

        # Check alert rules
        self._check_alerts(metric)

    def get_metrics(
        self, name: str, since: Optional[datetime] = None
    ) -> List[MetricData]:
        """Get metrics by name."""
        if name not in self.metrics:
            return []

        metrics = self.metrics[name]

        if since:
            metrics = [m for m in metrics if m.timestamp >= since]

        return metrics

    def get_latest_metric(self, name: str) -> Optional[MetricData]:
        """Get the latest metric value."""
        if name not in self.metrics or not self.metrics[name]:
            return None

        return self.metrics[name][-1]

    def add_alert_rule(self, rule: AlertRule):
        """Add an alert rule."""
        self.alert_rules[rule.name] = rule
        logger.info(f"Added alert rule: {rule.name}")

    def remove_alert_rule(self, name: str):
        """Remove an alert rule."""
        if name in self.alert_rules:
            del self.alert_rules[name]
            logger.info(f"Removed alert rule: {name}")

    def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status."""
        status = {
            "initialized": self.initialized,
            "total_metrics": sum(len(metrics) for metrics in self.metrics.values()),
            "metric_types": len(self.metrics),
            "alert_rules": len(self.alert_rules),
            "recent_alerts": len(
                [
                    alert_time
                    for alert_time in self.last_alerts.values()
                    if datetime.now() - alert_time < timedelta(hours=1)
                ]
            ),
        }

        return status
