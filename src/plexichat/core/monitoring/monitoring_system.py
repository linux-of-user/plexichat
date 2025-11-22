"""
PlexiChat Monitoring System

Provides comprehensive monitoring capabilities for the PlexiChat system.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import logging
from typing import Any

from .base_monitor import AlertRule, MetricData, MonitorBase

logger = logging.getLogger(__name__)


@dataclass
class AnalyticsEvent:
    """Analytics event data structure."""

    event_type: str
    data: dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    user_id: str | None = None
    session_id: str | None = None


class MonitoringSystem(MonitorBase):
    """Monitoring system for PlexiChat."""

    def __init__(self) -> None:
        super().__init__()
        self.metrics: dict[str, list[MetricData]] = {}
        self.alert_rules: dict[str, AlertRule] = {}
        self.last_alerts: dict[str, datetime] = {}
        self.initialized = False

        logger.info("Monitoring system initialized")

    def initialize(self) -> bool:
        """Initialize the monitoring system."""
        return super().initialize()

    def _setup_default_alerts(self) -> None:
        """Set up default alert rules with enhanced features."""
        default_rules = [
            AlertRule(
                name="high_cpu",
                metric="cpu_usage_percent",
                threshold=90.0,
                operator=">",
                severity="warning",
                description="High CPU usage detected",
                trend_type="average",
                time_window=300,  # 5 minutes
                notification_channels=["log", "email"],
            ),
            AlertRule(
                name="high_memory",
                metric="memory_percent",
                threshold=85.0,
                operator=">",
                severity="warning",
                description="High memory usage detected",
                trend_type="instant",
                notification_channels=["log"],
            ),
            AlertRule(
                name="low_disk",
                metric="disk_free_percent",
                threshold=10.0,
                operator="<",
                severity="error",
                description="Low disk space warning",
                trend_type="instant",
                notification_channels=["log", "email"],
            ),
            AlertRule(
                name="high_error_rate",
                metric="error_rate",
                threshold=5.0,
                operator=">",
                severity="error",
                description="High error rate detected",
                trend_type="average",
                time_window=600,  # 10 minutes
                notification_channels=["log", "webhook"],
            ),
            AlertRule(
                name="cpu_trend_up",
                metric="cpu_usage_percent",
                threshold=10.0,  # 10% increase per minute
                operator=">",
                severity="info",
                description="CPU usage trending upward",
                trend_type="trend_up",
                time_window=300,  # 5 minutes
                notification_channels=["log"],
            ),
        ]

        for rule in default_rules:
            self.alert_rules[rule.name] = rule

    async def _collect_metrics(self) -> None:
        """Collect current system metrics."""
        # Basic system metrics
        timestamp = datetime.now(UTC)

        # System health status
        self.record_metric(
            "system_health_status",
            1.0,  # 1.0 = healthy, 0.0 = unhealthy
            "status",
            {"status": "healthy"},
        )

    def record_metric(
        self,
        name: str,
        value: float,
        unit: str = "",
        tags: dict[str, str] | None = None,
    ) -> None:
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

    def get_metrics(self, name: str, since: datetime | None = None) -> list[MetricData]:
        """Get metrics by name."""
        if name not in self.metrics:
            return []

        metrics = self.metrics[name]

        if since:
            metrics = [m for m in metrics if m.timestamp >= since]

        return metrics

    def get_latest_metric(self, name: str) -> MetricData | None:
        """Get the latest metric value."""
        if name not in self.metrics or not self.metrics[name]:
            return None

        return self.metrics[name][-1]

    def add_alert_rule(self, rule: AlertRule) -> None:
        """Add an alert rule."""
        self.alert_rules[rule.name] = rule
        logger.info(f"Added alert rule: {rule.name}")

    def remove_alert_rule(self, name: str) -> None:
        """Remove an alert rule."""
        if name in self.alert_rules:
            del self.alert_rules[name]
            logger.info(f"Removed alert rule: {name}")

    def get_system_status(self) -> dict[str, Any]:
        """Get overall system status."""
        recent_alerts = len(
            [
                alert_time
                for alert_time in self.last_alerts.values()
                if datetime.now() - alert_time < timedelta(hours=1)
            ]
        )

        status = {
            "initialized": self.initialized,
            "total_metrics": sum(len(metrics) for metrics in self.metrics.values()),
            "metric_types": len(self.metrics),
            "alert_rules": len(self.alert_rules),
            "recent_alerts": recent_alerts,
        }

        return status

    def track_event(
        self,
        event_type: str,
        data: dict[str, Any],
        user_id: str | None = None,
        session_id: str | None = None,
    ) -> None:
        """Track an analytics event."""
        event = AnalyticsEvent(
            event_type=event_type, data=data, user_id=user_id, session_id=session_id
        )

        # Store event as a metric for now
        self.record_metric(
            f"event_{event_type}",
            1,
            "count",
            {
                "user_id": user_id or "anonymous",
                "session_id": session_id or "unknown",
                **{
                    k: str(v) for k, v in data.items()
                },  # Convert all values to strings for tags
            },
        )

        logger.info(f"Tracked event: {event_type} for user {user_id}")


# Global instance
monitoring_system = MonitoringSystem()


# Convenience functions
def record_metric(
    name: str, value: float, unit: str = "", tags: dict[str, str] | None = None
) -> None:
    """Record a metric value."""
    monitoring_system.record_metric(name, value, unit, tags)


def get_metrics(name: str, since: datetime | None = None) -> list[MetricData]:
    """Get metrics by name."""
    return monitoring_system.get_metrics(name, since)


def get_latest_metric(name: str) -> MetricData | None:
    """Get the latest metric value."""
    return monitoring_system.get_latest_metric(name)


def get_system_status() -> dict[str, Any]:
    """Get overall system status."""
    return monitoring_system.get_system_status()


def track_event(
    event_type: str,
    data: dict[str, Any],
    user_id: str | None = None,
    session_id: str | None = None,
) -> None:
    """Track an analytics event."""
    monitoring_system.track_event(event_type, data, user_id, session_id)


def get_analytics_manager() -> MonitoringSystem:
    """Get the analytics manager (backward compatibility)."""
    return monitoring_system


def get_analytics_metrics(**kwargs: Any) -> dict[str, Any]:
    """Get analytics metrics (backward compatibility)."""
    return monitoring_system.get_system_status()


# Export all
__all__ = [
    "AlertRule",
    "AnalyticsCollector",  # Backward compatibility
    "AnalyticsEvent",
    "EventType",
    "MetricData",
    "MonitoringSystem",
    "get_analytics_manager",  # Backward compatibility
    "get_analytics_metrics",  # Backward compatibility
    "get_latest_metric",
    "get_metrics",
    "get_system_status",
    "record_metric",
    "track_event",
    "monitoring_system",
]
