"""
PlexiChat Unified Monitoring System

Provides comprehensive monitoring capabilities for the PlexiChat system.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from plexichat.core.database.manager import database_manager

from .base_monitor import AlertRule, MetricData, MonitorBase

logger = logging.getLogger(__name__)


@dataclass
class MetricData:
    """Metric data structure."""

    name: str
    value: float
    unit: str
    timestamp: datetime = field(default_factory=datetime.now)
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class AlertRule:
    """Enhanced alert rule configuration with advanced conditions and policies."""

    name: str
    metric: str
    threshold: float
    operator: str  # >, <, >=, <=, ==, !=
    enabled: bool = True
    cooldown: int = 300  # seconds
    severity: str = "warning"  # info, warning, error, critical
    description: str = ""
    conditions: List[Dict[str, Any]] = field(
        default_factory=list
    )  # Advanced conditions
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
class AlertRule:
    """Alert rule configuration."""

    name: str
    metric: str
    threshold: float
    operator: str  # >, <, >=, <=, ==, !=
    enabled: bool = True
    cooldown: int = 300  # seconds


@dataclass
class AnalyticsEvent:
    """Analytics event data structure."""

    event_type: str
    data: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    user_id: Optional[str] = None
    session_id: Optional[str] = None

    def _setup_default_alerts(self):
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


class UnifiedMonitoringSystem(MonitorBase):
    """Unified monitoring system for PlexiChat."""

    def __init__(self):
        self.metrics: Dict[str, List[MetricData]] = {}
        self.alert_rules: Dict[str, AlertRule] = {}
        self.last_alerts: Dict[str, datetime] = {}
        self.initialized = False

        logger.info("Unified monitoring system initialized")

    def initialize(self) -> bool:
        """Initialize the monitoring system."""
        return super().initialize()

    def _get_alert_rules(self):
        """Override to provide alert rules to base."""
        return self.alert_rules

    # _setup_default_alerts inherited from base

    # _save_metric_to_db inherited from base

    # _save_alert_to_db inherited from base

    # Advanced alert methods inherited from base or to be implemented as overrides if needed

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
        super()._check_alerts(metric)

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

    def track_event(
        self,
        event_type: str,
        data: Dict[str, Any],
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
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
                **data,
            },
        )

        logger.info(f"Tracked event: {event_type} for user {user_id}")


# Global instance
unified_monitoring_system = UnifiedMonitoringSystem()


# Convenience functions
def record_metric(
    name: str, value: float, unit: str = "", tags: Optional[Dict[str, str]] = None
):
    """Record a metric value."""
    unified_monitoring_system.record_metric(name, value, unit, tags)


def get_metrics(name: str, since: Optional[datetime] = None) -> List[MetricData]:
    """Get metrics by name."""
    return unified_monitoring_system.get_metrics(name, since)


def get_latest_metric(name: str) -> Optional[MetricData]:
    """Get the latest metric value."""
    return unified_monitoring_system.get_latest_metric(name)


def get_system_status() -> Dict[str, Any]:
    """Get overall system status."""
    return unified_monitoring_system.get_system_status()


def track_event(
    event_type: str,
    data: Dict[str, Any],
    user_id: Optional[str] = None,
    session_id: Optional[str] = None,
):
    """Track an analytics event."""
    unified_monitoring_system.track_event(event_type, data, user_id, session_id)


def get_analytics_manager():
    """Get the analytics manager (backward compatibility)."""
    return unified_monitoring_system


def get_analytics_metrics(**kwargs) -> Dict[str, Any]:
    """Get analytics metrics (backward compatibility)."""
    return unified_monitoring_system.get_system_status()


# Alias for backward compatibility
UnifiedMonitoringManager = UnifiedMonitoringSystem
AnalyticsCollector = UnifiedMonitoringSystem  # Another alias


# Add EventType enum for compatibility
class EventType:
    """Event types for analytics."""

    USER_ACTION = "user_action"
    SYSTEM_EVENT = "system_event"
    ERROR_EVENT = "error_event"
    PERFORMANCE_EVENT = "performance_event"


# Global instance alias
unified_monitoring_manager = unified_monitoring_system

# Export all
__all__ = [
    "UnifiedMonitoringSystem",
    "UnifiedMonitoringManager",  # Backward compatibility
    "AnalyticsCollector",  # Backward compatibility
    "unified_monitoring_system",
    "unified_monitoring_manager",  # Backward compatibility
    "MetricData",
    "AlertRule",
    "AnalyticsEvent",
    "EventType",
    "record_metric",
    "get_metrics",
    "get_latest_metric",
    "get_system_status",
    "track_event",
    "get_analytics_manager",  # Backward compatibility
    "get_analytics_metrics",  # Backward compatibility
]
