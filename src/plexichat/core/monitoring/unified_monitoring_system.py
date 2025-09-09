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


class UnifiedMonitoringSystem:
    """Unified monitoring system for PlexiChat."""

    def __init__(self):
        self.metrics: Dict[str, List[MetricData]] = {}
        self.alert_rules: Dict[str, AlertRule] = {}
        self.last_alerts: Dict[str, datetime] = {}
        self.initialized = False

        logger.info("Unified monitoring system initialized")

    def initialize(self) -> bool:
        """Initialize the monitoring system."""
        try:
            # Set up default alert rules
            self._setup_default_alerts()
            self.initialized = True
            logger.info("Unified monitoring system initialization complete")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize monitoring system: {e}")
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

    async def _save_alert_to_db(
        self, rule: AlertRule, metric: MetricData, message: str
    ):
        """Save an alert to the database."""
        try:
            data = {
                "rule_id": rule.name,  # Using rule name as ID for simplicity
                "rule_name": rule.name,
                "metric_name": metric.name,
                "metric_value": metric.value,
                "threshold": rule.threshold,
                "operator": rule.operator,
                "severity": "warning",  # Default severity
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

    def _check_alerts(self, metric: MetricData):
        """Check if metric triggers any alerts with advanced conditions."""
        for rule_name, rule in self.alert_rules.items():
            if not rule.enabled or rule.metric != metric.name:
                continue

            # Check cooldown
            if rule_name in self.last_alerts:
                time_since_last = datetime.now() - self.last_alerts[rule_name]
                if time_since_last.total_seconds() < rule.cooldown:
                    continue

            # Check if alert should trigger based on rule type
            triggered = self._evaluate_alert_rule(rule, metric)

            if triggered:
                self._trigger_alert(rule, metric)

    def _evaluate_alert_rule(self, rule: AlertRule, metric: MetricData) -> bool:
        """Evaluate an alert rule with advanced conditions."""
        try:
            # Handle different trend types
            if rule.trend_type == "instant":
                return self._check_instant_condition(rule, metric)
            elif rule.trend_type == "average":
                return self._check_average_condition(rule, metric)
            elif rule.trend_type == "trend_up":
                return self._check_trend_condition(rule, metric, "up")
            elif rule.trend_type == "trend_down":
                return self._check_trend_condition(rule, metric, "down")
            else:
                return self._check_instant_condition(rule, metric)
        except Exception as e:
            logger.error(f"Error evaluating alert rule {rule.name}: {e}")
            return False

    def _check_instant_condition(self, rule: AlertRule, metric: MetricData) -> bool:
        """Check instant condition against threshold."""
        if rule.operator == ">":
            return metric.value > rule.threshold
        elif rule.operator == "<":
            return metric.value < rule.threshold
        elif rule.operator == ">=":
            return metric.value >= rule.threshold
        elif rule.operator == "<=":
            return metric.value <= rule.threshold
        elif rule.operator == "==":
            return metric.value == rule.threshold
        elif rule.operator == "!=":
            return metric.value != rule.threshold
        return False

    def _check_average_condition(self, rule: AlertRule, metric: MetricData) -> bool:
        """Check average condition over time window."""
        if rule.time_window <= 0:
            return self._check_instant_condition(rule, metric)

        # Get metrics from the time window
        since = datetime.now() - timedelta(seconds=rule.time_window)
        recent_metrics = self.get_metrics(rule.metric, since)

        if not recent_metrics:
            return False

        # Calculate average
        avg_value = sum(m.value for m in recent_metrics) / len(recent_metrics)

        # Check condition against average
        temp_metric = MetricData(
            name=metric.name,
            value=avg_value,
            unit=metric.unit,
            timestamp=metric.timestamp,
            tags=metric.tags,
        )

        return self._check_instant_condition(rule, temp_metric)

    def _check_trend_condition(
        self, rule: AlertRule, metric: MetricData, direction: str
    ) -> bool:
        """Check trend condition (increasing or decreasing)."""
        if rule.time_window <= 0:
            return False

        # Get metrics from the time window
        since = datetime.now() - timedelta(seconds=rule.time_window)
        recent_metrics = self.get_metrics(rule.metric, since)

        if len(recent_metrics) < 2:
            return False

        # Calculate trend (simple linear regression slope)
        n = len(recent_metrics)

    def _trigger_alert(self, rule: AlertRule, metric: MetricData):
        """Trigger an alert with enhanced features."""
        self.last_alerts[rule.name] = datetime.now()

        # Create detailed message
        message = self._create_alert_message(rule, metric)

        # Log based on severity
        if rule.severity == "critical":
            logger.critical(message)
        elif rule.severity == "error":
            logger.error(message)
        elif rule.severity == "warning":
            logger.warning(message)
        else:
            logger.info(message)

        # Send notifications to configured channels
        self._send_notifications(rule, metric, message)

        # Save alert to database asynchronously
        asyncio.create_task(self._save_alert_to_db(rule, metric, message))

    def _create_alert_message(self, rule: AlertRule, metric: MetricData) -> str:
        """Create a detailed alert message."""
        trend_info = ""
        if rule.trend_type != "instant":
            trend_info = f" ({rule.trend_type} over {rule.time_window}s)"

        condition_info = ""
        if rule.conditions:
            condition_info = f" with {len(rule.conditions)} additional conditions"

        return (
            f"ALERT [{rule.severity.upper()}]: {rule.name} - "
            f"{metric.name} {rule.operator} {rule.threshold} "
            f"(current: {metric.value:.2f}){trend_info}{condition_info}. "
            f"{rule.description}"
        )

    def _send_notifications(self, rule: AlertRule, metric: MetricData, message: str):
        """Send notifications to configured channels."""
        for channel in rule.notification_channels:
            try:
                if channel == "log":
                    # Already logged above
                    pass
                elif channel == "email":
                    self._send_email_notification(rule, metric, message)
                elif channel == "webhook":
                    self._send_webhook_notification(rule, metric, message)
                elif channel == "slack":
                    self._send_slack_notification(rule, metric, message)
                else:
                    logger.warning(f"Unknown notification channel: {channel}")
            except Exception as e:
                logger.error(f"Failed to send notification to {channel}: {e}")

    def _send_email_notification(
        self, rule: AlertRule, metric: MetricData, message: str
    ):
        """Send email notification."""
        # Placeholder for email implementation
        logger.info(f"Email notification would be sent: {message}")

    def _send_webhook_notification(
        self, rule: AlertRule, metric: MetricData, message: str
    ):
        """Send webhook notification."""
        # Placeholder for webhook implementation
        logger.info(f"Webhook notification would be sent: {message}")

    def _send_slack_notification(
        self, rule: AlertRule, metric: MetricData, message: str
    ):
        """Send Slack notification."""
        # Placeholder for Slack implementation
        logger.info(f"Slack notification would be sent: {message}")

    async def _save_alert_to_db(
        self, rule: AlertRule, metric: MetricData, message: str
    ):
        """Save an alert to the database with enhanced fields."""
        try:
            data = {
                "rule_id": rule.name,  # Using rule name as ID for simplicity
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
                "metadata": str(
                    {
                        "trend_type": getattr(rule, "trend_type", "instant"),
                        "time_window": getattr(rule, "time_window", 0),
                        "conditions": getattr(rule, "conditions", []),
                        "notification_channels": getattr(
                            rule, "notification_channels", []
                        ),
                        "escalation_policy": getattr(rule, "escalation_policy", {}),
                    }
                ),
            }

            async with database_manager.get_session() as session:
                await session.insert("alerts", data)
                await session.commit()

        except Exception as e:
            logger.error(f"Failed to save alert to database: {e}")
        x_values = [
            (m.timestamp - recent_metrics[0].timestamp).total_seconds()
            for m in recent_metrics
        ]
        y_values = [m.value for m in recent_metrics]

        # Calculate slope
        x_mean = sum(x_values) / n
        y_mean = sum(y_values) / n

        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, y_values))
        denominator = sum((x - x_mean) ** 2 for x in x_values)

        if denominator == 0:
            return False

        slope = numerator / denominator

        # Check trend direction
        if direction == "up":
            return slope > rule.threshold
        elif direction == "down":
            return slope < -rule.threshold

        return False

    def _check_advanced_conditions(self, rule: AlertRule, metric: MetricData) -> bool:
        """Check advanced conditions (multiple conditions with AND/OR logic)."""
        if not rule.conditions:
            return True

        results = []
        for condition in rule.conditions:
            condition_type = condition.get("type", "and")
            metric_name = condition.get("metric", rule.metric)
            operator = condition.get("operator", rule.operator)
            threshold = condition.get("threshold", rule.threshold)

            # Get the metric to check
            check_metric = (
                metric
                if metric_name == rule.metric
                else self.get_latest_metric(metric_name)
            )
            if not check_metric:
                results.append(False)
                continue

            # Evaluate condition
            if operator == ">":
                result = check_metric.value > threshold
            elif operator == "<":
                result = check_metric.value < threshold
            elif operator == ">=":
                result = check_metric.value >= threshold
            elif operator == "<=":
                result = check_metric.value <= threshold
            elif operator == "==":
                result = check_metric.value == threshold
            elif operator == "!=":
                result = check_metric.value != threshold
            else:
                result = False

            results.append(result)

        # Combine results based on condition types
        final_result = results[0] if results else True
        for i, result in enumerate(results[1:], 1):
            condition_type = rule.conditions[i - 1].get("type", "and")
            if condition_type.lower() == "and":
                final_result = final_result and result
            elif condition_type.lower() == "or":
                final_result = final_result or result

        return final_result

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
