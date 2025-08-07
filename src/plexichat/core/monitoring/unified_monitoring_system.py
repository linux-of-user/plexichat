"""
PlexiChat Unified Monitoring System

Provides comprehensive monitoring capabilities for the PlexiChat system.
"""

import logging
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta

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
    
    def record_metric(self, name: str, value: float, unit: str = "", tags: Optional[Dict[str, str]] = None):
        """Record a metric value."""
        metric = MetricData(
            name=name,
            value=value,
            unit=unit,
            tags=tags or {}
        )
        
        if name not in self.metrics:
            self.metrics[name] = []
        
        self.metrics[name].append(metric)
        
        # Keep only last 1000 metrics per name
        if len(self.metrics[name]) > 1000:
            self.metrics[name] = self.metrics[name][-1000:]
        
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
        logger.warning(f"ALERT: {rule.name} - {metric.name} {rule.operator} {rule.threshold} (current: {metric.value})")
    
    def get_metrics(self, name: str, since: Optional[datetime] = None) -> List[MetricData]:
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
            "recent_alerts": len([
                alert_time for alert_time in self.last_alerts.values()
                if datetime.now() - alert_time < timedelta(hours=1)
            ])
        }
        
        return status
    
    def track_event(self, event_type: str, data: Dict[str, Any], user_id: Optional[str] = None, session_id: Optional[str] = None):
        """Track an analytics event."""
        event = AnalyticsEvent(
            event_type=event_type,
            data=data,
            user_id=user_id,
            session_id=session_id
        )
        
        # Store event as a metric for now
        self.record_metric(f"event_{event_type}", 1, "count", {
            "user_id": user_id or "anonymous",
            "session_id": session_id or "unknown",
            **data
        })
        
        logger.info(f"Tracked event: {event_type} for user {user_id}")


# Global instance
unified_monitoring_system = UnifiedMonitoringSystem()


# Convenience functions
def record_metric(name: str, value: float, unit: str = "", tags: Optional[Dict[str, str]] = None):
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


def track_event(event_type: str, data: Dict[str, Any], user_id: Optional[str] = None, session_id: Optional[str] = None):
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
