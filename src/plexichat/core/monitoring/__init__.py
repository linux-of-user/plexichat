"""
import time
PlexiChat Core Monitoring System - SINGLE SOURCE OF TRUTH

Consolidates ALL monitoring and analytics functionality from:
- core/monitoring/system_monitor.py - INTEGRATED
- core/analytics/analytics_manager.py - INTEGRATED
- infrastructure/analytics/ (all modules) - INTEGRATED
- Feature-specific monitoring components - INTEGRATED

Provides a single, unified interface for all monitoring and analytics operations.
"""

import warnings
import logging
from typing import Any, Dict, List, Optional, Union
from datetime import datetime

# Import unified monitoring system (NEW SINGLE SOURCE OF TRUTH)
try:
    from .unified_monitoring_system import (
        UnifiedMonitoringManager,
        unified_monitoring_manager,
        MetricsCollector,
        AnalyticsCollector,
        SystemMonitor,
        AlertManager,

        # Data classes
        Metric,
        AnalyticsEvent,
        SystemMetrics,
        ApplicationMetrics,
        Alert,
        MetricType,
        EventType,
        AlertSeverity,
        HealthStatus,

        # Main functions
        start_monitoring,
        stop_monitoring,
        record_metric,
        track_event,
        get_system_metrics,
        get_metrics_history,
        get_analytics_metrics,

        # Exceptions
        MonitoringError,
        AnalyticsError,
    )

    # Backward compatibility aliases
    system_monitor = unified_monitoring_manager
    monitoring_manager = unified_monitoring_manager
    analytics_manager = unified_monitoring_manager

    logger = logging.getLogger(__name__)
    logger.info("Unified monitoring system imported successfully")

except ImportError as e:
    # Fallback definitions if unified monitoring system fails to import
    import logging

    warnings.warn(
        f"Failed to import unified monitoring system: {e}. Using fallback monitoring.",
        ImportWarning,
        stacklevel=2
    )

    logger = logging.getLogger(__name__)

    class MonitoringError(Exception):
        pass

    class AnalyticsError(Exception):
        pass

    class MetricType:
        COUNTER = "counter"
        GAUGE = "gauge"
        HISTOGRAM = "histogram"
        TIMER = "timer"

    class EventType:
        USER_LOGIN = "user_login"
        API_REQUEST = "api_request"
        SYSTEM_EVENT = "system_event"

    class AlertSeverity:
        INFO = "info"
        WARNING = "warning"
        ERROR = "error"
        CRITICAL = "critical"

    class HealthStatus:
        HEALTHY = "healthy"
        WARNING = "warning"
        CRITICAL = "critical"
        UNKNOWN = "unknown"

    class SystemMetrics:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class ApplicationMetrics:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class Metric:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class AnalyticsEvent:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class Alert:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class UnifiedMonitoringManager:
        def __init__(self):
            self.initialized = False

        async def initialize(self) -> bool:
            logger.warning("Using fallback monitoring manager")
            self.initialized = True
            return True

        async def shutdown(self):
            self.initialized = False

        def record_metric(self, name: str, value: Union[int, float], **kwargs):
            logger.debug(f"Recording metric: {name} = {value}")

        async def track_event(self, event_type, **kwargs):
            logger.debug(f"Tracking event: {event_type}")

        def get_system_health(self) -> Dict[str, Any]:
            return {
                "status": "unknown",
                "timestamp": datetime.now().isoformat(),
                "metrics": {},
                "active_alerts": 0
            }

        def get_analytics_summary(self, **kwargs) -> Dict[str, Any]:
            return {
                "total_events": 0,
                "event_types": {},
                "unique_users": 0
            }

    unified_monitoring_manager = UnifiedMonitoringManager()
    system_monitor = unified_monitoring_manager
    monitoring_manager = unified_monitoring_manager
    analytics_manager = unified_monitoring_manager
    SystemMonitor = UnifiedMonitoringManager

    async def start_monitoring():
        return await unified_monitoring_manager.initialize()

    async def stop_monitoring():
        await unified_monitoring_manager.shutdown()

    def record_metric(name: str, value: Union[int, float], **kwargs):
        unified_monitoring_manager.record_metric(name, value, **kwargs)

    async def track_event(event_type: str, **kwargs):
        await unified_monitoring_manager.track_event(event_type, **kwargs)

    def get_system_metrics() -> Dict[str, Any]:
        return unified_monitoring_manager.get_system_health()

    def get_metrics_history(metric_name: str, **kwargs) -> List[Dict[str, Any]]:
        return []

    def get_analytics_metrics(**kwargs) -> Dict[str, Any]:
        return unified_monitoring_manager.get_analytics_summary(**kwargs)

    # Fallback classes
    class MetricsCollector:
        pass

    class AnalyticsCollector:
        pass

    class AlertManager:
        pass

# Legacy functions for backward compatibility
async def get_user_analytics(user_id: int, days: int = 30) -> Dict[str, Any]:
    """Get user analytics (backward compatibility)."""
    return {"user_id": user_id, "days": days, "events": []}

async def get_user_engagement_metrics(user_id: int, days: int = 7) -> Dict[str, Any]:
    """Get user engagement metrics (backward compatibility)."""
    return {"user_id": user_id, "engagement_score": 0.0}

# Export all the main classes and functions
__all__ = [
    # Unified monitoring system (NEW SINGLE SOURCE OF TRUTH)
    "UnifiedMonitoringManager",
    "unified_monitoring_manager",
    "MetricsCollector",
    "AnalyticsCollector",
    "AlertManager",

    # Data classes
    "Metric",
    "AnalyticsEvent",
    "SystemMetrics",
    "ApplicationMetrics",
    "Alert",
    "MetricType",
    "EventType",
    "AlertSeverity",
    "HealthStatus",

    # Main functions
    "start_monitoring",
    "stop_monitoring",
    "record_metric",
    "track_event",
    "get_system_metrics",
    "get_metrics_history",
    "get_analytics_metrics",

    # Backward compatibility aliases
    "system_monitor",
    "monitoring_manager",
    "analytics_manager",
    "SystemMonitor",

    # Legacy functions
    "get_user_analytics",
    "get_user_engagement_metrics",

    # Exceptions
    "MonitoringError",
    "AnalyticsError",
]

__version__ = "3.0.0"
