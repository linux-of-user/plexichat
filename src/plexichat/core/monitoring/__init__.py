"""
PlexiChat Core Monitoring Module

Comprehensive monitoring and analytics system providing:
- Real-time performance monitoring
- System health tracking
- Performance analytics and trends
- Automated alerting
- Dashboard data aggregation
"""

# Use shared fallback implementations
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

try:
    from plexichat.core.utils.fallbacks import (
        AlertLevel,
        MetricType,
        PerformanceAlert,
        PerformanceMetric,
        SystemHealthStatus,
        get_fallback_instance,
        get_performance_dashboard,
        get_system_health_status,
        record_performance_metric,
        start_performance_monitoring,
        stop_performance_monitoring,
    )

    USE_SHARED_FALLBACKS = True
    logger.info("Using shared fallback implementations for monitoring")
except ImportError:
    # Fallback to local definitions if shared fallbacks unavailable
    USE_SHARED_FALLBACKS = False
    logger.warning("Shared fallbacks unavailable, using local implementations")

if USE_SHARED_FALLBACKS:
    performance_monitor = get_fallback_instance("PerformanceMonitor")
else:
    # Local fallbacks (preserved for compatibility)
    performance_monitor = None

    def start_performance_monitoring() -> None:
        pass

    def stop_performance_monitoring() -> None:
        pass

    def get_performance_dashboard() -> dict[str, Any]:
        return {}

    def get_system_health_status() -> dict[str, Any]:
        return {}

    def record_performance_metric(*args: Any, **kwargs: Any) -> None:
        pass

    class MetricType:
        pass

    class AlertLevel:
        pass

    class PerformanceMetric:
        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)

    class SystemHealthStatus:
        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)

    class PerformanceAlert:
        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)


__all__ = [
    "AlertLevel",
    "MetricType",
    "PerformanceAlert",
    "PerformanceMetric",
    "SystemHealthStatus",
    "get_performance_dashboard",
    "get_system_health_status",
    "performance_monitor",
    "record_performance_metric",
    "start_performance_monitoring",
    "stop_performance_monitoring",
]

from plexichat.core.utils.fallbacks import get_module_version

__version__ = get_module_version()
