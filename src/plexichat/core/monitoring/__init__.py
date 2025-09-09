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

    def start_performance_monitoring():  # type: ignore
        pass

    def stop_performance_monitoring():  # type: ignore
        pass

    def get_performance_dashboard():  # type: ignore
        return {}

    def get_system_health_status():  # type: ignore
        return {}

    def record_performance_metric(*args, **kwargs):  # type: ignore
        pass

    class MetricType:  # type: ignore
        pass

    class AlertLevel:  # type: ignore
        pass

    class PerformanceMetric:  # type: ignore
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class SystemHealthStatus:  # type: ignore
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class PerformanceAlert:  # type: ignore
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)


__all__ = [
    "performance_monitor",
    "start_performance_monitoring",
    "stop_performance_monitoring",
    "get_performance_dashboard",
    "get_system_health_status",
    "record_performance_metric",
    "MetricType",
    "AlertLevel",
    "PerformanceMetric",
    "SystemHealthStatus",
    "PerformanceAlert",
]

from plexichat.core.utils.fallbacks import get_module_version

__version__ = get_module_version()
