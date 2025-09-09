"""Core monitoring module with fallback implementations."""

try:
    from plexichat.core.utils.fallbacks import (
        MetricType,
        get_fallback_instance,
        get_module_version,
        performance_monitor,
        start_performance_monitoring,
        stop_performance_monitoring,
    )
except ImportError:
    # Retain old fallbacks
    pass

__version__ = get_module_version()
__all__ = ["performance_monitor", "start_performance_monitoring", "MetricType"]

performance_monitor = get_fallback_instance("PerformanceMonitor")
