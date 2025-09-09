"""Core monitoring module with fallback implementations."""

from plexichat.core.utils.fallbacks import (
    MetricType,
    get_fallback_instance,
    get_module_version,
    performance_monitor,
    start_performance_monitoring,
    stop_performance_monitoring,
)

__version__ = get_module_version()
__all__ = ["performance_monitor", "start_performance_monitoring", "MetricType"]

performance_monitor = get_fallback_instance("PerformanceMonitor")
