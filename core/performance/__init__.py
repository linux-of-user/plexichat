"""Core performance module with fallback implementations."""
try:
    from plexichat.core.utils.fallbacks import (
        PerformanceMonitor, measure_performance, get_fallback_instance,
        get_module_version
    )
except ImportError:
    # Retain old fallbacks
    pass

__version__ = get_module_version()
__all__ = ["PerformanceMonitor", "performance_monitor", "measure_performance"]

performance_monitor = get_fallback_instance('PerformanceMonitor')