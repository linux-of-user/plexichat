"""Core performance module with fallback implementations."""
__version__ = "0.0.0"
__all__ = ["PerformanceMonitor", "performance_monitor", "measure_performance"]

class PerformanceMonitor:
    def __init__(self):
        pass

performance_monitor = None

def measure_performance(*args, **kwargs):
    pass