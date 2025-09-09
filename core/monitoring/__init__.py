"""Core monitoring module with fallback implementations."""
__version__ = "0.0.0"
__all__ = ["performance_monitor", "start_performance_monitoring", "MetricType"]

performance_monitor = None

class MetricType:
    CPU = 1
    MEMORY = 2
    DISK = 3

def start_performance_monitoring(*args, **kwargs):
    pass

def stop_performance_monitoring(*args, **kwargs):
    pass