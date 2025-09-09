"""Core scheduler module with fallback implementations."""
try:
    from plexichat.core.utils.fallbacks import (
        TaskScheduler, ScheduledTask, TaskStatus, TaskType,
        schedule_once, schedule_recurring, get_fallback_instance, get_module_version
    )
except ImportError:
    # Retain old fallbacks
    pass

__version__ = get_module_version()
__all__ = ["TaskScheduler", "ScheduledTask", "TaskStatus", "TaskType", "task_scheduler", "schedule_once"]

task_scheduler = get_fallback_instance('TaskScheduler')