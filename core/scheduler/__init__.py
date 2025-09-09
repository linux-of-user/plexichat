"""Core scheduler module with fallback implementations."""

from plexichat.core.utils.fallbacks import (
    ScheduledTask,
    TaskScheduler,
    TaskStatus,
    TaskType,
    get_fallback_instance,
    get_module_version,
    schedule_once,
    schedule_recurring,
)

__version__ = get_module_version()
__all__ = [
    "TaskScheduler",
    "ScheduledTask",
    "TaskStatus",
    "TaskType",
    "task_scheduler",
    "schedule_once",
]

task_scheduler = get_fallback_instance("TaskScheduler")
