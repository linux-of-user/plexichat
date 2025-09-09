"""PlexiChat Scheduler"""

import logging
# Typing and datetime imports not used

# Use shared fallback implementations
logger = logging.getLogger(__name__)

try:
    from plexichat.core.utils.fallbacks import (
        TaskScheduler, ScheduledTask, TaskStatus, TaskType,
        schedule_once, schedule_recurring, schedule_cron, cancel_task, get_scheduled_tasks,
        get_fallback_instance
    )
    USE_SHARED_FALLBACKS = True
    logger.info("Using shared fallback implementations for scheduler")
except ImportError:
    # Fallback to local definitions if shared fallbacks unavailable
    USE_SHARED_FALLBACKS = False
    logger.warning("Shared fallbacks unavailable, using local implementations")

if USE_SHARED_FALLBACKS:
    task_scheduler = get_fallback_instance('TaskScheduler')
else:
    # Local fallbacks (preserved for compatibility)
    class TaskScheduler:  # type: ignore
        def __init__(self):
            pass

    class ScheduledTask:  # type: ignore
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class TaskStatus:  # type: ignore
        PENDING = "pending"
        RUNNING = "running"
        COMPLETED = "completed"
        FAILED = "failed"
        CANCELLED = "cancelled"

    class TaskType:  # type: ignore
        ONCE = "once"
        RECURRING = "recurring"
        CRON = "cron"

    task_scheduler = None

    def schedule_once(*args, **kwargs):  # type: ignore
        return None

    def schedule_recurring(*args, **kwargs):  # type: ignore
        return None

    def schedule_cron(*args, **kwargs):  # type: ignore
        return None

    def cancel_task(*args, **kwargs):  # type: ignore
        return False

    def get_scheduled_tasks(*args, **kwargs):  # type: ignore
        return []

__all__ = [
    "TaskScheduler",
    "ScheduledTask",
    "TaskStatus",
    "TaskType",
    "task_scheduler",
    "schedule_once",
    "schedule_recurring",
    "schedule_cron",
    "cancel_task",
    "get_scheduled_tasks",
]

from plexichat.core.utils.fallbacks import get_module_version

__version__ = get_module_version()
