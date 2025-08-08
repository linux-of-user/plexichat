"""PlexiChat Scheduler"""

import logging
# Typing and datetime imports not used

# Use fallback implementations to avoid import issues
logger = logging.getLogger(__name__)
logger.warning("Using fallback scheduler implementations")

# Fallback implementations
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

__version__ = "1.0.0"
