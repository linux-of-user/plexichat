"""PlexiChat Scheduler"""

import logging
from typing import Any, Callable, Dict, List
from datetime import datetime

try:
    from .task_scheduler import ()
        TaskScheduler, ScheduledTask, TaskStatus, TaskType,
        task_scheduler, schedule_once, schedule_recurring,
        schedule_cron, cancel_task, get_scheduled_tasks
    )
    logger = logging.getLogger(__name__)
    logger.info("Scheduler modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import scheduler modules: {e}")

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
