"""PlexiChat Scheduler"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from plexichat.core.scheduler.task_scheduler import (
        ScheduledTask,
        TaskScheduler,
        TaskStatus,
        TaskType,
        cancel_task,
        get_scheduled_tasks,
        schedule_cron,
        schedule_once,
        schedule_recurring,
        task_scheduler,
    )

    logger.info("Scheduler modules imported successfully")

except ImportError as e:
    logger.warning(f"Could not import scheduler modules: {e}")

    # Create stub classes and functions for type checking
    class TaskScheduler:  # type: ignore
        def __init__(self) -> None:
            pass

    class ScheduledTask:  # type: ignore
        def __init__(self, **kwargs: Any) -> None:
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

    async def schedule_once(*args: Any, **kwargs: Any) -> str | None:
        return None

    async def schedule_recurring(*args: Any, **kwargs: Any) -> str | None:
        return None

    async def schedule_cron(*args: Any, **kwargs: Any) -> str | None:
        return None

    async def cancel_task(*args: Any, **kwargs: Any) -> bool:
        return False

    def get_scheduled_tasks(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return []


__all__ = [
    "ScheduledTask",
    "TaskScheduler",
    "TaskStatus",
    "TaskType",
    "cancel_task",
    "get_scheduled_tasks",
    "schedule_cron",
    "schedule_once",
    "schedule_recurring",
    "task_scheduler",
]

from plexichat.core.utils.fallbacks import get_module_version

__version__ = get_module_version()
