"""PlexiChat Threading"""

import logging
from typing import Any, Callable, Optional

try:
    from plexichat.core.threading.thread_manager import (
        ThreadManager, AsyncThreadManager, ThreadTask,
        thread_manager, async_thread_manager,
        submit_task, run_in_thread, get_task_result,
        threaded, async_threaded
    )
    logger = logging.getLogger(__name__)
    logger.info("Threading modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import threading modules: {e}")

__all__ = [
    "ThreadManager",
    "AsyncThreadManager",
    "ThreadTask",
    "thread_manager",
    "async_thread_manager",
    "submit_task",
    "run_in_thread",
    "get_task_result",
    "threaded",
    "async_threaded",
]

from plexichat.src.plexichat.core.config_manager import get_config

__version__ = get_config("system.version", "0.0.0")
