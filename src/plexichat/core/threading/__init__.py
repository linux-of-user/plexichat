"""PlexiChat Threading"""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from plexichat.core.threading.thread_manager import (
        AsyncThreadManager,
        ThreadManager,
        ThreadTask,
    )

try:
    from plexichat.core.threading.thread_manager import (
        AsyncThreadManager,
        ThreadManager,
        ThreadTask,
        async_thread_manager,
        async_threaded,
        get_task_result,
        run_in_thread,
        submit_task,
        thread_manager,
        threaded,
    )

    logger = logging.getLogger(__name__)
    logger.info("Threading modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import threading modules: {e}")

__all__ = [
    "AsyncThreadManager",
    "ThreadManager",
    "ThreadTask",
    "async_thread_manager",
    "async_threaded",
    "get_task_result",
    "run_in_thread",
    "submit_task",
    "thread_manager",
    "threaded",
]

from plexichat.core.utils.fallbacks import get_module_version

__version__ = get_module_version()
