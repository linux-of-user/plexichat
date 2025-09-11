"""
PlexiChat Thread Manager

Thread management with performance optimization and database integration.
"""

import asyncio
import logging
import threading
import time
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from queue import Empty, Queue
from typing import Any, ParamSpec, TypeVar

try:
    from plexichat.core.database.manager import database_manager  # type: ignore
except ImportError:
    database_manager = None

try:
    from plexichat.core.logging import get_performance_logger  # type: ignore
    from plexichat.core.performance.optimization_engine import (
        PerformanceOptimizationEngine,  # type: ignore
    )
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

P = ParamSpec("P")
T = TypeVar("T")

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None


@dataclass
class ThreadTask:
    """Thread task definition."""

    task_id: str
    function: Callable[..., Any]
    args: tuple[Any, ...] = field(default_factory=tuple)
    kwargs: dict[str, Any] = field(default_factory=dict)
    priority: int = 0
    created_at: float | None = None

    def __post_init__(self) -> None:
        if self.created_at is None:
            self.created_at = time.time()


class ThreadManager:
    """Thread manager with performance optimization."""

    def __init__(self, max_workers: int = 10) -> None:
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.task_queue: Queue[ThreadTask] = Queue()
        self.active_tasks: dict[str, threading.Thread] = {}
        self.completed_tasks: dict[str, Any] = {}
        self.failed_tasks: dict[str, Exception] = {}
        self.performance_logger = performance_logger
        self.db_manager = database_manager
        self._shutdown = False
        self._worker_thread: threading.Thread | None = None
        self._start_worker()

    def _start_worker(self) -> None:
        """Start background worker thread."""
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()

    def _worker_loop(self) -> None:
        """Main worker loop."""
        while not self._shutdown:
            try:
                task = self.task_queue.get(timeout=1.0)
                if task:
                    self._execute_task(task)
                    self.task_queue.task_done()
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Worker loop error: {e}")

    def _execute_task(self, task: ThreadTask) -> None:
        """Execute a single task."""
        try:
            start_time = time.time()

            # Execute task
            result = task.function(*task.args, **task.kwargs)

            # Calculate duration
            duration = time.time() - start_time

            # Store result
            self.completed_tasks[task.task_id] = result

            # Performance tracking
            if self.performance_logger:
                self.performance_logger.record_metric(
                    "thread_task_duration", duration, "seconds"
                )
                self.performance_logger.increment_counter("thread_tasks_completed", 1)

            # Log to database
            if self.db_manager:
                _ = asyncio.create_task(
                    self._log_task_completion(task, result, duration)
                )

        except Exception as e:
            self.failed_tasks[task.task_id] = e
            logger.error(f"Task {task.task_id} failed: {e}")

            if self.performance_logger:
                self.performance_logger.increment_counter("thread_tasks_failed", 1)

    async def _log_task_completion(
        self, task: ThreadTask, result: Any, duration: float
    ) -> None:
        """Log task completion to database."""
        try:
            if self.db_manager:
                query = """
                    INSERT INTO thread_tasks (task_id, function_name, duration, status, created_at, completed_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """
                params: dict[str, Any] = {
                    "task_id": task.task_id,
                    "function_name": task.function.__name__,
                    "duration": duration,
                    "status": "completed",
                    "created_at": task.created_at,
                    "completed_at": time.time(),
                }
                if hasattr(self.db_manager, "execute_query"):
                    await self.db_manager.execute_query(query, params)  # type: ignore
        except Exception as e:
            logger.error(f"Error logging task completion: {e}")

    def submit_task(
        self, task_id: str, function: Callable[..., T], *args: Any, **kwargs: Any
    ) -> str:
        """Submit task for execution."""
        task = ThreadTask(task_id=task_id, function=function, args=args, kwargs=kwargs)
        self.task_queue.put(task)

        if self.performance_logger:
            self.performance_logger.increment_counter("thread_tasks_submitted", 1)

        return task_id

    def submit_batch(self, tasks: list[dict[str, Any]]) -> list[str]:
        """Submit multiple tasks."""
        task_ids = []
        for task_data in tasks:
            task_id = self.submit_task(
                task_data["task_id"],
                task_data["function"],
                *task_data.get("args", ()),
                **task_data.get("kwargs", {}),
            )
            task_ids.append(task_id)
        return task_ids

    def get_result(self, task_id: str, timeout: float | None = None) -> Any:
        """Get task result."""
        start_time = time.time()
        while task_id not in self.completed_tasks and task_id not in self.failed_tasks:
            if timeout and (time.time() - start_time) > timeout:
                raise TimeoutError(f"Task {task_id} timed out")
            time.sleep(0.1)

        if task_id in self.failed_tasks:
            raise self.failed_tasks[task_id]

        return self.completed_tasks.get(task_id)

    def is_completed(self, task_id: str) -> bool:
        """Check if task is completed."""
        return task_id in self.completed_tasks

    def is_failed(self, task_id: str) -> bool:
        """Check if task failed."""
        return task_id in self.failed_tasks

    def get_status(self) -> dict[str, Any]:
        """Get thread manager status."""
        return {
            "max_workers": self.max_workers,
            "active_tasks": len(self.active_tasks),
            "completed_tasks": len(self.completed_tasks),
            "failed_tasks": len(self.failed_tasks),
            "queue_size": self.task_queue.qsize(),
            "shutdown": self._shutdown,
        }

    def shutdown(self, wait: bool = True) -> None:
        """Shutdown thread manager."""
        self._shutdown = True
        if wait:
            self.task_queue.join()
        self.executor.shutdown(wait=wait)


class AsyncThreadManager:
    """Async thread manager for async/await integration."""

    def __init__(self, max_workers: int = 10) -> None:
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.performance_logger = performance_logger

    async def run_in_thread(
        self, function: Callable[..., T], *args: Any, **kwargs: Any
    ) -> T:
        """Run function in thread pool."""
        loop = asyncio.get_event_loop()

        start_time = time.time()
        try:
            result = await loop.run_in_executor(
                self.executor, function, *args, **kwargs
            )

            if self.performance_logger:
                duration = time.time() - start_time
                self.performance_logger.record_metric(
                    "async_thread_duration", duration, "seconds"
                )
                self.performance_logger.increment_counter(
                    "async_thread_tasks_completed", 1
                )

            return result
        except Exception:
            if self.performance_logger:
                self.performance_logger.increment_counter(
                    "async_thread_tasks_failed", 1
                )
            raise

    async def run_batch(self, tasks: list[dict[str, Any]]) -> list[Any]:
        """Run multiple tasks in parallel."""
        futures = []
        for task in tasks:
            future = self.run_in_thread(
                task["function"], *task.get("args", ()), **task.get("kwargs", {})
            )
            futures.append(future)

        return await asyncio.gather(*futures, return_exceptions=True)

    def shutdown(self) -> None:
        """Shutdown async thread manager."""
        self.executor.shutdown(wait=True)


# Global instances
thread_manager = ThreadManager()
async_thread_manager = AsyncThreadManager()


# Convenience functions
def submit_task(
    task_id: str, function: Callable[..., T], *args: Any, **kwargs: Any
) -> str:
    """Submit task to global thread manager."""
    return thread_manager.submit_task(task_id, function, *args, **kwargs)


async def run_in_thread(function: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run function in thread using global async manager."""
    return await async_thread_manager.run_in_thread(function, *args, **kwargs)


def get_task_result(task_id: str, timeout: float | None = None) -> Any:
    """Get task result from global thread manager."""
    return thread_manager.get_result(task_id, timeout)


# Decorators
def threaded(
    task_id: str | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., str]]:
    """Decorator to run function in thread."""

    def decorator(func: Callable[..., Any]) -> Callable[..., str]:
        def wrapper(*args: Any, **kwargs: Any) -> str:
            tid = task_id or f"{func.__name__}_{int(time.time())}"
            return submit_task(tid, func, *args, **kwargs)

        return wrapper

    return decorator


def async_threaded(func: Callable[..., T]) -> Callable[..., Awaitable[T]]:
    """Decorator to run async function in thread."""

    async def wrapper(*args: Any, **kwargs: Any) -> T:
        return await run_in_thread(func, *args, **kwargs)

    return wrapper