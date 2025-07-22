"""
PlexiChat Background Tasks Service

Background task management and execution system.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import uuid
import json

try:
    from plexichat.app.logger_config import get_logger
    from plexichat.core.config import settings
except ImportError:
    get_logger = lambda name: logging.getLogger(name)
    settings = {}

logger = get_logger(__name__)

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"

class TaskPriority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class TaskResult:
    """Task execution result."""
    success: bool
    result: Any = None
    error: Optional[str] = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class BackgroundTask:
    """Background task definition."""
    id: str
    name: str
    func: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    max_retries: int = 3
    retry_delay: float = 1.0
    timeout: Optional[float] = None
    scheduled_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    status: TaskStatus = TaskStatus.PENDING
    retries: int = 0
    result: Optional[TaskResult] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class TaskQueue:
    """Priority-based task queue."""

    def __init__(self):
        self.tasks: Dict[str, BackgroundTask] = {}
        self.pending_tasks: List[str] = []
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()

    async def add_task(self, task: BackgroundTask) -> None:
        """Add task to queue."""
        async with self._lock:
            self.tasks[task.id] = task

            # Insert in priority order
            inserted = False
            for i, task_id in enumerate(self.pending_tasks):
                existing_task = self.tasks[task_id]
                if task.priority.value > existing_task.priority.value:
                    self.pending_tasks.insert(i, task.id)
                    inserted = True
                    break

            if not inserted:
                self.pending_tasks.append(task.id)

            logger.debug(f"Added task {task.id} to queue (priority: {task.priority.name})")

    async def get_next_task(self) -> Optional[BackgroundTask]:
        """Get next task from queue."""
        async with self._lock:
            while self.pending_tasks:
                task_id = self.pending_tasks.pop(0)
                task = self.tasks.get(task_id)

                if task and task.status == TaskStatus.PENDING:
                    # Check if task is scheduled for future
                    if task.scheduled_at and task.scheduled_at > datetime.now():
                        # Re-add to queue for later
                        self.pending_tasks.append(task_id)
                        continue

                    task.status = TaskStatus.RUNNING
                    return task

            return None

    async def complete_task(self, task_id: str, result: TaskResult) -> None:
        """Mark task as completed."""
        async with self._lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                task.result = result
                task.status = TaskStatus.COMPLETED if result.success else TaskStatus.FAILED

                # Remove from running tasks
                if task_id in self.running_tasks:
                    del self.running_tasks[task_id]

                logger.debug(f"Task {task_id} completed with status: {task.status.value}")

    async def retry_task(self, task_id: str) -> bool:
        """Retry a failed task."""
        async with self._lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]

                if task.retries < task.max_retries:
                    task.retries += 1
                    task.status = TaskStatus.RETRYING

                    # Schedule retry with delay
                    task.scheduled_at = datetime.now() + timedelta(seconds=task.retry_delay * task.retries)

                    # Re-add to pending queue
                    self.pending_tasks.append(task_id)

                    logger.info(f"Retrying task {task_id} (attempt {task.retries}/{task.max_retries})")
                    return True
                else:
                    task.status = TaskStatus.FAILED
                    logger.error(f"Task {task_id} failed after {task.max_retries} retries")
                    return False

            return False

    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a task."""
        async with self._lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]

                # Cancel if running
                if task_id in self.running_tasks:
                    self.running_tasks[task_id].cancel()
                    del self.running_tasks[task_id]

                # Remove from pending queue
                if task_id in self.pending_tasks:
                    self.pending_tasks.remove(task_id)

                task.status = TaskStatus.CANCELLED
                logger.info(f"Cancelled task {task_id}")
                return True

            return False

    async def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task status."""
        if task_id in self.tasks:
            task = self.tasks[task_id]
            return {
                "id": task.id,
                "name": task.name,
                "status": task.status.value,
                "priority": task.priority.name,
                "retries": task.retries,
                "max_retries": task.max_retries,
                "created_at": task.created_at.isoformat(),
                "scheduled_at": task.scheduled_at.isoformat() if task.scheduled_at else None,
                "result": {
                    "success": task.result.success,
                    "error": task.result.error,
                    "execution_time": task.result.execution_time
                } if task.result else None
            }

        return None

    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        async with self._lock:
            stats = {
                "total_tasks": len(self.tasks),
                "pending_tasks": len(self.pending_tasks),
                "running_tasks": len(self.running_tasks),
                "status_counts": {}
            }

            # Count by status
            for task in self.tasks.values():
                status = task.status.value
                stats["status_counts"][status] = stats["status_counts"].get(status, 0) + 1

            return stats

class BackgroundTaskManager:
    """Background task manager."""

    def __init__(self, max_workers: int = 5):
        self.max_workers = max_workers
        self.queue = TaskQueue()
        self.workers: List[asyncio.Task] = []
        self.running = False
        self.shutdown_event = asyncio.Event()

    async def start(self) -> None:
        """Start the task manager."""
        if self.running:
            return

        self.running = True
        self.shutdown_event.clear()

        # Start worker tasks
        for i in range(self.max_workers):
            worker = asyncio.create_task(self._worker(f"worker-{i}"))
            self.workers.append(worker)

        logger.info(f"Started background task manager with {self.max_workers} workers")

    async def stop(self) -> None:
        """Stop the task manager."""
        if not self.running:
            return

        self.running = False
        self.shutdown_event.set()

        # Cancel all workers
        for worker in self.workers:
            worker.cancel()

        # Wait for workers to finish
        await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers.clear()

        logger.info("Stopped background task manager")

    async def _worker(self, worker_name: str) -> None:
        """Worker task that processes the queue."""
        logger.debug(f"Started worker: {worker_name}")

        try:
            while self.running:
                try:
                    # Get next task
                    task = await self.queue.get_next_task()

                    if task is None:
                        # No tasks available, wait a bit
                        await asyncio.sleep(0.1)
                        continue

                    logger.debug(f"Worker {worker_name} executing task {task.id}")

                    # Execute task
                    result = await self._execute_task(task)

                    # Handle result
                    await self.queue.complete_task(task.id, result)

                    if not result.success and task.retries < task.max_retries:
                        await self.queue.retry_task(task.id)

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Worker {worker_name} error: {e}")
                    await asyncio.sleep(1)

        except asyncio.CancelledError:
            pass

        logger.debug(f"Stopped worker: {worker_name}")

    async def _execute_task(self, task: BackgroundTask) -> TaskResult:
        """Execute a single task."""
        start_time = datetime.now()

        try:
            # Execute with timeout if specified
            if task.timeout:
                result = await asyncio.wait_for()
                    task.func(*task.args, **task.kwargs),
                    timeout=task.timeout
                )
            else:
                result = await task.func(*task.args, **task.kwargs)

            execution_time = (datetime.now() - start_time).total_seconds()

            return TaskResult()
                success=True,
                result=result,
                execution_time=execution_time
            )

        except asyncio.TimeoutError:
            execution_time = (datetime.now() - start_time).total_seconds()
            return TaskResult()
                success=False,
                error=f"Task timed out after {task.timeout} seconds",
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            return TaskResult()
                success=False,
                error=str(e),
                execution_time=execution_time
            )

    async def submit_task()
        self,
        func: Callable,
        *args,
        name: Optional[str] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        timeout: Optional[float] = None,
        scheduled_at: Optional[datetime] = None,
        **kwargs
    ) -> str:
        """Submit a task for background execution."""

        task_id = str(uuid.uuid4())
        task_name = name or f"{func.__name__}_{task_id[:8]}"

        task = BackgroundTask()
            id=task_id,
            name=task_name,
            func=func,
            args=args,
            kwargs=kwargs,
            priority=priority,
            max_retries=max_retries,
            retry_delay=retry_delay,
            timeout=timeout,
            scheduled_at=scheduled_at
        )

        await self.queue.add_task(task)

        logger.info(f"Submitted task {task_id}: {task_name}")
        return task_id

    async def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task status."""
        return await self.queue.get_task_status(task_id)

    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a task."""
        return await self.queue.cancel_task(task_id)

    async def get_stats(self) -> Dict[str, Any]:
        """Get manager statistics."""
        queue_stats = await self.queue.get_queue_stats()

        return {
            "running": self.running,
            "max_workers": self.max_workers,
            "active_workers": len([w for w in self.workers if not w.done()]),
            "queue_stats": queue_stats
        }

# Global task manager
task_manager = BackgroundTaskManager()
    max_workers=settings.get('background_tasks', {}).get('max_workers', 5)
)

# Convenience functions
async def submit_task(func: Callable, *args, **kwargs) -> str:
    """Submit a background task."""
    return await task_manager.submit_task(func, *args, **kwargs)

async def submit_scheduled_task()
    func: Callable,
    scheduled_at: datetime,
    *args,
    **kwargs
) -> str:
    """Submit a scheduled background task."""
    return await task_manager.submit_task()
        func, *args, scheduled_at=scheduled_at, **kwargs
    )

async def submit_high_priority_task(func: Callable, *args, **kwargs) -> str:
    """Submit a high priority background task."""
    return await task_manager.submit_task()
        func, *args, priority=TaskPriority.HIGH, **kwargs
    )

# Example background tasks
async def cleanup_old_files():
    """Example cleanup task."""
    logger.info("Running cleanup task...")
    await asyncio.sleep(2)  # Simulate work
    logger.info("Cleanup completed")
    return {"files_cleaned": 42}

async def send_notification(user_id: str, message: str):
    """Example notification task."""
    logger.info(f"Sending notification to user {user_id}: {message}")
    await asyncio.sleep(1)  # Simulate sending
    return {"notification_sent": True}

__all__ = [
    'TaskStatus', 'TaskPriority', 'TaskResult', 'BackgroundTask',
    'TaskQueue', 'BackgroundTaskManager', 'task_manager',
    'submit_task', 'submit_scheduled_task', 'submit_high_priority_task'
]
