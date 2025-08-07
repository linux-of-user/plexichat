"""
Asynchronous Task Queue System

High-performance async task queue with Redis backend, worker pools,
task scheduling, retry mechanisms, and monitoring.
"""

import asyncio
import json
import logging
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Union

logger = logging.getLogger(__name__)

# Optional Redis import - graceful degradation if not available
try:
    import aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("aioredis not available - using in-memory queue only")


class TaskStatus(Enum):
    """Task execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    CANCELLED = "cancelled"


class TaskPriority(Enum):
    """Task priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class TaskResult:
    """Task execution result."""
    task_id: str
    status: TaskStatus
    result: Any = None
    error: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration: float = 0.0
    retry_count: int = 0
    worker_id: Optional[str] = None


@dataclass
class Task:
    """Task definition."""
    id: str
    function_name: str
    args: tuple = field(default_factory=tuple)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    max_retries: int = 3
    retry_delay: float = 1.0
    timeout: Optional[float] = None
    scheduled_time: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    queue_name: str = "default"

    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary for serialization."""
        return {
            "id": self.id,
            "function_name": self.function_name,
            "args": self.args,
            "kwargs": self.kwargs,
            "priority": self.priority.value,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
            "timeout": self.timeout,
            "scheduled_time": self.scheduled_time.isoformat() if self.scheduled_time else None,
            "created_at": self.created_at.isoformat(),
            "queue_name": self.queue_name
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Task":
        """Create task from dictionary."""
        task = cls(
            id=data["id"],
            function_name=data["function_name"],
            args=tuple(data.get("args", [])),
            kwargs=data.get("kwargs", {}),
            priority=TaskPriority(data.get("priority", TaskPriority.NORMAL.value)),
            max_retries=data.get("max_retries", 3),
            retry_delay=data.get("retry_delay", 1.0),
            timeout=data.get("timeout"),
            queue_name=data.get("queue_name", "default")
        )

        if data.get("scheduled_time"):
            task.scheduled_time = datetime.fromisoformat(data["scheduled_time"])
        if data.get("created_at"):
            task.created_at = datetime.fromisoformat(data["created_at"])

        return task



class TaskWorker:
    """Async task worker."""

    def __init__(self, worker_id: str, queue: "AsyncTaskQueue"):
        self.worker_id = worker_id
        self.queue = queue
        self.is_running = False
        self.current_task: Optional[Task] = None
        self.processed_count = 0
        self.error_count = 0

    async def start(self):
        """Start the worker."""
        self.is_running = True
        logger.info(f"Worker {self.worker_id} started")

        while self.is_running:
            try:
                # Get next task from queue
                task = await self.queue.get_next_task()
                if not task:
                    await asyncio.sleep(0.1)  # Brief pause if no tasks
                    continue

                # Process the task
                await self._process_task(task)

            except Exception as e:
                logger.error(f"Worker {self.worker_id} error: {e}")
                self.error_count += 1
                await asyncio.sleep(1)  # Brief pause on error

    async def stop(self):
        """Stop the worker."""
        self.is_running = False
        logger.info(f"Worker {self.worker_id} stopped")

    async def _process_task(self, task: Task):
        """Process a single task."""
        self.current_task = task
        start_time = datetime.now()

        try:
            logger.info(f"Worker {self.worker_id} processing task {task.id}")

            # Update task status
            await self.queue.update_task_status(task.id, TaskStatus.RUNNING, worker_id=self.worker_id)

            # Get the function to execute
            func = self.queue.get_registered_function(task.function_name)
            if not func:
                raise ValueError(f"Function {task.function_name} not registered")

            # Execute the task with timeout
            if task.timeout:
                result = await asyncio.wait_for(
                    func(*task.args, **task.kwargs),
                    timeout=task.timeout
                )
            else:
                result = await func(*task.args, **task.kwargs)

            # Task completed successfully
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            task_result = TaskResult(
                task_id=task.id,
                status=TaskStatus.COMPLETED,
                result=result,
                start_time=start_time,
                end_time=end_time,
                duration=duration,
                worker_id=self.worker_id
            )

            await self.queue.complete_task(task.id, task_result)
            self.processed_count += 1

            logger.info(f"Task {task.id} completed in {duration:.2f}s")

        except Exception as e:
            # Task failed
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            task_result = TaskResult(
                task_id=task.id,
                status=TaskStatus.FAILED,
                error=str(e),
                start_time=start_time,
                end_time=end_time,
                duration=duration,
                worker_id=self.worker_id
            )

            await self.queue.handle_task_failure(task, task_result)
            self.error_count += 1

            logger.error(f"Task {task.id} failed: {e}")

        finally:
            self.current_task = None


class AsyncTaskQueue:
    """Asynchronous task queue with Redis backend."""

    def __init__(self, redis_url: Optional[str] = None, max_workers: int = 4):
        self.redis_url = redis_url
        self.max_workers = max_workers
        self.redis: Optional[Any] = None
        self.workers: List[TaskWorker] = []
        self.worker_tasks: List[asyncio.Task] = []
        self.registered_functions: Dict[str, Callable] = {}
        self.task_results: Dict[str, TaskResult] = {}
        self.task_queues: Dict[str, deque] = defaultdict(deque)
        self.scheduled_tasks: List[Task] = []
        self.is_running = False

        # Metrics
        self.metrics = {
            "tasks_submitted": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "tasks_retried": 0
        }

    async def start(self):
        """Start the task queue system."""
        if self.is_running:
            return

        logger.info("Starting async task queue...")

        # Connect to Redis if available
        if REDIS_AVAILABLE and self.redis_url:
            try:
                import aioredis
                self.redis = await aioredis.from_url(self.redis_url)
                logger.info("Connected to Redis backend")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}")
                self.redis = None

        # Start workers
        for i in range(self.max_workers):
            worker = TaskWorker(f"worker-{i}", self)
            self.workers.append(worker)
            task = asyncio.create_task(worker.start())
            self.worker_tasks.append(task)

        # Start scheduler
        self.scheduler_task = asyncio.create_task(self._scheduler_loop())

        self.is_running = True
        logger.info(f"Task queue started with {self.max_workers} workers")

    async def stop(self):
        """Stop the task queue system."""
        if not self.is_running:
            return

        logger.info("Stopping async task queue...")

        # Stop workers
        for worker in self.workers:
            await worker.stop()

        # Cancel worker tasks
        for task in self.worker_tasks:
            task.cancel()

        # Cancel scheduler
        if hasattr(self, 'scheduler_task'):
            self.scheduler_task.cancel()

        # Close Redis connection
        if self.redis:
            await self.redis.close()

        self.is_running = False
        logger.info("Task queue stopped")

    def register_function(self, name: str, func: Callable):
        """Register a function for task execution."""
        self.registered_functions[name] = func
        logger.info(f"Registered function: {name}")

    def get_registered_function(self, name: str) -> Optional[Callable]:
        """Get a registered function."""
        return self.registered_functions.get(name)

    async def submit_task(self, function_name: str, *args, **kwargs) -> str:
        """Submit a task for execution."""
        task_id = str(uuid.uuid4())
        task = Task(
            id=task_id,
            function_name=function_name,
            args=args,
            kwargs=kwargs
        )

        # Add to queue
        self.task_queues[task.queue_name].append(task)
        self.metrics["tasks_submitted"] += 1

        logger.info(f"Submitted task {task_id} ({function_name})")
        return task_id

    async def get_next_task(self) -> Optional[Task]:
        """Get the next task to process."""
        # Check all queues for tasks
        for queue_name, queue in self.task_queues.items():
            if queue:
                return queue.popleft()
        return None

    async def update_task_status(self, task_id: str, status: TaskStatus, **kwargs):
        """Update task status."""
        # In a real implementation, this would update persistent storage
        logger.debug(f"Task {task_id} status updated to {status.value}")

    async def complete_task(self, task_id: str, result: TaskResult):
        """Mark task as completed."""
        self.task_results[task_id] = result
        self.metrics["tasks_completed"] += 1

    async def handle_task_failure(self, task: Task, result: TaskResult):
        """Handle task failure and retry logic."""
        self.task_results[task.id] = result
        self.metrics["tasks_failed"] += 1

        # Implement retry logic here if needed
        if result.retry_count < task.max_retries:
            self.metrics["tasks_retried"] += 1
            # Re-queue the task for retry
            await asyncio.sleep(task.retry_delay)
            self.task_queues[task.queue_name].append(task)

    async def _scheduler_loop(self):
        """Process scheduled tasks."""
        while self.is_running:
            try:
                current_time = datetime.now()
                ready_tasks = [
                    task for task in self.scheduled_tasks
                    if task.scheduled_time and task.scheduled_time <= current_time
                ]

                for task in ready_tasks:
                    self.scheduled_tasks.remove(task)
                    self.task_queues[task.queue_name].append(task)

                await asyncio.sleep(1)  # Check every second

            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                await asyncio.sleep(5)


# Global task queue instance
task_queue = None

__all__ = [
    "TaskStatus",
    "TaskPriority",
    "TaskResult",
    "Task",
    "TaskWorker",
    "AsyncTaskQueue",
    "task_queue"
]
