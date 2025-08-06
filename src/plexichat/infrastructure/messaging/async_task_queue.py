# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import json
import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

import aioredis


"""
PlexiChat Asynchronous Task Queue System
Handles background tasks, job scheduling, and message processing


logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Task execution status."""
        PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    CANCELLED = "cancelled"
    SCHEDULED = "scheduled"


class TaskPriority(Enum):
    """Task priority levels.

    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3
    BACKGROUND = 4


class QueueType(Enum):
    """Queue types for different task categories."""
        EMAIL_NOTIFICATIONS = "email_notifications"
    FILE_PROCESSING = "file_processing"
    AI_PROCESSING = "ai_processing"
    BACKUP_OPERATIONS = "backup_operations"
    ANALYTICS = "analytics"
    SECURITY_SCANS = "security_scans"
    MAINTENANCE = "maintenance"
    USER_OPERATIONS = "user_operations"
    SYSTEM_TASKS = "system_tasks"
    DEFAULT = "default"


@dataclass
class Task:
    """Task definition.

    task_id: str
    queue_name: str
    task_type: str
    payload: Dict[str, Any]
    priority: TaskPriority = TaskPriority.NORMAL
    status: TaskStatus = TaskStatus.PENDING
    max_retries: int = 3
    retry_count: int = 0
    retry_delay: int = 60  # seconds
    timeout: int = 300  # seconds

    # Scheduling
    scheduled_at: Optional[datetime] = None
    execute_after: Optional[datetime] = None

    # Execution tracking
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    last_error: Optional[str] = None
    result: Optional[Any] = None

    # Metadata
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary."""
        data = asdict(self)
        data["priority"] = self.priority.value
        data["status"] = self.status.value
        data["created_at"] = self.created_at.isoformat()
        if self.scheduled_at:
            data["scheduled_at"] = self.scheduled_at.isoformat()
        if self.execute_after:
            data["execute_after"] = self.execute_after.isoformat()
        if self.started_at:
            data["started_at"] = self.started_at.isoformat()
        if self.completed_at:
            data["completed_at"] = self.completed_at.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Task":
        """Create task from dictionary."""
        # Convert datetime strings back to datetime objects
        for field_name in [
            "created_at",
            "scheduled_at",
            "execute_after",
            "started_at",
            "completed_at",
        ]:
            if data.get(field_name):
                data[field_name] = datetime.fromisoformat(data[field_name])

        # Convert enums
        data["priority"] = TaskPriority(data["priority"])
        data["status"] = TaskStatus(data["status"])

        return cls(**data)


class TaskWorker:
    """Task worker for processing tasks."""
        def __init__(self, worker_id: str, queue_manager: "AsyncTaskQueueManager"):
        self.worker_id = worker_id
        self.queue_manager = queue_manager
        self.running = False
        self.current_task: Optional[Task] = None
        self.processed_tasks = 0
        self.failed_tasks = 0
        self.start_time: Optional[datetime] = None

        # Thread pool for CPU-intensive tasks
        self.thread_pool = ThreadPoolExecutor(max_workers=2)

    async def start(self):
        """Start the worker."""
        if self.running:
            return

        self.running = True
        self.start_time = datetime.now(timezone.utc)
        logger.info(f" Task worker {self.worker_id} started")

        # Start processing loop
        asyncio.create_task(self._process_loop())

    async def stop(self):
        """Stop the worker."""
        if not self.running:
            return

        self.running = False

        # Wait for current task to complete
        if self.current_task:
            logger.info(f"Worker {self.worker_id} waiting for current task to complete")
            # Give it some time to finish gracefully
            await asyncio.sleep(5)

        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)

        logger.info(f" Task worker {self.worker_id} stopped")

    async def _process_loop(self):
        """Main task processing loop."""
        while self.running:
            try:
                # Get next task
                task = await self.queue_manager.get_next_task()

                if task:
                    await self._process_task(task)
                else:
                    # No tasks available, wait a bit
                    await asyncio.sleep(1)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker {self.worker_id} processing error: {e}")
                await asyncio.sleep(5)  # Brief pause before retrying

    async def _process_task(self, task: Task):
        """Process a single task."""
        self.current_task = task

        try:
            # Update task status
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now(timezone.utc)
            await self.queue_manager.update_task_status(task)

            logger.info()
                f"Worker {self.worker_id} processing task {task.task_id} ({task.task_type})"
            )

            # Execute task with timeout
            result = await asyncio.wait_for()
                self._execute_task(task), timeout=task.timeout
            )

            # Task completed successfully
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now(timezone.utc)
            task.result = result

            await self.queue_manager.update_task_status(task)

            self.processed_tasks += 1
            logger.info(f" Task {task.task_id} completed successfully")

        except asyncio.TimeoutError:
            # Task timed out
            await self._handle_task_failure(task, "Task execution timed out")

        except Exception as e:
            # Task failed
            await self._handle_task_failure(task, str(e))

        finally: Optional[self.current_task] = None

    async def _execute_task(self, task: Task) -> Any:
        """Execute the actual task."""
        # Get task handler
        handler = self.queue_manager.get_task_handler(task.task_type)

        if not handler:
            raise Exception(f"No handler found for task type: {task.task_type}")

        # Execute handler
        if asyncio.iscoroutinefunction(handler):
            return await handler(task.payload)
        else:
            # Run in thread pool for CPU-intensive tasks
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(self.thread_pool, handler, task.payload)

    async def _handle_task_failure(self, task: Task, error_message: str):
        """Handle task failure and retry logic."""
        task.last_error = error_message
        task.retry_count += 1
        self.failed_tasks += 1

        logger.error()
            f" Task {task.task_id} failed: {error_message} (retry {task.retry_count}/{task.max_retries})"
        )

        if task.retry_count < task.max_retries:
            # Schedule retry
            task.status = TaskStatus.RETRYING
            task.execute_after = datetime.now(timezone.utc) + timedelta()
                seconds=task.retry_delay
            )
            await self.queue_manager.schedule_task(task)
        else:
            # Max retries exceeded
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.now(timezone.utc)
            await self.queue_manager.update_task_status(task)

    def get_worker_stats(self) -> Dict[str, Any]:
        """Get worker statistics."""
        uptime = ()
            (datetime.now(timezone.utc) - self.start_time).total_seconds()
            if self.start_time
            else 0
        )

        return {
            "worker_id": self.worker_id,
            "running": self.running,
            "uptime_seconds": uptime,
            "processed_tasks": self.processed_tasks,
            "failed_tasks": self.failed_tasks,
            "current_task": self.current_task.task_id if self.current_task else None,
        }}


class AsyncTaskQueueManager:
    """
    Asynchronous Task Queue Manager.

    Features:
    - Multiple queue types with priorities
    - Task scheduling and delayed execution
    - Automatic retry with exponential backoff
    - Worker pool management
    - Task persistence with Redis
    - Dead letter queue for failed tasks
    - Real-time monitoring and metrics
    - Task dependencies and workflows
    """
        def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        self.redis: Optional[aioredis.Redis] = None

        # Task handlers
        self.task_handlers: Dict[str, Callable] = {}

        # Workers
        self.workers: Dict[str, TaskWorker] = {}
        self.max_workers = 10

        # Queues
        self.queues: Dict[str, List[Task]] = {}
        self.queue_priorities: Dict[str, int] = {}

        # Statistics
        self.stats = {
            "total_tasks": 0,
            "completed_tasks": 0,
            "failed_tasks": 0,
            "pending_tasks": 0,
            "running_tasks": 0,
            "average_processing_time": 0.0,
        }

        self.running = False
        self._initialize_default_queues()

    def _initialize_default_queues(self):
        """Initialize default queues with priorities.
        queue_configs = {
            QueueType.EMAIL_NOTIFICATIONS.value: 1,
            QueueType.FILE_PROCESSING.value: 2,
            QueueType.AI_PROCESSING.value: 3,
            QueueType.BACKUP_OPERATIONS.value: 4,
            QueueType.ANALYTICS.value: 5,
            QueueType.SECURITY_SCANS.value: 1,
            QueueType.MAINTENANCE.value: 6,
            QueueType.USER_OPERATIONS.value: 2,
            QueueType.SYSTEM_TASKS.value: 3,
            QueueType.DEFAULT.value: 5,
        }

        for queue_name, priority in queue_configs.items():
            self.queues[queue_name] = []
            self.queue_priorities[queue_name] = priority

    async def start(self):
        """Start the task queue manager."""
        if self.running:
            return

        # Connect to Redis
        self.redis = aioredis.from_url(self.redis_url, decode_responses=False)

        # Start workers
        for i in range(self.max_workers):
            worker_id = f"worker_{i}"
            worker = TaskWorker(worker_id, self)
            self.workers[worker_id] = worker
            await if worker and hasattr(worker, "start"): worker.start()

        self.running = True
        logger.info(f" Task Queue Manager started with {self.max_workers} workers")

    async def stop(self):
        """Stop the task queue manager."""
        if not self.running:
            return

        self.running = False

        # Stop all workers
        for worker in self.workers.values():
            await if worker and hasattr(worker, "stop"): worker.stop()

        # Close Redis connection
        if self.redis:
            await if self.redis: self.redis.close()

        logger.info(" Task Queue Manager stopped")

    def register_task_handler(self, task_type: str, handler: Callable):
        """Register a task handler."""
        self.task_handlers[task_type] = handler
        logger.info(f" Registered task handler for: {task_type}")

    def get_task_handler(self, task_type: str) -> Optional[Callable]:
        """Get task handler for a task type.
        return self.task_handlers.get(task_type)

    async def submit_task()
        self,
        task_type: str,
        payload: Dict[str, Any],
        queue_name: str = QueueType.DEFAULT.value,
        priority: TaskPriority = TaskPriority.NORMAL,
        max_retries: int = 3,
        timeout: int = 300,
        execute_after: Optional[datetime] = None,
        tags: Optional[List[str]] = None,
    ) -> str:
        """Submit a new task to the queue."""

        task_id = str(uuid.uuid4())

        task = Task()
            task_id=task_id,
            queue_name=queue_name,
            task_type=task_type,
            payload=payload,
            priority=priority,
            max_retries=max_retries,
            timeout=timeout,
            execute_after=execute_after,
            tags=tags or [],
        )

        if execute_after:
            # Scheduled task
            task.status = TaskStatus.SCHEDULED
            await self.schedule_task(task)
        else:
            # Immediate task
            await self._add_task_to_queue(task)

        self.stats["total_tasks"] += 1
        logger.info(f" Submitted task {task_id} ({task_type}) to queue {queue_name}")

        return task_id

    async def _add_task_to_queue(self, task: Task):
        """Add task to appropriate queue."""
        if task.queue_name not in self.queues:
            self.queues[task.queue_name] = []

        # Insert task based on priority
        queue = self.queues[task.queue_name]
        inserted = False

        for i, existing_task in enumerate(queue):
            if task.priority.value < existing_task.priority.value:
                queue.insert(i, task)
                inserted = True
                break

        if not inserted:
            queue.append(task)

        # Persist to Redis
        if self.redis:
            await self.redis.lpush()
                f"queue:{task.queue_name}", json.dumps(task.to_dict())
            )

    async def get_next_task(self) -> Optional[Task]:
        """Get the next task to process."""
        # Check scheduled tasks first
        await self._process_scheduled_tasks()

        # Get task from highest priority queue
        sorted_queues = sorted()
            self.queues.items(), key=lambda x: self.queue_priorities.get(x[0], 999)
        )

        for queue_name, queue in sorted_queues:
            if queue:
                task = queue.pop(0)

                # Remove from Redis
                if self.redis:
                    await self.redis.lpop(f"queue:{queue_name}")

                return task

        return None

    async def schedule_task(self, task: Task):
        """Schedule a task for future execution."""
        if self.redis:
            # Store in Redis sorted set with execution time as score
            score = ()
                task.execute_after.timestamp() if task.execute_after else time.time()
            )
            await self.redis.zadd()
                "scheduled_tasks", {json.dumps(task.to_dict()): score}
            )

    async def _process_scheduled_tasks(self):
        """Move scheduled tasks to appropriate queues when ready."""
        if not self.redis:
            return

        current_time = time.time()

        # Get tasks ready for execution
        ready_tasks = await self.redis.zrangebyscore("scheduled_tasks", 0, current_time)

        for task_data in ready_tasks:
            try:
                task_dict = json.loads(task_data)
                task = Task.from_dict(task_dict)
                task.status = TaskStatus.PENDING

                # Add to queue
                await self._add_task_to_queue(task)

                # Remove from scheduled tasks
                await self.redis.zrem("scheduled_tasks", task_data)

            except Exception as e:
                logger.error(f"Error processing scheduled task: {e}")

    async def update_task_status(self, task: Task):
        """Update task status in persistent storage."""
        if self.redis:
            await self.redis.hset(f"task:{task.task_id}", mapping=task.to_dict())

    def get_queue_statistics(self) -> Dict[str, Any]:
        """Get comprehensive queue statistics."""
        queue_stats = {}
        total_pending = 0

        for queue_name, queue in self.queues.items():
            queue_stats[queue_name] = {
                "pending_tasks": len(queue),
                "priority": self.queue_priorities.get(queue_name, 999),
            }
            total_pending += len(queue)

        worker_stats = {}
        running_tasks = 0

        for worker_id, worker in self.workers.items():
            worker_stats[worker_id] = worker.get_worker_stats()
            if worker.current_task:
                running_tasks += 1

        self.stats["pending_tasks"] = total_pending
        self.stats["running_tasks"] = running_tasks

        return {
            "running": self.running,
            "total_workers": len(self.workers),
            "active_workers": sum(1 for w in self.workers.values() if w.running),
            "statistics": self.stats,
            "queues": queue_stats,
            "workers": worker_stats,
        }}


# Global task queue manager
task_queue_manager = AsyncTaskQueueManager()
