"""
PlexiChat Task Scheduler

Task scheduling with threading and performance optimization.
"""

import threading
import asyncio
import logging
import time
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass
from uuid import uuid4

try:
    import croniter
except ImportError:
    croniter = None

from plexichat.core.services.core_services import DatabaseService
database_manager = DatabaseService()

try:
    from plexichat.core.threading.thread_manager import async_thread_manager, submit_task
except ImportError:
    async_thread_manager = None
    submit_task = None

try:
    from plexichat.core.logging import get_logger as _get_logger
    async def track_event(event_name: str, properties: Dict[str, Any] | None = None) -> None:  # type: ignore
        logger = _get_logger(__name__)
        logger.debug(f"analytics event: {event_name} - {properties}")
except Exception:
    async def track_event(event_name: str, properties: Dict[str, Any] | None = None) -> None:  # type: ignore
        return None

try:
    from plexichat.core.logging import get_logger as get_performance_logger  # type: ignore
    PerformanceOptimizationEngine = None
except Exception:
    PerformanceOptimizationEngine = None
    def get_performance_logger():  # type: ignore
        return None

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None

class TaskStatus(Enum):
    """Task status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class TaskType(Enum):
    """Task type enumeration."""
    ONCE = "once"
    RECURRING = "recurring"
    CRON = "cron"

@dataclass
class ScheduledTask:
    """Scheduled task definition."""
    task_id: str
    name: str
    function: Callable[..., Any]
    args: tuple
    kwargs: dict
    task_type: TaskType
    status: TaskStatus
    created_at: datetime
    scheduled_at: datetime
    next_run: Optional[datetime]
    last_run: Optional[datetime]
    run_count: int
    max_runs: Optional[int]
    cron_expression: Optional[str]
    interval_seconds: Optional[int]
    timeout_seconds: int
    retry_count: int
    max_retries: int
    metadata: Dict[str, Any]

class TaskScheduler:
    """Task scheduler with threading support."""
    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.async_thread_manager = async_thread_manager

        # Task storage
        self.tasks: Dict[str, ScheduledTask] = {}
        self.running_tasks: Dict[str, asyncio.Task] = {}

        # Scheduler state
        self.running = False
        self.scheduler_task = None

        # Statistics
        self.tasks_executed = 0
        self.tasks_failed = 0
        self.total_execution_time = 0.0

    async def start(self):
        """Start the task scheduler."""
        if self.running:
            return

        self.running = True
        self.scheduler_task = asyncio.create_task(self._scheduler_loop())

        # Load tasks from database
        await self._load_tasks()

        logger.info("Task scheduler started")

    async def stop(self):
        """Stop the task scheduler."""
        if not self.running:
            return

        self.running = False

        # Cancel scheduler task
        if self.scheduler_task:
            self.scheduler_task.cancel()
            try:
                await self.scheduler_task
            except asyncio.CancelledError:
                pass

        # Cancel running tasks
        for task in self.running_tasks.values():
            task.cancel()

        # Wait for tasks to complete
        if self.running_tasks:
            await asyncio.gather(*self.running_tasks.values(), return_exceptions=True)

        logger.info("Task scheduler stopped")

    async def _scheduler_loop(self):
        """Main scheduler loop."""
        while self.running:
            try:
                current_time = datetime.now()

                # Check for tasks to run
                tasks_to_run = []
                for task in self.tasks.values():
                    if self._should_run_task(task, current_time):
                        tasks_to_run.append(task)

                # Execute tasks
                for task in tasks_to_run:
                    await self._execute_task(task)

                # Clean up completed tasks
                await self._cleanup_completed_tasks()

                # Sleep for a short interval
                await asyncio.sleep(1)

            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
                await asyncio.sleep(5)

    def _should_run_task(self, task: ScheduledTask, current_time: datetime) -> bool:
        """Check if task should run."""
        try:
            # Skip if already running
            if task.task_id in self.running_tasks:
                return False

            # Skip if cancelled or completed (for once tasks)
            if task.status in [TaskStatus.CANCELLED, TaskStatus.COMPLETED]:
                return False

            # Check if it's time to run
            if task.next_run and current_time >= task.next_run:
                # Check max runs
                if task.max_runs and task.run_count >= task.max_runs:
                    task.status = TaskStatus.COMPLETED
                    return False

                return True

            return False

        except Exception as e:
            logger.error(f"Error checking if task should run: {e}")
            return False

    async def _execute_task(self, task: ScheduledTask):
        """Execute a scheduled task."""
        try:
            task.status = TaskStatus.RUNNING
            task.last_run = datetime.now()
            task.run_count += 1

            # Create execution task
            execution_task = asyncio.create_task(self._run_task_with_timeout(task))
            self.running_tasks[task.task_id] = execution_task

            logger.info(f"Started task: {task.name} ({task.task_id})")

        except Exception as e:
            logger.error(f"Error executing task {task.task_id}: {e}")
            task.status = TaskStatus.FAILED

    async def _run_task_with_timeout(self, task: ScheduledTask):
        """Run task with timeout and error handling."""
        start_time = time.time()

        try:
            # Run task with timeout
            if self.async_thread_manager:
                result = await asyncio.wait_for(
                    self.async_thread_manager.run_in_thread(task.function, *task.args, **task.kwargs),
                    timeout=task.timeout_seconds
                )
            else:
                result = await asyncio.wait_for(
                    self._run_task_async(task),
                    timeout=task.timeout_seconds
                )

            # Task completed successfully
            task.status = TaskStatus.COMPLETED if task.task_type == TaskType.ONCE else TaskStatus.PENDING
            task.retry_count = 0  # Reset retry count on success

            # Calculate next run time
            if task.task_type != TaskType.ONCE:
                task.next_run = self._calculate_next_run(task)

            # Performance tracking
            execution_time = time.time() - start_time
            self.total_execution_time += execution_time
            self.tasks_executed += 1

            if self.performance_logger:
                self.performance_logger.record_metric("scheduled_task_duration", execution_time, "seconds")
                self.performance_logger.record_metric("scheduled_tasks_completed", 1, "count")

            # Track analytics
            if track_event:
                props: Dict[str, Any] = {
                    "task_name": task.name,
                    "task_type": task.task_type.value,
                    "execution_time": execution_time,
                    "run_count": task.run_count,
                }
                await track_event("scheduled_task_completed", properties=props)  # type: ignore[arg-type]

            logger.info(f"Task completed: {task.name} ({task.task_id}) in {execution_time:.2f}s")

        except asyncio.TimeoutError:
            logger.error(f"Task timeout: {task.name} ({task.task_id})")
            await self._handle_task_failure(task, "Task timeout")

        except Exception as e:
            logger.error(f"Task error: {task.name} ({task.task_id}) - {e}")
            await self._handle_task_failure(task, str(e))

        finally:
            # Remove from running tasks
            if task.task_id in self.running_tasks:
                del self.running_tasks[task.task_id]

            # Update task in database
            await self._update_task_in_db(task)

    async def _run_task_async(self, task: ScheduledTask):
        """Run task asynchronously."""
        if asyncio.iscoroutinefunction(task.function):
            return await task.function(*task.args, **task.kwargs)
        else:
            return task.function(*task.args, **task.kwargs)

    async def _handle_task_failure(self, task: ScheduledTask, error_message: str):
        """Handle task failure with retry logic."""
        try:
            task.retry_count += 1

            if task.retry_count <= task.max_retries:
                # Schedule retry
                task.status = TaskStatus.PENDING
                retry_delay = min(60 * (2 ** task.retry_count), 3600)  # Exponential backoff, max 1 hour
                task.next_run = datetime.now() + timedelta(seconds=retry_delay)

                logger.info(f"Scheduling retry for task {task.name} in {retry_delay} seconds (attempt {task.retry_count}/{task.max_retries})")
            else:
                # Max retries exceeded
                task.status = TaskStatus.FAILED
                logger.error(f"Task failed permanently: {task.name} ({task.task_id}) - {error_message}")

            self.tasks_failed += 1

            if self.performance_logger:
                self.performance_logger.record_metric("scheduled_tasks_failed", 1, "count")

        except Exception as e:
            logger.error(f"Error handling task failure: {e}")

    def _calculate_next_run(self, task: ScheduledTask) -> Optional[datetime]:
        """Calculate next run time for recurring tasks."""
        try:
            current_time = datetime.now()

            if task.task_type == TaskType.RECURRING and task.interval_seconds:
                return current_time + timedelta(seconds=task.interval_seconds)

            elif task.task_type == TaskType.CRON and task.cron_expression:
                if croniter:
                    cron = croniter.croniter(task.cron_expression, current_time)
                    return cron.get_next(datetime)
                else:
                    logger.warning("croniter not available for cron tasks")
                    return None

            return None

        except Exception as e:
            logger.error(f"Error calculating next run time: {e}")
            return None

    async def _cleanup_completed_tasks(self):
        """Clean up completed one-time tasks."""
        try:
            completed_tasks = [
                task_id for task_id, task in self.tasks.items()
                if task.task_type == TaskType.ONCE and task.status == TaskStatus.COMPLETED
                and task.last_run and (datetime.now() - task.last_run).total_seconds() > 3600  # Keep for 1 hour
            ]

            for task_id in completed_tasks:
                del self.tasks[task_id]

                # Remove from database
                if self.db_manager:
                    query = "DELETE FROM scheduled_tasks WHERE task_id = ?"
                    await self.db_manager.execute_query(query, {"task_id": task_id})

            if completed_tasks:
                logger.info(f"Cleaned up {len(completed_tasks)} completed tasks")

        except Exception as e:
            logger.error(f"Error cleaning up completed tasks: {e}")

    async def schedule_once(self, name: str, function: Callable[..., Any], scheduled_at: datetime, args: tuple = (), kwargs: Optional[Dict[str, Any]] = None, timeout_seconds: int = 300, max_retries: int = 3, metadata: Optional[Dict[str, Any]] = None) -> str:
        """Schedule a one-time task."""
        try:
            task_id = str(uuid4())

            task = ScheduledTask(
                task_id=task_id,
                name=name,
                function=function,
                args=args,
                kwargs=kwargs or {},
                task_type=TaskType.ONCE,
                status=TaskStatus.PENDING,
                created_at=datetime.now(),
                scheduled_at=scheduled_at,
                next_run=scheduled_at,
                last_run=None,
                run_count=0,
                max_runs=1,
                cron_expression=None,
                interval_seconds=None,
                timeout_seconds=timeout_seconds,
                retry_count=0,
                max_retries=max_retries,
                metadata=metadata or {}
            )

            self.tasks[task_id] = task
            await self._save_task_to_db(task)

            logger.info(f"Scheduled one-time task: {name} at {scheduled_at}")
            return task_id

        except Exception as e:
            logger.error(f"Error scheduling one-time task: {e}")
            raise

    async def schedule_recurring(self, name: str, function: Callable[..., Any], interval_seconds: int, args: tuple = (), kwargs: Optional[Dict[str, Any]] = None, timeout_seconds: int = 300, max_runs: Optional[int] = None, max_retries: int = 3, metadata: Optional[Dict[str, Any]] = None) -> str:
        """Schedule a recurring task."""
        try:
            task_id = str(uuid4())
            next_run = datetime.now() + timedelta(seconds=interval_seconds)

            task = ScheduledTask(
                task_id=task_id,
                name=name,
                function=function,
                args=args,
                kwargs=kwargs or {},
                task_type=TaskType.RECURRING,
                status=TaskStatus.PENDING,
                created_at=datetime.now(),
                scheduled_at=next_run,
                next_run=next_run,
                last_run=None,
                run_count=0,
                max_runs=max_runs,
                cron_expression=None,
                interval_seconds=interval_seconds,
                timeout_seconds=timeout_seconds,
                retry_count=0,
                max_retries=max_retries,
                metadata=metadata or {}
            )

            self.tasks[task_id] = task
            await self._save_task_to_db(task)

            logger.info(f"Scheduled recurring task: {name} every {interval_seconds} seconds")
            return task_id

        except Exception as e:
            logger.error(f"Error scheduling recurring task: {e}")
            raise

    async def schedule_cron(self, name: str, function: Callable[..., Any], cron_expression: str, args: tuple = (), kwargs: Optional[Dict[str, Any]] = None, timeout_seconds: int = 300, max_runs: Optional[int] = None, max_retries: int = 3, metadata: Optional[Dict[str, Any]] = None) -> str:
        """Schedule a cron-based task."""
        try:
            if not croniter:
                raise ValueError("croniter library required for cron tasks")

            task_id = str(uuid4())

            # Calculate first run time
            cron = croniter.croniter(cron_expression, datetime.now())
            next_run = cron.get_next(datetime)

            task = ScheduledTask(
                task_id=task_id,
                name=name,
                function=function,
                args=args,
                kwargs=kwargs or {},
                task_type=TaskType.CRON,
                status=TaskStatus.PENDING,
                created_at=datetime.now(),
                scheduled_at=next_run,
                next_run=next_run,
                last_run=None,
                run_count=0,
                max_runs=max_runs,
                cron_expression=cron_expression,
                interval_seconds=None,
                timeout_seconds=timeout_seconds,
                retry_count=0,
                max_retries=max_retries,
                metadata=metadata or {}
            )

            self.tasks[task_id] = task
            await self._save_task_to_db(task)

            logger.info(f"Scheduled cron task: {name} with expression '{cron_expression}'")
            return task_id

        except Exception as e:
            logger.error(f"Error scheduling cron task: {e}")
            raise

    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a scheduled task."""
        try:
            if task_id not in self.tasks:
                return False

            task = self.tasks[task_id]
            task.status = TaskStatus.CANCELLED

            # Cancel if currently running
            if task_id in self.running_tasks:
                self.running_tasks[task_id].cancel()

            await self._update_task_in_db(task)

            logger.info(f"Cancelled task: {task.name} ({task_id})")
            return True

        except Exception as e:
            logger.error(f"Error cancelling task: {e}")
            return False

    async def _save_task_to_db(self, task: ScheduledTask):
        """Save task to database."""
        try:
            if self.db_manager:
                query = (
                    "INSERT INTO scheduled_tasks ("
                    "task_id, name, task_type, status, created_at, scheduled_at, "
                    "next_run, last_run, run_count, max_runs, cron_expression, "
                    "interval_seconds, timeout_seconds, retry_count, max_retries, metadata"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                )
                params = {
                    "task_id": task.task_id,
                    "name": task.name,
                    "task_type": task.task_type.value,
                    "status": task.status.value,
                    "created_at": task.created_at,
                    "scheduled_at": task.scheduled_at,
                    "next_run": task.next_run,
                    "last_run": task.last_run,
                    "run_count": task.run_count,
                    "max_runs": task.max_runs,
                    "cron_expression": task.cron_expression,
                    "interval_seconds": task.interval_seconds,
                    "timeout_seconds": task.timeout_seconds,
                    "retry_count": task.retry_count,
                    "max_retries": task.max_retries,
                    "metadata": str(task.metadata),
                }
                await self.db_manager.execute_query(query, params)  # type: ignore[reportUnknownMemberType]
        except Exception as e:
            logger.error(f"Error saving task to database: {e}")

    async def _update_task_in_db(self, task: ScheduledTask):
        """Update task in database."""
        try:
            if self.db_manager:
                query = (
                    "UPDATE scheduled_tasks SET "
                    "status = ?, next_run = ?, last_run = ?, run_count = ?, retry_count = ? "
                    "WHERE task_id = ?"
                )
                params = {
                    "status": task.status.value,
                    "next_run": task.next_run,
                    "last_run": task.last_run,
                    "run_count": task.run_count,
                    "retry_count": task.retry_count,
                    "task_id": task.task_id,
                }
                await self.db_manager.execute_query(query, params)  # type: ignore[reportUnknownMemberType]
        except Exception as e:
            logger.error(f"Error updating task in database: {e}")

    async def _load_tasks(self):
        """Load tasks from database."""
        try:
            if self.db_manager:
                query = "SELECT * FROM scheduled_tasks WHERE status NOT IN ('completed', 'cancelled')"
                result = await self.db_manager.execute_query(query)

                for row in result:
                    # Reconstruct task (simplified)
                    task_id = row[0]
                    # Would need to reconstruct function reference
                    logger.info(f"Loaded task from database: {task_id}")

        except Exception as e:
            logger.error(f"Error loading tasks from database: {e}")

    def get_tasks(self) -> List[Dict[str, Any]]:
        """Get all tasks."""
        try:
            return [
                {
                    "task_id": task.task_id,
                    "name": task.name,
                    "task_type": task.task_type.value,
                    "status": task.status.value,
                    "created_at": task.created_at.isoformat(),
                    "next_run": task.next_run.isoformat() if task.next_run else None,
                    "last_run": task.last_run.isoformat() if task.last_run else None,
                    "run_count": task.run_count,
                    "max_runs": task.max_runs,
                    "retry_count": task.retry_count,
                    "max_retries": task.max_retries
                }
                for task in self.tasks.values()
            ]
        except Exception as e:
            logger.error(f"Error getting tasks: {e}")
            return []

    def get_stats(self) -> Dict[str, Any]:
        """Get scheduler statistics."""
        avg_execution_time = self.total_execution_time / self.tasks_executed if self.tasks_executed > 0 else 0

        return {
            "running": self.running,
            "total_tasks": len(self.tasks),
            "running_tasks": len(self.running_tasks),
            "tasks_executed": self.tasks_executed,
            "tasks_failed": self.tasks_failed,
            "total_execution_time": self.total_execution_time,
            "average_execution_time": avg_execution_time,
            "task_status_counts": {
                status.value: sum(1 for task in self.tasks.values() if task.status == status)
                for status in TaskStatus
            }
        }

# Global task scheduler
task_scheduler = TaskScheduler()

# Convenience functions
async def schedule_once(name: str, function: Callable, scheduled_at: datetime, **kwargs) -> str:
    """Schedule one-time task."""
    return await task_scheduler.schedule_once(name, function, scheduled_at, **kwargs)

async def schedule_recurring(name: str, function: Callable, interval_seconds: int, **kwargs) -> str:
    """Schedule recurring task."""
    return await task_scheduler.schedule_recurring(name, function, interval_seconds, **kwargs)

async def schedule_cron(name: str, function: Callable, cron_expression: str, **kwargs) -> str:
    """Schedule cron task."""
    return await task_scheduler.schedule_cron(name, function, cron_expression, **kwargs)

async def cancel_task(task_id: str) -> bool:
    """Cancel task."""
    return await task_scheduler.cancel_task(task_id)

def get_scheduled_tasks() -> List[Dict[str, Any]]:
    """Get all scheduled tasks."""
    return task_scheduler.get_tasks()
