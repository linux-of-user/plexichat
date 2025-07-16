# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import json
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

import aiosqlite


"""
Advanced Task Manager for PlexiChat Clustering System

Provides comprehensive task management with:
- Intelligent task scheduling and distribution
- Priority-based task queuing
- Resource-aware task assignment
- Task monitoring and recovery
- Cross-node task coordination
"""

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Task execution status."""

    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class TaskPriority(Enum):
    """Task priority levels."""

    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5


class TaskType(Enum):
    """Types of tasks that can be executed."""

    BACKUP_OPERATION = "backup_operation"
    ANTIVIRUS_SCAN = "antivirus_scan"
    DATA_PROCESSING = "data_processing"
    MAINTENANCE = "maintenance"
    MONITORING = "monitoring"
    REPLICATION = "replication"
    RECOVERY = "recovery"
    CUSTOM = "custom"


@dataclass
class ClusterTask:
    """Represents a task in the cluster."""

    task_id: str
    task_type: TaskType
    priority: TaskPriority
    payload: Dict[str, Any]
    requirements: Dict[str, Any]
    status: TaskStatus = TaskStatus.PENDING
    assigned_node: Optional[str] = None
    created_at: Optional[datetime] = None
    assigned_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    timeout_seconds: int = 300

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)


@dataclass
class TaskMetrics:
    """Task execution metrics."""

    total_tasks: int = 0
    pending_tasks: int = 0
    running_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    average_execution_time: float = 0.0
    success_rate: float = 0.0
    last_updated: Optional[datetime] = None

    def __post_init__(self):
        if self.last_updated is None:
            self.last_updated = datetime.now(timezone.utc)


class AdvancedTaskManager:
    """
    Advanced Task Manager for PlexiChat Clustering

    Provides comprehensive task management capabilities:
    - Intelligent task scheduling based on node capabilities
    - Priority-based task queuing
    - Resource-aware task assignment
    - Task monitoring and automatic recovery
    - Cross-node task coordination and load balancing
    """

    def __init__(self, cluster_manager):
        self.cluster_manager = cluster_manager
        self.tasks: Dict[str, ClusterTask] = {}
        self.task_queue: List[str] = []  # Task IDs sorted by priority
        self.running_tasks: Dict[str, str] = {}  # task_id -> node_id
        self.task_history: List[str] = []  # Completed task IDs
        self.metrics = TaskMetrics()
        self.db_path = None
        self.background_tasks: Set[asyncio.Task] = set()

    async def initialize(self):
        """Initialize the task manager."""
        logger.info(" Initializing Advanced Task Manager")

        # Setup database
        await self._setup_database()

        # Load existing tasks
        await self._load_tasks_from_db()

        # Start background monitoring
        self._start_background_tasks()

        logger.info(" Advanced Task Manager initialized")

    async def _setup_database(self):
        """Setup SQLite database for task persistence."""
        self.db_path = self.cluster_manager.data_dir / "tasks.db"

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    task_type TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    requirements TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assigned_node TEXT,
                    created_at TEXT NOT NULL,
                    assigned_at TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    result TEXT,
                    error TEXT,
                    retry_count INTEGER DEFAULT 0,
                    max_retries INTEGER DEFAULT 3,
                    timeout_seconds INTEGER DEFAULT 300
                )
            """
            )
            await db.commit()

    async def _load_tasks_from_db(self):
        """Load tasks from database."""
        if not self.db_path or not self.db_path.exists() if self.db_path else False:
            return

        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT * FROM tasks WHERE status NOT IN ('completed', 'failed', 'cancelled')"
            ) as cursor:
                async for row in cursor:
                    task = ClusterTask(
                        task_id=row[0],
                        task_type=TaskType(row[1]),
                        priority=TaskPriority(row[2]),
                        payload=json.loads(row[3]),
                        requirements=json.loads(row[4]),
                        status=TaskStatus(row[5]),
                        assigned_node=row[6],
                        created_at=datetime.fromisoformat(row[7]),
                        assigned_at=datetime.fromisoformat(row[8]) if row[8] else None,
                        started_at=datetime.fromisoformat(row[9]) if row[9] else None,
                        completed_at=(
                            datetime.fromisoformat(row[10]) if row[10] else None
                        ),
                        result=json.loads(row[11]) if row[11] else None,
                        error=row[12],
                        retry_count=row[13],
                        max_retries=row[14],
                        timeout_seconds=row[15],
                    )
                    self.tasks[task.task_id] = task

                    # Add to appropriate queues
                    if task.status == TaskStatus.PENDING:
                        self._add_to_queue(task.task_id)
                    elif task.status == TaskStatus.RUNNING:
                        self.running_tasks[task.task_id] = task.assigned_node

        logger.info(f" Loaded {len(self.tasks)} tasks from database")

    def _start_background_tasks(self):
        """Start background monitoring tasks."""
        # Task scheduler
        task = asyncio.create_task(self._task_scheduler_loop())
        self.background_tasks.add(task)
        task.add_done_callback(self.background_tasks.discard)

        # Task monitor
        task = asyncio.create_task(self._task_monitor_loop())
        self.background_tasks.add(task)
        task.add_done_callback(self.background_tasks.discard)

        # Metrics updater
        task = asyncio.create_task(self._metrics_updater_loop())
        self.background_tasks.add(task)
        task.add_done_callback(self.background_tasks.discard)

    async def submit_task(
        self,
        task_type: TaskType,
        payload: Dict[str, Any],
        priority: TaskPriority = TaskPriority.NORMAL,
        requirements: Optional[Dict[str, Any]] = None,
        timeout_seconds: int = 300,
        max_retries: int = 3,
    ) -> str:
        """Submit a new task to the cluster."""
        task_id = f"task_{int(time.time() * 1000)}_{secrets.token_hex(4)}"

        task = ClusterTask(
            task_id=task_id,
            task_type=task_type,
            priority=priority,
            payload=payload,
            requirements=requirements or {},
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )

        self.tasks[task_id] = task
        self._add_to_queue(task_id)

        # Save to database
        await self._save_task_to_db(task)

        logger.info(
            f" Submitted task {task_id} ({task_type.value}) with priority {priority.value}"
        )
        return task_id

    def _add_to_queue(self, task_id: str):
        """Add task to priority queue."""
        task = self.tasks[task_id]

        # Insert based on priority (higher priority first)
        inserted = False
        for i, queued_task_id in enumerate(self.task_queue):
            queued_task = self.tasks[queued_task_id]
            if task.priority.value > queued_task.priority.value:
                self.task_queue.insert(i, task_id)
                inserted = True
                break

        if not inserted:
            self.task_queue.append(task_id)

    async def _task_scheduler_loop(self):
        """Background task scheduler loop."""
        while True:
            try:
                await self._schedule_pending_tasks()
                await asyncio.sleep(5)  # Check every 5 seconds
            except Exception as e:
                logger.error(f" Task scheduler error: {e}")
                await asyncio.sleep(10)

    async def _schedule_pending_tasks(self):
        """Schedule pending tasks to available nodes."""
        if not self.task_queue:
            return

        # Get available nodes
        available_nodes = await self.cluster_manager.node_manager.get_available_nodes()
        if not available_nodes:
            return

        # Schedule tasks
        scheduled_count = 0
        tasks_to_remove = []

        for task_id in self.task_queue[:]:
            if scheduled_count >= len(available_nodes):
                break

            task = self.tasks[task_id]

            # Find suitable node for this task
            suitable_node = await self._find_suitable_node(task, available_nodes)
            if suitable_node:
                await self._assign_task_to_node(task, suitable_node)
                tasks_to_remove.append(task_id)
                scheduled_count += 1

        # Remove scheduled tasks from queue
        for task_id in tasks_to_remove:
            self.task_queue.remove(task_id)

    async def _find_suitable_node(
        self, task: ClusterTask, available_nodes: List[Any]
    ) -> Optional[Any]:
        """Find the most suitable node for a task."""
        suitable_nodes = []

        for node in available_nodes:
            # Check if node meets task requirements
            if self._node_meets_requirements(node, task.requirements):
                suitable_nodes.append(node)

        if not suitable_nodes:
            return None

        # Use load balancer to select best node
        return await self.cluster_manager.load_balancer.select_optimal_node(
            suitable_nodes, task.requirements
        )

    def _node_meets_requirements(self, node: Any, requirements: Dict[str, Any]) -> bool:
        """Check if a node meets task requirements."""
        # Check CPU requirements
        if "min_cpu_cores" in requirements:
            if node.cpu_cores < requirements["min_cpu_cores"]:
                return False

        # Check memory requirements
        if "min_memory_gb" in requirements:
            if node.memory_gb < requirements["min_memory_gb"]:
                return False

        # Check capabilities
        if "required_capabilities" in requirements:
            required_caps = set(requirements["required_capabilities"])
            node_caps = set(node.capabilities)
            if not required_caps.issubset(node_caps):
                return False

        # Check node type
        if "node_type" in requirements:
            if node.node_type != requirements["node_type"]:
                return False

        return True

    async def _assign_task_to_node(self, task: ClusterTask, node: Any):
        """Assign a task to a specific node."""
        task.status = TaskStatus.ASSIGNED
        task.assigned_node = node.node_id
        task.assigned_at = datetime.now(timezone.utc)

        self.running_tasks[task.task_id] = node.node_id

        # Update database
        await self._update_task_in_db(task)

        # Send task to node
        try:
            await self._send_task_to_node(task, node)
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now(timezone.utc)
            await self._update_task_in_db(task)

            logger.info(f" Task {task.task_id} assigned to node {node.node_id}")

        except Exception as e:
            logger.error(
                f" Failed to send task {task.task_id} to node {node.node_id}: {e}"
            )
            task.status = TaskStatus.FAILED
            task.error = str(e)
            await self._update_task_in_db(task)

    async def _send_task_to_node(self, task: ClusterTask, node: Any):
        """Send task to node for execution."""
        # This would be implemented based on the communication protocol
        # For now, we'll simulate the task execution

    async def _task_monitor_loop(self):
        """Background task monitoring loop."""
        while True:
            try:
                await self._monitor_running_tasks()
                await asyncio.sleep(10)  # Check every 10 seconds
            except Exception as e:
                logger.error(f" Task monitor error: {e}")
                await asyncio.sleep(15)

    async def _monitor_running_tasks(self):
        """Monitor running tasks for timeouts and failures."""
        current_time = datetime.now(timezone.utc)
        tasks_to_retry = []

        for task_id, node_id in list(self.running_tasks.items()):
            task = self.tasks.get(task_id)
            if not task:
                continue

            # Check for timeout
            if task.started_at:
                elapsed = (current_time - task.started_at).total_seconds()
                if elapsed > task.timeout_seconds:
                    logger.warning(f" Task {task_id} timed out after {elapsed} seconds")
                    task.status = TaskStatus.TIMEOUT
                    task.error = f"Task timed out after {elapsed} seconds"
                    tasks_to_retry.append(task_id)

        # Handle timed out tasks
        for task_id in tasks_to_retry:
            await self._handle_failed_task(task_id)

    async def _handle_failed_task(self, task_id: str):
        """Handle a failed task (retry or mark as failed)."""
        task = self.tasks[task_id]

        # Remove from running tasks
        if task_id in self.running_tasks:
            del self.running_tasks[task_id]

        # Check if we should retry
        if task.retry_count < task.max_retries:
            task.retry_count += 1
            task.status = TaskStatus.PENDING
            task.assigned_node = None
            task.assigned_at = None
            task.started_at = None

            # Add back to queue
            self._add_to_queue(task_id)

            logger.info(
                f" Retrying task {task_id} (attempt {task.retry_count}/{task.max_retries})"
            )

        else:
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.now(timezone.utc)

            logger.error(
                f" Task {task_id} failed permanently after {task.retry_count} retries"
            )

        await self._update_task_in_db(task)

    async def _metrics_updater_loop(self):
        """Background metrics updater loop."""
        while True:
            try:
                await self._update_metrics()
                await asyncio.sleep(30)  # Update every 30 seconds
            except Exception as e:
                logger.error(f" Metrics updater error: {e}")
                await asyncio.sleep(60)

    async def _update_metrics(self):
        """Update task execution metrics."""
        total_tasks = len(self.tasks)
        pending_tasks = sum(
            1 for task in self.tasks.values() if task.status == TaskStatus.PENDING
        )
        running_tasks = sum(
            1 for task in self.tasks.values() if task.status == TaskStatus.RUNNING
        )
        completed_tasks = sum(
            1 for task in self.tasks.values() if task.status == TaskStatus.COMPLETED
        )
        failed_tasks = sum(
            1
            for task in self.tasks.values()
            if task.status in [TaskStatus.FAILED, TaskStatus.TIMEOUT]
        )

        # Calculate average execution time
        completed_task_times = []
        for task in self.tasks.values():
            if (
                task.status == TaskStatus.COMPLETED
                and task.started_at
                and task.completed_at
            ):
                execution_time = (task.completed_at - task.started_at).total_seconds()
                completed_task_times.append(execution_time)

        average_execution_time = (
            sum(completed_task_times) / len(completed_task_times)
            if completed_task_times
            else 0.0
        )
        success_rate = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0.0

        self.metrics = TaskMetrics(
            total_tasks=total_tasks,
            pending_tasks=pending_tasks,
            running_tasks=running_tasks,
            completed_tasks=completed_tasks,
            failed_tasks=failed_tasks,
            average_execution_time=average_execution_time,
            success_rate=success_rate,
            last_updated=datetime.now(timezone.utc),
        )

    async def _save_task_to_db(self, task: ClusterTask):
        """Save task to database."""
        if not self.db_path:
            return

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO tasks
                (task_id, task_type, priority, payload, requirements, status, assigned_node,
                 created_at, assigned_at, started_at, completed_at, result, error,
                 retry_count, max_retries, timeout_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    task.task_id,
                    task.task_type.value,
                    task.priority.value,
                    json.dumps(task.payload),
                    json.dumps(task.requirements),
                    task.status.value,
                    task.assigned_node,
                    task.created_at.isoformat(),
                    task.assigned_at.isoformat() if task.assigned_at else None,
                    task.started_at.isoformat() if task.started_at else None,
                    task.completed_at.isoformat() if task.completed_at else None,
                    json.dumps(task.result) if task.result else None,
                    task.error,
                    task.retry_count,
                    task.max_retries,
                    task.timeout_seconds,
                ),
            )
            await db.commit()

    async def _update_task_in_db(self, task: ClusterTask):
        """Update task in database."""
        await self._save_task_to_db(task)

    async def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific task."""
        task = self.tasks.get(task_id)
        if not task:
            return None

        return {
            "task_id": task.task_id,
            "task_type": task.task_type.value,
            "priority": task.priority.value,
            "status": task.status.value,
            "assigned_node": task.assigned_node,
            "created_at": task.created_at.isoformat(),
            "assigned_at": task.assigned_at.isoformat() if task.assigned_at else None,
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "completed_at": (
                task.completed_at.isoformat() if task.completed_at else None
            ),
            "result": task.result,
            "error": task.error,
            "retry_count": task.retry_count,
            "max_retries": task.max_retries,
        }

    async def get_cluster_task_metrics(self) -> Dict[str, Any]:
        """Get comprehensive task metrics for the cluster."""
        return {
            "total_tasks": self.metrics.total_tasks,
            "pending_tasks": self.metrics.pending_tasks,
            "running_tasks": self.metrics.running_tasks,
            "completed_tasks": self.metrics.completed_tasks,
            "failed_tasks": self.metrics.failed_tasks,
            "average_execution_time": self.metrics.average_execution_time,
            "success_rate": self.metrics.success_rate,
            "last_updated": self.metrics.last_updated.isoformat(),
            "queue_length": len(self.task_queue),
        }

    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a task."""
        task = self.tasks.get(task_id)
        if not task:
            return False

        if task.status in [
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        ]:
            return False

        task.status = TaskStatus.CANCELLED
        task.completed_at = datetime.now(timezone.utc)

        # Remove from queues
        if task_id in self.task_queue:
            self.task_queue.remove(task_id)
        if task_id in self.running_tasks:
            del self.running_tasks[task_id]

        await self._update_task_in_db(task)

        logger.info(f" Task {task_id} cancelled")
        return True

    async def shutdown(self):
        """Shutdown the task manager."""
        logger.info(" Shutting down Advanced Task Manager")

        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()

        # Wait for background tasks to complete
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)

        logger.info(" Advanced Task Manager shutdown complete")
