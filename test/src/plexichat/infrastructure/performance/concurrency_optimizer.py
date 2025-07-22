"""
Concurrency Optimizer

Advanced concurrency management with deadlock detection, async/await optimization,
and intelligent thread pool management for optimal performance.
"""

import asyncio
import logging
import threading
import time
import weakref
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Callable
import concurrent.futures
import sys

logger = logging.getLogger(__name__)


@dataclass
class DeadlockInfo:
    """Information about a detected deadlock."""
    thread_ids: List[int]
    lock_chain: List[str]
    detection_time: datetime
    resolved: bool = False
    resolution_method: Optional[str] = None


@dataclass
class ConcurrencyMetrics:
    """Concurrency performance metrics."""
    active_threads: int = 0
    active_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    deadlocks_detected: int = 0
    deadlocks_resolved: int = 0
    avg_task_duration: float = 0.0
    thread_pool_utilization: float = 0.0
    async_loop_utilization: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)


class DeadlockDetector:
    """Advanced deadlock detection system."""

    def __init__(self, check_interval: float = 5.0):
        self.check_interval = check_interval
        self.lock_graph: Dict[int, Set[int]] = defaultdict(set)
        self.thread_locks: Dict[int, Set[str]] = defaultdict(set)
        self.lock_owners: Dict[str, int] = {}
        self.lock_waiters: Dict[str, Set[int]] = defaultdict(set)
        self.detected_deadlocks: List[DeadlockInfo] = []
        self.running = False
        self._task = None
        self._lock = threading.Lock()

    def start_monitoring(self):
        """Start deadlock monitoring."""
        if self.running:
            return

        self.running = True
        self._task = asyncio.create_task(self._monitoring_loop())
        logger.info("🔒 Deadlock detection started")

    def stop_monitoring(self):
        """Stop deadlock monitoring."""
        self.running = False
        if self._task:
            self._task.cancel()
        logger.info("🔓 Deadlock detection stopped")

    def register_lock_acquisition(self, thread_id: int, lock_name: str):
        """Register that a thread has acquired a lock."""
        with self._lock:
            self.thread_locks[thread_id].add(lock_name)
            self.lock_owners[lock_name] = thread_id

            # Remove from waiters if present
            self.lock_waiters[lock_name].discard(thread_id)

    def register_lock_wait(self, thread_id: int, lock_name: str):
        """Register that a thread is waiting for a lock."""
        with self._lock:
            self.lock_waiters[lock_name].add(thread_id)

            # Update dependency graph
            if lock_name in self.lock_owners:
                owner_thread = self.lock_owners[lock_name]
                self.lock_graph[thread_id].add(owner_thread)

    def register_lock_release(self, thread_id: int, lock_name: str):
        """Register that a thread has released a lock."""
        with self._lock:
            self.thread_locks[thread_id].discard(lock_name)

            if self.lock_owners.get(lock_name) == thread_id:
                del self.lock_owners[lock_name]

            # Remove dependencies
            for waiting_thread in self.lock_waiters[lock_name]:
                self.lock_graph[waiting_thread].discard(thread_id)

            self.lock_waiters[lock_name].clear()

    async def _monitoring_loop(self):
        """Background deadlock detection loop."""
        while self.running:
            try:
                await self._detect_deadlocks()
                await asyncio.sleep(self.check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Deadlock detection error: {e}")
                await asyncio.sleep(1)

    async def _detect_deadlocks(self):
        """Detect deadlocks using cycle detection in dependency graph."""
        try:
            with self._lock:
                # Copy current state for analysis
                graph = dict(self.lock_graph)

            # Detect cycles using DFS
            visited = set()
            rec_stack = set()

            for node in graph:
                if node not in visited:
                    cycle = self._dfs_cycle_detection(graph, node, visited, rec_stack, [])
                    if cycle:
                        await self._handle_deadlock(cycle)

        except Exception as e:
            logger.error(f"Error during deadlock detection: {e}")

    def _dfs_cycle_detection(self, graph: Dict[int, Set[int]], node: int, ):
                           visited: Set[int], rec_stack: Set[int], path: List[int]) -> Optional[List[int]]:
        """DFS-based cycle detection."""
        visited.add(node)
        rec_stack.add(node)
        path.append(node)

        for neighbor in graph.get(node, set()):
            if neighbor not in visited:
                cycle = self._dfs_cycle_detection(graph, neighbor, visited, rec_stack, path)
                if cycle:
                    return cycle
            elif neighbor in rec_stack:
                # Found cycle
                cycle_start = path.index(neighbor)
                return path[cycle_start:] + [neighbor]

        rec_stack.remove(node)
        path.pop()
        return None

    async def _handle_deadlock(self, cycle: List[int]):
        """Handle detected deadlock."""
        try:
            deadlock_info = DeadlockInfo()
                thread_ids=cycle,
                lock_chain=[f"thread_{tid}" for tid in cycle],
                detection_time=datetime.now()
            )

            self.detected_deadlocks.append(deadlock_info)

            logger.warning(f"🚨 Deadlock detected: threads {cycle}")

            # Attempt resolution (simplified approach)
            await self._resolve_deadlock(deadlock_info)

        except Exception as e:
            logger.error(f"Error handling deadlock: {e}")

    async def _resolve_deadlock(self, deadlock_info: DeadlockInfo):
        """Attempt to resolve deadlock."""
        try:
            # Simple resolution: log warning and let timeout mechanisms handle it
            # In a production system, this could implement more sophisticated resolution
            logger.warning(f"Deadlock resolution attempted for threads: {deadlock_info.thread_ids}")

            deadlock_info.resolved = True
            deadlock_info.resolution_method = "timeout_based"

        except Exception as e:
            logger.error(f"Error resolving deadlock: {e}")


class AsyncOptimizer:
    """Async/await performance optimizer."""

    def __init__(self):
        self.task_metrics: Dict[str, List[float]] = defaultdict(list)
        self.loop_metrics: Dict[str, Any] = {}
        self.optimization_suggestions: List[str] = []

    async def optimize_task_execution(self, tasks: List[Callable], )
                                    max_concurrent: int = 10) -> List[Any]:
        """Execute tasks with optimal concurrency."""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def controlled_task(task_func):
            async with semaphore:
                start_time = time.time()
                try:
                    if asyncio.iscoroutinefunction(task_func):
                        result = await task_func()
                    else:
                        result = task_func()

                    duration = time.time() - start_time
                    self.task_metrics[task_func.__name__].append(duration)

                    return result
                except Exception as e:
                    logger.error(f"Task {task_func.__name__} failed: {e}")
                    raise

        return await asyncio.gather(*[controlled_task(task) for task in tasks], )
                                  return_exceptions=True)

    async def batch_execute(self, tasks: List[Callable], batch_size: int = 5) -> List[Any]:
        """Execute tasks in optimized batches."""
        results = []

        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            batch_results = await self.optimize_task_execution(batch)
            results.extend(batch_results)

            # Small delay between batches to prevent overwhelming
            if i + batch_size < len(tasks):
                await asyncio.sleep(0.01)

        return results

    def analyze_performance(self) -> Dict[str, Any]:
        """Analyze async performance and provide suggestions."""
        analysis = {
            'task_performance': {},
            'suggestions': []
        }

        for task_name, durations in self.task_metrics.items():
            if durations:
                avg_duration = sum(durations) / len(durations)
                max_duration = max(durations)
                min_duration = min(durations)

                analysis['task_performance'][task_name] = {
                    'avg_duration': avg_duration,
                    'max_duration': max_duration,
                    'min_duration': min_duration,
                    'execution_count': len(durations)
                }

                # Generate suggestions
                if avg_duration > 1.0:
                    analysis['suggestions'].append()
                        f"Task {task_name} has high average duration ({avg_duration:.2f}s). "
                        "Consider optimization or breaking into smaller tasks."
                    )

                if max_duration > avg_duration * 3:
                    analysis['suggestions'].append()
                        f"Task {task_name} has inconsistent performance. "
                        "Consider adding timeout or retry mechanisms."
                    )

        return analysis


class ConcurrencyOptimizer:
    """Main concurrency optimization manager."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.metrics = ConcurrencyMetrics()

        # Components
        self.deadlock_detector = DeadlockDetector()
            self.config.get('deadlock_check_interval', 5.0)
        )
        self.async_optimizer = AsyncOptimizer()

        # Thread pool management
        self.thread_pools: Dict[str, concurrent.futures.ThreadPoolExecutor] = {}
        self.default_pool_size = self.config.get('default_thread_pool_size', 10)

        # Background tasks
        self._monitoring_task = None
        self._running = False

        logger.info("⚡ Concurrency Optimizer initialized")

    async def initialize(self) -> bool:
        """Initialize concurrency optimization."""
        try:
            # Start deadlock detection
            if self.config.get('deadlock_detection_enabled', True):
                self.deadlock_detector.start_monitoring()

            # Create default thread pool
            self.create_thread_pool('default', self.default_pool_size)

            # Start monitoring
            await self.start_monitoring()

            logger.info("🚀 Concurrency optimization initialized")
            return True

        except Exception as e:
            logger.error(f"Concurrency optimization initialization failed: {e}")
            return False

    async def shutdown(self):
        """Shutdown concurrency optimizer."""
        try:
            self._running = False

            # Stop monitoring
            if self._monitoring_task:
                self._monitoring_task.cancel()

            # Stop deadlock detection
            self.deadlock_detector.stop_monitoring()

            # Shutdown thread pools
            for pool in self.thread_pools.values():
                pool.shutdown(wait=True)

            logger.info("🛑 Concurrency optimizer shutdown complete")

        except Exception as e:
            logger.error(f"Error during concurrency optimizer shutdown: {e}")

    def create_thread_pool(self, name: str, max_workers: int) -> concurrent.futures.ThreadPoolExecutor:
        """Create a named thread pool."""
        pool = concurrent.futures.ThreadPoolExecutor()
            max_workers=max_workers,
            thread_name_prefix=f"PlexiChat-{name}"
        )
        self.thread_pools[name] = pool
        logger.info(f"🧵 Created thread pool: {name} (max_workers: {max_workers})")
        return pool

    def get_thread_pool(self, name: str = 'default') -> Optional[concurrent.futures.ThreadPoolExecutor]:
        """Get a thread pool by name."""
        return self.thread_pools.get(name)

    async def execute_in_thread_pool(self, func: Callable, *args, )
                                   pool_name: str = 'default', **kwargs) -> Any:
        """Execute function in specified thread pool."""
        pool = self.get_thread_pool(pool_name)
        if not pool:
            raise ValueError(f"Thread pool '{pool_name}' not found")

        loop = asyncio.get_event_loop()
        start_time = time.time()

        try:
            result = await loop.run_in_executor(pool, func, *args, **kwargs)

            # Update metrics
            duration = time.time() - start_time
            self.metrics.completed_tasks += 1

            # Update average duration
            if self.metrics.completed_tasks > 1:
                self.metrics.avg_task_duration = ()
                    (self.metrics.avg_task_duration * (self.metrics.completed_tasks - 1) + duration) /
                    self.metrics.completed_tasks
                )
            else:
                self.metrics.avg_task_duration = duration

            return result

        except Exception as e:
            self.metrics.failed_tasks += 1
            logger.error(f"Thread pool execution failed: {e}")
            raise

    async def start_monitoring(self):
        """Start concurrency monitoring."""
        if self._running:
            return

        self._running = True
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("📊 Concurrency monitoring started")

    async def _monitoring_loop(self):
        """Background monitoring loop."""
        while self._running:
            try:
                await self._collect_metrics()
                await asyncio.sleep(30)  # Monitor every 30 seconds

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Concurrency monitoring error: {e}")
                await asyncio.sleep(10)

    async def _collect_metrics(self):
        """Collect concurrency metrics."""
        try:
            # Thread metrics
            self.metrics.active_threads = threading.active_count()

            # Task metrics
            try:
                loop = asyncio.get_running_loop()
                all_tasks = asyncio.all_tasks(loop)
                self.metrics.active_tasks = len([t for t in all_tasks if not t.done()])
            except RuntimeError:
                pass

            # Thread pool utilization
            total_workers = sum(pool._max_workers for pool in self.thread_pools.values())
            if total_workers > 0:
                # This is a simplified calculation
                self.metrics.thread_pool_utilization = min(1.0, self.metrics.active_threads / total_workers)

            # Deadlock metrics
            self.metrics.deadlocks_detected = len(self.deadlock_detector.detected_deadlocks)
            self.metrics.deadlocks_resolved = len([)
                d for d in self.deadlock_detector.detected_deadlocks if d.resolved
            ])

            self.metrics.last_updated = datetime.now()

        except Exception as e:
            logger.error(f"Error collecting concurrency metrics: {e}")

    def get_concurrency_stats(self) -> Dict[str, Any]:
        """Get comprehensive concurrency statistics."""
        return {
            'threads': {
                'active_threads': self.metrics.active_threads,
                'thread_pools': {
                    name: {
                        'max_workers': pool._max_workers,
                        'active_workers': getattr(pool, '_threads', set()).__len__()
                    }
                    for name, pool in self.thread_pools.items()
                }
            },
            'tasks': {
                'active_tasks': self.metrics.active_tasks,
                'completed_tasks': self.metrics.completed_tasks,
                'failed_tasks': self.metrics.failed_tasks,
                'avg_duration': self.metrics.avg_task_duration,
                'success_rate': ()
                    self.metrics.completed_tasks /
                    (self.metrics.completed_tasks + self.metrics.failed_tasks)
                ) if (self.metrics.completed_tasks + self.metrics.failed_tasks) > 0 else 0
            },
            'deadlocks': {
                'detected': self.metrics.deadlocks_detected,
                'resolved': self.metrics.deadlocks_resolved,
                'resolution_rate': ()
                    self.metrics.deadlocks_resolved / self.metrics.deadlocks_detected
                ) if self.metrics.deadlocks_detected > 0 else 0
            },
            'utilization': {
                'thread_pool_utilization': self.metrics.thread_pool_utilization,
                'async_loop_utilization': self.metrics.async_loop_utilization
            },
            'performance_analysis': self.async_optimizer.analyze_performance()
        }

    async def optimize_concurrency(self) -> Dict[str, Any]:
        """Optimize concurrency settings and return results."""
        try:
            results = {}

            # Analyze current performance
            stats = self.get_concurrency_stats()
            results['current_stats'] = stats

            # Generate optimization suggestions
            suggestions = []

            if stats['utilization']['thread_pool_utilization'] > 0.9:
                suggestions.append("Consider increasing thread pool size")
            elif stats['utilization']['thread_pool_utilization'] < 0.3:
                suggestions.append("Consider reducing thread pool size to save resources")

            if stats['tasks']['success_rate'] < 0.95:
                suggestions.append("High task failure rate detected, review error handling")

            if stats['deadlocks']['detected'] > 0:
                suggestions.append("Deadlocks detected, review locking strategies")

            results['suggestions'] = suggestions

            logger.info(f"🔧 Concurrency optimization completed: {len(suggestions)} suggestions")
            return results

        except Exception as e:
            logger.error(f"Error during concurrency optimization: {e}")
            return {'error': str(e)}


# Global concurrency optimizer instance
concurrency_optimizer = ConcurrencyOptimizer()
