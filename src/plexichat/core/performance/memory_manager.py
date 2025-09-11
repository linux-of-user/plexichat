"""
Memory Management System

Advanced memory management with pooling, leak detection, usage monitoring,
and automatic optimization for optimal performance.
"""

import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
import gc
import logging
import os
import threading
import tracemalloc
from typing import Any
import weakref

import psutil

logger = logging.getLogger(__name__)


@dataclass
class MemoryMetrics:
    """Memory usage metrics."""

    total_memory_mb: float = 0.0
    used_memory_mb: float = 0.0
    available_memory_mb: float = 0.0
    memory_percent: float = 0.0
    gc_collections: int = 0
    gc_objects: int = 0
    peak_memory_mb: float = 0.0
    memory_leaks_detected: int = 0
    last_updated: datetime = field(default_factory=datetime.now)


@dataclass
class ObjectPoolStats:
    """Object pool statistics."""

    pool_name: str
    object_type: str
    pool_size: int = 0
    active_objects: int = 0
    total_created: int = 0
    total_reused: int = 0
    hit_rate: float = 0.0


class ObjectPool:
    """Generic object pool for memory optimization."""

    def __init__(
        self,
        object_class: type,
        max_size: int = 100,
        factory_func: callable | None = None,
    ):
        self.object_class = object_class
        self.max_size = max_size
        self.factory_func = factory_func or object_class
        self.pool: deque = deque()
        self.active_objects: set[Any] = set()
        self.stats = ObjectPoolStats(
            pool_name=f"{object_class.__name__}Pool", object_type=object_class.__name__
        )
        self.lock = threading.Lock()

    def acquire(self) -> Any:
        """Acquire an object from the pool."""
        with self.lock:
            if self.pool:
                obj = self.pool.popleft()
                self.active_objects.add(obj)
                self.stats.total_reused += 1
                self._update_stats()
                return obj
            else:
                # Create new object
                obj = self.factory_func()
                self.active_objects.add(obj)
                self.stats.total_created += 1
                self._update_stats()
                return obj

    def release(self, obj: Any):
        """Release an object back to the pool."""
        with self.lock:
            if obj in self.active_objects:
                self.active_objects.remove(obj)

                if len(self.pool) < self.max_size:
                    # Reset object state if it has a reset method
                    if hasattr(obj, "reset"):
                        try:
                            obj.reset()
                        except Exception as e:
                            logger.warning(f"Failed to reset object: {e}")
                            # Don't add to pool if reset fails
                            return
                    self.pool.append(obj)
                # Pool is full, properly dispose of object
                elif hasattr(obj, "close"):
                    try:
                        obj.close()
                    except Exception as e:
                        logger.warning(f"Failed to close object: {e}")

                self._update_stats()

    def cleanup(self):
        """Clean up the object pool and release all resources."""
        with self.lock:
            # Close all pooled objects
            while self.pool:
                obj = self.pool.popleft()
                if hasattr(obj, "close"):
                    try:
                        obj.close()
                    except Exception as e:
                        logger.warning(f"Failed to close pooled object: {e}")

            # Close all active objects
            for obj in list(self.active_objects):
                if hasattr(obj, "close"):
                    try:
                        obj.close()
                    except Exception as e:
                        logger.warning(f"Failed to close active object: {e}")

            self.active_objects.clear()
            self._update_stats()

    def _update_stats(self):
        """Update pool statistics."""
        self.stats.pool_size = len(self.pool)
        self.stats.active_objects = len(self.active_objects)

        total_operations = self.stats.total_created + self.stats.total_reused
        if total_operations > 0:
            self.stats.hit_rate = self.stats.total_reused / total_operations

    def get_stats(self) -> ObjectPoolStats:
        """Get pool statistics."""
        with self.lock:
            return self.stats


class MemoryLeakDetector:
    """Memory leak detection system."""

    def __init__(self, check_interval: int = 300):
        self.check_interval = check_interval
        self.object_counts: dict[str, deque] = defaultdict(lambda: deque(maxlen=10))
        self.weak_refs: set[weakref.ref] = set()
        self.leak_threshold = 1.5  # 50% increase threshold
        self.running = False
        self._task = None

    def start_monitoring(self):
        """Start leak detection monitoring."""
        if self.running:
            return

        self.running = True
        tracemalloc.start()
        self._task = asyncio.create_task(self._monitoring_loop())
        logger.info("[DEBUG] Memory leak detection started")

    def stop_monitoring(self):
        """Stop leak detection monitoring."""
        self.running = False
        if self._task:
            self._task.cancel()
        tracemalloc.stop()
        logger.info("[STOP] Memory leak detection stopped")

    async def _monitoring_loop(self):
        """Background monitoring loop."""
        while self.running:
            try:
                await self._check_for_leaks()
                await asyncio.sleep(self.check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Memory leak detection error: {e}")
                await asyncio.sleep(60)

    async def _check_for_leaks(self):
        """Check for potential memory leaks."""
        try:
            # Get current object counts
            current_objects = {}
            for obj_type in gc.get_objects():
                type_name = type(obj_type).__name__
                current_objects[type_name] = current_objects.get(type_name, 0) + 1

            # Check for significant increases
            for obj_type, count in current_objects.items():
                self.object_counts[obj_type].append(count)

                if len(self.object_counts[obj_type]) >= 3:
                    recent_counts = list(self.object_counts[obj_type])
                    avg_old = sum(recent_counts[:-2]) / len(recent_counts[:-2])
                    current_count = recent_counts[-1]

                    if avg_old > 0 and current_count / avg_old > self.leak_threshold:
                        logger.warning(
                            f"[ALERT] Potential memory leak detected: {obj_type} "
                            f"count increased from {avg_old:.0f} to {current_count}"
                        )

            # Get tracemalloc snapshot
            if tracemalloc.is_tracing():
                snapshot = tracemalloc.take_snapshot()
                top_stats = snapshot.statistics("lineno")

                # Log top memory consumers
                for stat in top_stats[:5]:
                    logger.debug(f"Memory usage: {stat}")

        except Exception as e:
            logger.error(f"Error checking for memory leaks: {e}")


class MemoryManager:
    """Advanced memory management system."""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.metrics = MemoryMetrics()

        # Object pools
        self.object_pools: dict[str, ObjectPool] = {}

        # Memory monitoring
        self.leak_detector = MemoryLeakDetector(
            self.config.get("leak_check_interval", 300)
        )

        # Configuration
        self.gc_threshold = self.config.get("gc_threshold_mb", 100)
        self.monitoring_interval = self.config.get("monitoring_interval", 60)
        self.auto_gc_enabled = self.config.get("auto_gc_enabled", True)

        # Background tasks
        self._monitoring_task = None
        self._gc_task = None
        self._running = False

        logger.info("[BRAIN] Memory Manager initialized")

    async def initialize(self) -> bool:
        """Initialize memory management system."""
        try:
            # Start leak detection
            if self.config.get("leak_detection_enabled", True):
                self.leak_detector.start_monitoring()

            # Start monitoring
            await self.start_monitoring()

            # Configure garbage collection
            self._configure_gc()

            logger.info("[START] Memory management system initialized")
            return True

        except Exception as e:
            logger.error(f"Memory management initialization failed: {e}")
            return False

    async def shutdown(self):
        """Shutdown memory management system."""
        try:
            self._running = False

            # Stop monitoring tasks
            if self._monitoring_task:
                self._monitoring_task.cancel()
            if self._gc_task:
                self._gc_task.cancel()

            # Stop leak detection
            self.leak_detector.stop_monitoring()

            # Clear object pools
            self.object_pools.clear()

            logger.info("[STOP] Memory management shutdown complete")

        except Exception as e:
            logger.error(f"Error during memory management shutdown: {e}")

    def create_object_pool(
        self,
        name: str,
        object_class: type,
        max_size: int = 100,
        factory_func: callable | None = None,
    ) -> ObjectPool:
        """Create a new object pool."""
        pool = ObjectPool(object_class, max_size, factory_func)
        self.object_pools[name] = pool
        logger.info(f"[PACKAGE] Created object pool: {name} (max_size: {max_size})")
        return pool

    def get_object_pool(self, name: str) -> ObjectPool | None:
        """Get an existing object pool."""
        return self.object_pools.get(name)

    async def start_monitoring(self):
        """Start memory monitoring."""
        if self._running:
            return

        self._running = True
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())

        if self.auto_gc_enabled:
            self._gc_task = asyncio.create_task(self._gc_loop())

        logger.info("[METRICS] Memory monitoring started")

    async def _monitoring_loop(self):
        """Background monitoring loop."""
        while self._running:
            try:
                await self._collect_memory_metrics()
                await asyncio.sleep(self.monitoring_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Memory monitoring error: {e}")
                await asyncio.sleep(30)

    async def _collect_memory_metrics(self):
        """Collect memory usage metrics."""
        try:
            # System memory
            memory = psutil.virtual_memory()
            self.metrics.total_memory_mb = memory.total / (1024 * 1024)
            self.metrics.used_memory_mb = memory.used / (1024 * 1024)
            self.metrics.available_memory_mb = memory.available / (1024 * 1024)
            self.metrics.memory_percent = memory.percent

            # Process memory
            process = psutil.Process(os.getpid())
            process_memory = process.memory_info().rss / (1024 * 1024)
            self.metrics.peak_memory_mb = max(
                self.metrics.peak_memory_mb, process_memory
            )

            # Garbage collection stats
            gc_stats = gc.get_stats()
            if gc_stats:
                self.metrics.gc_collections = sum(
                    stat["collections"] for stat in gc_stats
                )

            self.metrics.gc_objects = len(gc.get_objects())
            self.metrics.last_updated = datetime.now()

            # Check for high memory usage
            if self.metrics.memory_percent > 90:
                logger.warning(
                    f"[ALERT] High memory usage: {self.metrics.memory_percent:.1f}%"
                )

        except Exception as e:
            logger.error(f"Error collecting memory metrics: {e}")

    async def _gc_loop(self):
        """Background garbage collection loop."""
        while self._running:
            try:
                # Check if GC is needed
                if self.metrics.used_memory_mb > self.gc_threshold:
                    await self.force_garbage_collection()

                await asyncio.sleep(120)  # Check every 2 minutes

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"GC loop error: {e}")
                await asyncio.sleep(60)

    def _configure_gc(self):
        """Configure garbage collection settings."""
        # Set GC thresholds for better performance
        gc.set_threshold(700, 10, 10)

        # Enable automatic garbage collection
        gc.enable()

        logger.info("[DELETE] Garbage collection configured")

    async def force_garbage_collection(self) -> dict[str, int]:
        """Force garbage collection and return statistics."""
        try:
            before_objects = len(gc.get_objects())
            before_memory = psutil.virtual_memory().used / (1024 * 1024)

            # Run garbage collection
            collected = gc.collect()

            after_objects = len(gc.get_objects())
            after_memory = psutil.virtual_memory().used / (1024 * 1024)

            stats = {
                "objects_before": before_objects,
                "objects_after": after_objects,
                "objects_collected": before_objects - after_objects,
                "memory_before_mb": before_memory,
                "memory_after_mb": after_memory,
                "memory_freed_mb": before_memory - after_memory,
                "gc_collected": collected,
            }

            logger.info(
                f"[DELETE] GC completed: freed {stats['memory_freed_mb']:.1f}MB, "
                f"collected {stats['objects_collected']} objects"
            )

            return stats

        except Exception as e:
            logger.error(f"Error during garbage collection: {e}")
            return {}

    def get_memory_stats(self) -> dict[str, Any]:
        """Get comprehensive memory statistics."""
        return {
            "system_memory": {
                "total_mb": self.metrics.total_memory_mb,
                "used_mb": self.metrics.used_memory_mb,
                "available_mb": self.metrics.available_memory_mb,
                "usage_percent": self.metrics.memory_percent,
                "peak_usage_mb": self.metrics.peak_memory_mb,
            },
            "garbage_collection": {
                "collections": self.metrics.gc_collections,
                "objects": self.metrics.gc_objects,
                "auto_gc_enabled": self.auto_gc_enabled,
                "gc_threshold_mb": self.gc_threshold,
            },
            "object_pools": {
                name: {
                    "pool_size": pool.stats.pool_size,
                    "active_objects": pool.stats.active_objects,
                    "total_created": pool.stats.total_created,
                    "total_reused": pool.stats.total_reused,
                    "hit_rate": pool.stats.hit_rate,
                }
                for name, pool in self.object_pools.items()
            },
            "leak_detection": {
                "enabled": self.leak_detector.running,
                "check_interval": self.leak_detector.check_interval,
                "leaks_detected": self.metrics.memory_leaks_detected,
            },
        }

    def optimize_memory_usage(self) -> dict[str, Any]:
        """Optimize memory usage and return optimization results."""
        try:
            results = {}

            # Force garbage collection
            gc_stats = asyncio.create_task(self.force_garbage_collection())
            results["garbage_collection"] = gc_stats

            # Clear object pool unused objects
            pools_cleared = 0
            for pool in self.object_pools.values():
                if len(pool.pool) > pool.max_size // 2:
                    # Clear half of the pooled objects
                    clear_count = len(pool.pool) // 2
                    for _ in range(clear_count):
                        if pool.pool:
                            pool.pool.popleft()
                    pools_cleared += 1

            results["pools_optimized"] = pools_cleared

            # Suggest optimizations
            suggestions = []
            if self.metrics.memory_percent > 80:
                suggestions.append("Consider reducing cache sizes")
            if self.metrics.gc_objects > 100000:
                suggestions.append(
                    "High object count detected, consider object pooling"
                )

            results["suggestions"] = suggestions

            logger.info(
                f"[CONFIG] Memory optimization completed: {len(suggestions)} suggestions"
            )
            return results

        except Exception as e:
            logger.error(f"Error during memory optimization: {e}")
            return {"error": str(e)}


# Global memory manager instance
memory_manager = MemoryManager()
