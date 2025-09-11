"""
Resource Management System

Comprehensive resource management with pooling, monitoring, cleanup automation,
and intelligent resource allocation for optimal system performance.
"""

import asyncio
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
import os
import tempfile
import threading
from typing import Any
import weakref

import psutil

logger = logging.getLogger(__name__)


@dataclass
class ResourceMetrics:
    """Resource usage metrics."""

    cpu_usage: float = 0.0
    memory_usage_mb: float = 0.0
    disk_usage_mb: float = 0.0
    network_io_mb: float = 0.0
    open_files: int = 0
    active_connections: int = 0
    thread_count: int = 0
    process_count: int = 0
    temp_files_count: int = 0
    temp_files_size_mb: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)


@dataclass
class ResourcePool:
    """Generic resource pool."""

    name: str
    resource_type: str
    max_size: int
    current_size: int = 0
    active_resources: int = 0
    total_created: int = 0
    total_reused: int = 0
    cleanup_threshold: float = 0.8
    last_cleanup: datetime = field(default_factory=datetime.now)


class FileResourceManager:
    """Manages file resources and temporary files."""

    def __init__(self, temp_dir: str | None = None, max_temp_size_mb: int = 1024) -> None:
        self.temp_dir = temp_dir or tempfile.gettempdir()
        self.max_temp_size_mb = max_temp_size_mb
        self.temp_files: dict[str, dict[str, Any]] = {}
        self.file_handles: set[weakref.ref[Any]] = set()
        self.lock = threading.Lock()

    def create_temp_file(self, prefix: str = "plexichat_", suffix: str = ".tmp") -> str:
        """Create a managed temporary file."""
        try:
            fd, filepath = tempfile.mkstemp(
                prefix=prefix, suffix=suffix, dir=self.temp_dir
            )
            os.close(fd)  # Close the file descriptor, keep the path

            with self.lock:
                self.temp_files[filepath] = {
                    "created": datetime.now(),
                    "size": 0,
                    "accessed": datetime.now(),
                }

            logger.debug(f"Created temp file: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Failed to create temp file: {e}")
            raise

    def register_file_handle(self, file_handle: Any) -> None:
        """Register a file handle for tracking."""
        with self.lock:
            self.file_handles.add(weakref.ref(file_handle, self._cleanup_file_ref))

    def _cleanup_file_ref(self, ref: weakref.ref[Any]) -> None:
        """Cleanup callback for file handle weak references."""
        with self.lock:
            self.file_handles.discard(ref)

    def cleanup_temp_files(self, max_age_hours: int = 24) -> dict[str, Any]:
        """Clean up old temporary files."""
        cleaned_files = 0
        freed_space_mb = 0.0
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)

        with self.lock:
            files_to_remove = []

            for filepath, info in self.temp_files.items():
                if info["created"] < cutoff_time or not os.path.exists(filepath):
                    files_to_remove.append(filepath)

            for filepath in files_to_remove:
                try:
                    if os.path.exists(filepath):
                        size = os.path.getsize(filepath)
                        os.remove(filepath)
                        freed_space_mb += size / (1024 * 1024)
                        cleaned_files += 1

                    del self.temp_files[filepath]

                except Exception as e:
                    logger.warning(f"Failed to remove temp file {filepath}: {e}")

        logger.info(
            f"[CLEAN] Cleaned {cleaned_files} temp files, freed {freed_space_mb:.1f}MB"
        )
        return {"files_cleaned": cleaned_files, "space_freed_mb": freed_space_mb}

    def get_temp_usage(self) -> dict[str, Any]:
        """Get temporary file usage statistics."""
        total_size = 0
        total_files = 0

        with self.lock:
            for filepath, info in self.temp_files.items():
                if os.path.exists(filepath):
                    try:
                        size = os.path.getsize(filepath)
                        info["size"] = size
                        total_size += size
                        total_files += 1
                    except OSError:
                        pass

        return {
            "total_files": total_files,
            "total_size_mb": total_size / (1024 * 1024),
            "max_allowed_mb": self.max_temp_size_mb,
            "usage_percent": (total_size / (1024 * 1024)) / self.max_temp_size_mb * 100,
            "temp_dir": self.temp_dir,
        }


class MemoryResourceManager:
    """Manages memory resources and performs cleanup."""

    def __init__(self, cleanup_threshold_mb: int = 512) -> None:
        self.cleanup_threshold_mb = cleanup_threshold_mb
        self.object_registry: dict[str, list[weakref.ref[Any]]] = defaultdict(list)
        self.gc_stats = {"collections": 0, "freed_objects": 0, "freed_mb": 0.0}
        self.lock = threading.Lock()

    def register_object(self, obj: Any, category: str = "default") -> None:
        """Register an object for memory tracking."""
        with self.lock:
            self.object_registry[category].append(
                weakref.ref(obj, self._cleanup_object_ref)
            )

    def _cleanup_object_ref(self, ref: weakref.ref[Any]) -> None:
        """Cleanup callback for object weak references."""
        with self.lock:
            for category, refs in self.object_registry.items():
                if ref in refs:
                    refs.remove(ref)
                    break

    def force_gc(self) -> dict[str, Any]:
        """Force garbage collection and return statistics."""
        import gc as gc_module

        before_mem = psutil.Process().memory_info().rss / (1024 * 1024)

        # Force full garbage collection
        collected = []
        for generation in range(3):
            collected.append(gc_module.collect(generation))

        after_mem = psutil.Process().memory_info().rss / (1024 * 1024)
        freed_mb = before_mem - after_mem

        stats = {
            "collections_performed": len(collected),
            "objects_collected": collected,
            "memory_freed_mb": freed_mb,
            "memory_before_mb": before_mem,
            "memory_after_mb": after_mem,
        }

        with self.lock:
            self.gc_stats["collections"] += 1
            self.gc_stats["freed_objects"] += sum(collected)
            self.gc_stats["freed_mb"] += freed_mb

        logger.info(
            f"[GC] Freed {freed_mb:.1f}MB, collected {sum(collected)} objects"
        )
        return stats

    def get_memory_usage(self) -> dict[str, Any]:
        """Get current memory usage statistics."""
        process = psutil.Process()
        memory_info = process.memory_info()

        with self.lock:
            tracked_objects = sum(
                len([ref for ref in refs if ref() is not None])
                for refs in self.object_registry.values()
            )

        return {
            "rss_mb": memory_info.rss / (1024 * 1024),
            "vms_mb": memory_info.vms / (1024 * 1024),
            "percent": process.memory_percent(),
            "tracked_objects": tracked_objects,
            "gc_stats": self.gc_stats.copy(),
            "cleanup_threshold_mb": self.cleanup_threshold_mb,
        }

    def should_cleanup(self) -> bool:
        """Check if memory cleanup should be performed."""
        current_mb = psutil.Process().memory_info().rss / (1024 * 1024)
        return current_mb > self.cleanup_threshold_mb


class ConnectionPoolManager:
    """Manages connection pools for various resources."""

    def __init__(self, default_max_size: int = 20) -> None:
        self.pools: dict[str, ResourcePool] = {}
        self.connections: dict[str, deque[Any]] = defaultdict(lambda: deque())
        self.active_connections: dict[str, set[Any]] = defaultdict(set)
        self.default_max_size = default_max_size
        self.lock = threading.Lock()

    def create_pool(
        self,
        pool_name: str,
        resource_type: str,
        max_size: int = 0,
        factory: Callable[[], Any] | None = None,
    ) -> ResourcePool:
        """Create a new resource pool."""
        with self.lock:
            if max_size == 0:
                max_size = self.default_max_size

            pool = ResourcePool(
                name=pool_name,
                resource_type=resource_type,
                max_size=max_size,
            )
            self.pools[pool_name] = pool

            logger.info(f"Created resource pool '{pool_name}' (max_size: {max_size})")
            return pool

    def get_resource(self, pool_name: str) -> Any | None:
        """Get a resource from the pool."""
        with self.lock:
            if pool_name not in self.pools:
                return None

            pool = self.pools[pool_name]
            connections = self.connections[pool_name]

            if connections:
                resource = connections.popleft()
                self.active_connections[pool_name].add(resource)
                pool.total_reused += 1
                return resource

            # No available resources and at capacity
            if pool.current_size >= pool.max_size:
                return None

            # Create new resource (placeholder - would be implemented per resource type)
            resource = self._create_resource(pool.resource_type)
            if resource:
                self.active_connections[pool_name].add(resource)
                pool.current_size += 1
                pool.total_created += 1
                pool.active_resources += 1

            return resource

    def return_resource(self, pool_name: str, resource: Any) -> bool:
        """Return a resource to the pool."""
        with self.lock:
            if pool_name not in self.pools:
                return False

            self.active_connections[pool_name].discard(resource)
            self.connections[pool_name].append(resource)
            self.pools[pool_name].active_resources -= 1

            return True

    def _create_resource(self, resource_type: str) -> Any | None:
        """Create a new resource (placeholder implementation)."""
        # This would be implemented based on the resource type
        return {"type": resource_type, "created": datetime.now()}

    def cleanup_pool(self, pool_name: str, max_idle_time: int = 300) -> dict[str, Any]:
        """Clean up idle resources in a pool."""
        if pool_name not in self.pools:
            return {"error": "Pool not found"}

        with self.lock:
            pool = self.pools[pool_name]
            connections = self.connections[pool_name]
            cutoff = datetime.now() - timedelta(seconds=max_idle_time)

            cleaned = 0
            # Simple cleanup - in real implementation, would track creation times
            while connections and cleaned < len(connections) // 2:
                connections.popleft()
                pool.current_size -= 1
                cleaned += 1

            pool.last_cleanup = datetime.now()

        logger.info(f"[POOL] Cleaned {cleaned} idle connections from '{pool_name}'")
        return {"cleaned_connections": cleaned, "remaining": len(connections)}

    def get_pool_stats(self) -> dict[str, dict[str, Any]]:
        """Get statistics for all pools."""
        with self.lock:
            return {
                name: {
                    "resource_type": pool.resource_type,
                    "max_size": pool.max_size,
                    "current_size": pool.current_size,
                    "active_resources": pool.active_resources,
                    "available_resources": len(self.connections[name]),
                    "total_created": pool.total_created,
                    "total_reused": pool.total_reused,
                    "last_cleanup": pool.last_cleanup.isoformat(),
                }
                for name, pool in self.pools.items()
            }


class ResourceManager:
    """Central resource management system."""

    def __init__(
        self,
        temp_dir: str | None = None,
        max_temp_size_mb: int = 1024,
        memory_threshold_mb: int = 512,
        cleanup_interval_seconds: int = 300,
    ) -> None:
        self.file_manager = FileResourceManager(temp_dir, max_temp_size_mb)
        self.memory_manager = MemoryResourceManager(memory_threshold_mb)
        self.connection_manager = ConnectionPoolManager()

        self.cleanup_interval = cleanup_interval_seconds
        self.running = False
        self.cleanup_task: asyncio.Task[None] | None = None

        logger.info("Resource manager initialized")

    async def start(self) -> None:
        """Start the resource manager and cleanup tasks."""
        if self.running:
            return

        self.running = True
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("Resource manager started")

    async def stop(self) -> None:
        """Stop the resource manager."""
        if not self.running:
            return

        self.running = False
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass

        logger.info("Resource manager stopped")

    async def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        while self.running:
            try:
                await self.perform_cleanup()
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")

            await asyncio.sleep(self.cleanup_interval)

    async def perform_cleanup(self) -> dict[str, Any]:
        """Perform comprehensive resource cleanup."""
        cleanup_stats = {}

        try:
            # File cleanup
            file_stats = self.file_manager.cleanup_temp_files()
            cleanup_stats["files"] = file_stats

            # Memory cleanup if needed
            if self.memory_manager.should_cleanup():
                memory_stats = self.memory_manager.force_gc()
                cleanup_stats["memory"] = memory_stats

            # Connection pool cleanup
            pool_stats = {}
            for pool_name in self.connection_manager.pools:
                stats = self.connection_manager.cleanup_pool(pool_name)
                pool_stats[pool_name] = stats
            cleanup_stats["pools"] = pool_stats

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            cleanup_stats["error"] = str(e)

        return cleanup_stats

    def get_resource_status(self) -> dict[str, Any]:
        """Get comprehensive resource status."""
        return {
            "file_resources": self.file_manager.get_temp_usage(),
            "memory_resources": self.memory_manager.get_memory_usage(),
            "connection_pools": self.connection_manager.get_pool_stats(),
            "system_metrics": self._get_system_metrics(),
        }

    def _get_system_metrics(self) -> ResourceMetrics:
        """Get current system resource metrics."""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()

            # Get file descriptor count if available
            try:
                open_files = process.num_fds() if hasattr(process, 'num_fds') else len(process.open_files())
            except (psutil.AccessDenied, AttributeError):
                open_files = 0

            return ResourceMetrics(
                cpu_usage=psutil.cpu_percent(),
                memory_usage_mb=memory_info.rss / (1024 * 1024),
                disk_usage_mb=0.0,  # Could be implemented if needed
                network_io_mb=0.0,  # Could be implemented if needed
                open_files=open_files,
                active_connections=sum(
                    len(conns) for conns in self.connection_manager.active_connections.values()
                ),
                thread_count=threading.active_count(),
                process_count=len(psutil.pids()),
                temp_files_count=len(self.file_manager.temp_files),
                temp_files_size_mb=self.file_manager.get_temp_usage()["total_size_mb"],
            )
        except Exception as e:
            logger.error(f"Error getting system metrics: {e}")
            return ResourceMetrics()


# Global instance
resource_manager = ResourceManager()

# Convenience functions
async def start_resource_management() -> None:
    """Start the global resource manager."""
    await resource_manager.start()


async def stop_resource_management() -> None:
    """Stop the global resource manager."""
    await resource_manager.stop()


def get_resource_status() -> dict[str, Any]:
    """Get resource status from the global manager."""
    return resource_manager.get_resource_status()


async def perform_resource_cleanup() -> dict[str, Any]:
    """Perform resource cleanup via the global manager."""
    return await resource_manager.perform_cleanup()


__all__ = [
    "ConnectionPoolManager",
    "FileResourceManager",
    "MemoryResourceManager",
    "ResourceManager",
    "ResourceMetrics",
    "ResourcePool",
    "get_resource_status",
    "perform_resource_cleanup",
    "resource_manager",
    "start_resource_management",
    "stop_resource_management",
]
