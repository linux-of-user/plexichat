"""
Resource Management System

Comprehensive resource management with pooling, monitoring, cleanup automation,
and intelligent resource allocation for optimal system performance.
"""

import asyncio
import gc
import logging
import os
import psutil
import threading
import time
import weakref
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Type, Callable
import tempfile
import shutil

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

    def __init__(self, temp_dir: Optional[str] = None, max_temp_size_mb: int = 1024):
        self.temp_dir = temp_dir or tempfile.gettempdir()
        self.max_temp_size_mb = max_temp_size_mb
        self.temp_files: Dict[str, Dict[str, Any]] = {}
        self.file_handles: Set[Any] = set()
        self.lock = threading.Lock()

    def create_temp_file(self, prefix: str = "plexichat_", suffix: str = ".tmp") -> str:
        """Create a managed temporary file."""
        try:
            fd, filepath = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=self.temp_dir)
            os.close(fd)  # Close the file descriptor, keep the path

            with self.lock:
                self.temp_files[filepath] = {
                    'created': datetime.now(),
                    'size': 0,
                    'accessed': datetime.now()
                }

            logger.debug(f"Created temp file: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Failed to create temp file: {e}")
            raise

    def register_file_handle(self, file_handle: Any):
        """Register a file handle for tracking."""
        with self.lock:
            self.file_handles.add(weakref.ref(file_handle, self._cleanup_file_ref))

    def _cleanup_file_ref(self, ref):
        """Cleanup callback for file handle weak references."""
        with self.lock:
            self.file_handles.discard(ref)

    def cleanup_temp_files(self, max_age_hours: int = 24) -> Dict[str, int]:
        """Clean up old temporary files."""
        cleaned_files = 0
        freed_space_mb = 0
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)

        with self.lock:
            files_to_remove = []

            for filepath, info in self.temp_files.items():
                if info['created'] < cutoff_time or not os.path.exists(filepath):
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

        logger.info(f"[CLEAN] Cleaned {cleaned_files} temp files, freed {freed_space_mb:.1f}MB")
        return {}'files_cleaned': cleaned_files, 'space_freed_mb': freed_space_mb}

    def get_temp_usage(self) -> Dict[str, Any]:
        """Get temporary file usage statistics."""
        total_size = 0
        total_files = 0

        with self.lock:
            for filepath, info in self.temp_files.items():
                if os.path.exists(filepath):
                    try:
                        size = os.path.getsize(filepath)
                        info['size'] = size
                        total_size += size
                        total_files += 1
                    except OSError:
                        pass

        return {}
            'total_files': total_files,
            'total_size_mb': total_size / (1024 * 1024),
            'max_size_mb': self.max_temp_size_mb,
            'usage_percent': (total_size / (1024 * 1024)) / self.max_temp_size_mb * 100,
            'open_handles': len(self.file_handles)
        }


class ConnectionResourceManager:
    """Manages network connections and database connections."""

    def __init__(self, max_connections: int = 1000):
        self.max_connections = max_connections
        self.active_connections: Dict[str, Dict[str, Any]] = {}
        self.connection_pools: Dict[str, List[Any]] = defaultdict(list)
        self.lock = threading.Lock()

    def register_connection(self, conn_id: str, connection_type: str, metadata: Dict[str, Any] = None):
        """Register an active connection."""
        with self.lock:
            self.active_connections[conn_id] = {
                'type': connection_type,
                'created': datetime.now(),
                'last_used': datetime.now(),
                'metadata': metadata or {}
            }

    def unregister_connection(self, conn_id: str):
        """Unregister a connection."""
        with self.lock:
            self.active_connections.pop(conn_id, None)

    def update_connection_usage(self, conn_id: str):
        """Update connection last used time."""
        with self.lock:
            if conn_id in self.active_connections:
                self.active_connections[conn_id]['last_used'] = datetime.now()

    def cleanup_stale_connections(self, max_idle_minutes: int = 30) -> int:
        """Clean up stale connections."""
        cutoff_time = datetime.now() - timedelta(minutes=max_idle_minutes)
        cleaned_count = 0

        with self.lock:
            stale_connections = [
                conn_id for conn_id, info in self.active_connections.items()
                if info['last_used'] < cutoff_time
            ]

            for conn_id in stale_connections:
                try:
                    # In a real implementation, this would close the actual connection
                    del self.active_connections[conn_id]
                    cleaned_count += 1
                except Exception as e:
                    logger.warning(f"Failed to cleanup connection {conn_id}: {e}")

        if cleaned_count > 0:
            logger.info(f"[PLUGIN] Cleaned up {cleaned_count} stale connections")

        return cleaned_count

    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics."""
        with self.lock:
            connection_types = defaultdict(int)
            for info in self.active_connections.values():
                connection_types[info['type']] += 1

            return {}
                'total_connections': len(self.active_connections),
                'max_connections': self.max_connections,
                'usage_percent': len(self.active_connections) / self.max_connections * 100,
                'by_type': dict(connection_types)
            }


class ResourceManager:
    """Main resource management system."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.metrics = ResourceMetrics()

        # Resource managers
        self.file_manager = FileResourceManager()
            temp_dir=self.config.get('temp_dir'),
            max_temp_size_mb=self.config.get('max_temp_size_mb', 1024)
        )
        self.connection_manager = ConnectionResourceManager()
            max_connections=self.config.get('max_connections', 1000)
        )

        # Resource pools
        self.resource_pools: Dict[str, ResourcePool] = {}

        # Configuration
        self.monitoring_interval = self.config.get('monitoring_interval', 60)
        self.cleanup_interval = self.config.get('cleanup_interval', 300)
        self.resource_thresholds = self.config.get('resource_thresholds', {)
            'cpu_percent': 80,
            'memory_percent': 85,
            'disk_percent': 90,
            'connections_percent': 90
        })

        # Background tasks
        self._monitoring_task = None
        self._cleanup_task = None
        self._running = False

        logger.info("[CONFIG] Resource Manager initialized")

    async def initialize(self) -> bool:
        """Initialize resource management system."""
        try:
            # Start monitoring
            await self.start_monitoring()

            # Create default resource pools
            self.create_resource_pool('database_connections', 'connection', 50)
            self.create_resource_pool('http_sessions', 'session', 20)
            self.create_resource_pool('file_handles', 'file', 100)

            logger.info("[START] Resource management system initialized")
            return True

        except Exception as e:
            logger.error(f"Resource management initialization failed: {e}")
            return False

    async def shutdown(self):
        """Shutdown resource management system."""
        try:
            self._running = False

            # Stop monitoring tasks
            if self._monitoring_task:
                self._monitoring_task.cancel()
            if self._cleanup_task:
                self._cleanup_task.cancel()

            # Cleanup all resources
            await self.cleanup_all_resources()

            logger.info("[STOP] Resource management shutdown complete")

        except Exception as e:
            logger.error(f"Error during resource management shutdown: {e}")

    def create_resource_pool(self, name: str, resource_type: str, max_size: int) -> ResourcePool:
        """Create a new resource pool."""
        pool = ResourcePool()
            name=name,
            resource_type=resource_type,
            max_size=max_size
        )
        self.resource_pools[name] = pool
        logger.info(f"[PACKAGE] Created resource pool: {name} (type: {resource_type}, max: {max_size})")
        return pool

    async def start_monitoring(self):
        """Start resource monitoring."""
        if self._running:
            return

        self._running = True
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

        logger.info("[METRICS] Resource monitoring started")

    async def _monitoring_loop(self):
        """Background monitoring loop."""
        while self._running:
            try:
                await self._collect_resource_metrics()
                await self._check_resource_thresholds()
                await asyncio.sleep(self.monitoring_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Resource monitoring error: {e}")
                await asyncio.sleep(30)

    async def _collect_resource_metrics(self):
        """Collect system resource metrics."""
        try:
            # CPU and memory
            self.metrics.cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            self.metrics.memory_usage_mb = memory.used / (1024 * 1024)

            # Disk usage
            disk = psutil.disk_usage('/')
            self.metrics.disk_usage_mb = disk.used / (1024 * 1024)

            # Network I/O
            network = psutil.net_io_counters()
            if network:
                self.metrics.network_io_mb = (network.bytes_sent + network.bytes_recv) / (1024 * 1024)

            # Process info
            process = psutil.Process()
            self.metrics.open_files = process.num_fds() if hasattr(process, 'num_fds') else 0
            self.metrics.thread_count = process.num_threads()

            # Connection stats
            conn_stats = self.connection_manager.get_connection_stats()
            self.metrics.active_connections = conn_stats['total_connections']

            # Temp file stats
            temp_stats = self.file_manager.get_temp_usage()
            self.metrics.temp_files_count = temp_stats['total_files']
            self.metrics.temp_files_size_mb = temp_stats['total_size_mb']

            self.metrics.last_updated = datetime.now()

        except Exception as e:
            logger.error(f"Error collecting resource metrics: {e}")

    async def _check_resource_thresholds(self):
        """Check if resource usage exceeds thresholds."""
        try:
            # Check CPU usage
            if self.metrics.cpu_usage > self.resource_thresholds['cpu_percent']:
                logger.warning(f"[ALERT] High CPU usage: {self.metrics.cpu_usage:.1f}%")
                await self._trigger_resource_optimization('cpu')

            # Check memory usage
            memory_percent = (self.metrics.memory_usage_mb / (psutil.virtual_memory().total / (1024 * 1024))) * 100
            if memory_percent > self.resource_thresholds['memory_percent']:
                logger.warning(f"[ALERT] High memory usage: {memory_percent:.1f}%")
                await self._trigger_resource_optimization('memory')

            # Check connection usage
            conn_stats = self.connection_manager.get_connection_stats()
            if conn_stats['usage_percent'] > self.resource_thresholds['connections_percent']:
                logger.warning(f"[ALERT] High connection usage: {conn_stats['usage_percent']:.1f}%")
                await self._trigger_resource_optimization('connections')

        except Exception as e:
            logger.error(f"Error checking resource thresholds: {e}")

    async def _trigger_resource_optimization(self, resource_type: str):
        """Trigger resource optimization for specific resource type."""
        try:
            if resource_type == 'memory':
                # Force garbage collection
                gc.collect()
                logger.info("[DELETE] Triggered garbage collection for memory optimization")

            elif resource_type == 'connections':
                # Cleanup stale connections
                cleaned = self.connection_manager.cleanup_stale_connections(max_idle_minutes=15)
                logger.info(f"[PLUGIN] Cleaned {cleaned} stale connections")

            elif resource_type == 'cpu':
                # Reduce background task frequency temporarily
                logger.info("[TIMER] Reducing background task frequency for CPU optimization")

        except Exception as e:
            logger.error(f"Error during resource optimization: {e}")

    async def _cleanup_loop(self):
        """Background cleanup loop."""
        while self._running:
            try:
                await self.cleanup_all_resources()
                await asyncio.sleep(self.cleanup_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")
                await asyncio.sleep(60)

    async def cleanup_all_resources(self) -> Dict[str, Any]:
        """Perform comprehensive resource cleanup."""
        try:
            results = {}

            # Cleanup temporary files
            temp_cleanup = self.file_manager.cleanup_temp_files()
            results['temp_files'] = temp_cleanup

            # Cleanup stale connections
            conn_cleanup = self.connection_manager.cleanup_stale_connections()
            results['connections'] = conn_cleanup

            # Force garbage collection
            collected = gc.collect()
            results['garbage_collection'] = {'objects_collected': collected}

            # Cleanup resource pools
            pool_cleanup = await self._cleanup_resource_pools()
            results['resource_pools'] = pool_cleanup

            logger.info(f"[CLEAN] Resource cleanup completed: {results}")
            return results

        except Exception as e:
            logger.error(f"Error during resource cleanup: {e}")
            return {}'error': str(e)}

    async def _cleanup_resource_pools(self) -> Dict[str, int]:
        """Cleanup resource pools."""
        cleaned_pools = 0

        for pool_name, pool in self.resource_pools.items():
            try:
                # Simple cleanup logic - in real implementation would be more sophisticated
                if pool.current_size > pool.max_size * pool.cleanup_threshold:
                    # Reduce pool size
                    target_size = int(pool.max_size * 0.7)
                    pool.current_size = target_size
                    pool.last_cleanup = datetime.now()
                    cleaned_pools += 1

            except Exception as e:
                logger.warning(f"Failed to cleanup pool {pool_name}: {e}")

        return {}'pools_cleaned': cleaned_pools}

    def get_resource_stats(self) -> Dict[str, Any]:
        """Get comprehensive resource statistics."""
        return {}
            'system_resources': {
                'cpu_usage_percent': self.metrics.cpu_usage,
                'memory_usage_mb': self.metrics.memory_usage_mb,
                'disk_usage_mb': self.metrics.disk_usage_mb,
                'network_io_mb': self.metrics.network_io_mb,
                'open_files': self.metrics.open_files,
                'thread_count': self.metrics.thread_count
            },
            'connections': self.connection_manager.get_connection_stats(),
            'temp_files': self.file_manager.get_temp_usage(),
            'resource_pools': {
                name: {
                    'type': pool.resource_type,
                    'current_size': pool.current_size,
                    'max_size': pool.max_size,
                    'active_resources': pool.active_resources,
                    'utilization_percent': (pool.current_size / pool.max_size) * 100,
                    'total_created': pool.total_created,
                    'total_reused': pool.total_reused,
                    'reuse_rate': (pool.total_reused / (pool.total_created + pool.total_reused)) if (pool.total_created + pool.total_reused) > 0 else 0
                }
                for name, pool in self.resource_pools.items()
            },
            'thresholds': self.resource_thresholds,
            'last_updated': self.metrics.last_updated.isoformat()
        }

    async def optimize_resources(self) -> Dict[str, Any]:
        """Optimize resource usage and return optimization results."""
        try:
            results = {}

            # Perform cleanup
            cleanup_results = await self.cleanup_all_resources()
            results['cleanup'] = cleanup_results

            # Optimize resource pools
            for pool_name, pool in self.resource_pools.items():
                if pool.current_size < pool.max_size * 0.5 and pool.total_reused > pool.total_created:
                    # Pool is underutilized, consider reducing size
                    old_size = pool.max_size
                    pool.max_size = max(10, int(pool.max_size * 0.8))
                    results[f'pool_{pool_name}'] = f"Reduced max size from {old_size} to {pool.max_size}"

            # Generate optimization suggestions
            suggestions = []
            stats = self.get_resource_stats()

            if stats['system_resources']['cpu_usage_percent'] > 70:
                suggestions.append("Consider reducing background task frequency")

            if stats['system_resources']['memory_usage_mb'] > 1024:
                suggestions.append("High memory usage detected, consider implementing memory pooling")

            if stats['connections']['usage_percent'] > 80:
                suggestions.append("High connection usage, consider connection pooling optimization")

            results['suggestions'] = suggestions

            logger.info(f"[CONFIG] Resource optimization completed: {len(suggestions)} suggestions")
            return results

        except Exception as e:
            logger.error(f"Error during resource optimization: {e}")
            return {}'error': str(e)}


# Global resource manager instance
resource_manager = ResourceManager()
