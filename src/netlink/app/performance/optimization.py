"""
Performance Optimization Module for NetLink
Provides caching, async operations, database optimization, and resource management.
"""

import asyncio
import time
import threading
import weakref
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass
from functools import wraps, lru_cache
import logging
import json
import gzip
import pickle

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    import aiofiles
    AIOFILES_AVAILABLE = True
except ImportError:
    AIOFILES_AVAILABLE = False

@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    value: Any
    created_at: datetime
    expires_at: Optional[datetime]
    access_count: int = 0
    last_accessed: Optional[datetime] = None

@dataclass
class PerformanceMetrics:
    """Performance metrics tracking."""
    request_count: int = 0
    total_response_time: float = 0.0
    min_response_time: float = float('inf')
    max_response_time: float = 0.0
    error_count: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    
    @property
    def avg_response_time(self) -> float:
        return self.total_response_time / max(self.request_count, 1)
    
    @property
    def cache_hit_rate(self) -> float:
        total_cache_requests = self.cache_hits + self.cache_misses
        return self.cache_hits / max(total_cache_requests, 1)

class EnhancedCache:
    """High-performance caching system with multiple backends."""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache: Dict[str, CacheEntry] = {}
        self.lock = threading.RLock()
        self.logger = logging.getLogger(__name__)
        
        # Enhanced Redis backend (if available)
        self.redis_client = None
        if REDIS_AVAILABLE:
            try:
                self.redis_client = redis.Redis(
                    host='localhost',
                    port=6379,
                    db=0,
                    decode_responses=True,
                    socket_connect_timeout=2,
                    socket_timeout=2,
                    retry_on_timeout=True,
                    health_check_interval=30,
                    max_connections=20
                )
                self.redis_client.ping()
                self.logger.info("Enhanced Redis cache backend connected")
            except Exception as e:
                self.logger.warning(f"Redis not available: {e}")
                self.redis_client = None
        
        # Performance metrics
        self.metrics = PerformanceMetrics()
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache."""
        with self.lock:
            # Try Redis first
            if self.redis_client:
                try:
                    value = self.redis_client.get(f"netlink:{key}")
                    if value is not None:
                        self.metrics.cache_hits += 1
                        return json.loads(value)
                except Exception as e:
                    self.logger.warning(f"Redis get error: {e}")
            
            # Try local cache
            if key in self.cache:
                entry = self.cache[key]
                
                # Check expiration
                if entry.expires_at and datetime.now() > entry.expires_at:
                    del self.cache[key]
                    self.metrics.cache_misses += 1
                    return default
                
                # Update access info
                entry.access_count += 1
                entry.last_accessed = datetime.now()
                self.metrics.cache_hits += 1
                return entry.value
            
            self.metrics.cache_misses += 1
            return default
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache."""
        ttl = ttl or self.default_ttl
        expires_at = datetime.now() + timedelta(seconds=ttl) if ttl > 0 else None
        
        with self.lock:
            # Store in Redis
            if self.redis_client:
                try:
                    serialized = json.dumps(value, default=str)
                    self.redis_client.setex(f"netlink:{key}", ttl, serialized)
                except Exception as e:
                    self.logger.warning(f"Redis set error: {e}")
            
            # Store in local cache
            entry = CacheEntry(
                value=value,
                created_at=datetime.now(),
                expires_at=expires_at
            )
            
            self.cache[key] = entry
            
            # Evict if over size limit
            if len(self.cache) > self.max_size:
                self._evict_lru()
    
    def delete(self, key: str) -> bool:
        """Delete key from cache."""
        with self.lock:
            # Delete from Redis
            if self.redis_client:
                try:
                    self.redis_client.delete(f"netlink:{key}")
                except Exception as e:
                    self.logger.warning(f"Redis delete error: {e}")
            
            # Delete from local cache
            return self.cache.pop(key, None) is not None
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self.lock:
            if self.redis_client:
                try:
                    # Delete all netlink keys
                    keys = self.redis_client.keys("netlink:*")
                    if keys:
                        self.redis_client.delete(*keys)
                except Exception as e:
                    self.logger.warning(f"Redis clear error: {e}")
            
            self.cache.clear()
    
    def _evict_lru(self) -> None:
        """Evict least recently used entries."""
        if not self.cache:
            return
        
        # Sort by last accessed time (None values go first)
        sorted_entries = sorted(
            self.cache.items(),
            key=lambda x: x[1].last_accessed or datetime.min
        )
        
        # Remove oldest 10% of entries
        remove_count = max(1, len(self.cache) // 10)
        for key, _ in sorted_entries[:remove_count]:
            del self.cache[key]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            return {
                "local_cache_size": len(self.cache),
                "max_size": self.max_size,
                "cache_hits": self.metrics.cache_hits,
                "cache_misses": self.metrics.cache_misses,
                "hit_rate": self.metrics.cache_hit_rate,
                "redis_available": self.redis_client is not None
            }

class AsyncTaskManager:
    """Asynchronous task management for improved performance."""
    
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.task_queue = asyncio.Queue()
        self.active_tasks = set()
        self.completed_tasks = []
        self.logger = logging.getLogger(__name__)
        self.running = False
    
    async def start(self):
        """Start the task manager."""
        if self.running:
            return
        
        self.running = True
        # Start worker coroutines
        workers = [
            asyncio.create_task(self._worker(f"worker-{i}"))
            for i in range(self.max_workers)
        ]
        
        self.logger.info(f"Started {self.max_workers} async workers")
        return workers
    
    async def stop(self):
        """Stop the task manager."""
        self.running = False
        
        # Cancel active tasks
        for task in self.active_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.active_tasks:
            await asyncio.gather(*self.active_tasks, return_exceptions=True)
    
    async def submit_task(self, coro_func: Callable, *args, **kwargs) -> asyncio.Task:
        """Submit a task for async execution."""
        task_id = f"task-{len(self.completed_tasks) + len(self.active_tasks)}"
        
        async def wrapped_task():
            try:
                start_time = time.time()
                result = await coro_func(*args, **kwargs)
                duration = time.time() - start_time
                
                self.completed_tasks.append({
                    "task_id": task_id,
                    "duration": duration,
                    "success": True,
                    "result": result,
                    "completed_at": datetime.now()
                })
                
                return result
            except Exception as e:
                self.logger.error(f"Task {task_id} failed: {e}")
                self.completed_tasks.append({
                    "task_id": task_id,
                    "success": False,
                    "error": str(e),
                    "completed_at": datetime.now()
                })
                raise
        
        task = asyncio.create_task(wrapped_task())
        self.active_tasks.add(task)
        
        # Remove from active when done
        task.add_done_callback(lambda t: self.active_tasks.discard(t))
        
        return task
    
    async def _worker(self, worker_name: str):
        """Worker coroutine."""
        while self.running:
            try:
                # Get task from queue (with timeout)
                task_func = await asyncio.wait_for(self.task_queue.get(), timeout=1.0)
                await task_func()
                self.task_queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Worker {worker_name} error: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get task manager statistics."""
        completed_successful = sum(1 for task in self.completed_tasks if task["success"])
        completed_failed = len(self.completed_tasks) - completed_successful
        
        return {
            "active_tasks": len(self.active_tasks),
            "completed_tasks": len(self.completed_tasks),
            "successful_tasks": completed_successful,
            "failed_tasks": completed_failed,
            "workers": self.max_workers,
            "running": self.running
        }

class DatabaseOptimizer:
    """Database performance optimization utilities."""
    
    def __init__(self):
        self.query_cache = EnhancedCache(max_size=500, default_ttl=300)
        self.connection_pool = None
        self.logger = logging.getLogger(__name__)
    
    def cache_query_result(self, query: str, params: tuple, result: Any, ttl: int = 300):
        """Cache query result."""
        cache_key = self._generate_query_key(query, params)
        self.query_cache.set(cache_key, result, ttl)
    
    def get_cached_query_result(self, query: str, params: tuple) -> Any:
        """Get cached query result."""
        cache_key = self._generate_query_key(query, params)
        return self.query_cache.get(cache_key)
    
    def _generate_query_key(self, query: str, params: tuple) -> str:
        """Generate cache key for query."""
        import hashlib
        query_hash = hashlib.md5(f"{query}:{params}".encode()).hexdigest()
        return f"query:{query_hash}"
    
    def optimize_query(self, query: str) -> str:
        """Basic query optimization suggestions."""
        optimized = query
        
        # Add LIMIT if not present in SELECT
        if "SELECT" in query.upper() and "LIMIT" not in query.upper():
            optimized += " LIMIT 1000"
        
        return optimized

class ResourceMonitor:
    """System resource monitoring and optimization."""
    
    def __init__(self):
        self.metrics_history = []
        self.max_history = 1000
        self.logger = logging.getLogger(__name__)
        self.monitoring = False
        self.monitor_thread = None
    
    def start_monitoring(self, interval: int = 60):
        """Start resource monitoring."""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
        self.logger.info(f"Resource monitoring started (interval: {interval}s)")
    
    def stop_monitoring(self):
        """Stop resource monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
    
    def _monitor_loop(self, interval: int):
        """Main monitoring loop."""
        while self.monitoring:
            try:
                metrics = self._collect_metrics()
                self.metrics_history.append(metrics)
                
                # Keep only recent metrics
                if len(self.metrics_history) > self.max_history:
                    self.metrics_history.pop(0)
                
                # Check for resource issues
                self._check_resource_alerts(metrics)
                
                time.sleep(interval)
            except Exception as e:
                self.logger.error(f"Resource monitoring error: {e}")
                time.sleep(interval)
    
    def _collect_metrics(self) -> Dict[str, Any]:
        """Collect current system metrics."""
        import psutil
        import gc
        
        # System metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Process metrics
        process = psutil.Process()
        process_memory = process.memory_info()
        
        # Python metrics
        gc_stats = gc.get_stats()
        
        return {
            "timestamp": datetime.now(),
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_available_mb": memory.available // (1024 * 1024),
            "disk_percent": disk.percent,
            "process_memory_mb": process_memory.rss // (1024 * 1024),
            "process_cpu_percent": process.cpu_percent(),
            "thread_count": process.num_threads(),
            "gc_collections": sum(stat["collections"] for stat in gc_stats),
            "gc_collected": sum(stat["collected"] for stat in gc_stats)
        }
    
    def _check_resource_alerts(self, metrics: Dict[str, Any]):
        """Check for resource usage alerts."""
        # CPU alert
        if metrics["cpu_percent"] > 80:
            self.logger.warning(f"High CPU usage: {metrics['cpu_percent']:.1f}%")
        
        # Memory alert
        if metrics["memory_percent"] > 85:
            self.logger.warning(f"High memory usage: {metrics['memory_percent']:.1f}%")
        
        # Disk alert
        if metrics["disk_percent"] > 90:
            self.logger.warning(f"High disk usage: {metrics['disk_percent']:.1f}%")
    
    def get_current_metrics(self) -> Optional[Dict[str, Any]]:
        """Get current metrics."""
        return self.metrics_history[-1] if self.metrics_history else None
    
    def get_metrics_summary(self, hours: int = 1) -> Dict[str, Any]:
        """Get metrics summary for the last N hours."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_metrics = [
            m for m in self.metrics_history
            if m["timestamp"] > cutoff_time
        ]
        
        if not recent_metrics:
            return {}
        
        return {
            "avg_cpu": sum(m["cpu_percent"] for m in recent_metrics) / len(recent_metrics),
            "max_cpu": max(m["cpu_percent"] for m in recent_metrics),
            "avg_memory": sum(m["memory_percent"] for m in recent_metrics) / len(recent_metrics),
            "max_memory": max(m["memory_percent"] for m in recent_metrics),
            "sample_count": len(recent_metrics)
        }

# Performance decorators
def cached(ttl: int = 3600, key_func: Optional[Callable] = None):
    """Decorator for caching function results."""
    def decorator(func):
        cache = EnhancedCache()
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}:{hash((args, tuple(sorted(kwargs.items()))))}"
            
            # Try cache first
            result = cache.get(cache_key)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache.set(cache_key, result, ttl)
            return result
        
        wrapper.cache = cache
        return wrapper
    return decorator

def timed(func):
    """Decorator to measure function execution time."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            logging.getLogger(__name__).debug(f"{func.__name__} executed in {duration:.3f}s")
            return result
        except Exception as e:
            duration = time.time() - start_time
            logging.getLogger(__name__).error(f"{func.__name__} failed after {duration:.3f}s: {e}")
            raise
    return wrapper

class PerformanceOptimizer:
    """Main performance optimization coordinator."""

    def __init__(self):
        self.cache = EnhancedCache()
        self.task_manager = AsyncTaskManager()
        self.db_optimizer = DatabaseOptimizer()
        self.resource_monitor = ResourceMonitor()
        self.compression_manager = CompressionManager()

        # Start monitoring
        self.resource_monitor.start_monitoring()

    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics."""
        return {
            "cache": self.cache.get_stats(),
            "tasks": self.task_manager.get_stats(),
            "resources": self.resource_monitor.get_current_metrics(),
            "compression": getattr(self.compression_manager, 'get_stats', lambda: {})()
        }

class CompressionManager:
    """Response compression manager."""

    def __init__(self):
        self.compression_stats = {
            "total_requests": 0,
            "compressed_requests": 0,
            "bytes_saved": 0
        }

    def should_compress(self, content_type: str, content_length: int) -> bool:
        """Determine if content should be compressed."""
        compressible_types = [
            'text/', 'application/json', 'application/javascript',
            'application/xml', 'application/rss+xml'
        ]

        return (
            content_length > 1024 and
            any(content_type.startswith(ct) for ct in compressible_types)
        )

    def compress_response(self, content: bytes, content_type: str) -> Optional[bytes]:
        """Compress response content."""
        self.compression_stats["total_requests"] += 1

        if not self.should_compress(content_type, len(content)):
            return None

        try:
            compressed = gzip.compress(content, compresslevel=6)

            if len(compressed) < len(content):
                self.compression_stats["compressed_requests"] += 1
                self.compression_stats["bytes_saved"] += len(content) - len(compressed)
                return compressed

            return None

        except Exception as e:
            logging.getLogger(__name__).error(f"Compression error: {e}")
            return None

    def get_stats(self) -> Dict[str, Any]:
        """Get compression statistics."""
        total = self.compression_stats["total_requests"]
        compressed = self.compression_stats["compressed_requests"]
        compression_rate = (compressed / total * 100) if total > 0 else 0

        return {
            **self.compression_stats,
            "compression_rate": round(compression_rate, 2)
        }

# Global instances
global_cache = EnhancedCache()
task_manager = AsyncTaskManager()
db_optimizer = DatabaseOptimizer()
resource_monitor = ResourceMonitor()
performance_optimizer = PerformanceOptimizer()
