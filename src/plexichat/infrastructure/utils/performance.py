import asyncio
import functools
import hashlib
import logging
import threading
import time
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)

class PerformanceCache:
    """High-performance in-memory cache with TTL and LRU eviction."""

    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache = {}
        self.access_times = {}
        self.expiry_times = {}
        self.lock = threading.RLock()

        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired, daemon=True)
        self.if cleanup_thread and hasattr(cleanup_thread, "start"): cleanup_thread.start()

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self.lock:
            if key not in self.cache:
                return None

            # Check expiry
            if key in self.expiry_times and datetime.now() > self.expiry_times[key]:
                self._remove_key(key)
                return None

            # Update access time for LRU
            self.access_times[key] = datetime.now()
            return self.cache[key]

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache with optional TTL."""
        with self.lock:
            # Evict if at capacity
            if len(self.cache) >= self.max_size and key not in self.cache:
                self._evict_lru()

            self.cache[key] = value
            self.access_times[key] = datetime.now()

            # Set expiry
            if ttl is None:
                ttl = self.default_ttl
            if ttl > 0:
                self.expiry_times[key] = datetime.now() + timedelta(seconds=ttl)

    def delete(self, key: str) -> bool:
        """Delete key from cache."""
        with self.lock:
            if key in self.cache:
                self._remove_key(key)
                return True
            return False

    def clear(self) -> None:
        """Clear all cache entries."""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()
            self.expiry_times.clear()

    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            return {
                'size': len(self.cache),
                'max_size': self.max_size,
                'hit_rate': getattr(self, '_hit_rate', 0.0),
                'expired_keys': len([k for k, exp in self.expiry_times.items()
                                   if datetime.now() > exp])
            }

    def _remove_key(self, key: str) -> None:
        """Remove key and associated metadata."""
        self.cache.pop(key, None)
        self.access_times.pop(key, None)
        self.expiry_times.pop(key, None)

    def _evict_lru(self) -> None:
        """Evict least recently used item."""
        if not self.access_times:
            return

        lru_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
        self._remove_key(lru_key)

    def _cleanup_expired(self) -> None:
        """Background thread to clean up expired entries."""
        while True:
            try:
                time.sleep(60)  # Check every minute
                with self.lock:
                    now = datetime.now()
                    expired_keys = [k for k, exp in self.expiry_times.items() if now > exp]
                    for key in expired_keys:
                        self._remove_key(key)
            except Exception as e:
                logger.error(f"Cache cleanup error: {e}")

class ConnectionPool:
    """Generic connection pool for database and external services."""

    def __init__(self, create_connection: Callable, max_connections: int = 10,
                 min_connections: int = 2, connection_timeout: int = 30):
        self.create_connection = create_connection
        self.max_connections = max_connections
        self.min_connections = min_connections
        self.connection_timeout = connection_timeout

        self.pool = deque()
        self.active_connections = set()
        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)

        # Initialize minimum connections
        self._initialize_pool()

    def _initialize_pool(self):
        """Initialize pool with minimum connections."""
        for _ in range(self.min_connections):
            try:
                conn = self.create_connection()
                self.pool.append(conn)
            except Exception as e:
                logger.error(f"Failed to create initial connection: {e}")

    @asynccontextmanager
    async def get_connection(self):
        """Get connection from pool (async context manager)."""
        connection = None
        try:
            connection = await self._acquire_connection()
            yield connection
        finally:
            if connection:
                await self._release_connection(connection)

    async def _acquire_connection(self):
        """Acquire connection from pool."""
        with self.condition:
            # Try to get from pool
            if self.pool:
                connection = self.pool.popleft()
                self.active_connections.add(connection)
                return connection

            # Create new connection if under limit
            if len(self.active_connections) < self.max_connections:
                try:
                    connection = self.create_connection()
                    self.active_connections.add(connection)
                    return connection
                except Exception as e:
                    logger.error(f"Failed to create new connection: {e}")
                    raise

            # Wait for available connection
            self.condition.wait(timeout=self.connection_timeout)
            if self.pool:
                connection = self.pool.popleft()
                self.active_connections.add(connection)
                return connection

            raise TimeoutError("Connection pool timeout")

    async def _release_connection(self, connection):
        """Release connection back to pool."""
        with self.condition:
            if connection in self.active_connections:
                self.active_connections.remove(connection)
                if self._is_connection_valid(connection):
                    self.pool.append(connection)
                else:
                    await self._close_connection(connection)
            self.condition.notify()

    def _is_connection_valid(self, connection) -> bool:
        """Check if connection is still valid."""
        try:
            # This is a generic check - specific implementations may override
            return True
        except Exception:
            return False

    async def _close_connection(self, connection):
        """Close a connection."""
        try:
            if hasattr(connection, 'close'):
                connection.close()
            elif hasattr(connection, 'aclose'):
                await connection.aclose()
        except Exception as e:
            logger.error(f"Error closing connection: {e}")

class PerformanceMonitor:
    """Performance monitoring and metrics collection."""

    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.metrics = {}
        self.counters = {}
        self.lock = threading.Lock()

        # Start system metrics collection if psutil is available
        if PSUTIL_AVAILABLE:
            self.system_thread = threading.Thread(target=self._collect_system_metrics, daemon=True)
            self.if system_thread and hasattr(system_thread, "start"): system_thread.start()

    def record_metric(self, name: str, value: float, timestamp: Optional[datetime] = None):
        """Record a performance metric."""
        with self.lock:
            if name not in self.metrics:
                self.metrics[name] = []
            
            if timestamp is None:
                timestamp = datetime.now()
            
            self.metrics[name].append((timestamp, value))
            
            # Keep only recent values
            if len(self.metrics[name]) > self.window_size:
                self.metrics[name] = self.metrics[name][-self.window_size:]

    def increment_counter(self, name: str, amount: int = 1):
        """Increment a counter metric."""
        with self.lock:
            self.counters[name] = self.counters.get(name, 0) + amount

    def get_metric_stats(self, name: str) -> Dict[str, Any]:
        """Get statistics for a specific metric."""
        with self.lock:
            if name not in self.metrics or not self.metrics[name]:
                return {"error": "No data available"}

            values = [v for _, v in self.metrics[name]]
            return {
                "count": len(values),
                "min": min(values),
                "max": max(values),
                "avg": sum(values) / len(values),
                "trend": self._calculate_trend(values)
            }

    def get_all_stats(self) -> Dict[str, Any]:
        """Get all performance statistics."""
        with self.lock:
            stats = {
                "metrics": {name: self.get_metric_stats(name) for name in self.metrics},
                "counters": self.counters.copy(),
                "system": self._get_system_stats() if PSUTIL_AVAILABLE else {}
            }
            return stats

    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction for a series of values."""
        if len(values) < 2:
            return "stable"
        
        # Simple linear regression
        n = len(values)
        x_sum = sum(range(n))
        y_sum = sum(values)
        xy_sum = sum(i * v for i, v in enumerate(values))
        x2_sum = sum(i * i for i in range(n))
        
        slope = (n * xy_sum - x_sum * y_sum) / (n * x2_sum - x_sum * x_sum)
        
        if slope > 0.01:
            return "increasing"
        elif slope < -0.01:
            return "decreasing"
        else:
            return "stable"

    def _collect_system_metrics(self):
        """Collect system-level metrics."""
        while True:
            try:
                if not PSUTIL_AVAILABLE:
                    break

                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                self.record_metric('system.cpu_percent', cpu_percent)

                # Memory usage
                memory = psutil.virtual_memory()
                self.record_metric('system.memory_percent', memory.percent)
                self.record_metric('system.memory_used_gb', memory.used / (1024**3))

                # Disk usage
                disk = psutil.disk_usage('/')
                self.record_metric('system.disk_percent', (disk.used / disk.total) * 100)

                # Network I/O
                net_io = psutil.net_io_counters()
                if net_io:
                    self.record_metric('system.network_bytes_sent', net_io.bytes_sent)
                    self.record_metric('system.network_bytes_recv', net_io.bytes_recv)

                time.sleep(30)  # Collect every 30 seconds

            except Exception as e:
                logger.error(f"Error collecting system metrics: {e}")
                time.sleep(60)  # Wait longer on error

    def _get_system_stats(self) -> Dict[str, Any]:
        """Get current system statistics."""
        if not PSUTIL_AVAILABLE:
            return {"error": "psutil not available"}

        try:
            return {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": (psutil.disk_usage('/').used / psutil.disk_usage('/').total) * 100
            }
        except Exception as e:
            return {"error": str(e)}

def cache_result(ttl: int = 300, key_func: Optional[Callable] = None):
    """Decorator to cache function results."""
    def decorator(func: Callable) -> Callable:
        cache = PerformanceCache(default_ttl=ttl)
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Default key generation
                key_parts = [func.__name__]
                key_parts.extend(str(arg) for arg in args)
                key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
                cache_key = hashlib.md5("|".join(key_parts).encode()).hexdigest()
            
            # Try to get from cache
            result = cache.get(cache_key)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache.set(cache_key, result, ttl)
            return result
        
        return wrapper
    return decorator

def async_cache_result(ttl: int = 300, key_func: Optional[Callable] = None):
    """Decorator to cache async function results."""
    def decorator(func: Callable) -> Callable:
        cache = PerformanceCache(default_ttl=ttl)
        
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Default key generation
                key_parts = [func.__name__]
                key_parts.extend(str(arg) for arg in args)
                key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
                cache_key = hashlib.md5("|".join(key_parts).encode()).hexdigest()
            
            # Try to get from cache
            result = cache.get(cache_key)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = await func(*args, **kwargs)
            cache.set(cache_key, result, ttl)
            return result
        
        return wrapper
    return decorator

def track_performance(metric_name: Optional[str] = None):
    """Decorator to track function performance."""
    def decorator(func: Callable) -> Callable:
        monitor = PerformanceMonitor()
        name = metric_name or f"{func.__module__}.{func.__name__}"
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                monitor.record_metric(f"{name}.duration", duration)
                monitor.increment_counter(f"{name}.calls")
                return result
            except Exception as e:
                duration = time.time() - start_time
                monitor.record_metric(f"{name}.duration", duration)
                monitor.increment_counter(f"{name}.errors")
                raise
        
        return wrapper
    return decorator

def async_track_performance(metric_name: Optional[str] = None):
    """Decorator to track async function performance."""
    def decorator(func: Callable) -> Callable:
        monitor = PerformanceMonitor()
        name = metric_name or f"{func.__module__}.{func.__name__}"
        
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                monitor.record_metric(f"{name}.duration", duration)
                monitor.increment_counter(f"{name}.calls")
                return result
            except Exception as e:
                duration = time.time() - start_time
                monitor.record_metric(f"{name}.duration", duration)
                monitor.increment_counter(f"{name}.errors")
                raise
        
        return wrapper
    return decorator

# Global instances
performance_monitor = PerformanceMonitor()
performance_cache = PerformanceCache()

def get_performance_stats() -> Dict[str, Any]:
    """Get all performance statistics."""
    return performance_monitor.get_all_stats()

def clear_all_caches():
    """Clear all performance caches."""
    performance_cache.clear()

def get_cache_stats() -> Dict[str, Any]:
    """Get cache statistics."""
    return performance_cache.stats()
