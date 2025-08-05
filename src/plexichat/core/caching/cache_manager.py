"""
PlexiChat Cache Manager

Caching system with threading and performance optimization.
"""

import asyncio
import json
import logging
import time
import threading
# datetime imports not used
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass

try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

try:
    from plexichat.core.threading.thread_manager import async_thread_manager
except ImportError:
    async_thread_manager = None

try:
    # PerformanceOptimizationEngine not used
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None

@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    key: str
    value: Any
    created_at: float
    expires_at: Optional[float]
    access_count: int = 0
    last_accessed: Optional[float] = None

    def __post_init__(self):
        if self.last_accessed is None:
            self.last_accessed = self.created_at

    def is_expired(self) -> bool:
        """Check if entry is expired."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    def touch(self):
        """Update access information."""
        self.access_count += 1
        self.last_accessed = time.time()

class CacheManager:
    """Cache manager with threading support."""

    def __init__(self, max_size: int = 10000, default_ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache: Dict[str, CacheEntry] = {}
        self.lock = threading.RLock()
        self.performance_logger = performance_logger
        self.db_manager = database_manager
        self.async_thread_manager = async_thread_manager

        # Statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0

        # Background cleanup
        self._cleanup_running = False
        self._start_cleanup_thread()

    def _start_cleanup_thread(self):
        """Start background cleanup thread."""
        if not self._cleanup_running:
            self._cleanup_running = True
            cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
            cleanup_thread.start()

    def _cleanup_loop(self):
        """Background cleanup loop."""
        while self._cleanup_running:
            try:
                self._cleanup_expired()
                time.sleep(60)  # Cleanup every minute
            except Exception as e:
                logger.error(f"Cache cleanup error: {e}")

    def _cleanup_expired(self):
        """Remove expired entries."""
        with self.lock:
            expired_keys = [
                key for key, entry in self.cache.items()
                if entry.is_expired()
            ]

            for key in expired_keys:
                del self.cache[key]
                self.evictions += 1

            if expired_keys and self.performance_logger:
                self.performance_logger.record_metric("cache_expired_entries", len(expired_keys), "count")

    def _evict_lru(self):
        """Evict least recently used entries."""
        if len(self.cache) <= self.max_size:
            return

        with self.lock:
            # Sort by last accessed time
            sorted_entries: list[tuple[str, CacheEntry]] = sorted(
                self.cache.items(),
                key=lambda x: x[1].last_accessed if x[1].last_accessed is not None else 0.0
            )

            # Remove oldest entries
            entries_to_remove = len(self.cache) - self.max_size + 1
            for i in range(entries_to_remove):
                if i < len(sorted_entries):
                    key, _ = sorted_entries[i]
                    del self.cache[key]
                    self.evictions += 1

            if self.performance_logger:
                self.performance_logger.record_metric("cache_lru_evictions", entries_to_remove, "count")

    def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache."""
        with self.lock:
            entry = self.cache.get(key)

            if entry is None:
                self.misses += 1
                if self.performance_logger:
                    self.performance_logger.record_metric("cache_misses", 1, "count")
                return default

            if entry.is_expired():
                del self.cache[key]
                self.misses += 1
                self.evictions += 1
                if self.performance_logger:
                    self.performance_logger.record_metric("cache_misses", 1, "count")
                    self.performance_logger.record_metric("cache_expired_on_access", 1, "count")
                return default

            entry.touch()
            self.hits += 1
            if self.performance_logger:
                self.performance_logger.record_metric("cache_hits", 1, "count")

            return entry.value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache."""
        try:
            with self.lock:
                current_time = time.time()
                expires_at = None

                if ttl is not None:
                    expires_at = current_time + ttl
                elif self.default_ttl > 0:
                    expires_at = current_time + self.default_ttl

                entry = CacheEntry(
                    key=key,
                    value=value,
                    created_at=current_time,
                    expires_at=expires_at
                )

                self.cache[key] = entry

                # Evict if necessary
                if len(self.cache) > self.max_size:
                    self._evict_lru()

                if self.performance_logger:
                    self.performance_logger.record_metric("cache_sets", 1, "count")

                return True
        except Exception as e:
            logger.error(f"Error setting cache key {key}: {e}")
            return False

    def delete(self, key: str) -> bool:
        """Delete key from cache."""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                if self.performance_logger:
                    self.performance_logger.record_metric("cache_deletes", 1, "count")
                return True
            return False

    def clear(self):
        """Clear all cache entries."""
        with self.lock:
            cleared_count = len(self.cache)
            self.cache.clear()
            if self.performance_logger:
                self.performance_logger.record_metric("cache_clears", 1, "count")
                self.performance_logger.record_metric("cache_cleared_entries", cleared_count, "count")

    def exists(self, key: str) -> bool:
        """Check if key exists and is not expired."""
        with self.lock:
            entry = self.cache.get(key)
            if entry is None:
                return False

            if entry.is_expired():
                del self.cache[key]
                self.evictions += 1
                return False

            return True

    def keys(self, pattern: Optional[str] = None) -> List[str]:
        """Get cache keys, optionally filtered by pattern."""
        with self.lock:
            if pattern is None:
                return list(self.cache.keys())

            import re
            regex = re.compile(pattern)
            return [key for key in self.cache.keys() if regex.match(key)]

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests) if total_requests > 0 else 0

            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "evictions": self.evictions,
                "hit_rate": hit_rate,
                "memory_usage": self._estimate_memory_usage()
            }

    def _estimate_memory_usage(self) -> int:
        """Estimate memory usage in bytes."""
        try:
            import sys
            total_size = 0
            for entry in self.cache.values():
                total_size += sys.getsizeof(entry.key)
                total_size += sys.getsizeof(entry.value)
                total_size += sys.getsizeof(entry)
            return total_size
        except Exception:
            return 0

    async def get_async(self, key: str, default: Any = None) -> Any:
        """Async get from cache."""
        if self.async_thread_manager:
            return await self.async_thread_manager.run_in_thread(self.get, key, default)
        return self.get(key, default)

    async def set_async(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Async set to cache."""
        if self.async_thread_manager:
            return await self.async_thread_manager.run_in_thread(self.set, key, value, ttl)
        return self.set(key, value, ttl)

    async def delete_async(self, key: str) -> bool:
        """Async delete from cache."""
        if self.async_thread_manager:
            return await self.async_thread_manager.run_in_thread(self.delete, key)
        return self.delete(key)

    def stop_cleanup(self):
        """Stop background cleanup."""
        self._cleanup_running = False

class DistributedCacheManager(CacheManager):
    """Distributed cache manager with database persistence."""

    def __init__(self, max_size: int = 10000, default_ttl: int = 3600):
        super().__init__(max_size, default_ttl)
        self.db_manager = database_manager

    async def get_from_db(self, key: str) -> Optional[Any]:
        """Get value from database cache."""
        if not self.db_manager:
            return None

        try:
            query = """
                SELECT value, expires_at FROM cache_entries
                WHERE key = ? AND (expires_at IS NULL OR expires_at > ?)
            """
            params = {"key": key, "expires_at": time.time()}

            result = await self.db_manager.execute_query(query, params)
            if result:
                if isinstance(result, dict):
                    value_json = result.get('value', '')
                    return json.loads(value_json) if value_json else None
                elif isinstance(result, (list, tuple)) and len(result) > 0:
                    row = result[0]
                    if isinstance(row, dict):
                        value_json = row.get('value', '')
                    elif isinstance(row, (list, tuple)) and len(row) >= 2:
                        value_json = row[0]
                    else:
                        value_json = str(row)
                    return json.loads(value_json)

            return None
        except Exception as e:
            logger.error(f"Error getting from database cache: {e}")
            return None

    async def set_to_db(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value to database cache."""
        if not self.db_manager:
            return

        try:
            expires_at = None
            if ttl is not None:
                expires_at = time.time() + ttl
            elif self.default_ttl > 0:
                expires_at = time.time() + self.default_ttl

            query = """
                INSERT OR REPLACE INTO cache_entries (key, value, created_at, expires_at)
                VALUES (?, ?, ?, ?)
            """
            params = {
                "key": key,
                "value": json.dumps(value, default=str),
                "created_at": time.time(),
                "expires_at": expires_at
            }

            await self.db_manager.execute_query(query, params)
        except Exception as e:
            logger.error(f"Error setting to database cache: {e}")

    async def get_distributed(self, key: str, default: Any = None) -> Any:
        """Get from local cache, fallback to database."""
        # Try local cache first
        value = self.get(key, None)
        if value is not None:
            return value

        # Try database cache
        value = await self.get_from_db(key)
        if value is not None:
            # Store in local cache
            self.set(key, value)
            return value

        return default

    async def set_distributed(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set to both local cache and database."""
        # Set to local cache
        local_success = self.set(key, value, ttl)

        # Set to database cache
        await self.set_to_db(key, value, ttl)

        return local_success

# Global cache managers
cache_manager = CacheManager()
distributed_cache_manager = DistributedCacheManager()

# DEPRECATED: Use unified_cache_integration instead
import warnings

def cache_get(key: str, default: Any = None) -> Any:
    """DEPRECATED: Use unified_cache_integration.cache_get_sync instead."""
    warnings.warn("cache_get is deprecated. Use unified_cache_integration.cache_get_sync", DeprecationWarning)
    return cache_manager.get(key, default)

def cache_set(key: str, value: Any, ttl: Optional[int] = None) -> bool:
    """DEPRECATED: Use unified_cache_integration.cache_set_sync instead."""
    warnings.warn("cache_set is deprecated. Use unified_cache_integration.cache_set_sync", DeprecationWarning)
    return cache_manager.set(key, value, ttl)

def cache_delete(key: str) -> bool:
    """DEPRECATED: Use unified_cache_integration.cache_delete_sync instead."""
    warnings.warn("cache_delete is deprecated. Use unified_cache_integration.cache_delete_sync", DeprecationWarning)
    return cache_manager.delete(key)

async def cache_get_async(key: str, default: Any = None) -> Any:
    """DEPRECATED: Use unified_cache_integration.cache_get instead."""
    warnings.warn("cache_get_async is deprecated. Use unified_cache_integration.cache_get", DeprecationWarning)
    return await cache_manager.get_async(key, default)

async def cache_set_async(key: str, value: Any, ttl: Optional[int] = None) -> bool:
    """DEPRECATED: Use unified_cache_integration.cache_set instead."""
    warnings.warn("cache_set_async is deprecated. Use unified_cache_integration.cache_set", DeprecationWarning)
    return await cache_manager.set_async(key, value, ttl)

# Decorators
def cached(ttl: Optional[int] = None, key_func: Optional[Callable] = None):
    """Decorator to cache function results."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}_{hash(str(args) + str(kwargs))}"

            # Try to get from cache
            result = await cache_get(cache_key)
            if result is not None:
                return result

            # Execute function and cache result
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            await cache_set_async(cache_key, result, ttl)

            return result
        return wrapper
    return decorator

def async_cached_decorator(ttl: Optional[int] = None, key_func: Optional[Callable] = None):
    """Decorator to cache async function results."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}_{hash(str(args) + str(kwargs))}"

            # Try to get from cache
            result = await cache_get_async(cache_key)
            if result is not None:
                return result

            # Execute function and cache result
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            await cache_set_async(cache_key, result, ttl)

            return result
        return wrapper
    return decorator
