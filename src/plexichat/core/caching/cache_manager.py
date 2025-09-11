"""
PlexiChat Cache Manager

Caching system with threading, performance optimization, and proper type hints.
"""

from collections.abc import Callable
from dataclasses import dataclass
import threading
import time
from typing import Any, TypeVar, Union

from plexichat.core.database import DatabaseManager
from plexichat.core.logging import get_logger

# Type variables for better type safety
T = TypeVar("T")
CacheKeyType = Union[str, int, tuple]

try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

try:
    from plexichat.core.threading.thread_manager import async_thread_manager
except ImportError:
    async_thread_manager = None

logger = get_logger(__name__)


@dataclass
class CacheEntry:
    """Cache entry with comprehensive metadata and type safety."""

    key: str
    value: Any
    created_at: float
    expires_at: float | None
    access_count: int = 0
    size_bytes: int = 0
    tags: list[str] = None

    def __post_init__(self) -> None:
        """Initialize after creation."""
        if self.tags is None:
            self.tags = []
        if self.size_bytes == 0:
            # Estimate size of the value
            try:
                self.size_bytes = len(str(self.value).encode("utf-8"))
            except Exception:
                self.size_bytes = 0

    def is_expired(self) -> bool:
        """Check if entry has expired."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    def touch(self) -> None:
        """Update access tracking."""
        self.access_count += 1


class CacheManager:
    """Thread-safe cache manager with comprehensive type hints."""

    def __init__(
        self, max_size: int = 10000, default_ttl: int = 3600, max_memory_mb: int = 100
    ) -> None:
        """
        Initialize cache manager.

        Args:
            max_size: Maximum number of entries
            default_ttl: Default time to live in seconds
            max_memory_mb: Maximum memory usage in MB
        """
        self.cache: dict[str, CacheEntry] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.lock = threading.RLock()
        self.active_connections = 0
        self.stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0,
            "evictions": 0,
            "memory_usage": 0,
        }

    def _cleanup_expired(self) -> int:
        """Remove expired entries and return count removed."""
        current_time = time.time()
        expired_keys = []

        for key, entry in self.cache.items():
            if entry.expires_at and entry.expires_at < current_time:
                expired_keys.append(key)

        for key in expired_keys:
            del self.cache[key]

        return len(expired_keys)

    def _calculate_memory_usage(self) -> int:
        """Calculate total memory usage of cache."""
        return sum(entry.size_bytes for entry in self.cache.values())

    def _evict_entries(self) -> int:
        """Evict entries based on LRU and return count evicted."""
        if not self.cache:
            return 0

        # Sort by access count and creation time (LRU)
        entries_by_usage = sorted(
            self.cache.items(), key=lambda x: (x[1].access_count, x[1].created_at)
        )

        evicted_count = 0
        target_size = int(self.max_size * 0.8)  # Evict down to 80%

        for key, entry in entries_by_usage:
            if len(self.cache) <= target_size:
                break
            del self.cache[key]
            evicted_count += 1
            self.stats["evictions"] += 1

        return evicted_count

    def get(self, key: CacheKeyType, default: T = None) -> Any | T:
        """
        Get value from cache with proper type handling.

        Args:
            key: Cache key
            default: Default value if not found

        Returns:
            Cached value or default
        """
        with self.lock:
            self._cleanup_expired()

            cache_key = str(key)

            if cache_key not in self.cache:
                self.stats["misses"] += 1
                return default

            entry = self.cache[cache_key]
            if entry.is_expired():
                del self.cache[cache_key]
                self.stats["misses"] += 1
                return default

            entry.touch()
            self.stats["hits"] += 1
            return entry.value

    def set(
        self,
        key: CacheKeyType,
        value: Any,
        ttl: int | None = None,
        tags: list[str] | None = None,
    ) -> bool:
        """
        Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
            tags: Optional tags for grouping

        Returns:
            True if successful
        """
        with self.lock:
            self._cleanup_expired()

            cache_key = str(key)
            expires_at = None

            if ttl is not None:
                expires_at = time.time() + ttl
            elif self.default_ttl:
                expires_at = time.time() + self.default_ttl

            entry = CacheEntry(
                key=cache_key,
                value=value,
                created_at=time.time(),
                expires_at=expires_at,
                tags=tags or [],
            )

            self.cache[cache_key] = entry
            self.stats["sets"] += 1

            # Check size and memory limits
            if (
                len(self.cache) > self.max_size
                or self._calculate_memory_usage() > self.max_memory_bytes
            ):
                self._evict_entries()

            return True

    def delete(self, key: CacheKeyType) -> bool:
        """
        Delete key from cache.

        Args:
            key: Cache key to delete

        Returns:
            True if deleted, False if not found
        """
        with self.lock:
            cache_key = str(key)
            if cache_key in self.cache:
                del self.cache[cache_key]
                self.stats["deletes"] += 1
                return True
            return False

    def delete_by_tags(self, tags: list[str]) -> int:
        """
        Delete entries by tags.

        Args:
            tags: List of tags to match

        Returns:
            Number of entries deleted
        """
        with self.lock:
            keys_to_delete = []

            for key, entry in self.cache.items():
                if any(tag in entry.tags for tag in tags):
                    keys_to_delete.append(key)

            for key in keys_to_delete:
                del self.cache[key]
                self.stats["deletes"] += 1

            return len(keys_to_delete)

    def clear(self) -> None:
        """Clear all cache entries."""
        with self.lock:
            self.cache.clear()
            # Reset stats except for totals
            self.stats.update({"hits": 0, "misses": 0, "memory_usage": 0})

    def get_stats(self) -> dict[str, Any]:
        """Get comprehensive cache statistics."""
        with self.lock:
            self._cleanup_expired()

            hit_rate = 0.0
            total_requests = self.stats["hits"] + self.stats["misses"]
            if total_requests > 0:
                hit_rate = self.stats["hits"] / total_requests

            return {
                **self.stats,
                "size": len(self.cache),
                "max_size": self.max_size,
                "memory_usage": self._calculate_memory_usage(),
                "max_memory_bytes": self.max_memory_bytes,
                "hit_rate": hit_rate,
                "memory_utilization": (
                    self._calculate_memory_usage() / self.max_memory_bytes
                    if self.max_memory_bytes > 0
                    else 0.0
                ),
            }

    def cached_decorator(
        self, ttl: int | None = None, key_func: Callable[..., str] | None = None
    ) -> Callable[[Callable], Callable]:
        """
        Decorator for caching function results.

        Args:
            ttl: Cache time to live
            key_func: Custom key generation function

        Returns:
            Decorator function
        """

        def decorator(func: Callable) -> Callable:
            def wrapper(*args, **kwargs):
                # Generate cache key
                if key_func:
                    cache_key = key_func(*args, **kwargs)
                else:
                    cache_key = (
                        f"{func.__name__}:"
                        f"{hash(str(args) + str(sorted(kwargs.items())))}"
                    )

                # Try cache first
                result = self.get(cache_key)
                if result is not None:
                    return result

                # Execute function and cache result
                result = func(*args, **kwargs)
                self.set(cache_key, result, ttl)
                return result

            return wrapper

        return decorator


class AsyncCacheManager:
    """Async wrapper for cache manager with proper typing."""

    def __init__(self, cache_manager: CacheManager) -> None:
        """Initialize with cache manager instance."""
        self.cache_manager = cache_manager

    async def get(self, key: CacheKeyType, default: T = None) -> Any | T:
        """Async get from cache."""
        return self.cache_manager.get(key, default)

    async def set(
        self,
        key: CacheKeyType,
        value: Any,
        ttl: int | None = None,
        tags: list[str] | None = None,
    ) -> bool:
        """Async set to cache."""
        return self.cache_manager.set(key, value, ttl, tags)

    async def delete(self, key: CacheKeyType) -> bool:
        """Async delete from cache."""
        return self.cache_manager.delete(key)

    async def delete_by_tags(self, tags: list[str]) -> int:
        """Async delete by tags."""
        return self.cache_manager.delete_by_tags(tags)

    def async_cached_decorator(
        self, ttl: int | None = None, key_func: Callable[..., str] | None = None
    ) -> Callable[[Callable], Callable]:
        """
        Async decorator for caching function results.

        Args:
            ttl: Cache time to live
            key_func: Custom key generation function

        Returns:
            Decorator function
        """

        def decorator(func: Callable) -> Callable:
            async def wrapper(*args, **kwargs):
                # Generate cache key
                if key_func:
                    cache_key = key_func(*args, **kwargs)
                else:
                    cache_key = (
                        f"{func.__name__}:"
                        f"{hash(str(args) + str(sorted(kwargs.items())))}"
                    )

                # Try cache first
                result = await self.get(cache_key)
                if result is not None:
                    return result

                # Execute function and cache result
                result = await func(*args, **kwargs)
                await self.set(cache_key, result, ttl)
                return result

            return wrapper

        return decorator


class DistributedCacheManager:
    """Distributed cache manager with database integration and typing."""

    def __init__(
        self,
        max_size: int = 10000,
        default_ttl: int = 3600,
        database_manager: DatabaseManager | None = None,
    ) -> None:
        """
        Initialize distributed cache manager.

        Args:
            max_size: Maximum cache size
            default_ttl: Default TTL
            database_manager: Database manager instance
        """
        self.local_cache = CacheManager(max_size, default_ttl)
        self.database_manager = database_manager

    def get(self, key: CacheKeyType, default: T = None) -> Any | T:
        """Get from distributed cache with fallback to database."""
        # Try local cache first
        value = self.local_cache.get(key)
        if value is not None:
            return value

        # Try database if available
        if self.database_manager:
            try:
                # This would be implemented with actual database queries
                logger.debug(f"Checking database for cache key: {key}")
                # TODO: Implement database cache lookup
            except Exception as e:
                logger.warning(f"Database cache lookup failed: {e}")

        return default

    def set(
        self,
        key: CacheKeyType,
        value: Any,
        ttl: int | None = None,
        tags: list[str] | None = None,
    ) -> bool:
        """Set in distributed cache with database persistence."""
        # Set in local cache
        success = self.local_cache.set(key, value, ttl, tags)

        # Set in database if available
        if self.database_manager and success:
            try:
                # This would be implemented with actual database operations
                logger.debug(f"Storing cache key in database: {key}")
                # TODO: Implement database cache storage
            except Exception as e:
                logger.warning(f"Database cache store failed: {e}")

        return success

    def delete(self, key: CacheKeyType) -> bool:
        """Delete from distributed cache."""
        local_deleted = self.local_cache.delete(key)

        if self.database_manager:
            try:
                # TODO: Implement database cache deletion
                logger.debug(f"Deleting cache key from database: {key}")
            except Exception as e:
                logger.warning(f"Database cache deletion failed: {e}")

        return local_deleted

    def get_stats(self) -> dict[str, Any]:
        """Get distributed cache statistics."""
        local_stats = self.local_cache.get_stats()
        local_stats["type"] = "distributed"
        local_stats["database_enabled"] = self.database_manager is not None
        return local_stats


# Global instances with proper typing
cache_manager: CacheManager = CacheManager()
async_cache_manager: AsyncCacheManager = AsyncCacheManager(cache_manager)
distributed_cache_manager: DistributedCacheManager = DistributedCacheManager(
    database_manager=database_manager
)


# Convenience functions with proper type hints
def cache_get(key: CacheKeyType, default: T = None) -> Any | T:
    """Get value from global cache."""
    return cache_manager.get(key, default)


def cache_set(
    key: CacheKeyType, value: Any, ttl: int | None = None, tags: list[str] | None = None
) -> bool:
    """Set value in global cache."""
    return cache_manager.set(key, value, ttl, tags)


def cache_delete(key: CacheKeyType) -> bool:
    """Delete key from global cache."""
    return cache_manager.delete(key)


async def cache_get_async(key: CacheKeyType, default: T = None) -> Any | T:
    """Async get value from global cache."""
    return await async_cache_manager.get(key, default)


async def cache_set_async(
    key: CacheKeyType, value: Any, ttl: int | None = None, tags: list[str] | None = None
) -> bool:
    """Async set value in global cache."""
    return await async_cache_manager.set(key, value, ttl, tags)


def cached(
    ttl: int | None = None, key_func: Callable[..., str] | None = None
) -> Callable[[Callable], Callable]:
    """Decorator for caching function results."""
    return cache_manager.cached_decorator(ttl, key_func)


def async_cached_decorator(
    ttl: int | None = None, key_func: Callable[..., str] | None = None
) -> Callable[[Callable], Callable]:
    """Async decorator for caching function results."""
    return async_cache_manager.async_cached_decorator(ttl, key_func)


__all__ = [
    "CacheEntry",
    "CacheManager",
    "AsyncCacheManager",
    "DistributedCacheManager",
    "cache_manager",
    "async_cache_manager",
    "distributed_cache_manager",
    "cache_get",
    "cache_set",
    "cache_delete",
    "cache_get_async",
    "cache_set_async",
    "cached",
    "async_cached_decorator",
    # Type exports
    "CacheKeyType",
]
