"""
PlexiChat Cache Manager

Caching system with threading and performance optimization.
"""

import asyncio
import json
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

try:
    from plexichat.core.database.manager import database_manager  # type: ignore
except ImportError:
    database_manager = None

try:
    from plexichat.core.threading.thread_manager import (
        async_thread_manager,  # type: ignore
    )
except ImportError:
    async_thread_manager = None

try:
    from plexichat.core.logging import get_performance_logger  # type: ignore
except ImportError:
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

    def is_expired(self) -> bool:
        """Check if entry has expired."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at


class CacheManager:
    """Cache manager with threading support."""

    def __init__(self, max_size: int = 10000, default_ttl: int = 3600):
        self.cache: Dict[str, CacheEntry] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.lock = threading.RLock()
        self.active_connections = 0
        self.stats = {"hits": 0, "misses": 0, "sets": 0, "deletes": 0, "evictions": 0}

    def _cleanup_expired(self):
        """Remove expired entries."""
        current_time = time.time()
        expired_keys = []
        for key, entry in self.cache.items():
            if entry.expires_at and entry.expires_at < current_time:
                expired_keys.append(key)

        for key in expired_keys:
            del self.cache[key]

    def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache."""
        with self.lock:
            self._cleanup_expired()

            if key not in self.cache:
                self.stats["misses"] += 1
                return default

            entry = self.cache[key]
            if entry.is_expired():
                del self.cache[key]
                self.stats["misses"] += 1
                return default

            self.stats["hits"] += 1
            return entry.value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache."""
        with self.lock:
            self._cleanup_expired()

            expires_at = None
            if ttl is not None:
                expires_at = time.time() + ttl
            elif self.default_ttl:
                expires_at = time.time() + self.default_ttl

            entry = CacheEntry(
                key=key, value=value, created_at=time.time(), expires_at=expires_at
            )

            self.cache[key] = entry
            self.stats["sets"] += 1

            # Evict if needed
            if len(self.cache) > self.max_size:
                oldest_key = min(
                    self.cache.keys(), key=lambda k: self.cache[k].created_at
                )
                del self.cache[oldest_key]
                self.stats["evictions"] += 1

    def delete(self, key: str) -> bool:
        """Delete key from cache."""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                self.stats["deletes"] += 1
                return True
            return False

    def clear(self) -> None:
        """Clear all cache entries."""
        with self.lock:
            self.cache.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            self._cleanup_expired()
            return {**self.stats, "size": len(self.cache), "max_size": self.max_size}

    def cached(self, ttl: Optional[int] = None):
        """Decorator for caching function results."""

        def decorator(func):
            def wrapper(*args, **kwargs):
                cache_key = (
                    f"{func.__name__}:{hash(str(args) + str(sorted(kwargs.items())))}"
                )

                result = self.get(cache_key)
                if result is not None:
                    return result

                result = func(*args, **kwargs)
                self.set(cache_key, result, ttl)
                return result

            return wrapper

        return decorator


class AsyncCacheManager:
    """Async wrapper for cache manager."""

    def __init__(self, cache_manager: CacheManager):
        self.cache_manager = cache_manager

    async def get(self, key: str, default: Any = None) -> Any:
        """Async get from cache."""
        return self.cache_manager.get(key, default)

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Async set to cache."""
        self.cache_manager.set(key, value, ttl)

    async def delete(self, key: str) -> bool:
        """Async delete from cache."""
        return self.cache_manager.delete(key)

    def async_cached_decorator(self, ttl: Optional[int] = None):
        """Async decorator for caching function results."""

        def decorator(func):
            async def wrapper(*args, **kwargs):
                cache_key = (
                    f"{func.__name__}:{hash(str(args) + str(sorted(kwargs.items())))}"
                )

                result = await self.get(cache_key)
                if result is not None:
                    return result

                result = await func(*args, **kwargs)
                await self.set(cache_key, result, ttl)
                return result

            return wrapper

        return decorator


class DistributedCacheManager:
    """Distributed cache manager."""

    def __init__(
        self, max_size: int = 10000, default_ttl: int = 3600, database_manager=None
    ):
        self.local_cache = CacheManager(max_size, default_ttl)
        self.database_manager = database_manager

    def get(self, key: str, default: Any = None) -> Any:
        """Get from distributed cache."""
        # Try local cache first
        value = self.local_cache.get(key)
        if value is not None:
            return value

        # Try database if available
        if self.database_manager:
            try:
                # This would be implemented with actual database queries
                logger.debug(f"Checking database for cache key: {key}")
            except Exception as e:
                logger.warning(f"Database cache lookup failed: {e}")

        return default

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set to distributed cache."""
        # Set in local cache
        self.local_cache.set(key, value, ttl)

        # Set in database if available
        if self.database_manager:
            try:
                # This would be implemented with actual database operations
                logger.debug(f"Storing cache key in database: {key}")
            except Exception as e:
                logger.warning(f"Database cache store failed: {e}")


# Global instances
cache_manager = CacheManager()
async_cache_manager = AsyncCacheManager(cache_manager)
distributed_cache_manager = DistributedCacheManager(database_manager=database_manager)


# Convenience functions
def cache_get(key: str, default: Any = None) -> Any:
    """Get value from global cache."""
    return cache_manager.get(key, default)


def cache_set(key: str, value: Any, ttl: Optional[int] = None) -> None:
    """Set value in global cache."""
    cache_manager.set(key, value, ttl)


def cache_delete(key: str) -> bool:
    """Delete key from global cache."""
    return cache_manager.delete(key)


async def cache_get_async(key: str, default: Any = None) -> Any:
    """Async get value from global cache."""
    return await async_cache_manager.get(key, default)


async def cache_set_async(key: str, value: Any, ttl: Optional[int] = None) -> None:
    """Async set value in global cache."""
    await async_cache_manager.set(key, value, ttl)


def cached(ttl: Optional[int] = None):
    """Decorator for caching function results."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            cache_key = (
                f"{func.__name__}:{hash(str(args) + str(sorted(kwargs.items())))}"
            )

            result = cache_get(cache_key)
            if result is not None:
                return result

            result = func(*args, **kwargs)
            cache_set(cache_key, result, ttl)
            return result

        return wrapper

    return decorator


def async_cached_decorator(ttl: Optional[int] = None):
    """Async decorator for caching function results."""

    def decorator(func):
        async def wrapper(*args, **kwargs):
            cache_key = (
                f"{func.__name__}:{hash(str(args) + str(sorted(kwargs.items())))}"
            )

            result = await cache_get_async(cache_key)
            if result is not None:
                return result

            result = await func(*args, **kwargs)
            await cache_set_async(cache_key, result, ttl)
            return result

        return wrapper

    return decorator
