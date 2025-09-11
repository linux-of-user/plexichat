"""PlexiChat Caching System with Type Safety and Proper Integration"""

import logging
from typing import Any, Dict, List, Optional, TypeVar, Union

# Import proper types
from plexichat.core.logging import get_logger

logger = get_logger(__name__)

# Type definitions for better type safety
CacheKeyType = Union[str, int, tuple]
CacheValueType = TypeVar("CacheValueType")
CacheExpirationTime = Optional[int | float]

try:
    from plexichat.core.utils.fallbacks import (
        CacheEntry,
        CacheManager,
        DistributedCacheManager,
        async_cached_decorator,
        cache_delete,
        cache_get,
        cache_get_async,
        cache_set,
        cache_set_async,
        cached,
        get_fallback_instance,
    )

    USE_SHARED_FALLBACKS = True
    logger.info("Using shared fallback implementations for caching")
except ImportError:
    # Fallback to local definitions if shared fallbacks unavailable
    USE_SHARED_FALLBACKS = False
    logger.warning("Shared fallbacks unavailable, using local implementations")

if USE_SHARED_FALLBACKS:
    cache_manager = get_fallback_instance("CacheManager")
    distributed_cache_manager = get_fallback_instance("DistributedCacheManager")
else:
    # Local fallbacks with proper type hints
    class CacheManager:
        """Local cache manager with type safety."""

        def __init__(self) -> None:
            self._cache: dict[CacheKeyType, Any] = {}

        def get(
            self, key: CacheKeyType, default: CacheValueType = None
        ) -> CacheValueType | None:
            """Get value from cache."""
            return self._cache.get(key, default)

        def set(
            self,
            key: CacheKeyType,
            value: CacheValueType,
            ttl: CacheExpirationTime = None,
        ) -> bool:
            """Set value in cache."""
            try:
                self._cache[key] = value
                return True
            except Exception as e:
                logger.error(f"Failed to set cache key {key}: {e}")
                return False

        def delete(self, key: CacheKeyType) -> bool:
            """Delete key from cache."""
            try:
                self._cache.pop(key, None)
                return True
            except Exception as e:
                logger.error(f"Failed to delete cache key {key}: {e}")
                return False

        def clear(self) -> bool:
            """Clear all cache entries."""
            try:
                self._cache.clear()
                return True
            except Exception as e:
                logger.error(f"Failed to clear cache: {e}")
                return False

        def get_stats(self) -> dict[str, Any]:
            """Get cache statistics."""
            return {
                "total_entries": len(self._cache),
                "total_size": sum(len(str(v)) for v in self._cache.values()),
            }

    class DistributedCacheManager:
        """Distributed cache manager with type safety."""

        def __init__(self) -> None:
            self._cache: dict[CacheKeyType, Any] = {}

        def get(
            self, key: CacheKeyType, default: CacheValueType = None
        ) -> CacheValueType | None:
            """Get value from distributed cache."""
            return self._cache.get(key, default)

        def set(
            self,
            key: CacheKeyType,
            value: CacheValueType,
            ttl: CacheExpirationTime = None,
        ) -> bool:
            """Set value in distributed cache."""
            try:
                self._cache[key] = value
                return True
            except Exception as e:
                logger.error(f"Failed to set distributed cache key {key}: {e}")
                return False

        def delete(self, key: CacheKeyType) -> bool:
            """Delete key from distributed cache."""
            try:
                self._cache.pop(key, None)
                return True
            except Exception as e:
                logger.error(f"Failed to delete distributed cache key {key}: {e}")
                return False

    class CacheEntry:
        """Cache entry with metadata."""

        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)

    cache_manager = CacheManager()
    distributed_cache_manager = DistributedCacheManager()

    def cache_get(
        key: CacheKeyType, default: CacheValueType = None
    ) -> CacheValueType | None:
        """Get value from global cache manager."""
        return cache_manager.get(key, default)

    def cache_set(
        key: CacheKeyType, value: CacheValueType, ttl: CacheExpirationTime = None
    ) -> bool:
        """Set value in global cache manager."""
        return cache_manager.set(key, value, ttl)

    def cache_delete(key: CacheKeyType) -> bool:
        """Delete key from global cache manager."""
        return cache_manager.delete(key)

    async def cache_get_async(
        key: CacheKeyType, default: CacheValueType = None
    ) -> CacheValueType | None:
        """Async get value from global cache manager."""
        return cache_manager.get(key, default)

    async def cache_set_async(
        key: CacheKeyType, value: CacheValueType, ttl: CacheExpirationTime = None
    ) -> bool:
        """Async set value in global cache manager."""
        return cache_manager.set(key, value, ttl)

    def cached(ttl: CacheExpirationTime = None):
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

    def async_cached_decorator(ttl: CacheExpirationTime = None):
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


__all__ = [
    "CacheManager",
    "DistributedCacheManager",
    "CacheEntry",
    "cache_manager",
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
    "CacheValueType",
    "CacheExpirationTime",
]

# Version information
try:
    from plexichat.core.utils.fallbacks import get_module_version

    __version__ = get_module_version()
except ImportError:
    __version__ = "1.0.0"
