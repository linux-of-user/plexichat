import asyncio
import hashlib
import json
import logging
import pickle
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class CacheBackend(Enum):
    """Cache backend types."""

    MEMORY = "memory"
    REDIS = "redis"
    MEMCACHED = "memcached"
    DATABASE = "database"
    FILE = "file"


class CacheStrategy(Enum):
    """Cache strategies."""

    LRU = "lru"
    LFU = "lfu"
    FIFO = "fifo"
    TTL = "ttl"


@dataclass
class CacheEntry:
    """Cache entry data structure."""

    key: str
    value: Any
    created_at: datetime
    last_accessed: datetime
    access_count: int = 0
    ttl_seconds: Optional[int] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if the cache entry is expired."""
        if self.ttl_seconds is None:
            return False

        expiry_time = self.created_at + timedelta(seconds=self.ttl_seconds)
        return datetime.now(timezone.utc) > expiry_time

    def touch(self):
        """Update last accessed time and increment access count."""
        self.last_accessed = datetime.now(timezone.utc)
        self.access_count += 1


class UnifiedCacheManager:
    """Enterprise-grade unified cache management system."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.memory_cache: Dict[str, CacheEntry] = {}
        self.cache_stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0,
            "evictions": 0,
        }
        self._lock = threading.RLock()
        self.max_memory_size = self.config.get("max_memory_size", 1000)
        self.default_ttl = self.config.get("default_ttl_seconds", 3600)
        self.strategy = CacheStrategy(self.config.get("strategy", "lru"))
        self.compression_enabled = self.config.get("compression_enabled", False)
        self.serialization_format = self.config.get("serialization_format", "pickle")

        # External cache backends (Redis, Memcached, etc.)
        self.redis_client = None
        self.memcached_client = None

        # Background cleanup
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False

    async def initialize(self):
        """Initialize the cache manager."""
        self._running = True

        # Initialize external backends if configured
        await self._initialize_backends()

        # Start background cleanup task
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

        logger.info("Unified Cache Manager initialized")

    async def shutdown(self):
        """Shutdown the cache manager."""
        self._running = False

        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        # Close external connections
        if self.redis_client:
            try:
                await self.redis_client.close()
            except:
                pass

        logger.info("Unified Cache Manager shutdown complete")

    async def _initialize_backends(self):
        """Initialize external cache backends."""
        # Redis initialization
        if self.config.get("l2_redis_enabled", False):
            try:
                import aioredis  # type: ignore

                redis_host = self.config.get("l2_redis_host", "localhost")
                redis_port = self.config.get("l2_redis_port", 6379)
                redis_db = self.config.get("l2_redis_db", 0)
                redis_url = f"redis://{redis_host}:{redis_port}/{redis_db}"
                self.redis_client = aioredis.from_url(redis_url)
                logger.info("Redis cache backend initialized")
            except ImportError:
                logger.warning("Redis not available, skipping Redis backend")
            except Exception as e:
                logger.error(f"Failed to initialize Redis: {e}")

    async def get(self, key: str, default: Any = None) -> Any:
        """Get a value from cache."""
        # Try memory cache first
        with self._lock:
            if key in self.memory_cache:
                entry = self.memory_cache[key]

                if entry.is_expired():
                    del self.memory_cache[key]
                    self.cache_stats["evictions"] += 1
                else:
                    entry.touch()
                    self.cache_stats["hits"] += 1
                    return entry.value

        # Try Redis if available
        if self.redis_client:
            try:
                redis_value = await self.redis_client.get(key)
                if redis_value:
                    value = self._deserialize(redis_value)
                    # Store in memory cache for faster access
                    await self.set(key, value, ttl=self.default_ttl, skip_redis=True)
                    self.cache_stats["hits"] += 1
                    return value
            except Exception as e:
                logger.error(f"Redis get error: {e}")

        self.cache_stats["misses"] += 1
        return default

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        tags: Optional[List[str]] = None,
        skip_redis: bool = False,
    ) -> bool:
        """Set a value in cache."""
        if ttl is None:
            ttl = self.default_ttl

        # Create cache entry
        entry = CacheEntry(
            key=key,
            value=value,
            created_at=datetime.now(timezone.utc),
            last_accessed=datetime.now(timezone.utc),
            ttl_seconds=ttl,
            tags=tags or [],
        )

        # Store in memory cache
        with self._lock:
            # Check if we need to evict entries
            if len(self.memory_cache) >= self.max_memory_size:
                self._evict_entries()

            self.memory_cache[key] = entry
            self.cache_stats["sets"] += 1

        # Store in Redis if available
        if self.redis_client and not skip_redis:
            try:
                serialized_value = self._serialize(value)
                if ttl is not None:
                    await self.redis_client.setex(key, ttl, serialized_value)
                else:
                    await self.redis_client.set(key, serialized_value)
            except Exception as e:
                logger.error(f"Redis set error: {e}")

        return True

    async def delete(self, key: str) -> bool:
        """Delete a key from cache."""
        deleted = False

        # Delete from memory cache
        with self._lock:
            if key in self.memory_cache:
                del self.memory_cache[key]
                self.cache_stats["deletes"] += 1
                deleted = True

        # Delete from Redis if available
        if self.redis_client:
            try:
                await self.redis_client.delete(key)
                deleted = True
            except Exception as e:
                logger.error(f"Redis delete error: {e}")

        return deleted

    async def clear(self) -> bool:
        """Clear all cache entries."""
        with self._lock:
            self.memory_cache.clear()

        # Clear Redis if available
        if self.redis_client:
            try:
                await self.redis_client.flushdb()
            except Exception as e:
                logger.error(f"Redis clear error: {e}")

        logger.info("Cache cleared")
        return True

    def _evict_entries(self):
        """Evict cache entries based on strategy."""
        if not self.memory_cache:
            return

        entries_to_remove = max(1, len(self.memory_cache) // 10)  # Remove 10%

        if self.strategy == CacheStrategy.LRU:
            # Remove least recently used
            sorted_entries = sorted(
                self.memory_cache.items(), key=lambda x: x[1].last_accessed
            )
        elif self.strategy == CacheStrategy.LFU:
            # Remove least frequently used
            sorted_entries = sorted(
                self.memory_cache.items(), key=lambda x: x[1].access_count
            )
        elif self.strategy == CacheStrategy.FIFO:
            # Remove oldest entries
            sorted_entries = sorted(
                self.memory_cache.items(), key=lambda x: x[1].created_at
            )
        else:  # TTL
            # Remove expired entries first, then oldest
            sorted_entries = sorted(
                self.memory_cache.items(),
                key=lambda x: (not x[1].is_expired(), x[1].created_at),
            )

        for i in range(min(entries_to_remove, len(sorted_entries))):
            key = sorted_entries[i][0]
            del self.memory_cache[key]
            self.cache_stats["evictions"] += 1

    def _serialize(self, value: Any) -> bytes:
        """Serialize value for storage."""
        if self.serialization_format == "json":
            return json.dumps(value).encode("utf-8")
        else:  # pickle
            return pickle.dumps(value)

    def _deserialize(self, data: bytes) -> Any:
        """Deserialize value from storage."""
        if self.serialization_format == "json":
            return json.loads(data.decode("utf-8"))
        else:  # pickle
            return pickle.loads(data)

    async def _cleanup_loop(self):
        """Background cleanup of expired entries."""
        while self._running:
            try:
                await asyncio.sleep(60)  # Cleanup every minute

                with self._lock:
                    expired_keys = []
                    for key, entry in self.memory_cache.items():
                        if entry.is_expired():
                            expired_keys.append(key)

                    for key in expired_keys:
                        del self.memory_cache[key]
                        self.cache_stats["evictions"] += 1

                    if expired_keys:
                        logger.debug(
                            f"Cleaned up {len(expired_keys)} expired cache entries"
                        )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cache cleanup: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_requests = self.cache_stats["hits"] + self.cache_stats["misses"]
            hit_rate = (
                (self.cache_stats["hits"] / total_requests) if total_requests > 0 else 0
            )

            return {
                **self.cache_stats,
                "hit_rate": hit_rate,
                "memory_entries": len(self.memory_cache),
                "memory_usage_percent": (len(self.memory_cache) / self.max_memory_size)
                * 100,
            }


class CacheKeyBuilder:
    """Helper class for building cache keys."""

    @staticmethod
    def build(prefix: str, *args, **kwargs) -> str:
        """Build a cache key from prefix and arguments."""
        key_parts = [prefix]

        # Add positional arguments
        for arg in args:
            key_parts.append(str(arg))

        # Add keyword arguments (sorted for consistency)
        for key, value in sorted(kwargs.items()):
            key_parts.append(f"{key}:{value}")

        return ":".join(key_parts)

    @staticmethod
    def hash_key(key: str) -> str:
        """Create a hash of the key for consistent length."""
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @staticmethod
    def user_key(user_id: str) -> str:
        """Build a user-specific cache key."""
        return f"user:{user_id}"

    @staticmethod
    def session_key(session_id: str) -> str:
        """Build a session-specific cache key."""
        return f"session:{session_id}"


def cached(
    ttl: int = 3600,
    key_func: Optional[Callable] = None,
    tags: Optional[List[str]] = None,
):
    """Decorator for caching function results."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Build cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = CacheKeyBuilder.build(
                    f"{func.__module__}.{func.__name__}", *args, **kwargs
                )

            # Try to get from cache
            cache_manager = get_cache_manager()
            cached_result = await cache_manager.get(cache_key)

            if cached_result is not None:
                return cached_result

            # Execute function and cache result
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            await cache_manager.set(cache_key, result, ttl=ttl, tags=tags)
            return result

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # For synchronous functions, use asyncio.run
            return asyncio.run(async_wrapper(*args, **kwargs))

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


# Global cache manager instance
_cache_manager: Optional[UnifiedCacheManager] = None


def get_cache_manager() -> UnifiedCacheManager:
    """Get the global cache manager instance."""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = UnifiedCacheManager()
    return _cache_manager


async def initialize_cache_manager(
    config: Optional[Dict[str, Any]] = None,
) -> UnifiedCacheManager:
    """Initialize and return the cache manager."""
    cache_manager = get_cache_manager()
    if config:
        cache_manager.config.update(config)
    await cache_manager.initialize()
    return cache_manager


# Convenience functions
async def cache_get(key: str, default: Any = None) -> Any:
    """Get a value from cache."""
    return await get_cache_manager().get(key, default)


async def cache_set(
    key: str, value: Any, ttl: Optional[int] = None, tags: Optional[List[str]] = None
) -> bool:
    """Set a value in cache."""
    return await get_cache_manager().set(key, value, ttl, tags)


async def cache_delete(key: str) -> bool:
    """Delete a key from cache."""
    return await get_cache_manager().delete(key)


async def cache_clear() -> bool:
    """Clear all cache entries."""
    return await get_cache_manager().clear()


# Export all public functions and classes
__all__ = [
    "UnifiedCacheManager",
    "CacheKeyBuilder",
    "cached",
    "get_cache_manager",
    "initialize_cache_manager",
    "cache_get",
    "cache_set",
    "cache_delete",
    "cache_clear",
]
