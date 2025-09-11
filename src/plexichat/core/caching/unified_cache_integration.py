"""
Unified Cache Integration System
Enterprise-grade caching with comprehensive type safety and proper integration.
"""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from functools import wraps
import hashlib
import json
import pickle
import threading
from typing import Any, Optional, TypeVar, Union, cast

from plexichat.core.config_manager import get_config
from plexichat.core.database import DatabaseManager
from plexichat.core.logging import get_logger

logger = get_logger(__name__)

# Type variables for better type safety
T = TypeVar("T")
CacheKeyType = Union[str, int, tuple, bytes]
CacheValueType = Any
CacheExpirationTime = Optional[int | float | datetime | timedelta]


class CacheBackend(Enum):
    """Cache backend types with comprehensive options."""

    MEMORY = "memory"
    REDIS = "redis"
    MEMCACHED = "memcached"
    DATABASE = "database"
    FILE = "file"
    HYBRID = "hybrid"


class CacheStrategy(Enum):
    """Cache eviction strategies."""

    LRU = "lru"
    LFU = "lfu"
    FIFO = "fifo"
    TTL = "ttl"
    ADAPTIVE = "adaptive"


@dataclass
class CacheEntry:
    """Cache entry with comprehensive metadata and type safety."""

    key: str
    value: Any
    created_at: datetime
    last_accessed: datetime
    access_count: int = 0
    ttl_seconds: int | None = None
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    size_bytes: int = 0

    def __post_init__(self) -> None:
        """Initialize computed fields."""
        if self.size_bytes == 0:
            try:
                # Estimate serialized size
                self.size_bytes = len(pickle.dumps(self.value))
            except Exception:
                self.size_bytes = len(str(self.value).encode("utf-8"))

    def is_expired(self) -> bool:
        """Check if the cache entry is expired."""
        if self.ttl_seconds is None:
            return False

        expiry_time = self.created_at + timedelta(seconds=self.ttl_seconds)
        return datetime.now(UTC) > expiry_time

    def touch(self) -> None:
        """Update last accessed time and increment access count."""
        self.last_accessed = datetime.now(UTC)
        self.access_count += 1


class UnifiedCacheManager:
    """Enterprise-grade unified cache management system with type safety."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialize unified cache manager.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.memory_cache: dict[str, CacheEntry] = {}

        # Performance statistics
        self.cache_stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0,
            "evictions": 0,
            "errors": 0,
        }

        # Thread safety
        self._lock = threading.RLock()

        # Configuration
        self.max_memory_size: int = self.config.get("max_memory_size", 1000)
        self.default_ttl: int = self.config.get("default_ttl_seconds", 3600)
        self.strategy: CacheStrategy = CacheStrategy(self.config.get("strategy", "lru"))
        self.compression_enabled: bool = self.config.get("compression_enabled", False)
        self.serialization_format: str = self.config.get(
            "serialization_format", "pickle"
        )

        # External cache backends
        self.redis_client: Any | None = None
        self.memcached_client: Any | None = None
        self.database_manager: DatabaseManager | None = None

        # Background tasks
        self._cleanup_task: asyncio.Task | None = None
        self._running: bool = False

    async def initialize(self, database_manager: DatabaseManager | None = None) -> None:
        """
        Initialize the cache manager with proper integration.

        Args:
            database_manager: Optional database manager for persistence
        """
        self._running = True
        self.database_manager = database_manager

        # Initialize external backends if configured
        await self._initialize_backends()

        # Start background cleanup task
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

        logger.info("Unified Cache Manager initialized successfully")

    async def shutdown(self) -> None:
        """Shutdown the cache manager gracefully."""
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
            except Exception as e:
                logger.warning(f"Error closing Redis connection: {e}")

        logger.info("Unified Cache Manager shutdown complete")

    async def _initialize_backends(self) -> None:
        """Initialize external cache backends based on configuration."""
        # Redis initialization
        if self.config.get("l2_redis_enabled", False):
            try:
                import aioredis  # type: ignore

                redis_host = self.config.get("l2_redis_host", "localhost")
                redis_port = self.config.get("l2_redis_port", 6379)
                redis_db = self.config.get("l2_redis_db", 0)
                redis_password = self.config.get("l2_redis_password", "")

                redis_url = f"redis://{redis_host}:{redis_port}/{redis_db}"
                if redis_password:
                    redis_url = f"redis://:{redis_password}@{redis_host}:{redis_port}/{redis_db}"

                self.redis_client = aioredis.from_url(redis_url)
                logger.info("Redis cache backend initialized")

            except ImportError:
                logger.warning("Redis library not available, skipping Redis backend")
            except Exception as e:
                logger.error(f"Failed to initialize Redis: {e}")
                self.cache_stats["errors"] += 1

    async def get(self, key: CacheKeyType, default: T = None) -> Any | T:
        """
        Get a value from cache with comprehensive fallback.

        Args:
            key: Cache key
            default: Default value if not found

        Returns:
            Cached value or default
        """
        try:
            cache_key = self._normalize_key(key)

            # Try memory cache first
            with self._lock:
                if cache_key in self.memory_cache:
                    entry = self.memory_cache[cache_key]

                    if entry.is_expired():
                        del self.memory_cache[cache_key]
                        self.cache_stats["evictions"] += 1
                    else:
                        entry.touch()
                        self.cache_stats["hits"] += 1
                        return entry.value

            # Try Redis if available
            if self.redis_client:
                try:
                    redis_value = await self.redis_client.get(cache_key)
                    if redis_value:
                        value = self._deserialize(redis_value)

                        # Store in memory cache for faster access next time
                        await self.set(
                            key, value, ttl=self.default_ttl, skip_redis=True
                        )
                        self.cache_stats["hits"] += 1
                        return value

                except Exception as e:
                    logger.error(f"Redis get error for key {cache_key}: {e}")
                    self.cache_stats["errors"] += 1

            # Try database if available
            if self.database_manager:
                try:
                    # TODO: Implement database cache retrieval
                    logger.debug(
                        f"Database cache lookup not implemented for key: {cache_key}"
                    )
                except Exception as e:
                    logger.error(f"Database cache lookup error: {e}")
                    self.cache_stats["errors"] += 1

            self.cache_stats["misses"] += 1
            return default

        except Exception as e:
            logger.error(f"Cache get operation failed for key {key}: {e}")
            self.cache_stats["errors"] += 1
            return default

    async def set(
        self,
        key: CacheKeyType,
        value: Any,
        ttl: CacheExpirationTime = None,
        tags: list[str] | None = None,
        skip_redis: bool = False,
    ) -> bool:
        """
        Set a value in cache with comprehensive backend support.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live
            tags: Optional tags for grouping
            skip_redis: Skip Redis storage (for internal use)

        Returns:
            True if successful
        """
        try:
            cache_key = self._normalize_key(key)
            ttl_seconds = self._normalize_ttl(ttl)

            # Create cache entry
            entry = CacheEntry(
                key=cache_key,
                value=value,
                created_at=datetime.now(UTC),
                last_accessed=datetime.now(UTC),
                ttl_seconds=ttl_seconds,
                tags=tags or [],
            )

            # Store in memory cache
            with self._lock:
                # Check if we need to evict entries
                if len(self.memory_cache) >= self.max_memory_size:
                    self._evict_entries()

                self.memory_cache[cache_key] = entry
                self.cache_stats["sets"] += 1

            # Store in Redis if available and not skipped
            if self.redis_client and not skip_redis:
                try:
                    serialized_value = self._serialize(value)
                    if ttl_seconds is not None:
                        await self.redis_client.setex(
                            cache_key, ttl_seconds, serialized_value
                        )
                    else:
                        await self.redis_client.set(cache_key, serialized_value)

                except Exception as e:
                    logger.error(f"Redis set error for key {cache_key}: {e}")
                    self.cache_stats["errors"] += 1

            # Store in database if available
            if self.database_manager:
                try:
                    # TODO: Implement database cache storage
                    logger.debug(
                        f"Database cache storage not implemented for key: {cache_key}"
                    )
                except Exception as e:
                    logger.error(f"Database cache storage error: {e}")
                    self.cache_stats["errors"] += 1

            return True

        except Exception as e:
            logger.error(f"Cache set operation failed for key {key}: {e}")
            self.cache_stats["errors"] += 1
            return False

    async def delete(self, key: CacheKeyType) -> bool:
        """
        Delete a key from cache across all backends.

        Args:
            key: Cache key to delete

        Returns:
            True if deleted from any backend
        """
        deleted = False
        cache_key = self._normalize_key(key)

        # Delete from memory cache
        with self._lock:
            if cache_key in self.memory_cache:
                del self.memory_cache[cache_key]
                self.cache_stats["deletes"] += 1
                deleted = True

        # Delete from Redis if available
        if self.redis_client:
            try:
                result = await self.redis_client.delete(cache_key)
                if result > 0:
                    deleted = True
            except Exception as e:
                logger.error(f"Redis delete error for key {cache_key}: {e}")
                self.cache_stats["errors"] += 1

        # Delete from database if available
        if self.database_manager:
            try:
                # TODO: Implement database cache deletion
                logger.debug(
                    f"Database cache deletion not implemented for key: {cache_key}"
                )
            except Exception as e:
                logger.error(f"Database cache deletion error: {e}")
                self.cache_stats["errors"] += 1

        return deleted

    async def clear(self) -> bool:
        """Clear all cache entries from all backends."""
        try:
            # Clear memory cache
            with self._lock:
                self.memory_cache.clear()

            # Clear Redis if available
            if self.redis_client:
                try:
                    await self.redis_client.flushdb()
                except Exception as e:
                    logger.error(f"Redis clear error: {e}")
                    self.cache_stats["errors"] += 1

            # Clear database cache if available
            if self.database_manager:
                try:
                    # TODO: Implement database cache clearing
                    logger.debug("Database cache clearing not implemented")
                except Exception as e:
                    logger.error(f"Database cache clearing error: {e}")
                    self.cache_stats["errors"] += 1

            logger.info("Cache cleared successfully")
            return True

        except Exception as e:
            logger.error(f"Cache clear operation failed: {e}")
            self.cache_stats["errors"] += 1
            return False

    async def invalidate_by_tags(self, tags: list[str]) -> int:
        """
        Invalidate cache entries by tags.

        Args:
            tags: List of tags to invalidate

        Returns:
            Number of entries invalidated
        """
        invalidated_count = 0
        keys_to_delete = []

        # Find entries with matching tags
        with self._lock:
            for cache_key, entry in self.memory_cache.items():
                entry_tags = entry.tags
                if any(tag in entry_tags for tag in tags):
                    keys_to_delete.append(cache_key)

        # Delete found entries
        for cache_key in keys_to_delete:
            if await self.delete(cache_key):
                invalidated_count += 1

        logger.debug(f"Invalidated {invalidated_count} entries by tags: {tags}")
        return invalidated_count

    def _normalize_key(self, key: CacheKeyType) -> str:
        """Normalize cache key to string format."""
        if isinstance(key, str):
            return key
        elif isinstance(key, (int, float)):
            return str(key)
        elif isinstance(key, bytes):
            return key.decode("utf-8", errors="replace")
        elif isinstance(key, tuple):
            return ":".join(str(k) for k in key)
        else:
            return str(key)

    def _normalize_ttl(self, ttl: CacheExpirationTime) -> int | None:
        """Normalize TTL to seconds."""
        if ttl is None:
            return None
        elif isinstance(ttl, (int, float)):
            return int(ttl)
        elif isinstance(ttl, timedelta):
            return int(ttl.total_seconds())
        elif isinstance(ttl, datetime):
            return int((ttl - datetime.now(UTC)).total_seconds())
        else:
            return None

    def _evict_entries(self) -> None:
        """Evict cache entries based on configured strategy."""
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
        else:  # TTL or ADAPTIVE
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
        """Serialize value for storage in external backends."""
        try:
            if self.serialization_format == "json":
                return json.dumps(value, default=str).encode("utf-8")
            else:  # pickle
                return pickle.dumps(value)
        except Exception as e:
            logger.error(f"Serialization error: {e}")
            # Fallback to string representation
            return str(value).encode("utf-8")

    def _deserialize(self, data: bytes) -> Any:
        """Deserialize value from external storage."""
        try:
            if self.serialization_format == "json":
                return json.loads(data.decode("utf-8"))
            else:  # pickle
                return pickle.loads(data)
        except Exception as e:
            logger.error(f"Deserialization error: {e}")
            # Fallback to string
            return data.decode("utf-8", errors="replace")

    async def _cleanup_loop(self) -> None:
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
                logger.error(f"Error in cache cleanup loop: {e}")
                self.cache_stats["errors"] += 1

    def get_stats(self) -> dict[str, Any]:
        """Get comprehensive cache statistics."""
        with self._lock:
            total_requests = self.cache_stats["hits"] + self.cache_stats["misses"]
            hit_rate = (
                (self.cache_stats["hits"] / total_requests) if total_requests > 0 else 0
            )

            return {
                **self.cache_stats,
                "hit_rate": hit_rate,
                "memory_entries": len(self.memory_cache),
                "max_memory_size": self.max_memory_size,
                "memory_usage_percent": (
                    (len(self.memory_cache) / self.max_memory_size) * 100
                    if self.max_memory_size > 0
                    else 0
                ),
                "strategy": self.strategy.value,
                "backends": {
                    "memory": True,
                    "redis": self.redis_client is not None,
                    "database": self.database_manager is not None,
                },
            }


class CacheKeyBuilder:
    """Helper class for building consistent cache keys."""

    @staticmethod
    def build(prefix: str, *args: Any, **kwargs: Any) -> str:
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
    def user_key(user_id: str | int) -> str:
        """Build a user-specific cache key."""
        return f"user:{user_id}"

    @staticmethod
    def session_key(session_id: str) -> str:
        """Build a session-specific cache key."""
        return f"session:{session_id}"

    @staticmethod
    def function_key(func: Callable, *args: Any, **kwargs: Any) -> str:
        """Build a function-specific cache key."""
        func_name = f"{func.__module__}.{func.__name__}"
        args_hash = hashlib.md5(str(args).encode()).hexdigest()[:8]
        kwargs_hash = hashlib.md5(str(sorted(kwargs.items())).encode()).hexdigest()[:8]
        return f"func:{func_name}:{args_hash}:{kwargs_hash}"


def cached(
    ttl: CacheExpirationTime = 3600,
    key_func: Callable[..., str] | None = None,
    tags: list[str] | None = None,
    cache_manager: UnifiedCacheManager | None = None,
) -> Callable[[Callable], Callable]:
    """
    Decorator for caching function results with comprehensive type safety.

    Args:
        ttl: Cache time to live
        key_func: Custom key generation function
        tags: Tags for cache invalidation
        cache_manager: Cache manager instance to use

    Returns:
        Decorator function
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get cache manager instance
            manager = cache_manager or get_cache_manager()

            # Build cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = CacheKeyBuilder.function_key(func, *args, **kwargs)

            # Try to get from cache
            cached_result = await manager.get(cache_key)
            if cached_result is not None:
                return cached_result

            # Execute function and cache result
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            await manager.set(cache_key, result, ttl=ttl, tags=tags)
            return result

        @wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            # For synchronous functions, run in event loop
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # If we're already in an event loop, create a task
                    return asyncio.create_task(async_wrapper(*args, **kwargs))
                else:
                    return loop.run_until_complete(async_wrapper(*args, **kwargs))
            except RuntimeError:
                # No event loop, create one
                return asyncio.run(async_wrapper(*args, **kwargs))

        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return cast("Callable", async_wrapper)
        else:
            return cast("Callable", sync_wrapper)

    return decorator


# Global cache manager instance
_cache_manager: UnifiedCacheManager | None = None


def get_cache_manager() -> UnifiedCacheManager:
    """Get the global cache manager instance with proper initialization."""
    global _cache_manager
    if _cache_manager is None:
        # Try to get configuration
        try:
            config_dict = {}
            caching_config = get_config("caching", None)
            if caching_config:
                config_dict = {
                    "max_memory_size": getattr(caching_config, "l1_max_items", 1000),
                    "default_ttl_seconds": getattr(
                        caching_config, "default_ttl_seconds", 3600
                    ),
                    "l2_redis_enabled": getattr(
                        caching_config, "l2_redis_enabled", False
                    ),
                    "l2_redis_host": getattr(
                        caching_config, "l2_redis_host", "localhost"
                    ),
                    "l2_redis_port": getattr(caching_config, "l2_redis_port", 6379),
                    "l2_redis_db": getattr(caching_config, "l2_redis_db", 0),
                    "l2_redis_password": getattr(
                        caching_config, "l2_redis_password", ""
                    ),
                }
        except Exception as e:
            logger.warning(f"Failed to load caching configuration: {e}")
            config_dict = {}

        _cache_manager = UnifiedCacheManager(config_dict)

    return _cache_manager


async def initialize_cache_manager(
    config: dict[str, Any] | None = None,
    database_manager: DatabaseManager | None = None,
) -> UnifiedCacheManager:
    """Initialize and return the cache manager with proper integration."""
    cache_manager = get_cache_manager()
    if config:
        cache_manager.config.update(config)
    await cache_manager.initialize(database_manager)
    return cache_manager


# Convenience functions with proper type hints
async def cache_get(key: CacheKeyType, default: T = None) -> Any | T:
    """Get a value from the global cache manager."""
    return await get_cache_manager().get(key, default)


async def cache_set(
    key: CacheKeyType,
    value: Any,
    ttl: CacheExpirationTime = None,
    tags: list[str] | None = None,
) -> bool:
    """Set a value in the global cache manager."""
    return await get_cache_manager().set(key, value, ttl, tags)


async def cache_delete(key: CacheKeyType) -> bool:
    """Delete a key from the global cache manager."""
    return await get_cache_manager().delete(key)


async def cache_clear() -> bool:
    """Clear all entries from the global cache manager."""
    return await get_cache_manager().clear()


async def cache_invalidate_by_tags(tags: list[str]) -> int:
    """Invalidate cache entries by tags."""
    return await get_cache_manager().invalidate_by_tags(tags)


# Export all public functions and classes
__all__ = [
    "UnifiedCacheManager",
    "CacheKeyBuilder",
    "CacheEntry",
    "CacheBackend",
    "CacheStrategy",
    "cached",
    "get_cache_manager",
    "initialize_cache_manager",
    "cache_get",
    "cache_set",
    "cache_delete",
    "cache_clear",
    "cache_invalidate_by_tags",
    # Type exports
    "CacheKeyType",
    "CacheValueType",
    "CacheExpirationTime",
]
