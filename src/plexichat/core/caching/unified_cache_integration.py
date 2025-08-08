#!/usr/bin/env python3
"""
Unified Cache Integration

Ensures all PlexiChat components use the comprehensive multi-tier caching system.
This module replaces all local caching implementations with the unified system.


import asyncio
import logging
from typing import Any, Dict, List, Optional, Callable
from functools import wraps

from plexichat.core.performance.multi_tier_cache_manager import get_cache_manager, MultiTierCacheManager
from plexichat.core.logging.unified_logging_manager import get_logger

logger = get_logger(__name__)


class UnifiedCacheIntegration:
    """Unified cache integration manager."""

    def __init__(self):
        self.cache_manager: Optional[MultiTierCacheManager] = None
        self.initialized = False
        self.fallback_cache: Dict[str, Any] = {}  # Emergency fallback

    async def initialize(self, config: Optional[Dict[str, Any]] = None) -> bool:
        """Initialize the unified caching system."""
        try:
            # Get the multi-tier cache manager
            self.cache_manager = get_cache_manager(config)

            # Initialize it
            init_result = await self.cache_manager.initialize()

            self.initialized = True

            logger.info("Unified cache integration initialized successfully")
            logger.info(f"Cache tiers available: {list(init_result.keys())}")

            return True

        except Exception as e:
            logger.error(f"Failed to initialize unified cache integration: {e}")
            logger.warning("Falling back to in-memory cache")
            return False

    async def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache."""
        if not self.initialized or not self.cache_manager:
            return self.fallback_cache.get(key, default)

        try:
            result = await self.cache_manager.get(key)
            return result if result is not None else default
        except Exception as e:
            logger.warning(f"Cache get error for key {key}: {e}")
            return self.fallback_cache.get(key, default)

    async def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> bool:
        """Set value in cache."""
        if not self.initialized or not self.cache_manager:
            self.fallback_cache[key] = value
            return True

        try:
            return await self.cache_manager.set(key, value, ttl_seconds)
        except Exception as e:
            logger.warning(f"Cache set error for key {key}: {e}")
            self.fallback_cache[key] = value
            return False

    async def delete(self, key: str) -> bool:
        """Delete value from cache."""
        if not self.initialized or not self.cache_manager:
            return self.fallback_cache.pop(key, None) is not None

        try:
            return await self.cache_manager.delete(key)
        except Exception as e:
            logger.warning(f"Cache delete error for key {key}: {e}")
            return self.fallback_cache.pop(key, None) is not None

    async def clear(self, pattern: Optional[str] = None) -> bool:
        """Clear cache entries."""
        if not self.initialized or not self.cache_manager:
            if pattern:
                # Clear matching keys from fallback
                keys_to_remove = [k for k in self.fallback_cache.keys() if pattern in k]
                for key in keys_to_remove:
                    del self.fallback_cache[key]
            else:
                self.fallback_cache.clear()
            return True

        try:
            # MultiTierCacheManager does not support pattern-based invalidation directly
            # Only support clearing all tiers
            return await self.cache_manager.clear()
        except Exception as e:
            logger.warning(f"Cache clear error: {e}")
            return False

    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        if not self.initialized or not self.cache_manager:
            return {
                "status": "fallback",
                "fallback_entries": len(self.fallback_cache),
                "initialized": False
            }

        try:
            return await self.cache_manager.get_stats()
        except Exception as e:
            logger.warning(f"Error getting cache stats: {e}")
            return {"error": str(e)}


# Global unified cache integration instance
_unified_cache: Optional[UnifiedCacheIntegration] = None


async def get_unified_cache() -> UnifiedCacheIntegration:
    """Get or create the unified cache integration instance.
    global _unified_cache

    if _unified_cache is None:
        _unified_cache = UnifiedCacheIntegration()
        await _unified_cache.initialize()

    return _unified_cache


# Convenience functions that replace all other caching functions
async def cache_get(key: str, default: Any = None) -> Any:
    """Get from unified cache."""
    cache = await get_unified_cache()
    return await cache.get(key, default)


async def cache_set(key: str, value: Any, ttl: Optional[int] = None) -> bool:
    Set to unified cache."""
    cache = await get_unified_cache()
    return await cache.set(key, value, ttl)


async def cache_delete(key: str) -> bool:
    """Delete from unified cache.
    cache = await get_unified_cache()
    return await cache.delete(key)


async def cache_clear(pattern: Optional[str] = None) -> bool:
    """Clear unified cache."""
    cache = await get_unified_cache()
    return await cache.clear(pattern)


# Synchronous wrappers for backward compatibility
def cache_get_sync(key: str, default: Any = None) -> Any:
    Synchronous get from unified cache."""
    try:
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(cache_get(key, default))
    except RuntimeError:
        # No event loop, create one
        return asyncio.run(cache_get(key, default))


def cache_set_sync(key: str, value: Any, ttl: Optional[int] = None) -> bool:
    """Synchronous set to unified cache.
    try:
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(cache_set(key, value, ttl))
    except RuntimeError:
        # No event loop, create one
        return asyncio.run(cache_set(key, value, ttl))


def cache_delete_sync(key: str) -> bool:
    """Synchronous delete from unified cache."""
    try:
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(cache_delete(key))
    except RuntimeError:
        # No event loop, create one
        return asyncio.run(cache_delete(key))


# Enhanced decorators that use the unified cache
def cached(ttl: Optional[int] = None, key_func: Optional[Callable] = None):
    Decorator to cache function results using unified cache."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__module__}.{func.__name__}_{hash(str(args) + str(kwargs))}"

            # Try to get from cache
            result = await cache_get(cache_key)
            if result is not None:
                return result

            # Execute function and cache result
            result = await func(*args, **kwargs)
            await cache_set(cache_key, result, ttl)

            return result

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__module__}.{func.__name__}_{hash(str(args) + str(kwargs))}"

            # Try to get from cache
            result = cache_get_sync(cache_key)
            if result is not None:
                return result

            # Execute function and cache result
            result = func(*args, **kwargs)
            cache_set_sync(cache_key, result, ttl)

            return result

        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


def cache_invalidate_on_change(cache_keys: List[str]):
    """Decorator to invalidate cache keys when function is called.
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)

            # Invalidate cache keys
            for key in cache_keys:
                await cache_delete(key)

            return result

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            result = func(*args, **kwargs)

            # Invalidate cache keys
            for key in cache_keys:
                cache_delete_sync(key)

            return result

        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


class CacheKeyBuilder:
    """Helper class for building consistent cache keys."""
        @staticmethod
    def user_key(user_id: str, suffix: str = "") -> str:
        """Build user-specific cache key."""
        return f"user:{user_id}:{suffix}" if suffix else f"user:{user_id}"

    @staticmethod
    def message_key(message_id: str, suffix: str = "") -> str:
        """Build message-specific cache key."""
        return f"message:{message_id}:{suffix}" if suffix else f"message:{message_id}"

    @staticmethod
    def channel_key(channel_id: str, suffix: str = "") -> str:
        """Build channel-specific cache key."""
        return f"channel:{channel_id}:{suffix}" if suffix else f"channel:{channel_id}"

    @staticmethod
    def query_key(table: str, query_hash: str) -> str:
        """Build database query cache key."""
        return f"query:{table}:{query_hash}"

    @staticmethod
    def api_key(endpoint: str, params_hash: str) -> str:
        """Build API response cache key."""
        return f"api:{endpoint}:{params_hash}"

    @staticmethod
    def session_key(session_id: str, suffix: str = "") -> str:
        """Build session-specific cache key."""
        return f"session:{session_id}:{suffix}" if suffix else f"session:{session_id}"


# Migration helper to replace old cache imports
class CacheMigrationHelper:
    """Helper to migrate from old caching systems.
        @staticmethod
    def replace_cache_manager_imports():
        """Log warning about deprecated cache manager usage."""
        logger.warning(
            "Deprecated cache manager detected. Please migrate to unified_cache_integration for optimal performance."
        )

    @staticmethod
    def get_migration_stats() -> Dict[str, Any]:
        """Get migration statistics."""
        # This would track which modules are still using old caching
        return {
            "unified_cache_usage": "active",
            "deprecated_cache_usage": "detected",
            "migration_status": "in_progress"
        }


# Initialize the unified cache on module import
async def _initialize_unified_cache():
    """Initialize unified cache on module import."""
    try:
        await get_unified_cache()
        logger.info("Unified cache integration ready")
    except Exception as e:
        logger.error(f"Failed to initialize unified cache on import: {e}")


# Schedule initialization
def _schedule_initialization():
    """Schedule cache initialization."""
    try:
        loop = asyncio.get_event_loop()
        loop.create_task(_initialize_unified_cache())
    except RuntimeError:
        # No event loop running, will initialize on first use
        pass


# Initialize when module is imported
_schedule_initialization()


# Export the main functions and classes
__all__ = [
    "UnifiedCacheIntegration",
    "get_unified_cache",
    "cache_get",
    "cache_set",
    "cache_delete",
    "cache_clear",
    "cache_get_sync",
    "cache_set_sync",
    "cache_delete_sync",
    "cached",
    "cache_invalidate_on_change",
    "CacheKeyBuilder",
    "CacheMigrationHelper"
]
