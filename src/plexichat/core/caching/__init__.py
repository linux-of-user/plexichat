"""PlexiChat Caching"""

import logging
# Typing imports not used

# Use fallback implementations to avoid import issues
logger = logging.getLogger(__name__)
logger.warning("Using fallback caching implementations")

# Fallback implementations
class CacheManager:  # type: ignore
    def __init__(self):
        self._cache = {}

    def get(self, key):
        return self._cache.get(key)

    def set(self, key, value, ttl=None):
        self._cache[key] = value

    def delete(self, key):
        self._cache.pop(key, None)

class DistributedCacheManager:  # type: ignore
    def __init__(self):
        self._cache = {}

    def get(self, key):
        return self._cache.get(key)

    def set(self, key, value, ttl=None):
        self._cache[key] = value

class CacheEntry:  # type: ignore
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

cache_manager = CacheManager()
distributed_cache_manager = DistributedCacheManager()

def cache_get(key):  # type: ignore
    return cache_manager.get(key)

def cache_set(key, value, ttl=None):  # type: ignore
    return cache_manager.set(key, value, ttl)

def cache_delete(key):  # type: ignore
    return cache_manager.delete(key)

async def cache_get_async(key):  # type: ignore
    return cache_manager.get(key)

async def cache_set_async(key, value, ttl=None):  # type: ignore
    return cache_manager.set(key, value, ttl)

def cached(*args, **kwargs):  # type: ignore
    def decorator(func):
        return func
    return decorator

def async_cached_decorator(*args, **kwargs):  # type: ignore
    def decorator(func):
        return func
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
]

from plexichat.core.unified_config import get_config

__version__ = get_config("system.version", "0.0.0")
