"""Core caching module with fallback implementations."""

from plexichat.core.utils.fallbacks import (
    CacheEntry,
    CacheManager,
    DistributedCacheManager,
    cache_get,
    cached,
    get_fallback_instance,
    get_module_version,
)

__version__ = get_module_version()
__all__ = [
    "CacheManager",
    "DistributedCacheManager",
    "CacheEntry",
    "cache_manager",
    "cache_get",
    "cached",
]

cache_manager = get_fallback_instance("CacheManager")
