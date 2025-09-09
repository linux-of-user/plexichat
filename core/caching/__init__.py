"""Core caching module with fallback implementations."""
try:
    from plexichat.core.utils.fallbacks import (
        CacheManager, DistributedCacheManager, CacheEntry, cache_get, cached,
        get_fallback_instance, get_module_version
    )
except ImportError:
    # Retain old fallbacks
    pass

__version__ = get_module_version()
__all__ = ["CacheManager", "DistributedCacheManager", "CacheEntry", "cache_manager", "cache_get", "cached"]

cache_manager = get_fallback_instance('CacheManager')