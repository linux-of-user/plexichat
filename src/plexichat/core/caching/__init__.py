"""PlexiChat Caching"""

import logging
from typing import Any, Optional

try:
    from .cache_manager import (
        CacheManager, DistributedCacheManager, CacheEntry,
        cache_manager, distributed_cache_manager,
        cache_get, cache_set, cache_delete,
        cache_get_async, cache_set_async,
        cached, async_cached
    )
    logger = logging.getLogger(__name__)
    logger.info("Caching modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import caching modules: {e}")

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
    "async_cached",
]

__version__ = "1.0.0"
