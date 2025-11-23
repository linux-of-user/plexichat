"""
PlexiChat Caching Integration
"""

from typing import Any, Optional
import time

_cache_store = {}

async def cache_get(key: str) -> Optional[Any]:
    """Get value from cache."""
    entry = _cache_store.get(key)
    if not entry:
        return None
    
    if entry["expires"] and time.time() > entry["expires"]:
        del _cache_store[key]
        return None
        
    return entry["value"]

async def cache_set(key: str, value: Any, ttl: int = 300, tags: list[str] = None) -> bool:
    """Set value in cache."""
    _cache_store[key] = {
        "value": value,
        "expires": time.time() + ttl if ttl else None,
        "tags": tags or []
    }
    return True

async def cache_delete(key: str) -> bool:
    """Delete value from cache."""
    if key in _cache_store:
        del _cache_store[key]
        return True
    return False

async def cache_clear() -> bool:
    """Clear all cache."""
    _cache_store.clear()
    return True

class CacheKeyBuilder:
    """Helper to build cache keys."""
    @staticmethod
    def build(*args) -> str:
        return ":".join(str(arg) for arg in args)
