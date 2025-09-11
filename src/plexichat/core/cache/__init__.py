"""PlexiChat Core Cache Module with Type Safety and Integration"""

from .manager import (
    CacheExpiration,
    CacheKey,
    CacheLevel,
    CacheStats,
    CacheStrategy,
    CacheTags,
    CacheValue,
    QuantumSecureCache,
    SecureCacheEntry,
    secure_cache,
)

__all__ = [
    "QuantumSecureCache",
    "secure_cache",
    "CacheLevel",
    "CacheStrategy",
    "SecureCacheEntry",
    "CacheStats",
    # Type exports for better integration
    "CacheKey",
    "CacheValue",
    "CacheExpiration",
    "CacheTags",
]
