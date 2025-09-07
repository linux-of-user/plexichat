"""
Unified Cache Manager Module
This module consolidates caching under 'plexichat.core.cache'.
Implementation is migrated from core/performance/cache_manager.py (QuantumSecureCache).
"""

# Re-export the implementation until we finalize the file move.
# This avoids duplication while keeping a canonical import path.

from plexichat.core.performance.cache_manager import (
    QuantumSecureCache,
    CacheLevel,
    CacheStrategy,
    SecureCacheEntry,
    CacheStats,
    secure_cache,
)

__all__ = [
    'QuantumSecureCache', 'CacheLevel', 'CacheStrategy', 'SecureCacheEntry', 'CacheStats', 'secure_cache'
]
