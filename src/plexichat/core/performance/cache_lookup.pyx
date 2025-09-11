"""Cython optimized multi-tier cache lookup.

Fast cache key validation and tier selection logic.
"""

from libc.stdint cimport uint64_t
from libc.string cimport strlen, memcpy
cimport cython
from typing import Tuple, Optional


@cython.boundscheck(False)
@cython.wraparound(False)
cdef uint64_t fast_hash_key(str key) -> uint64_t:
    """Fast 64-bit hash for cache keys."""
    cdef bytes key_bytes = key.encode('utf-8')
    cdef const char* c_key = key_bytes
    cdef int length = len(key_bytes)
    cdef uint64_t hash_val = 14695981039346656037  # fnv_offset_basis
    cdef int i
    cdef unsigned char c
    
    for i in range(length):
        c = <unsigned char>c_key[i]
        hash_val ^= c
        hash_val *= 1099511628211  # fnv_prime
    
    return hash_val


cpdef tuple tier_select(uint64_t key_hash, int num_tiers=4):
    """Select optimal cache tier based on key hash."""
    cdef int tier_index = <int>(key_hash % num_tiers)
    cdef list tier_names = ["L1_MEMORY", "L2_REDIS", "L3_MEMCACHED", "L4_CDN"]
    return tier_names[tier_index], tier_index


cpdef bint key_exists_in_tier(str key, str tier_name):
    """Simulate fast key existence check in specific tier."""
    # This would interface with actual cache backends
    # For optimization demo, return probabilistic result
    cdef uint64_t key_hash = fast_hash_key(key)
    cdef uint64_t tier_hash = fast_hash_key(tier_name)
    return (key_hash ^ tier_hash) % 2 == 0  # 50% hit rate simulation


cpdef str fast_cache_get(str key, list tier_order):
    """Fast multi-tier cache lookup with early exit."""
    cdef str tier
    for tier in tier_order:
        if key_exists_in_tier(key, tier):
            return f"found_in_{tier.lower()}"
    return None