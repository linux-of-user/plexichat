"""Cython optimized consistent hash ring operations.

Optimized hash calculations and node selection for cluster load balancing.
"""

from libc.stdlib cimport malloc, free
from libc.string cimport memcpy
import hashlib
from typing import Tuple


cdef int hash_string(const char* key, int key_len) nogil:
    """Fast string hashing for consistent hashing."""
    cdef int hash_val = 5381
    cdef int i
    for i in range(key_len):
        hash_val = ((hash_val << 5) + hash_val) + ord(key[i])
    return hash_val & 0x7fffffff  # Positive 32-bit hash


cpdef tuple build_hash_ring(list node_ids, int virtual_nodes_per_node=150):
    """Build consistent hash ring with virtual nodes."""
    cdef dict hash_ring = {}
    cdef int total_virtual_nodes = 0
    cdef str node_id
    cdef int i, v_node_key, hash_val
    
    for node_id in node_ids:
        for i in range(virtual_nodes_per_node):
            v_node_key = f"{node_id}:{i}".encode('utf-8')
            hash_val = int(hashlib.md5(v_node_key).hexdigest(), 16) % (2**32)
            hash_ring[hash_val] = node_id
            total_virtual_nodes += 1
    
    return hash_ring, total_virtual_nodes


cpdef str get_node_by_hash(dict hash_ring, str request_key):
    """Get node using consistent hashing."""
    if not hash_ring:
        return None
    
    cdef bytes key_bytes = request_key.encode('utf-8')
    cdef str key_hash = hashlib.md5(key_bytes).hexdigest()
    cdef int key_int = int(key_hash, 16)
    
    cdef list sorted_hashes = sorted(hash_ring.keys())
    cdef int i
    for i in range(len(sorted_hashes)):
        if sorted_hashes[i] >= key_int:
            return hash_ring[sorted_hashes[i]]
    
    # Wrap around
    return hash_ring[sorted_hashes[0]]