"""Cython optimized message checksum calculation.

Optimized SHA256 hashing for high-volume message processing.
"""

import hashlib
from libc.stdlib cimport malloc, free
from cpython.bytes cimport PyBytes_AsString


cdef unsigned char* sha256_hash(const char* data, Py_ssize_t length):
    """C-level SHA256 hashing optimized for strings."""
    cdef unsigned char* result = <unsigned char*>malloc(32)
    if result == NULL:
        return NULL
    
    cdef bytes py_data = data[:length]
    cdef const unsigned char* data_bytes = <const unsigned char*>PyBytes_AsString(py_data)
    
    cdef hashlib.sha256 hasher = hashlib.sha256()
    hasher.update(data_bytes[:length])
    cdef bytes hash_result = hasher.digest()
    
    memcpy(result, <const unsigned char*>hash_result, 32)
    return result


def calculate_checksum(str content):
    """Calculate SHA256 checksum for message content."""
    cdef bytes b_content = content.encode('utf-8')
    cdef Py_ssize_t length = len(b_content)
    cdef unsigned char* hash_result = sha256_hash(<char*>b_content, length)
    
    if hash_result == NULL:
        raise MemoryError("Failed to allocate memory for hash result")
    
    try:
        cdef bytes py_result = b''.join([chr(hash_result[i]) for i in range(32)])
        return py_result.hex()
    finally:
        free(hash_result)