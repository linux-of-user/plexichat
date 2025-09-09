"""Core caching module with fallback implementations."""
__version__ = "0.0.0"
__all__ = ["CacheManager", "DistributedCacheManager", "CacheEntry", "cache_manager", "cache_get", "cached"]

class CacheManager:
    def __init__(self):
        pass

class DistributedCacheManager:
    def __init__(self):
        pass

class CacheEntry:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

cache_manager = None

def cache_get(*args, **kwargs):
    pass

def cached(func):
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper