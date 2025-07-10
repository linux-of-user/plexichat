"""
Advanced Caching System
High-performance caching with multiple backends and intelligent cache management.
"""

import time
import json
import hashlib
import asyncio
from typing import Any, Optional, Dict, List, Union
from datetime import datetime, timedelta
from pathlib import Path
import logging

logger = logging.getLogger("netlink.performance.cache")

class CacheManager:
    """Advanced caching system with multiple backends."""
    
    def __init__(self):
        self.memory_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0,
            "evictions": 0
        }
        
        # Cache configuration
        self.config = {
            "max_memory_items": 10000,
            "default_ttl": 3600,  # 1 hour
            "cleanup_interval": 300,  # 5 minutes
            "compression_threshold": 1024,  # 1KB
            "enable_persistence": True
        }
        
        # File-based cache directory
        self.cache_dir = Path("cache")
        self.cache_dir.mkdir(exist_ok=True)
        
        # Start cleanup task
        asyncio.create_task(self._cleanup_task())
    
    async def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache."""
        try:
            # Check memory cache first
            if key in self.memory_cache:
                item = self.memory_cache[key]
                
                # Check if expired
                if item["expires_at"] > time.time():
                    self.cache_stats["hits"] += 1
                    return item["value"]
                else:
                    # Remove expired item
                    del self.memory_cache[key]
            
            # Check file cache if enabled
            if self.config["enable_persistence"]:
                file_value = await self._get_from_file(key)
                if file_value is not None:
                    # Store in memory for faster access
                    await self.set(key, file_value, ttl=self.config["default_ttl"])
                    self.cache_stats["hits"] += 1
                    return file_value
            
            self.cache_stats["misses"] += 1
            return default
            
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            self.cache_stats["misses"] += 1
            return default
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache."""
        try:
            if ttl is None:
                ttl = self.config["default_ttl"]
            
            expires_at = time.time() + ttl
            
            # Store in memory cache
            self.memory_cache[key] = {
                "value": value,
                "expires_at": expires_at,
                "created_at": time.time(),
                "access_count": 0
            }
            
            # Enforce memory limit
            if len(self.memory_cache) > self.config["max_memory_items"]:
                await self._evict_lru()
            
            # Store in file cache if enabled and value is large enough
            if (self.config["enable_persistence"] and 
                self._get_size(value) > self.config["compression_threshold"]):
                await self._set_to_file(key, value, expires_at)
            
            self.cache_stats["sets"] += 1
            return True
            
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete value from cache."""
        try:
            deleted = False
            
            # Remove from memory cache
            if key in self.memory_cache:
                del self.memory_cache[key]
                deleted = True
            
            # Remove from file cache
            if self.config["enable_persistence"]:
                file_deleted = await self._delete_from_file(key)
                deleted = deleted or file_deleted
            
            if deleted:
                self.cache_stats["deletes"] += 1
            
            return deleted
            
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            return False
    
    async def clear(self) -> bool:
        """Clear all cache."""
        try:
            # Clear memory cache
            self.memory_cache.clear()
            
            # Clear file cache
            if self.config["enable_persistence"]:
                for cache_file in self.cache_dir.glob("*.cache"):
                    cache_file.unlink()
            
            # Reset stats
            self.cache_stats = {
                "hits": 0,
                "misses": 0,
                "sets": 0,
                "deletes": 0,
                "evictions": 0
            }
            
            return True
            
        except Exception as e:
            logger.error(f"Cache clear error: {e}")
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        value = await self.get(key)
        return value is not None
    
    async def keys(self, pattern: str = "*") -> List[str]:
        """Get all cache keys matching pattern."""
        try:
            keys = []
            
            # Get from memory cache
            for key in self.memory_cache.keys():
                if pattern == "*" or pattern in key:
                    keys.append(key)
            
            # Get from file cache
            if self.config["enable_persistence"]:
                for cache_file in self.cache_dir.glob("*.cache"):
                    key = cache_file.stem
                    if (pattern == "*" or pattern in key) and key not in keys:
                        keys.append(key)
            
            return keys
            
        except Exception as e:
            logger.error(f"Cache keys error: {e}")
            return []
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self.cache_stats["hits"] + self.cache_stats["misses"]
        hit_rate = (self.cache_stats["hits"] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            **self.cache_stats,
            "hit_rate": round(hit_rate, 2),
            "memory_items": len(self.memory_cache),
            "memory_usage_mb": self._get_memory_usage(),
            "file_cache_items": len(list(self.cache_dir.glob("*.cache")))
        }
    
    async def _evict_lru(self):
        """Evict least recently used items."""
        try:
            # Sort by access count and creation time
            sorted_items = sorted(
                self.memory_cache.items(),
                key=lambda x: (x[1]["access_count"], x[1]["created_at"])
            )
            
            # Remove oldest 10% of items
            items_to_remove = max(1, len(sorted_items) // 10)
            
            for i in range(items_to_remove):
                key = sorted_items[i][0]
                del self.memory_cache[key]
                self.cache_stats["evictions"] += 1
                
        except Exception as e:
            logger.error(f"Cache eviction error: {e}")
    
    async def _get_from_file(self, key: str) -> Any:
        """Get value from file cache."""
        try:
            cache_file = self.cache_dir / f"{self._hash_key(key)}.cache"
            
            if not cache_file.exists():
                return None
            
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Check if expired
            if data["expires_at"] > time.time():
                return data["value"]
            else:
                # Remove expired file
                cache_file.unlink()
                return None
                
        except Exception as e:
            logger.error(f"File cache get error for key {key}: {e}")
            return None
    
    async def _set_to_file(self, key: str, value: Any, expires_at: float):
        """Set value to file cache."""
        try:
            cache_file = self.cache_dir / f"{self._hash_key(key)}.cache"
            
            data = {
                "key": key,
                "value": value,
                "expires_at": expires_at,
                "created_at": time.time()
            }
            
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, default=str)
                
        except Exception as e:
            logger.error(f"File cache set error for key {key}: {e}")
    
    async def _delete_from_file(self, key: str) -> bool:
        """Delete value from file cache."""
        try:
            cache_file = self.cache_dir / f"{self._hash_key(key)}.cache"
            
            if cache_file.exists():
                cache_file.unlink()
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"File cache delete error for key {key}: {e}")
            return False
    
    def _hash_key(self, key: str) -> str:
        """Generate hash for cache key."""
        return hashlib.md5(key.encode()).hexdigest()
    
    def _get_size(self, value: Any) -> int:
        """Get approximate size of value."""
        try:
            return len(json.dumps(value, default=str).encode())
        except:
            return 0
    
    def _get_memory_usage(self) -> float:
        """Get approximate memory usage in MB."""
        try:
            total_size = 0
            for item in self.memory_cache.values():
                total_size += self._get_size(item["value"])
            return round(total_size / (1024 * 1024), 2)
        except:
            return 0.0
    
    async def _cleanup_task(self):
        """Background task to clean up expired items."""
        while True:
            try:
                await asyncio.sleep(self.config["cleanup_interval"])
                
                current_time = time.time()
                expired_keys = []
                
                # Find expired memory cache items
                for key, item in self.memory_cache.items():
                    if item["expires_at"] <= current_time:
                        expired_keys.append(key)
                
                # Remove expired items
                for key in expired_keys:
                    del self.memory_cache[key]
                
                # Clean up expired file cache items
                if self.config["enable_persistence"]:
                    for cache_file in self.cache_dir.glob("*.cache"):
                        try:
                            with open(cache_file, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                            
                            if data["expires_at"] <= current_time:
                                cache_file.unlink()
                                
                        except Exception:
                            # Remove corrupted cache files
                            cache_file.unlink()
                
                if expired_keys:
                    logger.info(f"Cleaned up {len(expired_keys)} expired cache items")
                    
            except Exception as e:
                logger.error(f"Cache cleanup error: {e}")

# Global cache manager instance
cache_manager = CacheManager()

# Decorator for caching function results
def cached(ttl: int = 3600, key_prefix: str = ""):
    """Decorator to cache function results."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Generate cache key
            key_parts = [key_prefix or func.__name__]
            key_parts.extend(str(arg) for arg in args)
            key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
            cache_key = ":".join(key_parts)
            
            # Try to get from cache
            cached_result = await cache_manager.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Execute function and cache result
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            
            await cache_manager.set(cache_key, result, ttl)
            return result
        
        return wrapper
    return decorator
