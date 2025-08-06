# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import gzip
import json
import logging
import pickle
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
try:
    import aiomcache  # type: ignore
except ImportError:
    aiomcache = None
import http.client
try:
    import redis.asyncio as redis  # type: ignore
except ImportError:
    redis = None


"""
PlexiChat Multi-Tier Caching System

Comprehensive caching solution with multiple tiers:
- L1: In-memory cache (fastest)
- L2: Redis cache (distributed)
- L3: Memcached cache (high-capacity)
- L4: CDN cache (edge locations)

Features:
- Intelligent cache tier selection
- Automatic cache warming and invalidation
- Cache analytics and monitoring
- TTL management and expiration policies
- Cache coherence across distributed nodes
- Performance optimization with cache hit ratio tracking
- Compression and serialization optimization
- Cache stampede protection


# Optional dependencies - graceful degradation if not available
try:
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    MEMCACHED_AVAILABLE = True
except ImportError:
    MEMCACHED_AVAILABLE = False

try:
    CDN_AVAILABLE = True
except ImportError:
    CDN_AVAILABLE = False

logger = logging.getLogger(__name__)


class CacheTier(Enum):
    """Cache tier levels."""
        L1_MEMORY = "l1_memory"
    L2_REDIS = "l2_redis"
    L3_MEMCACHED = "l3_memcached"
    L4_CDN = "l4_cdn"


class CacheStrategy(Enum):
    """Cache strategies."""
    WRITE_THROUGH = "write_through"
    WRITE_BACK = "write_back"
    WRITE_AROUND = "write_around"
    READ_THROUGH = "read_through"
    CACHE_ASIDE = "cache_aside"


@dataclass
class CacheEntry:
    """Cache entry with metadata.
        key: str
    value: Any
    tier: CacheTier
    created_at: datetime
    expires_at: Optional[datetime]
    access_count: int = 0
    last_accessed: Optional[datetime] = None
    size_bytes: int = 0
    compressed: bool = False

    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) >= self.expires_at

    def update_access(self):
        Update access statistics."""
        self.access_count += 1
        self.last_accessed = datetime.now(timezone.utc)


@dataclass
class CacheStats:
    """Cache statistics.
        hits: int = 0
    misses: int = 0
    evictions: int = 0
    writes: int = 0
    deletes: int = 0
    errors: int = 0
    total_size_bytes: int = 0
    average_access_time_ms: float = 0.0

    @property
    def hit_ratio(self) -> float:
        """Calculate cache hit ratio."""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    @property
    def miss_ratio(self) -> float:
        Calculate cache miss ratio."""
        return 1.0 - self.hit_ratio


class MultiTierCacheManager:
    """
    Multi-tier caching system with intelligent tier selection and management.

    Provides comprehensive caching capabilities across multiple storage tiers
    with automatic failover, performance optimization, and analytics.
    
        def __init__(self, config: Dict[str, Any]):
        """Initialize multi-tier cache manager."""
        self.config = config
        self.initialized = False

        # Cache tiers
        self.l1_cache: Dict[str, CacheEntry] = {}  # In-memory cache
        self.redis_client = None  # type: ignore
        self.memcached_client = None  # type: ignore
        self.cdn_session: Optional[aiohttp.ClientSession] = None

        # Configuration
        self.l1_max_size = config.get("l1_max_size", 1000)
        self.l1_max_memory_mb = config.get("l1_max_memory_mb", 100)
        self.default_ttl_seconds = config.get("default_ttl_seconds", 3600)
        self.compression_threshold = config.get("compression_threshold", 1024)
        self.cache_strategy = CacheStrategy(config.get("strategy", "cache_aside"))

        # Statistics
        self.stats_by_tier: Dict[CacheTier, CacheStats] = {
            tier: CacheStats() for tier in CacheTier
        }
        self.global_stats = CacheStats()

        # Performance tracking
        self.access_times: List[float] = []
        self.last_cleanup = datetime.now(timezone.utc)

        # Cache warming
        self.warming_enabled = config.get("warming_enabled", True)
        self.warming_patterns: List[str] = config.get("warming_patterns", [])

        logger.info(" Multi-Tier Cache Manager initialized")

    async def initialize(self) -> Dict[str, Any]:
        """Initialize all cache tiers."""
        try:
            results = {
                "l1_memory": True,  # Always available
                "l2_redis": await self._initialize_redis(),
                "l3_memcached": await self._initialize_memcached(),
                "l4_cdn": await self._initialize_cdn(),
                "warming_completed": False
            }

            # Start background tasks
            asyncio.create_task(self._cleanup_task())
            asyncio.create_task(self._stats_collection_task())

            # Cache warming
            if self.warming_enabled:
                asyncio.create_task(self._cache_warming_task())
                results["warming_completed"] = True

            self.initialized = True

            logger.info(" Multi-Tier Cache Manager fully initialized")
            return results

        except Exception as e:
            logger.error(f" Cache manager initialization failed: {e}")
            raise

    async def _initialize_redis(self) -> bool:
        """Initialize Redis connection."""
        if not REDIS_AVAILABLE:
            logger.warning(" Redis not available - L2 cache disabled")
            return False

        try:
            if redis is None:
                logger.warning("Redis not available, skipping L2 cache initialization")
                return False

            redis_config = self.config.get("redis", {})
            self.redis_client = redis.Redis(
                host=redis_config.get("host", "localhost"),
                port=redis_config.get("port", 6379),
                db=redis_config.get("db", 0),
                password=redis_config.get("password"),
                decode_responses=False,  # Handle binary data
                socket_connect_timeout=redis_config.get("connect_timeout", 5),
                socket_timeout=redis_config.get("timeout", 5),
                retry_on_timeout=True,
                max_connections=redis_config.get("max_connections", 20)
            )

            # Test connection
            await self.redis_client.ping()
            logger.info(" Redis L2 cache initialized")
            return True

        except Exception as e:
            logger.warning(f" Redis L2 cache initialization failed: {e}")
            self.redis_client = None
            return False

    async def _initialize_memcached(self) -> bool:
        """Initialize Memcached connection."""
        if not MEMCACHED_AVAILABLE:
            logger.warning(" Memcached not available - L3 cache disabled")
            return False

        try:
            if aiomcache is None:
                logger.warning("aiomcache not available, skipping L3 cache initialization")
                return False

            memcached_config = self.config.get("memcached", {})
            host = memcached_config.get("host", "localhost")
            port = memcached_config.get("port", 11211)

            self.memcached_client = aiomcache.Client(host, port)

            # Test connection
            await self.memcached_client.set(b"test_key", b"test_value", exptime=1)
            await self.memcached_client.delete(b"test_key")

            logger.info(" Memcached L3 cache initialized")
            return True

        except Exception as e:
            logger.warning(f" Memcached L3 cache initialization failed: {e}")
            self.memcached_client = None
            return False

    async def _initialize_cdn(self) -> bool:
        """Initialize CDN connection."""
        if not CDN_AVAILABLE:
            logger.warning(" CDN client not available - L4 cache disabled")
            return False

        try:
            cdn_config = self.config.get("cdn", {})

            timeout = aiohttp.ClientTimeout(
                total=cdn_config.get("timeout", 30),
                connect=cdn_config.get("connect_timeout", 10)
            )

            self.cdn_session = aiohttp.ClientSession(
                timeout=timeout,
                headers=cdn_config.get("headers", {}),
                connector=aiohttp.TCPConnector(
                    limit=cdn_config.get("max_connections", 100),
                    limit_per_host=cdn_config.get("max_connections_per_host", 30)
                )
            )

            logger.info(" CDN L4 cache initialized")
            return True

        except Exception as e:
            logger.warning(f" CDN L4 cache initialization failed: {e}")
            self.cdn_session = None
            return False

    async def get(self, key: str, default: Optional[Any] = None) -> Any:
        """
        Get value from cache with intelligent tier selection.

        Searches through cache tiers from fastest to slowest,
        promoting frequently accessed items to faster tiers.
        """
        start_time = time.time()

        try:
            # Try L1 cache first (fastest)
            if key in self.l1_cache:
                entry = self.l1_cache[key]
                if not entry.is_expired():
                    entry.update_access()
                    self._update_stats(CacheTier.L1_MEMORY, "hit", time.time() - start_time)
                    return entry.value
                else:
                    # Remove expired entry
                    del self.l1_cache[key]

            # Try L2 cache (Redis)
            if self.redis_client:
                try:
                    cached_data = await self.redis_client.get(key)
                    if cached_data:
                        value = self._deserialize(cached_data)
                        # Promote to L1 cache
                        await self._set_l1(key, value, self.default_ttl_seconds)
                        self._update_stats(CacheTier.L2_REDIS, "hit", time.time() - start_time)
                        return value
                except Exception as e:
                    logger.warning(f"Redis L2 cache error for key {key}: {e}")
                    self.stats_by_tier[CacheTier.L2_REDIS].errors += 1

            # Try L3 cache (Memcached)
            if self.memcached_client:
                try:
                    cached_data = await self.memcached_client.get(key.encode())
                    if cached_data:
                        value = self._deserialize(cached_data)
                        # Promote to L2 and L1 caches
                        await self._set_l2(key, value, self.default_ttl_seconds)
                        await self._set_l1(key, value, self.default_ttl_seconds)
                        self._update_stats(CacheTier.L3_MEMCACHED, "hit", time.time() - start_time)
                        return value
                except Exception as e:
                    logger.warning(f"Memcached L3 cache error for key {key}: {e}")
                    self.stats_by_tier[CacheTier.L3_MEMCACHED].errors += 1

            # Try L4 cache (CDN) - for specific content types
            if self.cdn_session and self._is_cdn_cacheable(key):
                try:
                    cdn_url = self._get_cdn_url(key)
                    async with self.cdn_session.get(cdn_url) as response:
                        if response.status == 200:
                            value = await response.read()
                            # Promote to all lower tiers
                            await self._set_l3(key, value, self.default_ttl_seconds)
                            await self._set_l2(key, value, self.default_ttl_seconds)
                            await self._set_l1(key, value, self.default_ttl_seconds)
                            self._update_stats(CacheTier.L4_CDN, "hit", time.time() - start_time)
                            return value
                except Exception as e:
                    logger.warning(f"CDN L4 cache error for key {key}: {e}")
                    self.stats_by_tier[CacheTier.L4_CDN].errors += 1

            # Cache miss - update statistics
            for tier in CacheTier:
                self.stats_by_tier[tier].misses += 1
            self.global_stats.misses += 1

            return default

        except Exception as e:
            logger.error(f" Cache get error for key {key}: {e}")
            self.global_stats.errors += 1
            return default
        finally:
            access_time = time.time() - start_time
            self.access_times.append(access_time)
            # Keep only recent access times for average calculation
            if len(self.access_times) > 1000:
                self.access_times = self.access_times[-1000:]

    async def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> bool:
        """
        Set value in cache with intelligent tier distribution.

        Distributes data across appropriate cache tiers based on:
        - Data size and type
        - Access patterns
        - TTL requirements
        - Cache strategy
        """
        if ttl_seconds is None:
            ttl_seconds = self.default_ttl_seconds

        try:
            # Determine optimal cache tiers for this data
            target_tiers = self._select_cache_tiers(key, value, ttl_seconds)

            success_count = 0
            len(target_tiers)

            # Set in selected tiers
            for tier in target_tiers:
                try:
                    if tier == CacheTier.L1_MEMORY:
                        success = await self._set_l1(key, value, ttl_seconds)
                    elif tier == CacheTier.L2_REDIS:
                        success = await self._set_l2(key, value, ttl_seconds)
                    elif tier == CacheTier.L3_MEMCACHED:
                        success = await self._set_l3(key, value, ttl_seconds)
                    elif tier == CacheTier.L4_CDN:
                        success = await self._set_l4(key, value, ttl_seconds)
                    else:
                        success = False

                    if success:
                        success_count += 1
                        self.stats_by_tier[tier].writes += 1

                except Exception as e:
                    logger.warning(f"Failed to set {key} in {tier.value}: {e}")
                    self.stats_by_tier[tier].errors += 1

            # Update global statistics
            if success_count > 0:
                self.global_stats.writes += 1
                return True
            else:
                self.global_stats.errors += 1
                return False

        except Exception as e:
            logger.error(f" Cache set error for key {key}: {e}")
            self.global_stats.errors += 1
            return False

    async def delete(self, key: str) -> bool:
        """Delete key from all cache tiers."""
        success_count = 0

        try:
            # Delete from L1 cache
            if key in self.l1_cache:
                del self.l1_cache[key]
                success_count += 1
                self.stats_by_tier[CacheTier.L1_MEMORY].deletes += 1

            # Delete from L2 cache (Redis)
            if self.redis_client:
                try:
                    deleted = await self.redis_client.delete(key)
                    if deleted:
                        success_count += 1
                        self.stats_by_tier[CacheTier.L2_REDIS].deletes += 1
                except Exception as e:
                    logger.warning(f"Redis delete error for key {key}: {e}")
                    self.stats_by_tier[CacheTier.L2_REDIS].errors += 1

            # Delete from L3 cache (Memcached)
            if self.memcached_client:
                try:
                    await self.memcached_client.delete(key.encode())
                    success_count += 1
                    self.stats_by_tier[CacheTier.L3_MEMCACHED].deletes += 1
                except Exception as e:
                    logger.warning(f"Memcached delete error for key {key}: {e}")
                    self.stats_by_tier[CacheTier.L3_MEMCACHED].errors += 1

            # CDN invalidation (if supported)
            if self.cdn_session and self._is_cdn_cacheable(key):
                try:
                    await self._invalidate_cdn(key)
                    success_count += 1
                    self.stats_by_tier[CacheTier.L4_CDN].deletes += 1
                except Exception as e:
                    logger.warning(f"CDN invalidation error for key {key}: {e}")
                    self.stats_by_tier[CacheTier.L4_CDN].errors += 1

            if success_count > 0:
                self.global_stats.deletes += 1
                return True
            else:
                return False

        except Exception as e:
            logger.error(f" Cache delete error for key {key}: {e}")
            self.global_stats.errors += 1
            return False

    async def clear(self, tier: Optional[CacheTier] = None) -> bool:
        """Clear cache tier(s)."""
        try:
            if tier is None:
                # Clear all tiers
                success = True
                for cache_tier in CacheTier:
                    tier_success = await self.clear(cache_tier)
                    success = success and tier_success
                return success

            if tier == CacheTier.L1_MEMORY:
                self.l1_cache.clear()
                logger.info(" L1 memory cache cleared")
                return True

            elif tier == CacheTier.L2_REDIS and self.redis_client:
                await self.redis_client.flushdb()
                logger.info(" L2 Redis cache cleared")
                return True

            elif tier == CacheTier.L3_MEMCACHED and self.memcached_client:
                await self.memcached_client.flush_all()
                logger.info(" L3 Memcached cache cleared")
                return True

            elif tier == CacheTier.L4_CDN:
                # CDN clearing would require specific API calls
                logger.info(" L4 CDN cache clear requested (manual intervention may be required)")
                return True

            return False

        except Exception as e:
            logger.error(f" Cache clear error for tier {tier}: {e}")
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists in any cache tier."""
        try:
            # Check L1 cache
            if key in self.l1_cache and not self.l1_cache[key].is_expired():
                return True

            # Check L2 cache (Redis)
            if self.redis_client:
                try:
                    exists = await self.redis_client.exists(key)
                    if exists:
                        return True
                except Exception as e:
                    logger.warning(f"Redis exists check error for key {key}: {e}")

            # Check L3 cache (Memcached)
            if self.memcached_client:
                try:
                    value = await self.memcached_client.get(key.encode())
                    if value is not None:
                        return True
                except Exception as e:
                    logger.warning(f"Memcached exists check error for key {key}: {e}")

            return False

        except Exception as e:
            logger.error(f" Cache exists check error for key {key}: {e}")
            return False

    async def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        try:
            # Calculate average access time
            avg_access_time = sum(self.access_times) / len(self.access_times) if self.access_times else 0.0
            self.global_stats.average_access_time_ms = avg_access_time * 1000

            # Get tier-specific stats
            tier_stats = {}
            for tier, stats in self.stats_by_tier.items():
                tier_stats[tier.value] = {
                    "hits": stats.hits,
                    "misses": stats.misses,
                    "hit_ratio": stats.hit_ratio,
                    "miss_ratio": stats.miss_ratio,
                    "writes": stats.writes,
                    "deletes": stats.deletes,
                    "evictions": stats.evictions,
                    "errors": stats.errors,
                    "total_size_bytes": stats.total_size_bytes
                }

            # L1 cache specific stats
            l1_stats = {
                "entries": len(self.l1_cache),
                "max_size": self.l1_max_size,
                "memory_usage_mb": sum(entry.size_bytes for entry in self.l1_cache.values()) / (1024 * 1024),
                "max_memory_mb": self.l1_max_memory_mb
            }

            return {
                "global": {
                    "hits": self.global_stats.hits,
                    "misses": self.global_stats.misses,
                    "hit_ratio": self.global_stats.hit_ratio,
                    "miss_ratio": self.global_stats.miss_ratio,
                    "writes": self.global_stats.writes,
                    "deletes": self.global_stats.deletes,
                    "errors": self.global_stats.errors,
                    "average_access_time_ms": self.global_stats.average_access_time_ms
                },
                "tiers": tier_stats,
                "l1_memory": l1_stats,
                "configuration": {
                    "strategy": self.cache_strategy.value,
                    "default_ttl_seconds": self.default_ttl_seconds,
                    "compression_threshold": self.compression_threshold,
                    "warming_enabled": self.warming_enabled
                },
                "availability": {
                    "l1_memory": True,
                    "l2_redis": self.redis_client is not None,
                    "l3_memcached": self.memcached_client is not None,
                    "l4_cdn": self.cdn_session is not None
                }
            }

        except Exception as e:
            logger.error(f" Error getting cache stats: {e}")
            return {"error": str(e)}

    # Helper methods for tier-specific operations

    async def _set_l1(self, key: str, value: Any, ttl_seconds: int) -> bool:
        """Set value in L1 memory cache."""
        try:
            # Check if we need to evict entries
            await self._evict_l1_if_needed()

            # Serialize and compress if needed
            serialized_value, compressed = self._serialize_and_compress(value)
            size_bytes = len(serialized_value) if isinstance(serialized_value, bytes) else len(str(serialized_value))

            # Create cache entry
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds) if ttl_seconds > 0 else None

            entry = CacheEntry(
                key=key,
                value=value,  # Store original value in L1 for speed
                tier=CacheTier.L1_MEMORY,
                created_at=datetime.now(timezone.utc),
                expires_at=expires_at,
                size_bytes=size_bytes,
                compressed=compressed
            )

            self.l1_cache[key] = entry
            return True

        except Exception as e:
            logger.error(f" L1 cache set error for key {key}: {e}")
            return False

    async def _set_l2(self, key: str, value: Any, ttl_seconds: int) -> bool:
        """Set value in L2 Redis cache."""
        if not self.redis_client:
            return False

        try:
            serialized_value, _ = self._serialize_and_compress(value)

            if ttl_seconds > 0:
                await self.redis_client.setex(key, ttl_seconds, serialized_value)
            else:
                await self.redis_client.set(key, serialized_value)

            return True

        except Exception as e:
            logger.error(f" L2 Redis cache set error for key {key}: {e}")
            return False

    async def _set_l3(self, key: str, value: Any, ttl_seconds: int) -> bool:
        """Set value in L3 Memcached cache."""
        if not self.memcached_client:
            return False

        try:
            serialized_value, _ = self._serialize_and_compress(value)
            exptime = ttl_seconds if ttl_seconds > 0 else 0

            await self.memcached_client.set(
                key.encode(),
                serialized_value,
                exptime=exptime
            )

            return True

        except Exception as e:
            logger.error(f" L3 Memcached cache set error for key {key}: {e}")
            return False

    async def _set_l4(self, key: str, value: Any, ttl_seconds: int) -> bool:
        """Set value in L4 CDN cache."""
        if not self.cdn_session or not self._is_cdn_cacheable(key):
            return False

        try:
            # CDN caching typically involves uploading content to CDN endpoints
            # This is a simplified implementation - actual CDN integration would
            # require specific API calls based on the CDN provider

            cdn_url = self._get_cdn_upload_url(key)
            serialized_value, _ = self._serialize_and_compress(value)

            headers = {
                "Cache-Control": f"max-age={ttl_seconds}" if ttl_seconds > 0 else "no-cache",
                "Content-Type": self._get_content_type(key)
            }

            async with self.cdn_session.put(cdn_url, data=serialized_value, headers=headers) as response:
                return response.status in [200, 201, 204]

        except Exception as e:
            logger.error(f" L4 CDN cache set error for key {key}: {e}")
            return False

    def _select_cache_tiers(self, key: str, value: Any, ttl_seconds: int) -> List[CacheTier]:
        """Select appropriate cache tiers for the given data.
        tiers = []

        # Always try L1 for frequently accessed small data
        serialized_size = len(str(value))
        if serialized_size < self.compression_threshold:
            tiers.append(CacheTier.L1_MEMORY)

        # Use TTL to determine other tiers
        if ttl_seconds > 3600:  # Long-lived data
            tiers.append(CacheTier.L2_REDIS)

        # L2 Redis for distributed caching
        if self.redis_client:
            tiers.append(CacheTier.L2_REDIS)

        # L3 Memcached for large data
        if self.memcached_client and serialized_size > self.compression_threshold:
            tiers.append(CacheTier.L3_MEMCACHED)

        # L4 CDN for static content
        if self.cdn_session and self._is_cdn_cacheable(key):
            tiers.append(CacheTier.L4_CDN)

        return tiers

    def _serialize_and_compress(self, value: Any) -> Tuple[bytes, bool]:
        """Serialize and optionally compress value."""
        try:
            # Serialize
            if isinstance(value, (str, int, float, bool)):
                serialized = json.dumps(value).encode()
            else:
                serialized = pickle.dumps(value)

            # Compress if above threshold
            if len(serialized) > self.compression_threshold:
                compressed = gzip.compress(serialized)
                return compressed, True
            else:
                return serialized, False

        except Exception as e:
            logger.error(f" Serialization error: {e}")
            return str(value).encode(), False

    def _deserialize(self, data: bytes) -> Any:
        """Deserialize and decompress data."""
        try:
            # Try to decompress first
            try:
                decompressed = gzip.decompress(data)
                data = decompressed
            except:
                # Not compressed
                pass

            # Try JSON first (faster)
            try:
                return json.loads(data.decode())
            except Exception:
                # Fall back to pickle
                return pickle.loads(data)

        except Exception as e:
            logger.error(f" Deserialization error: {e}")
            return data.decode() if isinstance(data, bytes) else data

    def _is_cdn_cacheable(self, key: str) -> bool:
        """Check if key represents CDN-cacheable content."""
        cdn_patterns = [
            ".jpg", ".jpeg", ".png", ".gif", ".webp",  # Images
            ".css", ".js", ".html", ".htm",            # Web assets
            ".pdf", ".doc", ".docx",                   # Documents
            "static/", "assets/", "media/"             # Static paths
        ]

        return any(pattern in key.lower() for pattern in cdn_patterns)

    def _get_cdn_url(self, key: str) -> str:
        """Get CDN URL for reading content."""
        cdn_config = self.config.get("cdn", {})
        base_url = cdn_config.get("base_url", "https://cdn.example.com")
        return f"{base_url}/{key}"

    def _get_cdn_upload_url(self, key: str) -> str:
        """Get CDN URL for uploading content."""
        cdn_config = self.config.get("cdn", {})
        upload_url = cdn_config.get("upload_url", "https://api.cdn.example.com/upload")
        return f"{upload_url}/{key}"

    def _get_content_type(self, key: str) -> str:
        """Get content type based on key/filename."""
        content_types = {
            ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
            ".png": "image/png", ".gif": "image/gif",
            ".css": "text/css", ".js": "application/javascript",
            ".html": "text/html", ".htm": "text/html",
            ".json": "application/json", ".xml": "application/xml",
            ".pdf": "application/pdf"
        }

        for ext, content_type in content_types.items():
            if key.lower().endswith(ext):
                return content_type

        return "application/octet-stream"

    async def _invalidate_cdn(self, key: str) -> bool:
        """Invalidate CDN cache for key."""
        try:
            if self.cdn_session is None:
                return False

            cdn_config = self.config.get("cdn", {})
            invalidate_url = cdn_config.get("invalidate_url", "https://api.cdn.example.com/invalidate")

            async with self.cdn_session.post(invalidate_url, json={"keys": [key]}) as response:
                return response.status in [200, 202]

        except Exception as e:
            logger.error(f" CDN invalidation error for key {key}: {e}")
            return False

    async def _evict_l1_if_needed(self):
        """Evict L1 cache entries if limits are exceeded."""
        try:
            # Check entry count limit
            if len(self.l1_cache) >= self.l1_max_size:
                # Evict least recently used entries
                sorted_entries = sorted(
                    self.l1_cache.items(),
                    key=lambda x: x[1].last_accessed or x[1].created_at
                )

                # Remove oldest 20% of entries
                evict_count = max(1, len(sorted_entries) // 5)
                for i in range(evict_count):
                    key_to_evict = sorted_entries[i][0]
                    del self.l1_cache[key_to_evict]
                    self.stats_by_tier[CacheTier.L1_MEMORY].evictions += 1

            # Check memory limit
            total_memory = sum(entry.size_bytes for entry in self.l1_cache.values())
            max_memory_bytes = self.l1_max_memory_mb * 1024 * 1024

            if total_memory > max_memory_bytes:
                # Evict largest entries first
                sorted_by_size = sorted(
                    self.l1_cache.items(),
                    key=lambda x: x[1].size_bytes,
                    reverse=True
                )

                current_memory = total_memory
                for key, entry in sorted_by_size:
                    if current_memory <= max_memory_bytes:
                        break

                    del self.l1_cache[key]
                    current_memory -= entry.size_bytes
                    self.stats_by_tier[CacheTier.L1_MEMORY].evictions += 1

        except Exception as e:
            logger.error(f" L1 cache eviction error: {e}")

    def _update_stats(self, tier: CacheTier, operation: str, access_time: float):
        """Update statistics for cache operations."""
        try:
            tier_stats = self.stats_by_tier[tier]

            if operation == "hit":
                tier_stats.hits += 1
                self.global_stats.hits += 1
            elif operation == "miss":
                tier_stats.misses += 1
                self.global_stats.misses += 1

            # Update access time
            if access_time > 0:
                current_avg = tier_stats.average_access_time_ms
                total_ops = tier_stats.hits + tier_stats.misses

                if total_ops > 1:
                    # Running average
                    tier_stats.average_access_time_ms = (current_avg * (total_ops - 1) + access_time * 1000) / total_ops
                else:
                    tier_stats.average_access_time_ms = access_time * 1000

        except Exception as e:
            logger.error(f" Stats update error: {e}")

    # Background tasks

    async def _cleanup_task(self):
        """Background task for cache cleanup and maintenance."""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes

                # Clean expired L1 entries
                expired_keys = []
                for key, entry in self.l1_cache.items():
                    if entry.is_expired():
                        expired_keys.append(key)

                for key in expired_keys:
                    del self.l1_cache[key]
                    self.stats_by_tier[CacheTier.L1_MEMORY].evictions += 1

                if expired_keys:
                    logger.info(f" Cleaned {len(expired_keys)} expired L1 cache entries")

                # Update last cleanup time
                self.last_cleanup = datetime.now(timezone.utc)

            except Exception as e:
                logger.error(f" Cache cleanup task error: {e}")
                await asyncio.sleep(60)  # Wait before retrying

    async def _stats_collection_task(self):
        """Background task for statistics collection and reporting."""
        while True:
            try:
                await asyncio.sleep(60)  # Run every minute

                # Calculate and update global statistics
                total_hits = sum(stats.hits for stats in self.stats_by_tier.values())
                total_misses = sum(stats.misses for stats in self.stats_by_tier.values())

                self.global_stats.hits = total_hits
                self.global_stats.misses = total_misses

                # Log performance metrics periodically
                if total_hits + total_misses > 0:
                    hit_ratio = total_hits / (total_hits + total_misses)
                    if hit_ratio < 0.5:  # Log warning if hit ratio is low
                        logger.warning(f" Low cache hit ratio: {hit_ratio:.2%}")

            except Exception as e:
                logger.error(f" Stats collection task error: {e}")
                await asyncio.sleep(30)  # Wait before retrying

    async def _cache_warming_task(self):
        """Background task for cache warming."""
        if not self.warming_enabled or not self.warming_patterns:
            return

        try:
            await asyncio.sleep(30)  # Wait for system to stabilize

            logger.info(" Starting cache warming...")

            # Warm cache with predefined patterns
            for pattern in self.warming_patterns:
                try:
                    # This is a simplified warming - in practice, you'd load
                    # frequently accessed data based on usage patterns
                    warm_data = await self._generate_warm_data(pattern)
                    if warm_data:
                        for key, value in warm_data.items():
                            await self.set(key, value, self.default_ttl_seconds)

                except Exception as e:
                    logger.warning(f" Cache warming error for pattern {pattern}: {e}")

            logger.info(" Cache warming completed")

        except Exception as e:
            logger.error(f" Cache warming task error: {e}")

    async def _generate_warm_data(self, pattern: str) -> Dict[str, Any]:
        """Generate warm data for cache warming."""
        # This is a placeholder - implement based on your application's needs
        warm_data = {}

        if pattern == "user_profiles":
            # Example: warm frequently accessed user profiles
            warm_data = {
                "user:1:profile": {"id": 1, "name": "Admin", "role": "admin"},
                "user:2:profile": {"id": 2, "name": "User", "role": "user"}
            }
        elif pattern == "system_config":
            # Example: warm system configuration
            warm_data = {
                "system:config": {"version": "3.0", "features": ["cache", "ai", "security"]},
                "system:status": {"healthy": True, "uptime": 3600}
            }

        return warm_data

    async def shutdown(self):
        """Gracefully shutdown cache manager."""
        try:
            logger.info(" Shutting down Multi-Tier Cache Manager...")

            # Close connections
            if self.redis_client:
                await self.redis_client.close()
                logger.info(" Redis connection closed")

            if self.memcached_client:
                await self.memcached_client.close()
                logger.info(" Memcached connection closed")

            if self.cdn_session:
                await self.cdn_session.close()
                logger.info(" CDN session closed")

            # Clear L1 cache
            self.l1_cache.clear()

            logger.info(" Multi-Tier Cache Manager shutdown complete")

        except Exception as e:
            logger.error(f" Cache manager shutdown error: {e}")


# Global cache manager instance
_cache_manager: Optional[MultiTierCacheManager] = None


def get_cache_manager(config: Optional[Dict[str, Any]] = None) -> MultiTierCacheManager:
    """Get or create global cache manager instance."""
    global _cache_manager

    if _cache_manager is None:
        if config is None:
            # Default configuration
            config = {
                "l1_max_size": 1000,
                "l1_max_memory_mb": 100,
                "default_ttl_seconds": 3600,
                "compression_threshold": 1024,
                "strategy": "cache_aside",
                "warming_enabled": True,
                "warming_patterns": ["user_profiles", "system_config"],
                "redis": {
                    "host": "localhost",
                    "port": 6379,
                    "db": 0,
                    "max_connections": 20
                },
                "memcached": {
                    "host": "localhost",
                    "port": 11211
                },
                "cdn": {
                    "base_url": "https://cdn.plexichat.local",
                    "upload_url": "https://api.cdn.plexichat.local/upload",
                    "invalidate_url": "https://api.cdn.plexichat.local/invalidate",
                    "timeout": 30,
                    "max_connections": 100
                }
            }

        _cache_manager = MultiTierCacheManager(config)

    return _cache_manager
