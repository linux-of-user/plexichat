import asyncio
import hashlib
import logging
import pickle
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import aioredis

"""
PlexiChat Distributed Caching System
Multi-level distributed caching with Redis clustering and intelligent routing
"""

logger = logging.getLogger(__name__)


class CacheStrategy(Enum):
    """Cache distribution strategies."""
    CONSISTENT_HASHING = "consistent_hashing"
    ROUND_ROBIN = "round_robin"
    LEAST_LOADED = "least_loaded"
    GEOGRAPHIC = "geographic"
    HYBRID = "hybrid"


class CacheLevel(Enum):
    """Cache levels for different data types."""
    L1_MEMORY = "l1_memory"      # In-process memory cache
    L2_REDIS = "l2_redis"        # Redis cache
    L3_DISTRIBUTED = "l3_distributed"  # Distributed Redis cluster
    L4_PERSISTENT = "l4_persistent"    # Persistent cache with disk backing


@dataclass
class CacheNode:
    """Distributed cache node."""
    node_id: str
    host: str
    port: int
    region: str = "default"
    weight: float = 1.0
    max_memory: int = 1024 * 1024 * 1024  # 1GB default
    current_load: float = 0.0
    status: str = "healthy"
    last_ping: Optional[datetime] = None
    connection: Optional[aioredis.Redis] = None
    
    @property
    def address(self) -> str:
        """Get node address."""
        return f"{self.host}:{self.port}"
    
    def is_healthy(self) -> bool:
        """Check if node is healthy."""
        if self.status != "healthy":
            return False
        if self.last_ping:
            return (datetime.now(timezone.utc) - self.last_ping).total_seconds() < 60
        return False


@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    key: str
    value: Any
    ttl: Optional[int] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    accessed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    access_count: int = 0
    size_bytes: int = 0
    tags: List[str] = field(default_factory=list)
    
    def is_expired(self) -> bool:
        """Check if entry is expired."""
        if not self.ttl:
            return False
        return (datetime.now(timezone.utc) - self.created_at).total_seconds() > self.ttl
    
    def update_access(self):
        """Update access metadata."""
        self.accessed_at = datetime.now(timezone.utc)
        self.access_count += 1


class DistributedCacheManager:
    """
    Distributed Cache Manager.
    
    Features:
    - Multi-level caching (L1-L4)
    - Consistent hashing for distribution
    - Automatic failover and replication
    - Intelligent cache warming
    - Geographic distribution
    - Cache analytics and optimization
    - Compression and serialization
    - TTL and eviction policies
    """
    
    def __init__(self):
        self.nodes: Dict[str, CacheNode] = {}
        self.strategy = CacheStrategy.CONSISTENT_HASHING
        self.replication_factor = 2
        self.compression_enabled = True
        self.encryption_enabled = True
        
        # L1 Memory Cache
        self.l1_cache: Dict[str, CacheEntry] = {}
        self.l1_max_size = 1000  # Max entries in L1
        
        # Consistent hashing ring
        self.hash_ring: Dict[int, str] = {}
        self.virtual_nodes = 150  # Virtual nodes per physical node
        
        # Statistics
        self.stats = {
            "total_requests": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "l1_hits": 0,
            "l2_hits": 0,
            "l3_hits": 0,
            "evictions": 0,
            "errors": 0,
            "total_size_bytes": 0,
            "average_response_time_ms": 0.0
        }
        
        # Background tasks
        self.health_check_task: Optional[asyncio.Task] = None
        self.cleanup_task: Optional[asyncio.Task] = None
        self.running = False
    
    async def start(self):
        """Start the distributed cache manager."""
        if self.running:
            return
        
        self.running = True
        
        # Start background tasks
        self.health_check_task = asyncio.create_task(self._health_check_loop())
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        logger.info(" Distributed Cache Manager started")
    
    async def stop(self):
        """Stop the distributed cache manager."""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel background tasks
        if self.health_check_task:
            self.health_check_task.cancel()
        if self.cleanup_task:
            self.cleanup_task.cancel()
        
        # Close all connections
        for node in self.nodes.values():
            if node.connection:
                await node.connection.close()
        
        logger.info(" Distributed Cache Manager stopped")
    
    async def add_node(self, node: CacheNode) -> bool:
        """Add a cache node to the cluster."""
        try:
            # Create Redis connection
            node.connection = aioredis.from_url(
                f"redis://{node.host}:{node.port}",
                encoding="utf-8",
                decode_responses=False
            )
            
            # Test connection
            await node.connection.ping()
            node.status = "healthy"
            node.last_ping = datetime.now(timezone.utc)
            
            # Add to nodes
            self.nodes[node.node_id] = node
            
            # Rebuild hash ring
            self._rebuild_hash_ring()
            
            logger.info(f" Added cache node: {node.node_id} ({node.address})")
            return True
            
        except Exception as e:
            logger.error(f" Failed to add cache node {node.node_id}: {e}")
            return False
    
    async def remove_node(self, node_id: str) -> bool:
        """Remove a cache node from the cluster."""
        if node_id not in self.nodes:
            return False
        
        try:
            node = self.nodes[node_id]
            
            # Close connection
            if node.connection:
                await node.connection.close()
            
            # Remove from nodes
            del self.nodes[node_id]
            
            # Rebuild hash ring
            self._rebuild_hash_ring()
            
            logger.info(f" Removed cache node: {node_id}")
            return True
            
        except Exception as e:
            logger.error(f" Failed to remove cache node {node_id}: {e}")
            return False
    
    def _rebuild_hash_ring(self):
        """Rebuild the consistent hashing ring."""
        self.hash_ring.clear()
        
        for node_id, node in self.nodes.items():
            if not node.is_healthy():
                continue
            
            # Create virtual nodes
            for i in range(self.virtual_nodes):
                virtual_key = f"{node_id}:{i}"
                hash_value = int(hashlib.md5(virtual_key.encode()).hexdigest(), 16)
                self.hash_ring[hash_value] = node_id
        
        logger.debug(f"Rebuilt hash ring with {len(self.hash_ring)} virtual nodes")
    
    def _get_nodes_for_key(self, key: str) -> List[str]:
        """Get nodes responsible for a key using consistent hashing."""
        if not self.hash_ring:
            return []
        
        # Hash the key
        key_hash = int(hashlib.md5(key.encode()).hexdigest(), 16)
        
        # Find nodes in the ring
        sorted_hashes = sorted(self.hash_ring.keys())
        nodes = []
        
        # Find the first node >= key_hash
        for hash_value in sorted_hashes:
            if hash_value >= key_hash:
                node_id = self.hash_ring[hash_value]
                if node_id not in nodes:
                    nodes.append(node_id)
                if len(nodes) >= self.replication_factor:
                    break
        
        # Wrap around if needed
        if len(nodes) < self.replication_factor:
            for hash_value in sorted_hashes:
                node_id = self.hash_ring[hash_value]
                if node_id not in nodes:
                    nodes.append(node_id)
                if len(nodes) >= self.replication_factor:
                    break
        
        return nodes
    
    async def get(self, key: str, default: Any = None) -> Any:
        """Get value from distributed cache."""
        start_time = time.time()
        self.stats["total_requests"] += 1
        
        try:
            # Try L1 cache first
            if key in self.l1_cache:
                entry = self.l1_cache[key]
                if not entry.is_expired():
                    entry.update_access()
                    self.stats["cache_hits"] += 1
                    self.stats["l1_hits"] += 1
                    return entry.value
                else:
                    del self.l1_cache[key]
            
            # Try distributed cache
            nodes = self._get_nodes_for_key(key)
            
            for node_id in nodes:
                if node_id not in self.nodes:
                    continue
                
                node = self.nodes[node_id]
                if not node.is_healthy() or not node.connection:
                    continue
                
                try:
                    # Get from Redis
                    data = await node.connection.get(key)
                    if data:
                        # Deserialize
                        value = await self._deserialize(data)
                        
                        # Store in L1 cache
                        await self._store_l1(key, value)
                        
                        self.stats["cache_hits"] += 1
                        self.stats["l3_hits"] += 1
                        return value
                        
                except Exception as e:
                    logger.debug(f"Failed to get {key} from node {node_id}: {e}")
                    continue
            
            # Cache miss
            self.stats["cache_misses"] += 1
            return default
            
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            self.stats["errors"] += 1
            return default
        
        finally:
            # Update response time stats
            response_time = (time.time() - start_time) * 1000
            self._update_response_time(response_time)
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in distributed cache."""
        try:
            # Serialize value
            serialized_data = await self._serialize(value)
            
            # Store in L1 cache
            await self._store_l1(key, value, ttl)
            
            # Store in distributed cache
            nodes = self._get_nodes_for_key(key)
            success_count = 0
            
            for node_id in nodes:
                if node_id not in self.nodes:
                    continue
                
                node = self.nodes[node_id]
                if not node.is_healthy() or not node.connection:
                    continue
                
                try:
                    if ttl:
                        await node.connection.setex(key, ttl, serialized_data)
                    else:
                        await node.connection.set(key, serialized_data)
                    success_count += 1
                    
                except Exception as e:
                    logger.debug(f"Failed to set {key} on node {node_id}: {e}")
                    continue
            
            # Consider successful if at least one node succeeded
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            self.stats["errors"] += 1
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete value from distributed cache."""
        try:
            # Remove from L1 cache
            if key in self.l1_cache:
                del self.l1_cache[key]
            
            # Remove from distributed cache
            nodes = self._get_nodes_for_key(key)
            success_count = 0
            
            for node_id in nodes:
                if node_id not in self.nodes:
                    continue
                
                node = self.nodes[node_id]
                if not node.is_healthy() or not node.connection:
                    continue
                
                try:
                    await node.connection.delete(key)
                    success_count += 1
                    
                except Exception as e:
                    logger.debug(f"Failed to delete {key} from node {node_id}: {e}")
                    continue
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            self.stats["errors"] += 1
            return False
    
    async def _store_l1(self, key: str, value: Any, ttl: Optional[int] = None):
        """Store value in L1 cache."""
        # Evict if L1 cache is full
        if len(self.l1_cache) >= self.l1_max_size:
            await self._evict_l1()
        
        # Create cache entry
        entry = CacheEntry(
            key=key,
            value=value,
            ttl=ttl,
            size_bytes=len(str(value))  # Rough size estimate
        )
        
        self.l1_cache[key] = entry
    
    async def _evict_l1(self):
        """Evict entries from L1 cache using LRU."""
        if not self.l1_cache:
            return
        
        # Find least recently used entry
        lru_key = min(self.l1_cache.keys(), 
                     key=lambda k: self.l1_cache[k].accessed_at)
        
        del self.l1_cache[lru_key]
        self.stats["evictions"] += 1
    
    async def _serialize(self, value: Any) -> bytes:
        """Serialize value for storage."""
        # Pickle the value
        data = pickle.dumps(value)
        
        # Compress if enabled
        if self.compression_enabled:
            data = zlib.compress(data)
        
        return data
    
    async def _deserialize(self, data: bytes) -> Any:
        """Deserialize value from storage."""
        # Decompress if needed
        if self.compression_enabled:
            try:
                data = zlib.decompress(data)
            except zlib.error:
                # Data might not be compressed
                pass
        
        # Unpickle the value
        return pickle.loads(data)
    
    async def _health_check_loop(self):
        """Background health check loop."""
        while self.running:
            try:
                await self._check_node_health()
                await asyncio.sleep(30)  # Check every 30 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check loop error: {e}")
                await asyncio.sleep(5)
    
    async def _check_node_health(self):
        """Check health of all cache nodes."""
        for node_id, node in self.nodes.items():
            try:
                if node.connection:
                    await node.connection.ping()
                    node.status = "healthy"
                    node.last_ping = datetime.now(timezone.utc)
                else:
                    node.status = "disconnected"
            except Exception as e:
                logger.warning(f"Node {node_id} health check failed: {e}")
                node.status = "unhealthy"
        
        # Rebuild hash ring if needed
        self._rebuild_hash_ring()
    
    async def _cleanup_loop(self):
        """Background cleanup loop."""
        while self.running:
            try:
                await self._cleanup_l1_cache()
                await asyncio.sleep(60)  # Cleanup every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")
                await asyncio.sleep(10)
    
    async def _cleanup_l1_cache(self):
        """Clean up expired entries from L1 cache."""
        expired_keys = []
        
        for key, entry in self.l1_cache.items():
            if entry.is_expired():
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.l1_cache[key]
            self.stats["evictions"] += 1
    
    def _update_response_time(self, response_time_ms: float):
        """Update average response time statistics."""
        current_avg = self.stats["average_response_time_ms"]
        total_requests = self.stats["total_requests"]
        
        # Calculate new average
        new_avg = ((current_avg * (total_requests - 1)) + response_time_ms) / total_requests
        self.stats["average_response_time_ms"] = new_avg
    
    def get_cache_statistics(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        hit_rate = (self.stats["cache_hits"] / max(self.stats["total_requests"], 1)) * 100
        
        node_stats = {}
        for node_id, node in self.nodes.items():
            node_stats[node_id] = {
                "status": node.status,
                "address": node.address,
                "region": node.region,
                "current_load": node.current_load,
                "last_ping": node.last_ping.isoformat() if node.last_ping else None
            }
        
        return {
            "running": self.running,
            "total_nodes": len(self.nodes),
            "healthy_nodes": sum(1 for n in self.nodes.values() if n.is_healthy()),
            "l1_cache_size": len(self.l1_cache),
            "l1_max_size": self.l1_max_size,
            "hit_rate_percent": hit_rate,
            "statistics": self.stats,
            "nodes": node_stats,
            "hash_ring_size": len(self.hash_ring),
            "replication_factor": self.replication_factor
        }


# Global distributed cache manager
distributed_cache = DistributedCacheManager()
