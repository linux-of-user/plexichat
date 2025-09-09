"""
Cache Cluster Manager

Advanced clustering support for distributed caching with automatic
failover, load balancing, and consistency management.
"""

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class CacheNode:
    """Represents a cache node in the cluster."""

    node_id: str
    host: str
    port: int
    weight: float = 1.0
    is_healthy: bool = True
    last_health_check: Optional[datetime] = None
    response_time_ms: float = 0.0
    error_count: int = 0
    total_requests: int = 0


@dataclass
class ClusterMetrics:
    """Cluster-wide cache metrics."""

    total_nodes: int = 0
    healthy_nodes: int = 0
    total_requests: int = 0
    total_hits: int = 0
    total_misses: int = 0
    avg_response_time: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)


class CacheClusterManager:
    """Manages distributed cache cluster with automatic failover."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.nodes: Dict[str, CacheNode] = {}
        self.healthy_nodes: Set[str] = set()
        self.metrics = ClusterMetrics()

        # Configuration
        self.health_check_interval = self.config.get("health_check_interval", 30)
        self.max_retries = self.config.get("max_retries", 3)
        self.timeout_seconds = self.config.get("timeout_seconds", 5)
        self.consistency_level = self.config.get("consistency_level", "eventual")

        # Consistent hashing ring
        self.hash_ring: Dict[int, str] = {}
        self.virtual_nodes = self.config.get("virtual_nodes", 150)

        # Background tasks
        self._health_check_task = None
        self._metrics_task = None
        self._running = False

        logger.info("[LINK] Cache Cluster Manager initialized")

    async def initialize(self, nodes: List[Dict[str, Any]]) -> bool:
        """Initialize cluster with node configurations."""
        try:
            # Add nodes to cluster
            for node_config in nodes:
                await self.add_node(
                    node_config["node_id"],
                    node_config["host"],
                    node_config["port"],
                    node_config.get("weight", 1.0),
                )

            # Build consistent hash ring
            self._build_hash_ring()

            # Start background tasks
            await self.start_monitoring()

            logger.info(
                f"[START] Cache cluster initialized with {len(self.nodes)} nodes"
            )
            return True

        except Exception as e:
            logger.error(f"Cluster initialization failed: {e}")
            return False

    async def add_node(
        self, node_id: str, host: str, port: int, weight: float = 1.0
    ) -> bool:
        """Add a new node to the cluster."""
        try:
            node = CacheNode(node_id=node_id, host=host, port=port, weight=weight)

            # Test node connectivity
            if await self._test_node_health(node):
                self.nodes[node_id] = node
                self.healthy_nodes.add(node_id)
                self._rebuild_hash_ring()

                logger.info(f"[SUCCESS] Added cache node: {node_id} ({host}:{port})")
                return True
            else:
                logger.warning(f"[ERROR] Failed to add unhealthy node: {node_id}")
                return False

        except Exception as e:
            logger.error(f"Error adding node {node_id}: {e}")
            return False

    async def remove_node(self, node_id: str) -> bool:
        """Remove a node from the cluster."""
        try:
            if node_id in self.nodes:
                del self.nodes[node_id]
                self.healthy_nodes.discard(node_id)
                self._rebuild_hash_ring()

                logger.info(f"[DELETE] Removed cache node: {node_id}")
                return True
            else:
                logger.warning(f"Node {node_id} not found in cluster")
                return False

        except Exception as e:
            logger.error(f"Error removing node {node_id}: {e}")
            return False

    def get_node_for_key(self, key: str) -> Optional[str]:
        """Get the appropriate node for a given key using consistent hashing."""
        if not self.healthy_nodes:
            return None

        # Calculate hash for the key
        key_hash = int(hashlib.md5(key.encode()).hexdigest(), 16)

        # Find the first node in the ring >= key_hash
        for ring_hash in sorted(self.hash_ring.keys()):
            if ring_hash >= key_hash:
                node_id = self.hash_ring[ring_hash]
                if node_id in self.healthy_nodes:
                    return node_id

        # Wrap around to the first node
        if self.hash_ring:
            first_hash = min(self.hash_ring.keys())
            node_id = self.hash_ring[first_hash]
            if node_id in self.healthy_nodes:
                return node_id

        return None

    def get_replica_nodes(self, key: str, replica_count: int = 2) -> List[str]:
        """Get replica nodes for a key for redundancy."""
        if not self.healthy_nodes or replica_count <= 0:
            return []

        primary_node = self.get_node_for_key(key)
        if not primary_node:
            return []

        replicas = [primary_node]
        key_hash = int(hashlib.md5(key.encode()).hexdigest(), 16)

        # Find next nodes in the ring
        sorted_hashes = sorted(self.hash_ring.keys())
        primary_index = None

        for i, ring_hash in enumerate(sorted_hashes):
            if ring_hash >= key_hash:
                primary_index = i
                break

        if primary_index is None:
            primary_index = 0

        # Add replica nodes
        for i in range(1, replica_count):
            replica_index = (primary_index + i) % len(sorted_hashes)
            replica_hash = sorted_hashes[replica_index]
            replica_node = self.hash_ring[replica_hash]

            if replica_node in self.healthy_nodes and replica_node not in replicas:
                replicas.append(replica_node)

        return replicas[:replica_count]

    async def start_monitoring(self):
        """Start background monitoring tasks."""
        if self._running:
            return

        self._running = True
        self._health_check_task = asyncio.create_task(self._health_check_loop())
        self._metrics_task = asyncio.create_task(self._metrics_collection_loop())

        logger.info("[METRICS] Cache cluster monitoring started")

    async def stop_monitoring(self):
        """Stop background monitoring tasks."""
        self._running = False

        if self._health_check_task:
            self._health_check_task.cancel()
        if self._metrics_task:
            self._metrics_task.cancel()

        logger.info("[STOP] Cache cluster monitoring stopped")

    async def _health_check_loop(self):
        """Background health check loop."""
        while self._running:
            try:
                await self._check_all_nodes_health()
                await asyncio.sleep(self.health_check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check loop error: {e}")
                await asyncio.sleep(5)

    async def _check_all_nodes_health(self):
        """Check health of all nodes."""
        tasks = []
        for node_id, node in self.nodes.items():
            task = asyncio.create_task(self._check_node_health(node_id, node))
            tasks.append(task)

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_node_health(self, node_id: str, node: CacheNode):
        """Check health of a specific node."""
        try:
            start_time = time.time()
            is_healthy = await self._test_node_health(node)
            response_time = (time.time() - start_time) * 1000

            node.last_health_check = datetime.now()
            node.response_time_ms = response_time

            if is_healthy:
                if not node.is_healthy:
                    logger.info(f"[SUCCESS] Node {node_id} is back online")
                    node.error_count = 0

                node.is_healthy = True
                self.healthy_nodes.add(node_id)
            else:
                node.error_count += 1

                if node.is_healthy:
                    logger.warning(f"[ERROR] Node {node_id} is unhealthy")

                node.is_healthy = False
                self.healthy_nodes.discard(node_id)

                # Rebuild hash ring if node status changed
                self._rebuild_hash_ring()

        except Exception as e:
            logger.error(f"Health check error for node {node_id}: {e}")
            node.is_healthy = False
            self.healthy_nodes.discard(node_id)

    async def _test_node_health(self, node: CacheNode) -> bool:
        """Test if a node is healthy."""
        try:
            # This would implement actual health check
            # For now, simulate a health check
            await asyncio.sleep(0.01)  # Simulate network delay
            return True

        except Exception as e:
            logger.error(f"Node health test failed for {node.node_id}: {e}")
            return False

    def _build_hash_ring(self):
        """Build consistent hash ring."""
        self.hash_ring.clear()

        for node_id, node in self.nodes.items():
            # Create virtual nodes for better distribution
            for i in range(int(self.virtual_nodes * node.weight)):
                virtual_key = f"{node_id}:{i}"
                hash_value = int(hashlib.md5(virtual_key.encode()).hexdigest(), 16)
                self.hash_ring[hash_value] = node_id

        logger.debug(f"Built hash ring with {len(self.hash_ring)} virtual nodes")

    def _rebuild_hash_ring(self):
        """Rebuild hash ring when nodes change."""
        self._build_hash_ring()
        logger.debug("Hash ring rebuilt due to node changes")

    async def _metrics_collection_loop(self):
        """Background metrics collection loop."""
        while self._running:
            try:
                await self._collect_cluster_metrics()
                await asyncio.sleep(60)  # Collect every minute

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Metrics collection error: {e}")
                await asyncio.sleep(30)

    async def _collect_cluster_metrics(self):
        """Collect cluster-wide metrics."""
        try:
            self.metrics.total_nodes = len(self.nodes)
            self.metrics.healthy_nodes = len(self.healthy_nodes)

            # Calculate average response time
            if self.nodes:
                total_response_time = sum(
                    node.response_time_ms for node in self.nodes.values()
                )
                self.metrics.avg_response_time = total_response_time / len(self.nodes)

            self.metrics.last_updated = datetime.now()

        except Exception as e:
            logger.error(f"Error collecting cluster metrics: {e}")

    def get_cluster_status(self) -> Dict[str, Any]:
        """Get comprehensive cluster status."""
        return {
            "cluster_health": {
                "total_nodes": self.metrics.total_nodes,
                "healthy_nodes": self.metrics.healthy_nodes,
                "unhealthy_nodes": self.metrics.total_nodes
                - self.metrics.healthy_nodes,
                "health_percentage": (
                    (self.metrics.healthy_nodes / self.metrics.total_nodes * 100)
                    if self.metrics.total_nodes > 0
                    else 0
                ),
            },
            "performance": {
                "avg_response_time_ms": self.metrics.avg_response_time,
                "total_requests": self.metrics.total_requests,
                "hit_rate": (
                    (
                        self.metrics.total_hits
                        / (self.metrics.total_hits + self.metrics.total_misses)
                    )
                    if (self.metrics.total_hits + self.metrics.total_misses) > 0
                    else 0
                ),
            },
            "nodes": {
                node_id: {
                    "host": node.host,
                    "port": node.port,
                    "is_healthy": node.is_healthy,
                    "response_time_ms": node.response_time_ms,
                    "error_count": node.error_count,
                    "last_health_check": (
                        node.last_health_check.isoformat()
                        if node.last_health_check
                        else None
                    ),
                }
                for node_id, node in self.nodes.items()
            },
            "hash_ring": {
                "virtual_nodes": len(self.hash_ring),
                "distribution": self._get_hash_ring_distribution(),
            },
        }

    def _get_hash_ring_distribution(self) -> Dict[str, int]:
        """Get distribution of keys across nodes in hash ring."""
        distribution = {}
        for node_id in self.hash_ring.values():
            distribution[node_id] = distribution.get(node_id, 0) + 1
        return distribution


# Global cluster manager instance
cache_cluster_manager = CacheClusterManager()
