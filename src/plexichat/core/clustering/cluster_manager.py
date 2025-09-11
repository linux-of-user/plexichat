"""
PlexiChat Cluster Manager

Main cluster manager class with async methods for node management, health checking,
and load distribution. Includes support for node discovery, automatic failover,
and cluster-wide configuration synchronization.
"""

import asyncio
import hashlib
import logging
import secrets
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

import numba
from numba import njit
import psutil

from plexichat.infrastructure.utils.compilation import optimizer

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Types of cluster nodes."""

    NETWORKING = "networking"
    ENDPOINT = "endpoint"
    GENERAL = "general"
    CACHE = "cache"
    DATABASE = "database"
    LOAD_BALANCER = "load_balancer"


class NodeStatus(Enum):
    """Node status states."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    STARTING = "starting"
    STOPPING = "stopping"
    FAILED = "failed"
    MAINTENANCE = "maintenance"
    UNKNOWN = "unknown"


class ClusterStatus(Enum):
    """Cluster health status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    FAILED = "failed"
    MAINTENANCE = "maintenance"


@dataclass
class NodeMetrics:
    """Node performance and health metrics."""

    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    network_latency: float = 0.0
    request_rate: float = 0.0
    error_rate: float = 0.0
    uptime_seconds: int = 0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def health_score(self) -> float:
        """Calculate overall health score (0-1, higher is better)."""
        # Weight factors for different metrics
        cpu_score = max(0, 1 - (self.cpu_usage / 100))
        memory_score = max(0, 1 - (self.memory_usage / 100))
        disk_score = max(0, 1 - (self.disk_usage / 100))
        error_score = max(0, 1 - min(self.error_rate, 1.0))
        latency_score = max(0, 1 - min(self.network_latency / 1000, 1.0))

        # Weighted average
        return (
            cpu_score * 0.25
            + memory_score * 0.25
            + disk_score * 0.15
            + error_score * 0.25
            + latency_score * 0.1
        )


@dataclass
class ClusterNode:
    """Represents a node in the cluster."""

    node_id: str
    hostname: str
    ip_address: str
    port: int
    node_type: NodeType = NodeType.GENERAL
    status: NodeStatus = NodeStatus.UNKNOWN
    region: str = "default"
    zone: str = "default"
    weight: float = 1.0
    capabilities: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    metrics: NodeMetrics = field(default_factory=NodeMetrics)
    last_heartbeat: Optional[datetime] = None
    joined_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = "1.0.0"

    @property
    def address(self) -> str:
        """Get node address."""
        return f"{self.ip_address}:{self.port}"

    @property
    def is_healthy(self) -> bool:
        """Check if node is healthy."""
        if self.status not in [NodeStatus.ACTIVE, NodeStatus.STARTING]:
            return False

        if self.last_heartbeat:
            heartbeat_age = (
                datetime.now(timezone.utc) - self.last_heartbeat
            ).total_seconds()
            return (
                heartbeat_age < 60
            )  # Consider unhealthy if no heartbeat for 60 seconds

        return False

    def update_metrics(self, metrics: NodeMetrics) -> None:
        """Update node metrics."""
        self.metrics = metrics
        self.last_heartbeat = datetime.now(timezone.utc)


@dataclass
class ClusterConfiguration:
    """Cluster-wide configuration."""

    cluster_id: str
    cluster_name: str = "PlexiChat Cluster"
    min_nodes: int = 1
    max_nodes: int = 100
    replication_factor: int = 2
    health_check_interval: int = 30
    heartbeat_timeout: int = 60
    auto_scaling_enabled: bool = True
    load_balancing_strategy: str = "round_robin"
    failover_enabled: bool = True
    backup_enabled: bool = True
    encryption_enabled: bool = True
    version: str = "1.0.0"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ClusterManager:
    """
    Main cluster manager for PlexiChat.

    Features:
    - Node discovery and registration
    - Health monitoring and failover
    - Load balancing and distribution
    - Configuration synchronization
    - Auto-scaling and recovery
    - Security integration
    - Performance monitoring
    """

    def __init__(self, config: Optional[ClusterConfiguration] = None):
        """Initialize cluster manager."""
        self.config = config or ClusterConfiguration(
            cluster_id=f"cluster-{secrets.token_hex(8)}"
        )

        # Node management
        self.nodes: Dict[str, ClusterNode] = {}
        self.healthy_nodes: Set[str] = set()
        self.node_discovery_enabled = True

        # Load balancing
        self.load_balancer_index = 0
        self.consistent_hash_ring: Dict[int, str] = {}
        self.virtual_nodes_per_node = 150

        # Background tasks
        self.health_check_task: Optional[asyncio.Task] = None
        self.discovery_task: Optional[asyncio.Task] = None
        self.metrics_task: Optional[asyncio.Task] = None
        self.config_sync_task: Optional[asyncio.Task] = None

        # State management
        self.running = False
        self.local_node_id: Optional[str] = None

        # Statistics
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "nodes_added": 0,
            "nodes_removed": 0,
            "failovers": 0,
            "config_syncs": 0,
            "health_checks": 0,
        }

        # Security integration
        self.security_enabled = True
        self.node_auth_tokens: Dict[str, str] = {}

        logger.info(
            f"Cluster Manager initialized for cluster: {self.config.cluster_id}"
        )

    async def start(self) -> bool:
        """Start the cluster manager."""
        try:
            if self.running:
                logger.warning("Cluster manager is already running")
                return True

            logger.info("Starting cluster manager...")

            # Initialize local node
            await self._initialize_local_node()

            # Start background tasks
            self.running = True
            self.health_check_task = asyncio.create_task(self._health_check_loop())
            self.discovery_task = asyncio.create_task(self._discovery_loop())
            self.metrics_task = asyncio.create_task(self._metrics_collection_loop())
            self.config_sync_task = asyncio.create_task(self._config_sync_loop())

            # Build initial hash ring
            self._rebuild_hash_ring()

            logger.info(
                f"Cluster manager started successfully for cluster: {self.config.cluster_id}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to start cluster manager: {e}")
            await self.stop()
            return False

    async def stop(self) -> bool:
        """Stop the cluster manager."""
        try:
            if not self.running:
                return True

            logger.info("Stopping cluster manager...")
            self.running = False

            # Cancel background tasks
            tasks = [
                self.health_check_task,
                self.discovery_task,
                self.metrics_task,
                self.config_sync_task,
            ]

            for task in tasks:
                if task and not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

            # Gracefully leave cluster
            if self.local_node_id:
                await self._leave_cluster()

            logger.info("Cluster manager stopped successfully")
            return True

        except Exception as e:
            logger.error(f"Error stopping cluster manager: {e}")
            return False

    async def register_node(self, node: ClusterNode) -> bool:
        """Register a new node in the cluster."""
        try:
            # Validate node
            if not await self._validate_node(node):
                logger.warning(f"Node validation failed for {node.node_id}")
                return False

            # Check for duplicate node ID
            if node.node_id in self.nodes:
                logger.warning(f"Node {node.node_id} already exists in cluster")
                return False

            # Add node to cluster
            self.nodes[node.node_id] = node

            # Generate authentication token for node
            if self.security_enabled:
                self.node_auth_tokens[node.node_id] = secrets.token_hex(32)

            # Update statistics
            self.stats["nodes_added"] += 1

            # Rebuild hash ring
            self._rebuild_hash_ring()

            # Sync configuration to new node
            await self._sync_config_to_node(node.node_id)

            logger.info(f"Node {node.node_id} registered successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to register node {node.node_id}: {e}")
            return False

    async def unregister_node(self, node_id: str) -> bool:
        """Unregister a node from the cluster."""
        try:
            if node_id not in self.nodes:
                logger.warning(f"Node {node_id} not found in cluster")
                return False

            # Remove from healthy nodes
            self.healthy_nodes.discard(node_id)

            # Remove authentication token
            self.node_auth_tokens.pop(node_id, None)

            # Remove node
            del self.nodes[node_id]

            # Update statistics
            self.stats["nodes_removed"] += 1

            # Rebuild hash ring
            self._rebuild_hash_ring()

            # Trigger failover if necessary
            await self._handle_node_failure(node_id)

            logger.info(f"Node {node_id} unregistered successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to unregister node {node_id}: {e}")
            return False

    async def get_node(self, node_id: str) -> Optional[ClusterNode]:
        """Get a specific node by ID."""
        return self.nodes.get(node_id)

    async def get_all_nodes(self) -> List[ClusterNode]:
        """Get all nodes in the cluster."""
        return list(self.nodes.values())

    async def get_healthy_nodes(self) -> List[ClusterNode]:
        """Get all healthy nodes in the cluster."""
        return [
            self.nodes[node_id]
            for node_id in self.healthy_nodes
            if node_id in self.nodes
        ]

    async def get_nodes_by_type(self, node_type: NodeType) -> List[ClusterNode]:
        """Get nodes by type."""
        return [node for node in self.nodes.values() if node.node_type == node_type]

    async def get_node_for_request(
        self, request_key: Optional[str] = None
    ) -> Optional[ClusterNode]:
        """Get the best node for handling a request."""
        try:
            healthy_nodes = await self.get_healthy_nodes()

            if not healthy_nodes:
                logger.warning("No healthy nodes available for request")
                return None

            # Use consistent hashing if request key provided
            if request_key and self.config.load_balancing_strategy == "consistent_hash":
                return await self._get_node_by_consistent_hash(request_key)

            # Use round-robin load balancing
            elif self.config.load_balancing_strategy == "round_robin":
                return await self._get_node_by_round_robin()

            # Use least loaded node
            elif self.config.load_balancing_strategy == "least_loaded":
                return await self._get_least_loaded_node()

            # Default to round-robin
            else:
                return await self._get_node_by_round_robin()

        except Exception as e:
            logger.error(f"Error selecting node for request: {e}")
            return None

    async def update_node_metrics(self, node_id: str, metrics: NodeMetrics) -> bool:
        """Update metrics for a specific node."""
        try:
            if node_id not in self.nodes:
                logger.warning(f"Node {node_id} not found for metrics update")
                return False

            node = self.nodes[node_id]
            node.update_metrics(metrics)

            # Update healthy nodes set based on health score
            if node.is_healthy and metrics.health_score > 0.5:
                self.healthy_nodes.add(node_id)
            else:
                self.healthy_nodes.discard(node_id)
                if node.is_healthy:  # Was healthy, now unhealthy
                    await self._handle_node_failure(node_id)

            return True

        except Exception as e:
            logger.error(f"Failed to update metrics for node {node_id}: {e}")
            return False

    async def get_cluster_status(self) -> Dict[str, Any]:
        """Get comprehensive cluster status."""
        try:
            healthy_nodes = len(self.healthy_nodes)
            total_nodes = len(self.nodes)

            # Calculate cluster health
            if total_nodes == 0:
                cluster_health = ClusterStatus.FAILED
            elif healthy_nodes == 0:
                cluster_health = ClusterStatus.CRITICAL
            elif healthy_nodes < self.config.min_nodes:
                cluster_health = ClusterStatus.DEGRADED
            elif healthy_nodes / total_nodes < 0.7:
                cluster_health = ClusterStatus.DEGRADED
            else:
                cluster_health = ClusterStatus.HEALTHY

            # Calculate average metrics
            avg_cpu = 0.0
            avg_memory = 0.0
            avg_disk = 0.0
            avg_latency = 0.0
            total_requests = 0

            if self.nodes:
                avg_cpu = sum(
                    node.metrics.cpu_usage for node in self.nodes.values()
                ) / len(self.nodes)
                avg_memory = sum(
                    node.metrics.memory_usage for node in self.nodes.values()
                ) / len(self.nodes)
                avg_disk = sum(
                    node.metrics.disk_usage for node in self.nodes.values()
                ) / len(self.nodes)
                avg_latency = sum(
                    node.metrics.network_latency for node in self.nodes.values()
                ) / len(self.nodes)
                total_requests = sum(
                    node.metrics.request_rate for node in self.nodes.values()
                )

            return {
                "cluster_id": self.config.cluster_id,
                "cluster_name": self.config.cluster_name,
                "status": cluster_health.value,
                "total_nodes": total_nodes,
                "healthy_nodes": healthy_nodes,
                "unhealthy_nodes": total_nodes - healthy_nodes,
                "min_nodes": self.config.min_nodes,
                "max_nodes": self.config.max_nodes,
                "health_percentage": (healthy_nodes / max(total_nodes, 1)) * 100,
                "load_balancer_status": "active" if healthy_nodes > 0 else "inactive",
                "metrics": {
                    "avg_cpu_usage": avg_cpu,
                    "avg_memory_usage": avg_memory,
                    "avg_disk_usage": avg_disk,
                    "avg_network_latency": avg_latency,
                    "total_request_rate": total_requests,
                    "avg_response_time": avg_latency,
                },
                "statistics": self.stats.copy(),
                "configuration": {
                    "replication_factor": self.config.replication_factor,
                    "auto_scaling_enabled": self.config.auto_scaling_enabled,
                    "failover_enabled": self.config.failover_enabled,
                    "load_balancing_strategy": self.config.load_balancing_strategy,
                },
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"Error getting cluster status: {e}")
            return {
                "cluster_id": self.config.cluster_id,
                "status": "error",
                "error": str(e),
            }

    async def scale_cluster(self, target_nodes: int) -> Dict[str, Any]:
        """Scale cluster to target number of nodes."""
        try:
            current_nodes = len(self.nodes)

            if target_nodes < self.config.min_nodes:
                return {
                    "success": False,
                    "message": f"Target nodes ({target_nodes}) below minimum ({self.config.min_nodes})",
                }

            if target_nodes > self.config.max_nodes:
                return {
                    "success": False,
                    "message": f"Target nodes ({target_nodes}) above maximum ({self.config.max_nodes})",
                }

            operation_id = f"scale-{secrets.token_hex(8)}"

            if target_nodes > current_nodes:
                # Scale up
                nodes_to_add = target_nodes - current_nodes
                logger.info(f"Scaling up cluster by {nodes_to_add} nodes")

                # This would trigger node provisioning in a real implementation
                # For now, we'll just log the operation

            elif target_nodes < current_nodes:
                # Scale down
                nodes_to_remove = current_nodes - target_nodes
                logger.info(f"Scaling down cluster by {nodes_to_remove} nodes")

                # Select nodes to remove (prefer unhealthy nodes first)
                nodes_to_remove_list = await self._select_nodes_for_removal(
                    nodes_to_remove
                )

                # Remove selected nodes
                for node_id in nodes_to_remove_list:
                    await self.unregister_node(node_id)

            return {
                "success": True,
                "operation_id": operation_id,
                "current_nodes": len(self.nodes),
                "target_nodes": target_nodes,
                "estimated_time": "2-5 minutes",
            }

        except Exception as e:
            logger.error(f"Error scaling cluster: {e}")
            return {"success": False, "error": str(e)}

    async def rebalance_cluster(self) -> Dict[str, Any]:
        """Rebalance cluster load distribution."""
        try:
            operation_id = f"rebalance-{secrets.token_hex(8)}"

            # Rebuild hash ring for better distribution
            self._rebuild_hash_ring()

            # Sync configuration to all nodes
            await self._sync_config_to_all_nodes()

            logger.info("Cluster rebalancing completed")

            return {
                "success": True,
                "operation_id": operation_id,
                "message": "Cluster rebalancing completed",
                "estimated_time": "1-2 minutes",
            }

        except Exception as e:
            logger.error(f"Error rebalancing cluster: {e}")
            return {"success": False, "error": str(e)}

    # Private methods

    async def _initialize_local_node(self) -> None:
        """Initialize the local node."""
        try:
            # Get local system information
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)

            # Create local node
            self.local_node_id = f"node-{hostname}-{secrets.token_hex(4)}"

            local_node = ClusterNode(
                node_id=self.local_node_id,
                hostname=hostname,
                ip_address=ip_address,
                port=8000,  # Default port
                node_type=NodeType.GENERAL,
                status=NodeStatus.ACTIVE,
                capabilities={"api", "websocket", "clustering"},
                metadata={"deployment": "local", "environment": "development"},
            )

            # Register local node
            await self.register_node(local_node)

            logger.info(f"Local node initialized: {self.local_node_id}")

        except Exception as e:
            logger.error(f"Failed to initialize local node: {e}")
            raise

    async def _validate_node(self, node: ClusterNode) -> bool:
        """Validate a node before registration."""
        try:
            # Basic validation
            if not node.node_id or not node.hostname or not node.ip_address:
                return False

            # Check if node is reachable (in a real implementation)
            # For now, we'll assume all nodes are valid

            return True

        except Exception as e:
            logger.error(f"Node validation error: {e}")
            return False

    async def _health_check_loop(self) -> None:
        """Background health check loop."""
        while self.running:
            try:
                await self._perform_health_checks()
                await asyncio.sleep(self.config.health_check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check loop error: {e}")
                await asyncio.sleep(5)

    async def _perform_health_checks(self) -> None:
        """Perform health checks on all nodes."""
        try:
            self.stats["health_checks"] += 1

            # Check each node
            for node_id, node in self.nodes.items():
                try:
                    # In a real implementation, this would ping the node
                    # For now, we'll simulate health checks

                    # Check heartbeat timeout
                    if node.last_heartbeat:
                        heartbeat_age = (
                            datetime.now(timezone.utc) - node.last_heartbeat
                        ).total_seconds()

                        if heartbeat_age > self.config.heartbeat_timeout:
                            # Node is unresponsive
                            if node_id in self.healthy_nodes:
                                logger.warning(f"Node {node_id} heartbeat timeout")
                                self.healthy_nodes.discard(node_id)
                                await self._handle_node_failure(node_id)
                        else:
                            # Node is responsive
                            if (
                                node_id not in self.healthy_nodes
                                and node.metrics.health_score > 0.5
                            ):
                                logger.info(f"Node {node_id} is back online")
                                self.healthy_nodes.add(node_id)

                    # Update local node metrics
                    if node_id == self.local_node_id:
                        await self._update_local_node_metrics()

                except Exception as e:
                    logger.error(f"Health check failed for node {node_id}: {e}")

        except Exception as e:
            logger.error(f"Error performing health checks: {e}")

    async def _update_local_node_metrics(self) -> None:
        """Update metrics for the local node."""
        try:
            if not self.local_node_id or self.local_node_id not in self.nodes:
                return

            # Get system metrics
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")

            metrics = NodeMetrics(
                cpu_usage=cpu_usage,
                memory_usage=memory.percent,
                disk_usage=disk.percent,
                network_latency=0.0,  # Local node has no network latency
                request_rate=0.0,  # Would be updated by request handlers
                error_rate=0.0,  # Would be updated by error handlers
                uptime_seconds=int(time.time() - psutil.boot_time()),
            )

            await self.update_node_metrics(self.local_node_id, metrics)

        except Exception as e:
            logger.error(f"Error updating local node metrics: {e}")

    async def _discovery_loop(self) -> None:
        """Background node discovery loop."""
        while self.running:
            try:
                if self.node_discovery_enabled:
                    await self._discover_nodes()
                await asyncio.sleep(60)  # Discovery every minute

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Discovery loop error: {e}")
                await asyncio.sleep(10)

    async def _discover_nodes(self) -> None:
        """Discover new nodes in the network."""
        try:
            # In a real implementation, this would use service discovery
            # mechanisms like DNS, Consul, etcd, or Kubernetes API

            # For now, this is a placeholder
            logger.debug("Node discovery check completed")

        except Exception as e:
            logger.error(f"Node discovery error: {e}")

    async def _metrics_collection_loop(self) -> None:
        """Background metrics collection loop."""
        while self.running:
            try:
                await self._collect_cluster_metrics()
                await asyncio.sleep(30)  # Collect metrics every 30 seconds

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Metrics collection loop error: {e}")
                await asyncio.sleep(10)

    async def _collect_cluster_metrics(self) -> None:
        """Collect cluster-wide metrics."""
        try:
            # This would collect and aggregate metrics from all nodes
            # For now, this is a placeholder
            logger.debug("Cluster metrics collection completed")

        except Exception as e:
            logger.error(f"Metrics collection error: {e}")

    async def _config_sync_loop(self) -> None:
        """Background configuration synchronization loop."""
        while self.running:
            try:
                await self._sync_config_to_all_nodes()
                await asyncio.sleep(300)  # Sync config every 5 minutes

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Config sync loop error: {e}")
                await asyncio.sleep(30)

    async def _sync_config_to_all_nodes(self) -> None:
        """Synchronize configuration to all nodes."""
        try:
            self.stats["config_syncs"] += 1

            for node_id in self.nodes:
                await self._sync_config_to_node(node_id)

        except Exception as e:
            logger.error(f"Config sync error: {e}")

    async def _sync_config_to_node(self, node_id: str) -> None:
        """Synchronize configuration to a specific node."""
        try:
            if node_id not in self.nodes:
                return

            # In a real implementation, this would send configuration
            # updates to the node via API calls

            logger.debug(f"Configuration synced to node {node_id}")

        except Exception as e:
            logger.error(f"Config sync error for node {node_id}: {e}")

    async def _handle_node_failure(self, node_id: str) -> None:
        """Handle node failure and trigger failover if necessary."""
        try:
            if not self.config.failover_enabled:
                return

            logger.warning(f"Handling failure for node {node_id}")

            # Update node status
            if node_id in self.nodes:
                self.nodes[node_id].status = NodeStatus.FAILED

            # Trigger failover procedures
            self.stats["failovers"] += 1

            # Rebuild hash ring to exclude failed node
            self._rebuild_hash_ring()

            # In a real implementation, this would:
            # 1. Redistribute load from failed node
            # 2. Update load balancer configuration
            # 3. Notify monitoring systems
            # 4. Trigger auto-scaling if needed

            logger.info(f"Failover completed for node {node_id}")

        except Exception as e:
            logger.error(f"Error handling node failure {node_id}: {e}")

    @njit
    def _rebuild_hash_ring_internal(self, node_ids_list, virtual_nodes_per_node):
        """Numba-optimized internal hash ring builder."""
        hash_ring = {}
        for node_id_bytes in node_ids_list:
            node_id = node_id_bytes.decode('utf-8')
            for i in range(virtual_nodes_per_node):
                virtual_key = f"{node_id}:{i}".encode('utf-8')
                import hashlib
                m = hashlib.md5()
                m.update(virtual_key)
                hash_value = int(m.hexdigest(), 16)
                hash_ring[hash_value] = node_id
        return hash_ring

    def _rebuild_hash_ring(self) -> None:
        """Rebuild consistent hash ring for load balancing with Numba optimization."""
        try:
            self.consistent_hash_ring.clear()

            # Prepare node IDs for Numba
            node_ids = [nid.encode('utf-8') for nid in self.healthy_nodes if nid in self.nodes]
            if node_ids:
                # Use compiled function
                compiled_ring = self._rebuild_hash_ring_internal(
                    node_ids, int(self.virtual_nodes_per_node)
                )
                self.consistent_hash_ring = dict(compiled_ring)

            logger.debug(
                f"Hash ring rebuilt with {len(self.consistent_hash_ring)} virtual nodes"
            )

        except Exception as e:
            logger.error(f"Error rebuilding hash ring: {e}")

# Register the hash ring function for compilation (Numba)
optimizer.register_function(
    "plexichat.core.clustering.cluster_manager",
    "_rebuild_hash_ring_internal",
    compiler="numba"
)

    async def _get_node_by_consistent_hash(self, key: str) -> Optional[ClusterNode]:
        """Get node using consistent hashing."""
        try:
            if not self.consistent_hash_ring:
                return None

            # Hash the key
            key_hash = int(hashlib.md5(key.encode()).hexdigest(), 16)

            # Find the first node >= key_hash
            for hash_value in sorted(self.consistent_hash_ring.keys()):
                if hash_value >= key_hash:
                    node_id = self.consistent_hash_ring[hash_value]
                    return self.nodes.get(node_id)

            # Wrap around to first node
            if self.consistent_hash_ring:
                first_hash = min(self.consistent_hash_ring.keys())
                node_id = self.consistent_hash_ring[first_hash]
                return self.nodes.get(node_id)

            return None

        except Exception as e:
            logger.error(f"Error in consistent hash selection: {e}")
            return None

    async def _get_node_by_round_robin(self) -> Optional[ClusterNode]:
        """Get node using round-robin load balancing."""
        try:
            healthy_nodes = list(self.healthy_nodes)

            if not healthy_nodes:
                return None

            # Select next node in round-robin fashion
            node_id = healthy_nodes[self.load_balancer_index % len(healthy_nodes)]
            self.load_balancer_index += 1

            return self.nodes.get(node_id)

        except Exception as e:
            logger.error(f"Error in round-robin selection: {e}")
            return None

    async def _get_least_loaded_node(self) -> Optional[ClusterNode]:
        """Get the least loaded healthy node."""
        try:
            healthy_nodes = [
                self.nodes[node_id]
                for node_id in self.healthy_nodes
                if node_id in self.nodes
            ]

            if not healthy_nodes:
                return None

            # Find node with lowest CPU usage
            return min(healthy_nodes, key=lambda node: node.metrics.cpu_usage)

        except Exception as e:
            logger.error(f"Error in least loaded selection: {e}")
            return None

    async def _select_nodes_for_removal(self, count: int) -> List[str]:
        """Select nodes for removal during scale-down."""
        try:
            # Prefer unhealthy nodes first
            unhealthy_nodes = [
                node_id for node_id in self.nodes if node_id not in self.healthy_nodes
            ]
            healthy_nodes = list(self.healthy_nodes)

            nodes_to_remove = []

            # Remove unhealthy nodes first
            nodes_to_remove.extend(unhealthy_nodes[:count])
            remaining = count - len(nodes_to_remove)

            # Remove healthy nodes if needed (prefer highest loaded)
            if remaining > 0 and healthy_nodes:
                # Sort by load (highest first)
                sorted_healthy = sorted(
                    healthy_nodes,
                    key=lambda node_id: self.nodes[node_id].metrics.cpu_usage,
                    reverse=True,
                )
                nodes_to_remove.extend(sorted_healthy[:remaining])

            return nodes_to_remove[:count]

        except Exception as e:
            logger.error(f"Error selecting nodes for removal: {e}")
            return []

    async def _leave_cluster(self) -> None:
        """Gracefully leave the cluster."""
        try:
            if self.local_node_id:
                logger.info(f"Node {self.local_node_id} leaving cluster")

                # Update node status
                if self.local_node_id in self.nodes:
                    self.nodes[self.local_node_id].status = NodeStatus.STOPPING

                # In a real implementation, this would notify other nodes
                # about the graceful shutdown

        except Exception as e:
            logger.error(f"Error leaving cluster: {e}")


# Global cluster manager instance
_global_cluster_manager: Optional[ClusterManager] = None


def get_cluster_manager() -> ClusterManager:
    """Get the global cluster manager instance."""
    global _global_cluster_manager
    if _global_cluster_manager is None:
        _global_cluster_manager = ClusterManager()
    return _global_cluster_manager


async def initialize_cluster_manager(
    config: Optional[ClusterConfiguration] = None,
) -> ClusterManager:
    """Initialize the global cluster manager."""
    global _global_cluster_manager
    _global_cluster_manager = ClusterManager(config)
    await _global_cluster_manager.start()
    return _global_cluster_manager


async def shutdown_cluster_manager() -> None:
    """Shutdown the global cluster manager."""
    global _global_cluster_manager
    if _global_cluster_manager:
        await _global_cluster_manager.stop()
        _global_cluster_manager = None


__all__ = [
    "ClusterManager",
    "ClusterNode",
    "ClusterConfiguration",
    "NodeMetrics",
    "NodeType",
    "NodeStatus",
    "ClusterStatus",
    "get_cluster_manager",
    "initialize_cluster_manager",
    "shutdown_cluster_manager",
]
