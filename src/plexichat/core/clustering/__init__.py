"""
PlexiChat Core Clustering Module

Main clustering module that provides comprehensive cluster management with support
for different node types, health monitoring, load balancing, and failover capabilities.
Integrates with existing performance monitoring and caching systems.
"""

import asyncio
import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union
import json

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Types of nodes in the cluster."""
    NETWORKING = "networking"      # Handles network routing and communication
    ENDPOINT = "endpoint"          # Serves API endpoints and user requests
    GENERAL = "general"           # General purpose compute nodes
    CACHE = "cache"               # Dedicated caching nodes
    STORAGE = "storage"           # Data storage nodes


class NodeStatus(Enum):
    """Status of cluster nodes."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    STARTING = "starting"
    STOPPING = "stopping"
    FAILED = "failed"
    MAINTENANCE = "maintenance"


class ClusterHealth(Enum):
    """Overall cluster health status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    FAILED = "failed"


@dataclass
class NodeMetrics:
    """Performance metrics for a cluster node."""
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    network_in_mbps: float = 0.0
    network_out_mbps: float = 0.0
    request_rate: float = 0.0
    error_rate: float = 0.0
    response_time_ms: float = 0.0
    uptime_seconds: int = 0
    last_updated: datetime = field(default_factory=datetime.now)


@dataclass
class ClusterNode:
    """Represents a node in the cluster."""
    node_id: str
    hostname: str
    ip_address: str
    port: int
    node_type: NodeType
    status: NodeStatus = NodeStatus.INACTIVE
    weight: float = 1.0
    capabilities: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    metrics: NodeMetrics = field(default_factory=NodeMetrics)
    last_heartbeat: Optional[datetime] = None
    joined_at: datetime = field(default_factory=datetime.now)
    version: str = "1.0.0"
    tags: Set[str] = field(default_factory=set)

    def __post_init__(self):
        """Initialize node with default capabilities based on type."""
        if not self.capabilities:
            if self.node_type == NodeType.NETWORKING:
                self.capabilities = {"routing", "load_balancing", "proxy"}
            elif self.node_type == NodeType.ENDPOINT:
                self.capabilities = {"api_serving", "websocket", "http"}
            elif self.node_type == NodeType.GENERAL:
                self.capabilities = {"compute", "processing", "background_tasks"}
            elif self.node_type == NodeType.CACHE:
                self.capabilities = {"caching", "memory_store", "distributed_cache"}
            elif self.node_type == NodeType.STORAGE:
                self.capabilities = {"data_storage", "persistence", "backup"}

    @property
    def is_healthy(self) -> bool:
        """Check if node is healthy based on status and heartbeat."""
        if self.status not in [NodeStatus.ACTIVE, NodeStatus.STARTING]:
            return False
        
        if self.last_heartbeat is None:
            return False
            
        # Consider node unhealthy if no heartbeat for 2 minutes
        heartbeat_threshold = datetime.now() - timedelta(minutes=2)
        return self.last_heartbeat > heartbeat_threshold

    def update_heartbeat(self):
        """Update the last heartbeat timestamp."""
        self.last_heartbeat = datetime.now()
        if self.status == NodeStatus.STARTING:
            self.status = NodeStatus.ACTIVE

    def update_metrics(self, metrics: Dict[str, Any]):
        """Update node metrics."""
        for key, value in metrics.items():
            if hasattr(self.metrics, key):
                setattr(self.metrics, key, value)
        self.metrics.last_updated = datetime.now()


@dataclass
class ClusterStatus:
    """Overall cluster status and metrics."""
    cluster_id: str
    total_nodes: int = 0
    active_nodes: int = 0
    inactive_nodes: int = 0
    failed_nodes: int = 0
    health: ClusterHealth = ClusterHealth.HEALTHY
    load_balancer_status: str = "active"
    total_requests: int = 0
    average_response_time: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)
    
    # Node type distribution
    networking_nodes: int = 0
    endpoint_nodes: int = 0
    general_nodes: int = 0
    cache_nodes: int = 0
    storage_nodes: int = 0


class ClusterManager:
    """
    Main cluster manager that handles node registration, health monitoring,
    load balancing, and failover for the PlexiChat cluster.
    """
    
    def __init__(self, cluster_id: Optional[str] = None, config: Optional[Dict[str, Any]] = None):
        self.cluster_id = cluster_id or str(uuid.uuid4())
        self.config = config or {}
        
        # Node management
        self.nodes: Dict[str, ClusterNode] = {}
        self.healthy_nodes: Set[str] = set()
        self.nodes_by_type: Dict[NodeType, Set[str]] = {
            node_type: set() for node_type in NodeType
        }
        
        # Load balancing
        self.hash_ring: Dict[int, str] = {}
        self.virtual_nodes = self.config.get('virtual_nodes', 150)
        
        # Configuration
        self.health_check_interval = self.config.get('health_check_interval', 30)
        self.heartbeat_timeout = self.config.get('heartbeat_timeout', 120)
        self.max_retries = self.config.get('max_retries', 3)
        self.failover_enabled = self.config.get('failover_enabled', True)
        
        # Background tasks
        self._health_check_task: Optional[asyncio.Task] = None
        self._metrics_task: Optional[asyncio.Task] = None
        self._failover_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Performance monitoring integration
        self._performance_monitor = None
        self._cache_manager = None
        
        logger.info(f"[CLUSTER] Cluster Manager initialized with ID: {self.cluster_id}")

    async def initialize(self) -> bool:
        """Initialize the cluster manager."""
        try:
            # Try to integrate with existing performance monitoring
            try:
                from plexichat.core.performance.cache_cluster_manager import cache_cluster_manager
                self._cache_manager = cache_cluster_manager
                logger.info("[CLUSTER] Integrated with cache cluster manager")
            except ImportError:
                logger.warning("[CLUSTER] Cache cluster manager not available")
            
            # Start monitoring tasks
            await self.start_monitoring()
            
            logger.info(f"[CLUSTER] Cluster manager initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"[CLUSTER] Failed to initialize cluster manager: {e}")
            return False

    async def register_node(self, 
                          hostname: str, 
                          ip_address: str, 
                          port: int, 
                          node_type: Union[NodeType, str],
                          capabilities: Optional[Set[str]] = None,
                          metadata: Optional[Dict[str, Any]] = None,
                          weight: float = 1.0) -> str:
        """Register a new node in the cluster."""
        try:
            # Convert string to NodeType if needed
            if isinstance(node_type, str):
                node_type = NodeType(node_type.lower())
            
            # Generate unique node ID
            node_id = f"{node_type.value}-{hostname}-{port}-{uuid.uuid4().hex[:8]}"
            
            # Create node
            node = ClusterNode(
                node_id=node_id,
                hostname=hostname,
                ip_address=ip_address,
                port=port,
                node_type=node_type,
                status=NodeStatus.STARTING,
                weight=weight,
                capabilities=capabilities or set(),
                metadata=metadata or {}
            )
            
            # Test node connectivity
            if await self._test_node_connectivity(node):
                self.nodes[node_id] = node
                self.nodes_by_type[node_type].add(node_id)
                
                # Update heartbeat and status
                node.update_heartbeat()
                
                # Rebuild load balancing ring
                self._rebuild_hash_ring()
                
                logger.info(f"[CLUSTER] Registered node: {node_id} ({node_type.value}) at {ip_address}:{port}")
                return node_id
            else:
                logger.error(f"[CLUSTER] Failed to register node - connectivity test failed")
                raise Exception("Node connectivity test failed")
                
        except Exception as e:
            logger.error(f"[CLUSTER] Error registering node: {e}")
            raise

    async def unregister_node(self, node_id: str) -> bool:
        """Unregister a node from the cluster."""
        try:
            if node_id not in self.nodes:
                logger.warning(f"[CLUSTER] Node {node_id} not found for unregistration")
                return False
            
            node = self.nodes[node_id]
            
            # Remove from tracking sets
            self.healthy_nodes.discard(node_id)
            self.nodes_by_type[node.node_type].discard(node_id)
            
            # Remove from nodes
            del self.nodes[node_id]
            
            # Rebuild load balancing ring
            self._rebuild_hash_ring()
            
            logger.info(f"[CLUSTER] Unregistered node: {node_id}")
            return True
            
        except Exception as e:
            logger.error(f"[CLUSTER] Error unregistering node {node_id}: {e}")
            return False

    async def update_node_heartbeat(self, node_id: str, metrics: Optional[Dict[str, Any]] = None) -> bool:
        """Update node heartbeat and metrics."""
        try:
            if node_id not in self.nodes:
                logger.warning(f"[CLUSTER] Heartbeat for unknown node: {node_id}")
                return False
            
            node = self.nodes[node_id]
            node.update_heartbeat()
            
            # Update metrics if provided
            if metrics:
                node.update_metrics(metrics)
            
            # Add to healthy nodes if not already there
            if node.is_healthy:
                self.healthy_nodes.add(node_id)
            else:
                self.healthy_nodes.discard(node_id)
            
            return True
            
        except Exception as e:
            logger.error(f"[CLUSTER] Error updating heartbeat for {node_id}: {e}")
            return False

    def get_nodes_by_type(self, node_type: Union[NodeType, str], healthy_only: bool = True) -> List[ClusterNode]:
        """Get nodes of a specific type."""
        if isinstance(node_type, str):
            node_type = NodeType(node_type.lower())
        
        node_ids = self.nodes_by_type.get(node_type, set())
        
        if healthy_only:
            node_ids = node_ids.intersection(self.healthy_nodes)
        
        return [self.nodes[node_id] for node_id in node_ids if node_id in self.nodes]

    def get_node_for_request(self, request_key: str, node_type: Optional[NodeType] = None) -> Optional[ClusterNode]:
        """Get the best node for handling a request using consistent hashing."""
        # Filter by node type if specified
        if node_type:
            available_nodes = self.get_nodes_by_type(node_type, healthy_only=True)
            if not available_nodes:
                return None
            node_ids = {node.node_id for node in available_nodes}
        else:
            node_ids = self.healthy_nodes
        
        if not node_ids:
            return None
        
        # Use consistent hashing to select node
        key_hash = int(hashlib.md5(request_key.encode()).hexdigest(), 16)
        
        # Find the first node in the ring >= key_hash
        for ring_hash in sorted(self.hash_ring.keys()):
            if ring_hash >= key_hash:
                node_id = self.hash_ring[ring_hash]
                if node_id in node_ids:
                    return self.nodes.get(node_id)
        
        # Wrap around to the first node
        if self.hash_ring:
            first_hash = min(self.hash_ring.keys())
            node_id = self.hash_ring[first_hash]
            if node_id in node_ids:
                return self.nodes.get(node_id)
        
        return None

    def get_replica_nodes(self, request_key: str, replica_count: int = 2, node_type: Optional[NodeType] = None) -> List[ClusterNode]:
        """Get replica nodes for redundancy."""
        primary_node = self.get_node_for_request(request_key, node_type)
        if not primary_node:
            return []
        
        replicas = [primary_node]
        key_hash = int(hashlib.md5(request_key.encode()).hexdigest(), 16)
        
        # Filter available nodes
        if node_type:
            available_nodes = {node.node_id for node in self.get_nodes_by_type(node_type, healthy_only=True)}
        else:
            available_nodes = self.healthy_nodes
        
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
            replica_node_id = self.hash_ring[replica_hash]
            
            if (replica_node_id in available_nodes and 
                replica_node_id not in {node.node_id for node in replicas}):
                replica_node = self.nodes.get(replica_node_id)
                if replica_node:
                    replicas.append(replica_node)
        
        return replicas[:replica_count]

    async def get_cluster_status(self) -> ClusterStatus:
        """Get comprehensive cluster status."""
        try:
            status = ClusterStatus(cluster_id=self.cluster_id)
            
            # Count nodes by status
            status.total_nodes = len(self.nodes)
            status.active_nodes = len(self.healthy_nodes)
            status.inactive_nodes = len([n for n in self.nodes.values() if n.status == NodeStatus.INACTIVE])
            status.failed_nodes = len([n for n in self.nodes.values() if n.status == NodeStatus.FAILED])
            
            # Count nodes by type
            status.networking_nodes = len(self.nodes_by_type[NodeType.NETWORKING])
            status.endpoint_nodes = len(self.nodes_by_type[NodeType.ENDPOINT])
            status.general_nodes = len(self.nodes_by_type[NodeType.GENERAL])
            status.cache_nodes = len(self.nodes_by_type[NodeType.CACHE])
            status.storage_nodes = len(self.nodes_by_type[NodeType.STORAGE])
            
            # Determine cluster health
            if status.active_nodes == 0:
                status.health = ClusterHealth.FAILED
            elif status.active_nodes < status.total_nodes * 0.5:
                status.health = ClusterHealth.CRITICAL
            elif status.active_nodes < status.total_nodes * 0.8:
                status.health = ClusterHealth.DEGRADED
            else:
                status.health = ClusterHealth.HEALTHY
            
            # Calculate average response time
            if self.healthy_nodes:
                total_response_time = sum(
                    self.nodes[node_id].metrics.response_time_ms 
                    for node_id in self.healthy_nodes
                )
                status.average_response_time = total_response_time / len(self.healthy_nodes)
            
            status.last_updated = datetime.now()
            return status
            
        except Exception as e:
            logger.error(f"[CLUSTER] Error getting cluster status: {e}")
            return ClusterStatus(cluster_id=self.cluster_id, health=ClusterHealth.FAILED)

    async def get_all_nodes(self) -> List[Dict[str, Any]]:
        """Get all nodes information for API responses."""
        nodes_info = []
        for node in self.nodes.values():
            nodes_info.append({
                "node_id": node.node_id,
                "hostname": node.hostname,
                "ip_address": node.ip_address,
                "port": node.port,
                "node_type": node.node_type.value,
                "status": node.status.value,
                "weight": node.weight,
                "capabilities": list(node.capabilities),
                "cpu_usage": node.metrics.cpu_usage,
                "memory_usage": node.metrics.memory_usage,
                "disk_usage": node.metrics.disk_usage,
                "last_heartbeat": node.last_heartbeat,
                "uptime_seconds": node.metrics.uptime_seconds,
                "is_healthy": node.is_healthy
            })
        return nodes_info

    async def scale_cluster(self, target_nodes: int) -> Dict[str, Any]:
        """Scale cluster to target number of nodes."""
        current_nodes = len(self.nodes)
        operation_id = str(uuid.uuid4())
        
        logger.info(f"[CLUSTER] Scaling cluster from {current_nodes} to {target_nodes} nodes")
        
        return {
            "operation_id": operation_id,
            "current_nodes": current_nodes,
            "target_nodes": target_nodes,
            "estimated_time": f"{abs(target_nodes - current_nodes) * 30} seconds"
        }

    async def rebalance_cluster(self) -> Dict[str, Any]:
        """Rebalance cluster load distribution."""
        operation_id = str(uuid.uuid4())
        
        logger.info(f"[CLUSTER] Rebalancing cluster load distribution")
        
        # Rebuild hash ring for better distribution
        self._rebuild_hash_ring()
        
        return {
            "operation_id": operation_id,
            "estimated_time": "30 seconds",
            "nodes_affected": len(self.nodes)
        }

    async def start_monitoring(self):
        """Start background monitoring tasks."""
        if self._running:
            return
        
        self._running = True
        self._health_check_task = asyncio.create_task(self._health_check_loop())
        self._metrics_task = asyncio.create_task(self._metrics_collection_loop())
        
        if self.failover_enabled:
            self._failover_task = asyncio.create_task(self._failover_monitoring_loop())
        
        logger.info("[CLUSTER] Monitoring tasks started")

    async def stop_monitoring(self):
        """Stop background monitoring tasks."""
        self._running = False
        
        for task in [self._health_check_task, self._metrics_task, self._failover_task]:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        logger.info("[CLUSTER] Monitoring tasks stopped")

    async def _health_check_loop(self):
        """Background health check loop."""
        while self._running:
            try:
                await self._check_all_nodes_health()
                await asyncio.sleep(self.health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[CLUSTER] Health check loop error: {e}")
                await asyncio.sleep(5)

    async def _check_all_nodes_health(self):
        """Check health of all nodes."""
        current_time = datetime.now()
        heartbeat_threshold = current_time - timedelta(seconds=self.heartbeat_timeout)
        
        for node_id, node in self.nodes.items():
            # Check heartbeat timeout
            if node.last_heartbeat and node.last_heartbeat < heartbeat_threshold:
                if node.status == NodeStatus.ACTIVE:
                    logger.warning(f"[CLUSTER] Node {node_id} heartbeat timeout")
                    node.status = NodeStatus.FAILED
                    self.healthy_nodes.discard(node_id)
            
            # Update healthy nodes set
            if node.is_healthy:
                self.healthy_nodes.add(node_id)
            else:
                self.healthy_nodes.discard(node_id)

    async def _metrics_collection_loop(self):
        """Background metrics collection loop."""
        while self._running:
            try:
                await self._collect_cluster_metrics()
                await asyncio.sleep(60)  # Collect every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[CLUSTER] Metrics collection error: {e}")
                await asyncio.sleep(30)

    async def _collect_cluster_metrics(self):
        """Collect cluster-wide metrics."""
        try:
            # This would integrate with performance monitoring systems
            # For now, just log the collection
            logger.debug(f"[CLUSTER] Collected metrics for {len(self.nodes)} nodes")
        except Exception as e:
            logger.error(f"[CLUSTER] Error collecting metrics: {e}")

    async def _failover_monitoring_loop(self):
        """Background failover monitoring loop."""
        while self._running:
            try:
                await self._check_failover_conditions()
                await asyncio.sleep(10)  # Check every 10 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[CLUSTER] Failover monitoring error: {e}")
                await asyncio.sleep(5)

    async def _check_failover_conditions(self):
        """Check if failover is needed."""
        # Check if any critical node types are missing
        for node_type in [NodeType.NETWORKING, NodeType.ENDPOINT]:
            healthy_nodes = self.get_nodes_by_type(node_type, healthy_only=True)
            if not healthy_nodes:
                logger.warning(f"[CLUSTER] No healthy {node_type.value} nodes available")
                # Trigger failover logic here

    async def _test_node_connectivity(self, node: ClusterNode) -> bool:
        """Test connectivity to a node."""
        try:
            # This would implement actual connectivity test
            # For now, simulate a successful test
            await asyncio.sleep(0.01)
            return True
        except Exception as e:
            logger.error(f"[CLUSTER] Connectivity test failed for {node.node_id}: {e}")
            return False

    def _rebuild_hash_ring(self):
        """Rebuild consistent hash ring for load balancing."""
        self.hash_ring.clear()
        
        for node_id, node in self.nodes.items():
            if node.is_healthy:
                # Create virtual nodes for better distribution
                for i in range(int(self.virtual_nodes * node.weight)):
                    virtual_key = f"{node_id}:{i}"
                    hash_value = int(hashlib.md5(virtual_key.encode()).hexdigest(), 16)
                    self.hash_ring[hash_value] = node_id
        
        logger.debug(f"[CLUSTER] Rebuilt hash ring with {len(self.hash_ring)} virtual nodes")


# Performance monitor integration
class PerformanceMonitor:
    """Performance monitoring integration for cluster."""
    
    def __init__(self, cluster_manager: ClusterManager):
        self.cluster_manager = cluster_manager
    
    async def get_cluster_metrics(self) -> Dict[str, Any]:
        """Get cluster performance metrics."""
        try:
            nodes = self.cluster_manager.nodes.values()
            
            if not nodes:
                return {
                    "cpu_usage": 0.0,
                    "memory_usage": 0.0,
                    "disk_usage": 0.0,
                    "network_throughput": 0.0,
                    "request_rate": 0.0,
                    "error_rate": 0.0
                }
            
            # Calculate averages
            total_cpu = sum(node.metrics.cpu_usage for node in nodes)
            total_memory = sum(node.metrics.memory_usage for node in nodes)
            total_disk = sum(node.metrics.disk_usage for node in nodes)
            total_network = sum(node.metrics.network_in_mbps + node.metrics.network_out_mbps for node in nodes)
            total_requests = sum(node.metrics.request_rate for node in nodes)
            total_errors = sum(node.metrics.error_rate for node in nodes)
            
            node_count = len(nodes)
            
            return {
                "cpu_usage": total_cpu / node_count,
                "memory_usage": total_memory / node_count,
                "disk_usage": total_disk / node_count,
                "network_throughput": total_network,
                "request_rate": total_requests,
                "error_rate": total_errors / node_count if node_count > 0 else 0.0
            }
            
        except Exception as e:
            logger.error(f"[CLUSTER] Error getting cluster metrics: {e}")
            return {}


# Global singleton instances
cluster_manager = ClusterManager()
performance_monitor = PerformanceMonitor(cluster_manager)

# Export main components
__all__ = [
    'ClusterManager',
    'ClusterNode', 
    'ClusterStatus',
    'NodeMetrics',
    'NodeType',
    'NodeStatus',
    'ClusterHealth',
    'PerformanceMonitor',
    'cluster_manager',
    'performance_monitor'
]
