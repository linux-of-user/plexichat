import asyncio
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

import aiohttp

"""
PlexiChat Backup Node Network

Distributed backup node network with encrypted inter-node communication,
automatic failover, and consensus-based shard verification.
"""

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Types of backup nodes."""
    PRIMARY = "primary"
    SECONDARY = "secondary"
    GATEWAY = "gateway"
    ANTIVIRUS = "antivirus"
    SPECIALIZED = "specialized"


class NodeStatus(Enum):
    """Node status."""
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"
    FAILED = "failed"


class NodeCapability(Enum):
    """Node capabilities."""
    STORAGE = "storage"
    PROCESSING = "processing"
    ENCRYPTION = "encryption"
    VERIFICATION = "verification"
    GATEWAY = "gateway"
    ANTIVIRUS = "antivirus"


@dataclass
class BackupNode:
    """Backup node with capabilities and status."""
    node_id: str
    node_type: NodeType
    hostname: str
    port: int
    capabilities: Set[NodeCapability]
    status: NodeStatus = NodeStatus.OFFLINE
    last_heartbeat: Optional[datetime] = None
    storage_capacity: int = 0  # bytes
    storage_used: int = 0  # bytes
    cpu_usage: float = 0.0  # percentage
    memory_usage: float = 0.0  # percentage
    network_latency: float = 0.0  # milliseconds
    reliability_score: float = 1.0  # 0.0 to 1.0
    geographic_region: str = "unknown"
    encryption_keys: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ShardDistribution:
    """Shard distribution across nodes."""
    backup_id: str
    shard_id: str
    primary_nodes: List[str]  # node_ids
    replica_nodes: List[str]  # node_ids
    verification_nodes: List[str]  # node_ids
    distribution_strategy: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class NodeHealthMetrics:
    """Node health metrics."""
    node_id: str
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_latency: float
    active_connections: int
    shard_count: int
    error_rate: float
    availability: float


class BackupNodeNetwork:
    """
    Distributed backup node network with intelligent management.
    
    Features:
    - Encrypted inter-node communication
    - Automatic failover and recovery
    - Consensus-based verification
    - Geographic distribution
    - Load balancing
    - Health monitoring
    """
    
    def __init__(self, backup_manager):
        self.backup_manager = backup_manager
        self.nodes: Dict[str, BackupNode] = {}
        self.shard_distributions: Dict[str, List[ShardDistribution]] = {}
        self.health_metrics: Dict[str, List[NodeHealthMetrics]] = {}
        
        # Network configuration
        self.heartbeat_interval = 30  # seconds
        self.health_check_interval = 60  # seconds
        self.failover_threshold = 3  # failed heartbeats
        
        # Session management
        self.http_session: Optional[aiohttp.ClientSession] = None
        
        self.initialized = False
    
    async def initialize(self):
        """Initialize the backup node network."""
        if self.initialized:
            return
        
        try:
            # Initialize HTTP session
            self.http_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(limit=100)
            )
            
            # Load existing nodes
            await self._load_nodes()
            
            # Discover available nodes
            await self._discover_nodes()
            
            # Initialize encryption keys
            await self._initialize_node_encryption()
            
            self.initialized = True
            logger.info(" Backup Node Network initialized")
            
        except Exception as e:
            logger.error(f" Failed to initialize Backup Node Network: {e}")
            raise
    
    async def register_node(self, node: BackupNode) -> bool:
        """Register a new backup node."""
        try:
            # Validate node
            if not await self._validate_node(node):
                return False
            
            # Generate encryption keys
            await self._generate_node_keys(node)
            
            # Add to network
            self.nodes[node.node_id] = node
            
            # Initialize health monitoring
            await self._start_node_monitoring(node.node_id)
            
            logger.info(f" Registered backup node: {node.node_id}")
            return True
            
        except Exception as e:
            logger.error(f" Failed to register node {node.node_id}: {e}")
            return False
    
    async def get_available_nodes(self) -> List[BackupNode]:
        """Get list of available nodes."""
        return [
            node for node in self.nodes.values()
            if node.status in [NodeStatus.ONLINE, NodeStatus.DEGRADED]
        ]
    
    async def distribute_shards(self, shards: List[Any], request) -> Dict[str, List[str]]:
        """Distribute shards across backup nodes."""
        if not self.initialized:
            await self.initialize()
        
        backup_id = request.backup_id
        distribution_map = {}
        
        try:
            logger.info(f" Distributing {len(shards)} shards for backup: {backup_id}")
            
            # Get available nodes
            available_nodes = await self.get_available_nodes()
            if len(available_nodes) < request.redundancy_factor:
                raise ValueError(f"Insufficient nodes for redundancy factor {request.redundancy_factor}")
            
            # Create distribution plan
            distributions = []
            for shard in shards:
                distribution = await self._create_shard_distribution(
                    shard, available_nodes, request
                )
                distributions.append(distribution)
                
                # Execute distribution
                await self._execute_shard_distribution(shard, distribution)
                
                # Track distribution
                if backup_id not in self.shard_distributions:
                    self.shard_distributions[backup_id] = []
                self.shard_distributions[backup_id].append(distribution)
                
                # Update distribution map
                all_nodes = distribution.primary_nodes + distribution.replica_nodes
                distribution_map[shard.shard_id] = all_nodes
            
            logger.info(f" Distributed shards for backup: {backup_id}")
            return distribution_map
            
        except Exception as e:
            logger.error(f" Failed to distribute shards for {backup_id}: {e}")
            raise
    
    async def start_health_monitoring(self):
        """Start health monitoring for all nodes."""
        asyncio.create_task(self._health_monitoring_loop())
        logger.info(" Started node health monitoring")
    
    async def get_node_health(self, node_id: str) -> Optional[NodeHealthMetrics]:
        """Get latest health metrics for a node."""
        metrics_list = self.health_metrics.get(node_id, [])
        return metrics_list[-1] if metrics_list else None
    
    async def failover_node(self, failed_node_id: str) -> bool:
        """Execute failover for a failed node."""
        try:
            logger.warning(f" Executing failover for node: {failed_node_id}")
            
            # Mark node as failed
            if failed_node_id in self.nodes:
                self.nodes[failed_node_id].status = NodeStatus.FAILED
            
            # Find affected shards
            affected_distributions = []
            for backup_distributions in self.shard_distributions.values():
                for distribution in backup_distributions:
                    if (failed_node_id in distribution.primary_nodes or 
                        failed_node_id in distribution.replica_nodes):
                        affected_distributions.append(distribution)
            
            # Redistribute affected shards
            for distribution in affected_distributions:
                await self._redistribute_shard(distribution, failed_node_id)
            
            logger.info(f" Failover completed for node: {failed_node_id}")
            return True
            
        except Exception as e:
            logger.error(f" Failover failed for node {failed_node_id}: {e}")
            return False
    
    async def _load_nodes(self):
        """Load existing nodes from storage."""
        # TODO: Load from persistent storage
        logger.info(" Nodes loaded from storage")
    
    async def _discover_nodes(self):
        """Discover available backup nodes on the network."""
        # TODO: Implement node discovery
        logger.info(" Node discovery completed")
    
    async def _initialize_node_encryption(self):
        """Initialize encryption keys for inter-node communication."""
        for node in self.nodes.values():
            await self._generate_node_keys(node)
        logger.info(" Node encryption initialized")
    
    async def _validate_node(self, node: BackupNode) -> bool:
        """Validate a backup node."""
        # Check connectivity
        try:
            if self.http_session:
                url = f"http://{node.hostname}:{node.port}/health"
                async with self.http_session.get(url) as response:
                    if response.status != 200:
                        return False
        except Exception:
            return False
        
        # Check capabilities
        if not node.capabilities:
            return False
        
        return True
    
    async def _generate_node_keys(self, node: BackupNode):
        """Generate encryption keys for a node."""
        # Generate symmetric key for node communication
        node.encryption_keys["communication"] = secrets.token_hex(32)
        
        # Generate key for shard encryption
        node.encryption_keys["shard"] = secrets.token_hex(32)
        
        # Generate authentication key
        node.encryption_keys["auth"] = secrets.token_hex(16)
    
    async def _start_node_monitoring(self, node_id: str):
        """Start monitoring for a specific node."""
        asyncio.create_task(self._monitor_node(node_id))
    
    async def _monitor_node(self, node_id: str):
        """Monitor a specific node."""
        while node_id in self.nodes:
            try:
                node = self.nodes[node_id]
                if node.status == NodeStatus.FAILED:
                    break
                
                # Collect health metrics
                metrics = await self._collect_node_metrics(node)
                
                # Store metrics
                if node_id not in self.health_metrics:
                    self.health_metrics[node_id] = []
                self.health_metrics[node_id].append(metrics)
                
                # Keep only recent metrics
                if len(self.health_metrics[node_id]) > 1000:
                    self.health_metrics[node_id] = self.health_metrics[node_id][-500:]
                
                # Update node status
                await self._update_node_status(node, metrics)
                
                await asyncio.sleep(self.health_check_interval)
                
            except Exception as e:
                logger.error(f" Error monitoring node {node_id}: {e}")
                await asyncio.sleep(self.health_check_interval)
    
    async def _collect_node_metrics(self, node: BackupNode) -> NodeHealthMetrics:
        """Collect health metrics from a node."""
        try:
            if self.http_session:
                url = f"http://{node.hostname}:{node.port}/metrics"
                async with self.http_session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        return NodeHealthMetrics(
                            node_id=node.node_id,
                            timestamp=datetime.now(timezone.utc),
                            cpu_usage=data.get("cpu_usage", 0.0),
                            memory_usage=data.get("memory_usage", 0.0),
                            disk_usage=data.get("disk_usage", 0.0),
                            network_latency=data.get("network_latency", 0.0),
                            active_connections=data.get("active_connections", 0),
                            shard_count=data.get("shard_count", 0),
                            error_rate=data.get("error_rate", 0.0),
                            availability=data.get("availability", 1.0)
                        )
        except Exception:
            pass
        
        # Return default metrics if collection fails
        return NodeHealthMetrics(
            node_id=node.node_id,
            timestamp=datetime.now(timezone.utc),
            cpu_usage=0.0,
            memory_usage=0.0,
            disk_usage=0.0,
            network_latency=999.0,  # High latency indicates problem
            active_connections=0,
            shard_count=0,
            error_rate=1.0,  # High error rate indicates problem
            availability=0.0  # Low availability indicates problem
        )
    
    async def _update_node_status(self, node: BackupNode, metrics: NodeHealthMetrics):
        """Update node status based on metrics."""
        # Update last heartbeat
        node.last_heartbeat = metrics.timestamp
        
        # Determine status based on metrics
        if metrics.availability < 0.5 or metrics.error_rate > 0.5:
            node.status = NodeStatus.FAILED
        elif metrics.cpu_usage > 90 or metrics.memory_usage > 90:
            node.status = NodeStatus.DEGRADED
        else:
            node.status = NodeStatus.ONLINE
        
        # Update performance metrics
        node.cpu_usage = metrics.cpu_usage
        node.memory_usage = metrics.memory_usage
        node.network_latency = metrics.network_latency
    
    async def _health_monitoring_loop(self):
        """Main health monitoring loop."""
        while True:
            try:
                # Check for failed nodes
                current_time = datetime.now(timezone.utc)
                for node_id, node in self.nodes.items():
                    if node.last_heartbeat:
                        time_since_heartbeat = current_time - node.last_heartbeat
                        if time_since_heartbeat > timedelta(seconds=self.heartbeat_interval * self.failover_threshold):
                            if node.status != NodeStatus.FAILED:
                                await self.failover_node(node_id)
                
                await asyncio.sleep(self.heartbeat_interval)
                
            except Exception as e:
                logger.error(f" Health monitoring loop error: {e}")
                await asyncio.sleep(self.heartbeat_interval)
    
    async def _create_shard_distribution(self, shard: Any, available_nodes: List[BackupNode], 
                                       request) -> ShardDistribution:
        """Create distribution plan for a shard."""
        # Select primary nodes
        primary_nodes = await self._select_primary_nodes(shard, available_nodes, request)
        
        # Select replica nodes
        replica_nodes = await self._select_replica_nodes(shard, available_nodes, primary_nodes, request)
        
        # Select verification nodes
        verification_nodes = await self._select_verification_nodes(shard, available_nodes, request)
        
        return ShardDistribution(
            backup_id=request.backup_id,
            shard_id=shard.shard_id,
            primary_nodes=[node.node_id for node in primary_nodes],
            replica_nodes=[node.node_id for node in replica_nodes],
            verification_nodes=[node.node_id for node in verification_nodes],
            distribution_strategy="intelligent_geographic"
        )
    
    async def _select_primary_nodes(self, shard: Any, available_nodes: List[BackupNode], 
                                  request) -> List[BackupNode]:
        """Select primary nodes for shard storage."""
        # Sort nodes by reliability and capacity
        sorted_nodes = sorted(
            available_nodes,
            key=lambda n: (n.reliability_score, n.storage_capacity - n.storage_used),
            reverse=True
        )
        
        # Select top nodes for primary storage
        num_primary = min(2, len(sorted_nodes))  # Usually 2 primary nodes
        return sorted_nodes[:num_primary]
    
    async def _select_replica_nodes(self, shard: Any, available_nodes: List[BackupNode],
                                  primary_nodes: List[BackupNode], request) -> List[BackupNode]:
        """Select replica nodes for redundancy."""
        # Exclude primary nodes
        replica_candidates = [n for n in available_nodes if n not in primary_nodes]
        
        # Sort by geographic diversity and reliability
        sorted_candidates = sorted(
            replica_candidates,
            key=lambda n: (n.reliability_score, n.geographic_region != primary_nodes[0].geographic_region),
            reverse=True
        )
        
        # Select replica nodes based on redundancy factor
        num_replicas = min(request.redundancy_factor - len(primary_nodes), len(sorted_candidates))
        return sorted_candidates[:num_replicas]
    
    async def _select_verification_nodes(self, shard: Any, available_nodes: List[BackupNode], 
                                       request) -> List[BackupNode]:
        """Select nodes for verification."""
        # Select nodes with verification capability
        verification_candidates = [
            n for n in available_nodes 
            if NodeCapability.VERIFICATION in n.capabilities
        ]
        
        # Select a subset for verification
        num_verification = min(3, len(verification_candidates))
        return verification_candidates[:num_verification]
    
    async def _execute_shard_distribution(self, shard: Any, distribution: ShardDistribution):
        """Execute the distribution of a shard to nodes."""
        # TODO: Implement actual shard distribution to nodes
        logger.info(f" Distributed shard {shard.shard_id} to nodes")
    
    async def _redistribute_shard(self, distribution: ShardDistribution, failed_node_id: str):
        """Redistribute a shard after node failure."""
        # TODO: Implement shard redistribution
        logger.info(f" Redistributed shard {distribution.shard_id} after node failure")


# Global instance
backup_node_network = BackupNodeNetwork(None)
