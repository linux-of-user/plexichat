#!/usr/bin/env python3
"""
Distribution Manager for Distributed Backup System

Handles distribution of encrypted shards across multiple users/nodes.
Provides load balancing, redundancy, and geographic distribution.
"""

import asyncio
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from uuid import uuid4

# Import shard and encryption components
from .shard_manager import ShardInfo, ShardSet, ShardStatus
from .encryption_manager import EncryptedData

logger = logging.getLogger(__name__)

class NodeType(Enum):
    """Types of storage nodes."""
    USER = "user"           # Regular user storage
    DEDICATED = "dedicated" # Dedicated backup node
    CLOUD = "cloud"         # Cloud storage
    LOCAL = "local"         # Local storage

class NodeStatus(Enum):
    """Node status."""
    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"
    OVERLOADED = "overloaded"
    UNREACHABLE = "unreachable"

class DistributionStrategy(Enum):
    """Distribution strategies."""
    ROUND_ROBIN = "round_robin"
    LOAD_BALANCED = "load_balanced"
    GEOGRAPHIC = "geographic"
    RANDOM = "random"
    AFFINITY_BASED = "affinity_based"

@dataclass
class StorageNode:
    """Represents a storage node."""
    node_id: str
    node_type: NodeType
    user_id: Optional[str]  # For user nodes
    capacity_mb: int
    used_mb: int
    location: str  # Geographic location or path
    status: NodeStatus
    last_seen: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def available_mb(self) -> int:
        """Get available storage in MB."""
        return max(0, self.capacity_mb - self.used_mb)
    
    @property
    def usage_percent(self) -> float:
        """Get usage percentage."""
        return (self.used_mb / self.capacity_mb * 100) if self.capacity_mb > 0 else 100.0
    
    @property
    def is_available(self) -> bool:
        """Check if node is available for storage."""
        return (self.status == NodeStatus.ONLINE and 
                self.available_mb > 0 and 
                self.usage_percent < 90.0)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "user_id": self.user_id,
            "capacity_mb": self.capacity_mb,
            "used_mb": self.used_mb,
            "location": self.location,
            "status": self.status.value,
            "last_seen": self.last_seen.isoformat(),
            "metadata": self.metadata
        }

@dataclass
class ShardDistribution:
    """Represents distribution of a shard."""
    shard_id: str
    node_id: str
    storage_path: str
    stored_at: datetime
    verified_at: Optional[datetime] = None
    access_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DistributionPlan:
    """Plan for distributing shards."""
    backup_id: str
    shard_distributions: List[ShardDistribution]
    strategy: DistributionStrategy
    created_at: datetime
    redundancy_factor: int
    
    @property
    def total_shards(self) -> int:
        """Get total number of shards."""
        return len(self.shard_distributions)
    
    @property
    def unique_nodes(self) -> Set[str]:
        """Get unique node IDs used."""
        return {dist.node_id for dist in self.shard_distributions}

class DistributionManager:
    """Manages distribution of shards across storage nodes."""
    
    def __init__(self, storage_dir: Path):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Node management
        self.nodes: Dict[str, StorageNode] = {}
        self.distribution_plans: Dict[str, DistributionPlan] = {}
        self.shard_locations: Dict[str, List[ShardDistribution]] = {}
        
        # Configuration
        self.default_strategy = DistributionStrategy.LOAD_BALANCED
        self.min_redundancy = 3
        self.max_shards_per_node = 100
        
        # Initialize with local node
        self._initialize_local_node()
    
    def _initialize_local_node(self):
        """Initialize local storage node."""
        local_node = StorageNode(
            node_id="local",
            node_type=NodeType.LOCAL,
            user_id=None,
            capacity_mb=10240,  # 10GB default
            used_mb=0,
            location=str(self.storage_dir),
            status=NodeStatus.ONLINE,
            last_seen=datetime.now(timezone.utc),
            metadata={"description": "Local backup storage"}
        )
        self.nodes["local"] = local_node
        logger.info("Initialized local storage node")
    
    def register_node(self, node_id: str, node_type: NodeType, capacity_mb: int,
                     location: str, user_id: Optional[str] = None, 
                     metadata: Optional[Dict[str, Any]] = None) -> StorageNode:
        """Register a new storage node."""
        node = StorageNode(
            node_id=node_id,
            node_type=node_type,
            user_id=user_id,
            capacity_mb=capacity_mb,
            used_mb=0,
            location=location,
            status=NodeStatus.ONLINE,
            last_seen=datetime.now(timezone.utc),
            metadata=metadata or {}
        )
        
        self.nodes[node_id] = node
        logger.info(f"Registered storage node {node_id} ({node_type.value}) with {capacity_mb}MB capacity")
        return node
    
    def unregister_node(self, node_id: str) -> bool:
        """Unregister a storage node."""
        if node_id in self.nodes:
            # Check if node has any shards
            node_shards = [dist for distributions in self.shard_locations.values() 
                          for dist in distributions if dist.node_id == node_id]
            
            if node_shards:
                logger.warning(f"Cannot unregister node {node_id}: has {len(node_shards)} shards")
                return False
            
            del self.nodes[node_id]
            logger.info(f"Unregistered storage node {node_id}")
            return True
        
        return False
    
    def update_node_status(self, node_id: str, status: NodeStatus, 
                          used_mb: Optional[int] = None):
        """Update node status and usage."""
        if node_id in self.nodes:
            node = self.nodes[node_id]
            node.status = status
            node.last_seen = datetime.now(timezone.utc)
            
            if used_mb is not None:
                node.used_mb = used_mb
            
            logger.debug(f"Updated node {node_id} status to {status.value}")
    
    def get_available_nodes(self, exclude_nodes: Optional[Set[str]] = None) -> List[StorageNode]:
        """Get list of available storage nodes."""
        exclude_nodes = exclude_nodes or set()
        
        available = [
            node for node in self.nodes.values()
            if node.is_available and node.node_id not in exclude_nodes
        ]
        
        return sorted(available, key=lambda n: n.usage_percent)
    
    def create_distribution_plan(self, shard_set: ShardSet, 
                               strategy: Optional[DistributionStrategy] = None) -> DistributionPlan:
        """Create a distribution plan for a shard set."""
        strategy = strategy or self.default_strategy
        
        logger.info(f"Creating distribution plan for {len(shard_set.all_shards)} shards using {strategy.value}")
        
        if strategy == DistributionStrategy.ROUND_ROBIN:
            return self._create_round_robin_plan(shard_set)
        elif strategy == DistributionStrategy.LOAD_BALANCED:
            return self._create_load_balanced_plan(shard_set)
        elif strategy == DistributionStrategy.RANDOM:
            return self._create_random_plan(shard_set)
        else:
            # Default to load balanced
            return self._create_load_balanced_plan(shard_set)
    
    def _create_load_balanced_plan(self, shard_set: ShardSet) -> DistributionPlan:
        """Create load-balanced distribution plan."""
        distributions = []
        available_nodes = self.get_available_nodes()
        
        if not available_nodes:
            raise ValueError("No available storage nodes")
        
        # Distribute shards across nodes, avoiding same backup on same node
        used_nodes_for_backup = set()
        
        for shard in shard_set.all_shards:
            # Find best node (lowest usage, not already used for this backup)
            candidate_nodes = [n for n in available_nodes 
                             if n.node_id not in used_nodes_for_backup]
            
            if not candidate_nodes:
                # If all nodes used, reset and use least loaded
                candidate_nodes = available_nodes
                used_nodes_for_backup.clear()
            
            # Select node with lowest usage
            selected_node = min(candidate_nodes, key=lambda n: n.usage_percent)
            used_nodes_for_backup.add(selected_node.node_id)
            
            # Create distribution
            storage_path = f"{selected_node.location}/shard_{shard.shard_id}"
            distribution = ShardDistribution(
                shard_id=shard.shard_id,
                node_id=selected_node.node_id,
                storage_path=storage_path,
                stored_at=datetime.now(timezone.utc),
                metadata={"shard_type": shard.shard_type.value}
            )
            distributions.append(distribution)
            
            # Update node usage estimate
            selected_node.used_mb += shard.size // (1024 * 1024)  # Convert to MB
        
        return DistributionPlan(
            backup_id=shard_set.backup_id,
            shard_distributions=distributions,
            strategy=DistributionStrategy.LOAD_BALANCED,
            created_at=datetime.now(timezone.utc),
            redundancy_factor=len(set(d.node_id for d in distributions))
        )
    
    def _create_round_robin_plan(self, shard_set: ShardSet) -> DistributionPlan:
        """Create round-robin distribution plan."""
        distributions = []
        available_nodes = self.get_available_nodes()
        
        if not available_nodes:
            raise ValueError("No available storage nodes")
        
        node_index = 0
        
        for shard in shard_set.all_shards:
            selected_node = available_nodes[node_index % len(available_nodes)]
            node_index += 1
            
            storage_path = f"{selected_node.location}/shard_{shard.shard_id}"
            distribution = ShardDistribution(
                shard_id=shard.shard_id,
                node_id=selected_node.node_id,
                storage_path=storage_path,
                stored_at=datetime.now(timezone.utc),
                metadata={"shard_type": shard.shard_type.value}
            )
            distributions.append(distribution)
        
        return DistributionPlan(
            backup_id=shard_set.backup_id,
            shard_distributions=distributions,
            strategy=DistributionStrategy.ROUND_ROBIN,
            created_at=datetime.now(timezone.utc),
            redundancy_factor=len(set(d.node_id for d in distributions))
        )
    
    def _create_random_plan(self, shard_set: ShardSet) -> DistributionPlan:
        """Create random distribution plan."""
        distributions = []
        available_nodes = self.get_available_nodes()
        
        if not available_nodes:
            raise ValueError("No available storage nodes")
        
        for shard in shard_set.all_shards:
            selected_node = random.choice(available_nodes)
            
            storage_path = f"{selected_node.location}/shard_{shard.shard_id}"
            distribution = ShardDistribution(
                shard_id=shard.shard_id,
                node_id=selected_node.node_id,
                storage_path=storage_path,
                stored_at=datetime.now(timezone.utc),
                metadata={"shard_type": shard.shard_type.value}
            )
            distributions.append(distribution)
        
        return DistributionPlan(
            backup_id=shard_set.backup_id,
            shard_distributions=distributions,
            strategy=DistributionStrategy.RANDOM,
            created_at=datetime.now(timezone.utc),
            redundancy_factor=len(set(d.node_id for d in distributions))
        )
    
    async def execute_distribution_plan(self, plan: DistributionPlan, 
                                      shard_data: Dict[str, bytes]) -> bool:
        """Execute a distribution plan by storing shards on nodes."""
        try:
            logger.info(f"Executing distribution plan for backup {plan.backup_id}")
            
            success_count = 0
            
            for distribution in plan.shard_distributions:
                shard_id = distribution.shard_id
                
                if shard_id not in shard_data:
                    logger.warning(f"Shard data not found for {shard_id}")
                    continue
                
                # Store shard on node
                success = await self._store_shard_on_node(
                    distribution.node_id,
                    distribution.storage_path,
                    shard_data[shard_id]
                )
                
                if success:
                    # Update shard locations
                    if shard_id not in self.shard_locations:
                        self.shard_locations[shard_id] = []
                    self.shard_locations[shard_id].append(distribution)
                    success_count += 1
                else:
                    logger.error(f"Failed to store shard {shard_id} on node {distribution.node_id}")
            
            # Store distribution plan
            self.distribution_plans[plan.backup_id] = plan
            
            logger.info(f"Distribution plan executed: {success_count}/{len(plan.shard_distributions)} shards stored")
            return success_count == len(plan.shard_distributions)
            
        except Exception as e:
            logger.error(f"Failed to execute distribution plan: {e}")
            return False
    
    async def _store_shard_on_node(self, node_id: str, storage_path: str, data: bytes) -> bool:
        """Store shard data on a specific node."""
        try:
            node = self.nodes.get(node_id)
            if not node or not node.is_available:
                return False
            
            # For local storage, write directly to file
            if node.node_type == NodeType.LOCAL:
                storage_file = Path(storage_path)
                storage_file.parent.mkdir(parents=True, exist_ok=True)
                
                with open(storage_file, 'wb') as f:
                    f.write(data)
                
                # Update node usage
                node.used_mb += len(data) // (1024 * 1024)
                return True
            
            # For remote nodes, implement API calls here
            # This would involve HTTP requests to the node's API
            logger.warning(f"Remote storage not implemented for node type {node.node_type}")
            return False
            
        except Exception as e:
            logger.error(f"Failed to store shard on node {node_id}: {e}")
            return False
    
    async def retrieve_shard(self, shard_id: str) -> Optional[bytes]:
        """Retrieve shard data from any available location."""
        try:
            distributions = self.shard_locations.get(shard_id, [])
            if not distributions:
                logger.warning(f"No locations found for shard {shard_id}")
                return None
            
            # Try each location until successful
            for distribution in distributions:
                node = self.nodes.get(distribution.node_id)
                if not node or node.status != NodeStatus.ONLINE:
                    continue
                
                try:
                    if node.node_type == NodeType.LOCAL:
                        storage_file = Path(distribution.storage_path)
                        if storage_file.exists():
                            with open(storage_file, 'rb') as f:
                                data = f.read()
                            
                            # Update access count
                            distribution.access_count += 1
                            return data
                    
                    # For remote nodes, implement API calls here
                    
                except Exception as e:
                    logger.warning(f"Failed to retrieve shard from {distribution.node_id}: {e}")
                    continue
            
            logger.error(f"Failed to retrieve shard {shard_id} from any location")
            return None
            
        except Exception as e:
            logger.error(f"Error retrieving shard {shard_id}: {e}")
            return None
    
    def get_distribution_status(self, backup_id: str) -> Dict[str, Any]:
        """Get distribution status for a backup."""
        plan = self.distribution_plans.get(backup_id)
        if not plan:
            return {"error": "Distribution plan not found"}
        
        status = {
            "backup_id": backup_id,
            "total_shards": plan.total_shards,
            "unique_nodes": len(plan.unique_nodes),
            "strategy": plan.strategy.value,
            "created_at": plan.created_at.isoformat(),
            "redundancy_factor": plan.redundancy_factor,
            "shard_status": []
        }
        
        for distribution in plan.shard_distributions:
            node = self.nodes.get(distribution.node_id)
            shard_status = {
                "shard_id": distribution.shard_id,
                "node_id": distribution.node_id,
                "node_status": node.status.value if node else "unknown",
                "stored_at": distribution.stored_at.isoformat(),
                "access_count": distribution.access_count
            }
            status["shard_status"].append(shard_status)
        
        return status
    
    def cleanup_backup_distribution(self, backup_id: str) -> bool:
        """Clean up distribution for a backup."""
        try:
            plan = self.distribution_plans.get(backup_id)
            if not plan:
                return False
            
            deleted_count = 0
            
            for distribution in plan.shard_distributions:
                # Remove shard from node
                node = self.nodes.get(distribution.node_id)
                if node and node.node_type == NodeType.LOCAL:
                    storage_file = Path(distribution.storage_path)
                    if storage_file.exists():
                        try:
                            storage_file.unlink()
                            deleted_count += 1
                        except Exception as e:
                            logger.warning(f"Failed to delete shard file {storage_file}: {e}")
                
                # Remove from shard locations
                shard_id = distribution.shard_id
                if shard_id in self.shard_locations:
                    self.shard_locations[shard_id] = [
                        d for d in self.shard_locations[shard_id] 
                        if d.node_id != distribution.node_id
                    ]
                    if not self.shard_locations[shard_id]:
                        del self.shard_locations[shard_id]
            
            # Remove distribution plan
            del self.distribution_plans[backup_id]
            
            logger.info(f"Cleaned up distribution for backup {backup_id}: {deleted_count} shards deleted")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup backup distribution: {e}")
            return False

# Export main classes
__all__ = [
    "DistributionManager",
    "StorageNode",
    "ShardDistribution",
    "DistributionPlan",
    "NodeType",
    "NodeStatus",
    "DistributionStrategy"
]
