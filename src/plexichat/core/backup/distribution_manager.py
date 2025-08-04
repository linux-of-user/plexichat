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

class AdvancedDistributionManager:
    """Advanced distribution manager with intelligent geographic distribution and automatic replication."""

    def __init__(self, storage_dir: Path, p2p_manager=None):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # P2P network integration
        self.p2p_manager = p2p_manager

        # Node management
        self.nodes: Dict[str, StorageNode] = {}
        self.distribution_plans: Dict[str, DistributionPlan] = {}
        self.shard_locations: Dict[str, List[ShardDistribution]] = {}

        # Geographic regions for intelligent distribution
        self.geographic_regions = {
            "us-east": {"nodes": set(), "capacity_gb": 0.0},
            "us-west": {"nodes": set(), "capacity_gb": 0.0},
            "europe": {"nodes": set(), "capacity_gb": 0.0},
            "asia": {"nodes": set(), "capacity_gb": 0.0},
            "other": {"nodes": set(), "capacity_gb": 0.0}
        }

        # Enhanced configuration
        self.default_strategy = DistributionStrategy.GEOGRAPHIC
        self.min_redundancy = 5  # Increased for massive scale
        self.max_redundancy = 10
        self.max_shards_per_node = 1000  # Increased for scale
        self.geographic_distribution_enabled = True
        self.auto_replication_enabled = True
        self.replication_check_interval = 3600  # 1 hour

        # Health monitoring
        self.node_health_scores: Dict[str, float] = {}
        self.failed_nodes: Set[str] = set()
        self.maintenance_nodes: Set[str] = set()

        # Statistics
        self.stats = {
            "total_distributions": 0,
            "successful_replications": 0,
            "failed_replications": 0,
            "auto_repairs": 0,
            "geographic_distributions": 0,
            "load_balanced_distributions": 0
        }

        # Initialize with local node
        self._initialize_local_node()

        # Start background tasks
        asyncio.create_task(self._monitor_node_health())
        asyncio.create_task(self._auto_replication_task())
    
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
                     metadata: Optional[Dict[str, Any]] = None,
                     geographic_region: Optional[str] = None) -> StorageNode:
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

        # Add geographic region info
        if geographic_region:
            node.metadata["geographic_region"] = geographic_region
        else:
            # Auto-detect region from location
            node.metadata["geographic_region"] = self._detect_geographic_region(location)

        # Update geographic regions
        region = node.metadata["geographic_region"]
        if region in self.geographic_regions:
            self.geographic_regions[region]["nodes"].add(node_id)
            self.geographic_regions[region]["capacity_gb"] += capacity_mb / 1024

        self.nodes[node_id] = node
        self.node_health_scores[node_id] = 100.0  # Start with perfect health

        logger.info(f"Registered storage node {node_id} ({node_type.value}) in {region} with {capacity_mb}MB capacity")
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
        elif strategy == DistributionStrategy.GEOGRAPHIC:
            return await self._create_geographic_plan(shard_set)
        elif strategy == DistributionStrategy.RANDOM:
            return self._create_random_plan(shard_set)
        elif strategy == DistributionStrategy.AFFINITY_BASED:
            return await self._create_affinity_based_plan(shard_set)
        else:
            # Default to geographic for massive scale
            return await self._create_geographic_plan(shard_set)
    
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

    async def _create_geographic_plan(self, shard_set: ShardSet) -> DistributionPlan:
        """Create geographic distribution plan for maximum redundancy."""
        distributions = []
        available_nodes = self.get_available_nodes()

        if not available_nodes:
            raise ValueError("No available storage nodes")

        # Group nodes by geographic region
        nodes_by_region = {}
        for node in available_nodes:
            region = node.metadata.get("geographic_region", "other")
            if region not in nodes_by_region:
                nodes_by_region[region] = []
            nodes_by_region[region].append(node)

        # Ensure we have nodes in multiple regions
        if len(nodes_by_region) < 2:
            logger.warning("Insufficient geographic diversity, falling back to load balanced")
            return self._create_load_balanced_plan(shard_set)

        # Create multiple copies of each shard across different regions
        for shard in shard_set.all_shards:
            shard_distributions = []
            regions_used = set()

            # Try to place copies in different regions
            for copy_index in range(self.min_redundancy):
                # Find best region that hasn't been used
                best_region = None
                best_node = None

                for region, region_nodes in nodes_by_region.items():
                    if region in regions_used and len(regions_used) < len(nodes_by_region):
                        continue  # Skip already used regions if we have alternatives

                    # Find best node in this region
                    available_region_nodes = [n for n in region_nodes
                                            if n.node_id not in [d.node_id for d in shard_distributions]]

                    if available_region_nodes:
                        # Select node with best health score and available capacity
                        region_node = max(available_region_nodes,
                                        key=lambda n: (self.node_health_scores.get(n.node_id, 0), n.available_mb))

                        if not best_node or self.node_health_scores.get(region_node.node_id, 0) > self.node_health_scores.get(best_node.node_id, 0):
                            best_region = region
                            best_node = region_node

                if best_node:
                    storage_path = f"{best_node.location}/shard_{shard.shard_id}_{copy_index}"
                    distribution = ShardDistribution(
                        shard_id=shard.shard_id,
                        node_id=best_node.node_id,
                        storage_path=storage_path,
                        stored_at=datetime.now(timezone.utc),
                        metadata={
                            "shard_type": shard.shard_type.value,
                            "copy_index": copy_index,
                            "geographic_region": best_region,
                            "distribution_strategy": "geographic"
                        }
                    )
                    shard_distributions.append(distribution)
                    regions_used.add(best_region)

                    # Update node usage
                    best_node.used_mb += shard.size // (1024 * 1024)

            distributions.extend(shard_distributions)

        self.stats["geographic_distributions"] += 1

        return DistributionPlan(
            backup_id=shard_set.backup_id,
            shard_distributions=distributions,
            strategy=DistributionStrategy.GEOGRAPHIC,
            created_at=datetime.now(timezone.utc),
            redundancy_factor=len(set(d.metadata.get("geographic_region") for d in distributions))
        )

    async def _create_affinity_based_plan(self, shard_set: ShardSet) -> DistributionPlan:
        """Create affinity-based distribution plan considering node relationships."""
        distributions = []
        available_nodes = self.get_available_nodes()

        if not available_nodes:
            raise ValueError("No available storage nodes")

        # Calculate node affinity scores based on user relationships, geographic proximity, etc.
        node_affinities = await self._calculate_node_affinities(available_nodes)

        for shard in shard_set.all_shards:
            # Select nodes with diverse affinities to minimize correlated failures
            selected_nodes = self._select_diverse_nodes(available_nodes, node_affinities, self.min_redundancy)

            for i, node in enumerate(selected_nodes):
                storage_path = f"{node.location}/shard_{shard.shard_id}_{i}"
                distribution = ShardDistribution(
                    shard_id=shard.shard_id,
                    node_id=node.node_id,
                    storage_path=storage_path,
                    stored_at=datetime.now(timezone.utc),
                    metadata={
                        "shard_type": shard.shard_type.value,
                        "copy_index": i,
                        "affinity_score": node_affinities.get(node.node_id, 0.0),
                        "distribution_strategy": "affinity_based"
                    }
                )
                distributions.append(distribution)

                # Update node usage
                node.used_mb += shard.size // (1024 * 1024)

        return DistributionPlan(
            backup_id=shard_set.backup_id,
            shard_distributions=distributions,
            strategy=DistributionStrategy.AFFINITY_BASED,
            created_at=datetime.now(timezone.utc),
            redundancy_factor=len(set(d.node_id for d in distributions))
        )

    def _detect_geographic_region(self, location: str) -> str:
        """Detect geographic region from location string."""
        location_lower = location.lower()

        if any(term in location_lower for term in ["us-east", "east", "virginia", "ohio", "new york"]):
            return "us-east"
        elif any(term in location_lower for term in ["us-west", "west", "california", "oregon", "nevada"]):
            return "us-west"
        elif any(term in location_lower for term in ["europe", "eu", "london", "frankfurt", "paris", "ireland"]):
            return "europe"
        elif any(term in location_lower for term in ["asia", "tokyo", "singapore", "mumbai", "seoul"]):
            return "asia"
        else:
            return "other"

    async def _calculate_node_affinities(self, nodes: List[StorageNode]) -> Dict[str, float]:
        """Calculate affinity scores between nodes."""
        affinities = {}

        for node in nodes:
            score = 0.0

            # Geographic diversity bonus
            region = node.metadata.get("geographic_region", "other")
            region_count = len(self.geographic_regions[region]["nodes"])
            if region_count > 0:
                score += 100.0 / region_count  # Higher score for less populated regions

            # Health score factor
            score += self.node_health_scores.get(node.node_id, 50.0)

            # Capacity factor
            if node.capacity_mb > 0:
                score += (node.available_mb / node.capacity_mb) * 50.0

            # User diversity (if different users, higher score)
            if node.user_id:
                user_node_count = len([n for n in nodes if n.user_id == node.user_id])
                score += 50.0 / user_node_count

            affinities[node.node_id] = score

        return affinities

    def _select_diverse_nodes(self, available_nodes: List[StorageNode],
                            affinities: Dict[str, float], count: int) -> List[StorageNode]:
        """Select diverse nodes to minimize correlated failures."""
        if len(available_nodes) <= count:
            return available_nodes

        selected = []
        remaining = available_nodes.copy()

        # First, select the highest affinity node
        best_node = max(remaining, key=lambda n: affinities.get(n.node_id, 0.0))
        selected.append(best_node)
        remaining.remove(best_node)

        # Then select nodes that are most diverse from already selected ones
        while len(selected) < count and remaining:
            best_candidate = None
            best_diversity_score = -1

            for candidate in remaining:
                diversity_score = 0.0

                for selected_node in selected:
                    # Geographic diversity
                    if (candidate.metadata.get("geographic_region") !=
                        selected_node.metadata.get("geographic_region")):
                        diversity_score += 50.0

                    # User diversity
                    if candidate.user_id != selected_node.user_id:
                        diversity_score += 30.0

                    # Network diversity (different endpoints)
                    if candidate.location != selected_node.location:
                        diversity_score += 20.0

                # Add base affinity score
                diversity_score += affinities.get(candidate.node_id, 0.0) * 0.1

                if diversity_score > best_diversity_score:
                    best_diversity_score = diversity_score
                    best_candidate = candidate

            if best_candidate:
                selected.append(best_candidate)
                remaining.remove(best_candidate)
            else:
                break

        return selected

    async def _monitor_node_health(self):
        """Background task to monitor node health."""
        while True:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes

                for node_id, node in self.nodes.items():
                    health_score = await self._check_node_health(node)
                    self.node_health_scores[node_id] = health_score

                    # Update node status based on health
                    if health_score < 20.0:
                        node.status = NodeStatus.UNREACHABLE
                        self.failed_nodes.add(node_id)
                    elif health_score < 50.0:
                        node.status = NodeStatus.OVERLOADED
                    else:
                        node.status = NodeStatus.ONLINE
                        self.failed_nodes.discard(node_id)

            except Exception as e:
                logger.error(f"Node health monitoring error: {e}")

    async def _check_node_health(self, node: StorageNode) -> float:
        """Check health of a specific node."""
        health_score = 100.0

        try:
            # Check if node is reachable
            if self.p2p_manager:
                # Use P2P manager to ping node
                response_time = await self._ping_node(node.node_id)
                if response_time is None:
                    health_score -= 50.0  # Unreachable
                elif response_time > 5000:  # 5 seconds
                    health_score -= 30.0  # Very slow
                elif response_time > 1000:  # 1 second
                    health_score -= 15.0  # Slow

            # Check storage usage
            if node.usage_percent > 95.0:
                health_score -= 40.0  # Nearly full
            elif node.usage_percent > 85.0:
                health_score -= 20.0  # Getting full

            # Check last seen time
            time_since_seen = datetime.now(timezone.utc) - node.last_seen
            if time_since_seen.total_seconds() > 3600:  # 1 hour
                health_score -= 25.0
            elif time_since_seen.total_seconds() > 300:  # 5 minutes
                health_score -= 10.0

        except Exception as e:
            logger.error(f"Health check failed for node {node.node_id}: {e}")
            health_score = 0.0

        return max(0.0, health_score)

    async def _ping_node(self, node_id: str) -> Optional[float]:
        """Ping a node and return response time in milliseconds."""
        if self.p2p_manager:
            try:
                start_time = time.time()
                # Use P2P manager to send health check
                success = await self.p2p_manager._health_check_node(node_id)
                response_time = (time.time() - start_time) * 1000
                return response_time if success else None
            except:
                return None
        return None

    async def _auto_replication_task(self):
        """Background task for automatic shard replication."""
        while True:
            try:
                await asyncio.sleep(self.replication_check_interval)

                if self.auto_replication_enabled:
                    await self._check_and_repair_replications()

            except Exception as e:
                logger.error(f"Auto replication task error: {e}")

    async def _check_and_repair_replications(self):
        """Check and repair under-replicated shards."""
        try:
            repairs_needed = 0
            repairs_completed = 0

            for backup_id, plan in self.distribution_plans.items():
                # Group distributions by shard
                shard_distributions = {}
                for dist in plan.shard_distributions:
                    if dist.shard_id not in shard_distributions:
                        shard_distributions[dist.shard_id] = []
                    shard_distributions[dist.shard_id].append(dist)

                # Check each shard's replication level
                for shard_id, distributions in shard_distributions.items():
                    # Count healthy replicas
                    healthy_replicas = [
                        dist for dist in distributions
                        if (dist.node_id not in self.failed_nodes and
                            self.node_health_scores.get(dist.node_id, 0) > 50.0)
                    ]

                    if len(healthy_replicas) < self.min_redundancy:
                        repairs_needed += 1

                        # Attempt to create additional replicas
                        if await self._replicate_shard(shard_id, backup_id,
                                                     self.min_redundancy - len(healthy_replicas)):
                            repairs_completed += 1
                            self.stats["auto_repairs"] += 1

            if repairs_needed > 0:
                logger.info(f"Auto-replication: {repairs_completed}/{repairs_needed} repairs completed")

        except Exception as e:
            logger.error(f"Replication check and repair failed: {e}")

    async def _replicate_shard(self, shard_id: str, backup_id: str, copies_needed: int) -> bool:
        """Create additional replicas of a shard."""
        try:
            if not self.p2p_manager:
                return False

            # Try to retrieve shard data from existing replicas
            shard_data = await self.p2p_manager.request_shard(shard_id, backup_id)

            if not shard_data:
                logger.error(f"Could not retrieve shard {shard_id} for replication")
                return False

            # Find suitable nodes for new replicas
            available_nodes = self.get_available_nodes()
            existing_nodes = set()

            # Get nodes that already have this shard
            if backup_id in self.distribution_plans:
                for dist in self.distribution_plans[backup_id].shard_distributions:
                    if dist.shard_id == shard_id:
                        existing_nodes.add(dist.node_id)

            # Filter out nodes that already have the shard
            candidate_nodes = [n for n in available_nodes if n.node_id not in existing_nodes]

            if len(candidate_nodes) < copies_needed:
                logger.warning(f"Insufficient nodes for shard replication: need {copies_needed}, have {len(candidate_nodes)}")
                copies_needed = len(candidate_nodes)

            # Select best nodes for replication
            selected_nodes = self._select_diverse_nodes(candidate_nodes,
                                                      await self._calculate_node_affinities(candidate_nodes),
                                                      copies_needed)

            # Offer shard to selected nodes
            if self.p2p_manager:
                offer_results = await self.p2p_manager.offer_shard(
                    shard_id, backup_id, shard_data,
                    [n.node_id for n in selected_nodes], copies_needed
                )

                successful_offers = sum(1 for success in offer_results.values() if success)

                if successful_offers > 0:
                    self.stats["successful_replications"] += successful_offers
                    logger.info(f"Successfully replicated shard {shard_id} to {successful_offers} additional nodes")
                    return True
                else:
                    self.stats["failed_replications"] += 1
                    return False

            return False

        except Exception as e:
            logger.error(f"Shard replication failed: {e}")
            self.stats["failed_replications"] += 1
            return False

    def get_advanced_stats(self) -> Dict[str, Any]:
        """Get advanced distribution statistics."""
        stats = self.stats.copy()

        # Geographic distribution stats
        geographic_stats = {}
        for region, info in self.geographic_regions.items():
            geographic_stats[region] = {
                "node_count": len(info["nodes"]),
                "total_capacity_gb": info["capacity_gb"],
                "average_health": sum(self.node_health_scores.get(nid, 0) for nid in info["nodes"]) / len(info["nodes"]) if info["nodes"] else 0
            }

        stats.update({
            "total_nodes": len(self.nodes),
            "healthy_nodes": len([nid for nid, score in self.node_health_scores.items() if score > 70.0]),
            "failed_nodes": len(self.failed_nodes),
            "geographic_regions": geographic_stats,
            "average_redundancy": sum(len(plan.shard_distributions) for plan in self.distribution_plans.values()) / len(self.distribution_plans) if self.distribution_plans else 0,
            "auto_replication_enabled": self.auto_replication_enabled,
            "geographic_distribution_enabled": self.geographic_distribution_enabled
        })

        return stats

# Backward compatibility alias
DistributionManager = AdvancedDistributionManager

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
