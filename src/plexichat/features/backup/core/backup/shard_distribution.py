import asyncio
import hashlib
import secrets
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from ...core.config import get_config
from ...core.logging import get_logger
from ..security.quantum_encryption import EncryptedData, QuantumEncryptionEngine

"""
Intelligent Shard Distribution System for NetLink

AI-powered shard distribution with geographic redundancy, automatic rebalancing,
and intelligent placement based on access patterns and node capabilities.
"""

logger = get_logger(__name__)


class ShardStatus(Enum):
    """Shard status enumeration."""
    CREATING = "creating"
    ACTIVE = "active"
    REPLICATING = "replicating"
    MIGRATING = "migrating"
    CORRUPTED = "corrupted"
    ARCHIVED = "archived"
    DELETED = "deleted"


class NodeCapability(Enum):
    """Node capability types."""
    STORAGE = "storage"
    BANDWIDTH = "bandwidth"
    COMPUTE = "compute"
    RELIABILITY = "reliability"
    GEOGRAPHIC = "geographic"


class DistributionStrategy(Enum):
    """Shard distribution strategies."""
    BALANCED = "balanced"           # Even distribution across nodes
    PROXIMITY = "proximity"         # Prefer geographically close nodes
    PERFORMANCE = "performance"     # Optimize for access speed
    RELIABILITY = "reliability"     # Maximize redundancy
    COST_OPTIMIZED = "cost_optimized"  # Minimize storage costs
    AI_OPTIMIZED = "ai_optimized"   # AI-driven optimization


@dataclass
class GeographicLocation:
    """Geographic location information."""
    region: str
    country: str
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None


@dataclass
class NodeCapabilities:
    """Node capability metrics."""
    storage_capacity: int  # GB
    available_storage: int  # GB
    bandwidth_mbps: int
    cpu_cores: int
    memory_gb: int
    reliability_score: float  # 0.0 - 1.0
    uptime_percentage: float  # 0.0 - 100.0
    geographic_location: GeographicLocation
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class BackupNode:
    """Backup network node."""
    node_id: str
    node_type: str  # primary, secondary, witness
    address: str
    port: int
    capabilities: NodeCapabilities
    is_active: bool = True
    trust_score: float = 1.0  # 0.0 - 1.0
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataShard:
    """Data shard with metadata."""
    shard_id: str
    data_hash: str
    size_bytes: int
    created_at: datetime
    last_accessed: datetime
    access_count: int = 0
    status: ShardStatus = ShardStatus.CREATING
    replicas: List[str] = field(default_factory=list)  # Node IDs
    encryption_context: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AccessPattern:
    """Data access pattern analysis."""
    shard_id: str
    access_frequency: float  # accesses per hour
    access_locations: List[str]  # geographic regions
    access_times: List[datetime]  # recent access timestamps
    user_patterns: Dict[str, int]  # user_id -> access_count
    bandwidth_usage: float  # MB/hour
    last_analyzed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class IntelligentShardDistributor:
    """
    AI-powered intelligent shard distribution system.
    
    Features:
    - Geographic redundancy optimization
    - Access pattern analysis
    - Automatic load balancing
    - Node capability matching
    - Predictive placement
    - Cost optimization
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._load_default_config()
        
        # Core components
        self.nodes: Dict[str, BackupNode] = {}
        self.shards: Dict[str, DataShard] = {}
        self.access_patterns: Dict[str, AccessPattern] = {}
        
        # Distribution settings
        self.redundancy_factor = self.config.get("redundancy_factor", 3)
        self.min_geographic_spread = self.config.get("min_geographic_spread", 2)
        self.rebalancing_threshold = self.config.get("rebalancing_threshold", 0.8)
        self.strategy = DistributionStrategy(self.config.get("strategy", "ai_optimized"))
        
        # AI/ML components
        self.placement_model = None
        self.access_predictor = None
        self.load_balancer = None
        
        # Performance tracking
        self.placement_history = deque(maxlen=1000)
        self.performance_metrics = defaultdict(list)
        
        # Initialize encryption engine
        self.encryption_engine = QuantumEncryptionEngine()
        
        logger.info(f" Intelligent Shard Distributor initialized with {self.strategy.value} strategy")
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default shard distribution configuration."""
        return {
            "redundancy_factor": 3,
            "min_geographic_spread": 2,
            "rebalancing_threshold": 0.8,
            "strategy": "ai_optimized",
            "max_shard_size": 67108864,  # 64MB
            "min_shard_size": 16777216,  # 16MB
            "enable_compression": True,
            "enable_deduplication": True,
            "enable_ai_placement": True,
            "rebalancing_interval": 3600,  # 1 hour
            "access_pattern_window": 168   # 1 week in hours
        }
    
    async def initialize_distribution_system(self) -> Dict[str, Any]:
        """Initialize the intelligent distribution system."""
        try:
            logger.info(" Initializing intelligent shard distribution system...")
            
            # Initialize AI models
            await self._initialize_ai_models()
            
            # Discover available nodes
            await self._discover_backup_nodes()
            
            # Analyze existing shards
            await self._analyze_existing_shards()
            
            # Start background tasks
            await self._start_background_tasks()
            
            logger.info(f" Distribution system initialized with {len(self.nodes)} nodes")
            
            return {
                "success": True,
                "nodes_discovered": len(self.nodes),
                "shards_analyzed": len(self.shards),
                "strategy": self.strategy.value,
                "redundancy_factor": self.redundancy_factor
            }
            
        except Exception as e:
            logger.error(f" Failed to initialize distribution system: {e}")
            return {"success": False, "error": str(e)}
    
    async def _initialize_ai_models(self):
        """Initialize AI/ML models for intelligent placement."""
        try:
            # Placeholder for actual ML model initialization
            # In production, load pre-trained models or initialize new ones
            
            self.placement_model = {
                "type": "decision_tree",
                "features": ["storage_capacity", "bandwidth", "reliability", "geographic_distance"],
                "weights": [0.3, 0.25, 0.25, 0.2],
                "trained": False
            }
            
            self.access_predictor = {
                "type": "time_series",
                "window_size": 168,  # 1 week
                "features": ["hour_of_day", "day_of_week", "user_activity"],
                "accuracy": 0.0
            }
            
            self.load_balancer = {
                "type": "reinforcement_learning",
                "state_space": ["node_load", "network_latency", "storage_usage"],
                "action_space": ["migrate", "replicate", "archive"],
                "learning_rate": 0.01
            }
            
            logger.info(" AI models initialized for intelligent placement")
            
        except Exception as e:
            logger.error(f" Failed to initialize AI models: {e}")
    
    async def _discover_backup_nodes(self):
        """Discover available backup nodes in the network."""
        # Placeholder for node discovery
        # In production, this would use network discovery protocols
        
        # Create some example nodes for testing
        example_nodes = [
            {
                "node_id": "node_us_east_1",
                "address": "10.0.1.100",
                "region": "us-east-1",
                "storage_gb": 1000,
                "bandwidth_mbps": 1000
            },
            {
                "node_id": "node_eu_west_1", 
                "address": "10.0.2.100",
                "region": "eu-west-1",
                "storage_gb": 2000,
                "bandwidth_mbps": 500
            },
            {
                "node_id": "node_ap_south_1",
                "address": "10.0.3.100", 
                "region": "ap-south-1",
                "storage_gb": 1500,
                "bandwidth_mbps": 750
            }
        ]
        
        for node_data in example_nodes:
            node = BackupNode(
                node_id=node_data["node_id"],
                node_type="primary",
                address=node_data["address"],
                port=8765,
                capabilities=NodeCapabilities(
                    storage_capacity=node_data["storage_gb"],
                    available_storage=int(node_data["storage_gb"] * 0.8),
                    bandwidth_mbps=node_data["bandwidth_mbps"],
                    cpu_cores=8,
                    memory_gb=32,
                    reliability_score=0.95,
                    uptime_percentage=99.5,
                    geographic_location=GeographicLocation(
                        region=node_data["region"],
                        country="Unknown"
                    )
                )
            )
            
            self.nodes[node.node_id] = node
        
        logger.info(f" Discovered {len(self.nodes)} backup nodes")
    
    async def _analyze_existing_shards(self):
        """Analyze existing shards for optimization opportunities."""
        # Placeholder for shard analysis
        logger.info(" Analyzing existing shards for optimization")
    
    async def _start_background_tasks(self):
        """Start background tasks for monitoring and optimization."""
        # Start rebalancing task
        asyncio.create_task(self._rebalancing_loop())
        
        # Start access pattern analysis
        asyncio.create_task(self._access_pattern_analysis_loop())
        
        # Start node monitoring
        asyncio.create_task(self._node_monitoring_loop())
        
        logger.info(" Background optimization tasks started")
    
    async def distribute_shard(self, data: bytes, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Distribute a data shard using intelligent placement."""
        try:
            # Generate shard ID
            shard_id = f"shard_{secrets.token_hex(16)}"
            data_hash = hashlib.sha256(data).hexdigest()
            
            # Encrypt shard data
            encrypted_data = await self.encryption_engine.encrypt_data(data)
            
            # Select optimal nodes for placement
            selected_nodes = await self._select_optimal_nodes(
                data_size=len(data),
                metadata=metadata or {}
            )
            
            if len(selected_nodes) < self.redundancy_factor:
                raise ValueError(f"Insufficient nodes: need {self.redundancy_factor}, found {len(selected_nodes)}")
            
            # Create shard record
            shard = DataShard(
                shard_id=shard_id,
                data_hash=data_hash,
                size_bytes=len(data),
                created_at=datetime.now(timezone.utc),
                last_accessed=datetime.now(timezone.utc),
                replicas=selected_nodes,
                encryption_context={
                    "algorithm": encrypted_data.context.algorithm.value,
                    "key_ids": encrypted_data.context.key_ids
                },
                metadata=metadata or {}
            )
            
            # Store shard on selected nodes
            placement_results = await self._store_shard_replicas(shard, encrypted_data)
            
            # Update shard status
            if all(result["success"] for result in placement_results):
                shard.status = ShardStatus.ACTIVE
                self.shards[shard_id] = shard
                
                # Record successful placement
                await self._record_placement_success(shard, selected_nodes)
                
                logger.info(f" Shard {shard_id} distributed to {len(selected_nodes)} nodes")
                
                return {
                    "success": True,
                    "shard_id": shard_id,
                    "replicas": selected_nodes,
                    "size_bytes": len(data),
                    "encrypted": True
                }
            else:
                # Handle partial failures
                failed_nodes = [r["node_id"] for r in placement_results if not r["success"]]
                logger.warning(f" Partial failure distributing shard {shard_id}: {failed_nodes}")
                
                return {
                    "success": False,
                    "error": "Partial placement failure",
                    "failed_nodes": failed_nodes
                }
                
        except Exception as e:
            logger.error(f" Failed to distribute shard: {e}")
            return {"success": False, "error": str(e)}
    
    async def _select_optimal_nodes(self, data_size: int, metadata: Dict[str, Any]) -> List[str]:
        """Select optimal nodes for shard placement using AI."""
        try:
            # Get available nodes with sufficient capacity
            candidate_nodes = []
            for node_id, node in self.nodes.items():
                if (node.is_active and 
                    node.capabilities.available_storage * 1024 * 1024 * 1024 >= data_size):
                    candidate_nodes.append(node_id)
            
            if len(candidate_nodes) < self.redundancy_factor:
                raise ValueError(f"Insufficient candidate nodes: {len(candidate_nodes)}")
            
            # Apply AI-powered selection based on strategy
            if self.strategy == DistributionStrategy.AI_OPTIMIZED:
                selected = await self._ai_node_selection(candidate_nodes, data_size, metadata)
            elif self.strategy == DistributionStrategy.GEOGRAPHIC:
                selected = await self._geographic_node_selection(candidate_nodes)
            elif self.strategy == DistributionStrategy.PERFORMANCE:
                selected = await self._performance_node_selection(candidate_nodes)
            else:
                # Default balanced selection
                selected = await self._balanced_node_selection(candidate_nodes)
            
            return selected[:self.redundancy_factor]
            
        except Exception as e:
            logger.error(f" Node selection failed: {e}")
            raise
    
    async def _ai_node_selection(self, candidates: List[str], data_size: int, metadata: Dict[str, Any]) -> List[str]:
        """AI-powered node selection."""
        # Placeholder for actual AI model inference
        # For now, use a scoring system based on multiple factors
        
        node_scores = {}
        
        for node_id in candidates:
            node = self.nodes[node_id]
            
            # Calculate composite score
            storage_score = node.capabilities.available_storage / node.capabilities.storage_capacity
            reliability_score = node.capabilities.reliability_score
            bandwidth_score = min(node.capabilities.bandwidth_mbps / 1000, 1.0)
            uptime_score = node.capabilities.uptime_percentage / 100
            
            # Weighted composite score
            composite_score = (
                storage_score * 0.3 +
                reliability_score * 0.3 +
                bandwidth_score * 0.2 +
                uptime_score * 0.2
            )
            
            node_scores[node_id] = composite_score
        
        # Select top scoring nodes with geographic diversity
        sorted_nodes = sorted(node_scores.items(), key=lambda x: x[1], reverse=True)
        selected = []
        used_regions = set()
        
        for node_id, score in sorted_nodes:
            node = self.nodes[node_id]
            region = node.capabilities.geographic_location.region
            
            # Ensure geographic diversity
            if len(selected) < self.min_geographic_spread or region not in used_regions:
                selected.append(node_id)
                used_regions.add(region)
                
                if len(selected) >= self.redundancy_factor:
                    break
        
        return selected
    
    async def _geographic_node_selection(self, candidates: List[str]) -> List[str]:
        """Geographic diversity-focused node selection."""
        regions = defaultdict(list)
        
        for node_id in candidates:
            node = self.nodes[node_id]
            region = node.capabilities.geographic_location.region
            regions[region].append(node_id)
        
        selected = []
        for region, nodes in regions.items():
            if selected and len(selected) >= self.redundancy_factor:
                break
            # Select best node from each region
            best_node = max(nodes, key=lambda n: self.nodes[n].capabilities.reliability_score)
            selected.append(best_node)
        
        return selected
    
    async def _performance_node_selection(self, candidates: List[str]) -> List[str]:
        """Performance-optimized node selection."""
        # Sort by bandwidth and reliability
        sorted_candidates = sorted(
            candidates,
            key=lambda n: (
                self.nodes[n].capabilities.bandwidth_mbps,
                self.nodes[n].capabilities.reliability_score
            ),
            reverse=True
        )
        
        return sorted_candidates[:self.redundancy_factor]
    
    async def _balanced_node_selection(self, candidates: List[str]) -> List[str]:
        """Balanced node selection."""
        # Simple round-robin selection
        return candidates[:self.redundancy_factor]
    
    async def _store_shard_replicas(self, shard: DataShard, encrypted_data: EncryptedData) -> List[Dict[str, Any]]:
        """Store shard replicas on selected nodes."""
        results = []
        
        for node_id in shard.replicas:
            try:
                # In production, this would make network calls to store data
                # For now, simulate storage
                result = await self._simulate_shard_storage(node_id, shard, encrypted_data)
                results.append(result)
                
            except Exception as e:
                logger.error(f" Failed to store shard on node {node_id}: {e}")
                results.append({
                    "node_id": node_id,
                    "success": False,
                    "error": str(e)
                })
        
        return results
    
    async def _simulate_shard_storage(self, node_id: str, shard: DataShard, encrypted_data: EncryptedData) -> Dict[str, Any]:
        """Simulate shard storage on a node."""
        # Simulate network delay
        await asyncio.sleep(0.1)
        
        # Update node storage
        node = self.nodes[node_id]
        storage_used_gb = shard.size_bytes / (1024 * 1024 * 1024)
        node.capabilities.available_storage -= storage_used_gb
        
        return {
            "node_id": node_id,
            "success": True,
            "storage_path": f"/backup/shards/{shard.shard_id}",
            "stored_at": datetime.now(timezone.utc).isoformat()
        }
    
    async def _record_placement_success(self, shard: DataShard, selected_nodes: List[str]):
        """Record successful shard placement for ML training."""
        placement_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "shard_id": shard.shard_id,
            "size_bytes": shard.size_bytes,
            "selected_nodes": selected_nodes,
            "strategy": self.strategy.value,
            "success": True
        }
        
        self.placement_history.append(placement_record)
    
    async def _rebalancing_loop(self):
        """Background task for automatic shard rebalancing."""
        while True:
            try:
                await asyncio.sleep(self.config.get("rebalancing_interval", 3600))
                await self._perform_rebalancing()
                
            except Exception as e:
                logger.error(f" Rebalancing loop error: {e}")
    
    async def _access_pattern_analysis_loop(self):
        """Background task for access pattern analysis."""
        while True:
            try:
                await asyncio.sleep(1800)  # 30 minutes
                await self._analyze_access_patterns()
                
            except Exception as e:
                logger.error(f" Access pattern analysis error: {e}")
    
    async def _node_monitoring_loop(self):
        """Background task for node health monitoring."""
        while True:
            try:
                await asyncio.sleep(300)  # 5 minutes
                await self._monitor_node_health()
                
            except Exception as e:
                logger.error(f" Node monitoring error: {e}")
    
    async def _perform_rebalancing(self):
        """Perform intelligent shard rebalancing."""
        logger.info(" Starting intelligent shard rebalancing...")
        
        # Analyze current distribution
        distribution_analysis = await self._analyze_current_distribution()
        
        if distribution_analysis["needs_rebalancing"]:
            # Identify shards to migrate
            migration_plan = await self._create_migration_plan(distribution_analysis)
            
            # Execute migrations
            await self._execute_migration_plan(migration_plan)
            
            logger.info(f" Rebalancing completed: {len(migration_plan)} migrations")
        else:
            logger.info(" Distribution is optimal, no rebalancing needed")
    
    async def _analyze_current_distribution(self) -> Dict[str, Any]:
        """Analyze current shard distribution for optimization opportunities."""
        # Calculate node utilization
        node_utilization = {}
        for node_id, node in self.nodes.items():
            used_storage = node.capabilities.storage_capacity - node.capabilities.available_storage
            utilization = used_storage / node.capabilities.storage_capacity
            node_utilization[node_id] = utilization
        
        # Check if rebalancing is needed
        max_utilization = max(node_utilization.values()) if node_utilization else 0
        min_utilization = min(node_utilization.values()) if node_utilization else 0
        utilization_variance = max_utilization - min_utilization
        
        needs_rebalancing = utilization_variance > self.rebalancing_threshold
        
        return {
            "needs_rebalancing": needs_rebalancing,
            "utilization_variance": utilization_variance,
            "node_utilization": node_utilization,
            "overloaded_nodes": [n for n, u in node_utilization.items() if u > 0.9],
            "underloaded_nodes": [n for n, u in node_utilization.items() if u < 0.3]
        }
    
    async def _create_migration_plan(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create intelligent migration plan."""
        migration_plan = []
        
        # Simple migration strategy: move shards from overloaded to underloaded nodes
        overloaded = analysis["overloaded_nodes"]
        underloaded = analysis["underloaded_nodes"]
        
        for overloaded_node in overloaded:
            for underloaded_node in underloaded:
                # Find shards to migrate
                shards_to_migrate = [
                    shard for shard in self.shards.values()
                    if overloaded_node in shard.replicas and len(shard.replicas) > self.redundancy_factor
                ]
                
                if shards_to_migrate:
                    migration_plan.append({
                        "shard_id": shards_to_migrate[0].shard_id,
                        "from_node": overloaded_node,
                        "to_node": underloaded_node,
                        "reason": "load_balancing"
                    })
                    break
        
        return migration_plan
    
    async def _execute_migration_plan(self, migration_plan: List[Dict[str, Any]]):
        """Execute shard migration plan."""
        for migration in migration_plan:
            try:
                await self._migrate_shard(
                    migration["shard_id"],
                    migration["from_node"],
                    migration["to_node"]
                )
                logger.info(f" Migrated shard {migration['shard_id']} from {migration['from_node']} to {migration['to_node']}")
                
            except Exception as e:
                logger.error(f" Migration failed for shard {migration['shard_id']}: {e}")
    
    async def _migrate_shard(self, shard_id: str, from_node: str, to_node: str):
        """Migrate a shard from one node to another."""
        # In production, this would involve:
        # 1. Copy shard data from source to destination
        # 2. Verify integrity
        # 3. Update shard replica list
        # 4. Delete from source node
        
        # For now, simulate migration
        await asyncio.sleep(1)  # Simulate migration time
        
        # Update shard replica list
        if shard_id in self.shards:
            shard = self.shards[shard_id]
            if from_node in shard.replicas:
                shard.replicas.remove(from_node)
            if to_node not in shard.replicas:
                shard.replicas.append(to_node)
    
    async def _analyze_access_patterns(self):
        """Analyze shard access patterns for optimization."""
        logger.info(" Analyzing access patterns...")
        
        # This would analyze actual access logs
        # For now, simulate pattern analysis
        for shard_id, shard in self.shards.items():
            if shard_id not in self.access_patterns:
                self.access_patterns[shard_id] = AccessPattern(
                    shard_id=shard_id,
                    access_frequency=1.0,  # Default frequency
                    access_locations=["us-east-1"],
                    access_times=[datetime.now(timezone.utc)],
                    user_patterns={},
                    bandwidth_usage=0.1
                )
    
    async def _monitor_node_health(self):
        """Monitor backup node health and availability."""
        logger.debug(" Monitoring node health...")
        
        for node_id, node in self.nodes.items():
            # In production, this would ping nodes and check health
            # For now, simulate health checks
            node.last_seen = datetime.now(timezone.utc)
            
            # Simulate occasional node issues
            if secrets.randbelow(1000) < 1:  # 0.1% chance
                node.is_active = False
                logger.warning(f" Node {node_id} appears to be offline")
    
    async def get_distribution_status(self) -> Dict[str, Any]:
        """Get current distribution system status."""
        total_shards = len(self.shards)
        active_nodes = sum(1 for node in self.nodes.values() if node.is_active)
        total_storage = sum(node.capabilities.storage_capacity for node in self.nodes.values())
        used_storage = sum(node.capabilities.storage_capacity - node.capabilities.available_storage 
                          for node in self.nodes.values())
        
        return {
            "total_shards": total_shards,
            "active_nodes": active_nodes,
            "total_nodes": len(self.nodes),
            "storage_utilization": (used_storage / total_storage * 100) if total_storage > 0 else 0,
            "redundancy_factor": self.redundancy_factor,
            "distribution_strategy": self.strategy.value,
            "rebalancing_enabled": True,
            "ai_optimization": self.config.get("enable_ai_placement", True)
        }


# Global distributor instance
_shard_distributor: Optional[IntelligentShardDistributor] = None


def get_shard_distributor() -> IntelligentShardDistributor:
    """Get the global shard distributor instance."""
    global _shard_distributor
    if _shard_distributor is None:
        config = get_config().get("shard_distribution", {})
        _shard_distributor = IntelligentShardDistributor(config)
    return _shard_distributor
