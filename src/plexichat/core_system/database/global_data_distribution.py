import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


"""
NetLink Global Data Distribution System

Advanced global data distribution with:
- Multi-region data replication
- Intelligent data placement based on access patterns
- Conflict-free replicated data types (CRDTs)
- Global consistency models (eventual, strong, causal)
- Automatic failover and disaster recovery
- Data sovereignty and compliance management
"""

logger = logging.getLogger(__name__)


class ConsistencyModel(Enum):
    """Global consistency models."""
    EVENTUAL = "eventual"
    STRONG = "strong"
    CAUSAL = "causal"
    MONOTONIC_READ = "monotonic_read"
    MONOTONIC_WRITE = "monotonic_write"
    READ_YOUR_WRITES = "read_your_writes"
    WRITES_FOLLOW_READS = "writes_follow_reads"


class ReplicationStrategy(Enum):
    """Data replication strategies."""
    MASTER_SLAVE = "master_slave"
    MASTER_MASTER = "master_master"
    QUORUM_BASED = "quorum_based"
    EVENTUAL_CONSISTENCY = "eventual_consistency"
    CONFLICT_FREE = "conflict_free"


class DataLocality(Enum):
    """Data locality preferences."""
    GLOBAL = "global"
    REGIONAL = "regional"
    LOCAL = "local"
    USER_BASED = "user_based"
    COMPLIANCE_BASED = "compliance_based"


@dataclass
class DataRegion:
    """Global data region configuration."""
    region_id: str
    region_name: str
    location: str  # Geographic location
    compliance_zones: List[str]  # GDPR, CCPA, etc.
    latency_ms: float
    bandwidth_mbps: float
    storage_capacity_gb: int
    compute_capacity: float
    is_primary: bool = False
    is_active: bool = True
    
    def is_compliant_for(self, compliance_requirements: List[str]) -> bool:
        """Check if region meets compliance requirements."""
        return all(req in self.compliance_zones for req in compliance_requirements)


@dataclass
class DataPlacement:
    """Data placement decision."""
    data_id: str
    data_type: str
    primary_region: str
    replica_regions: List[str]
    consistency_model: ConsistencyModel
    replication_strategy: ReplicationStrategy
    access_pattern: Dict[str, Any]
    compliance_requirements: List[str]
    placement_score: float
    placement_reason: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ConflictResolutionRule:
    """Conflict resolution rule for distributed data."""
    rule_id: str
    data_type: str
    field_name: str
    resolution_strategy: str  # "last_write_wins", "merge", "custom"
    custom_resolver: Optional[str] = None  # Function name for custom resolution
    priority: int = 0


@dataclass
class GlobalTransaction:
    """Global distributed transaction."""
    transaction_id: str
    operations: List[Dict[str, Any]]
    participating_regions: Set[str]
    consistency_level: ConsistencyModel
    started_at: datetime
    timeout_seconds: int = 30
    status: str = "PENDING"  # PENDING, COMMITTED, ABORTED
    coordinator_region: Optional[str] = None


class VectorClock:
    """Vector clock for causal consistency."""
    
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.clock: Dict[str, int] = {node_id: 0}
    
    def tick(self):
        """Increment local clock."""
        self.clock[self.node_id] += 1
    
    def update(self, other_clock: Dict[str, int]):
        """Update clock with received clock."""
        for node_id, timestamp in other_clock.items():
            self.clock[node_id] = max(self.clock.get(node_id, 0), timestamp)
        self.tick()
    
    def compare(self, other_clock: Dict[str, int]) -> str:
        """Compare with another clock."""
        self_dominates = False
        other_dominates = False
        
        all_nodes = set(self.clock.keys()) | set(other_clock.keys())
        
        for node_id in all_nodes:
            self_time = self.clock.get(node_id, 0)
            other_time = other_clock.get(node_id, 0)
            
            if self_time > other_time:
                self_dominates = True
            elif self_time < other_time:
                other_dominates = True
        
        if self_dominates and not other_dominates:
            return "AFTER"
        elif other_dominates and not self_dominates:
            return "BEFORE"
        elif not self_dominates and not other_dominates:
            return "EQUAL"
        else:
            return "CONCURRENT"


class CRDTManager:
    """Manages Conflict-free Replicated Data Types."""
    
    def __init__(self):
        self.crdts: Dict[str, Any] = {}
        self.vector_clocks: Dict[str, VectorClock] = {}
    
    def create_g_counter(self, counter_id: str, node_id: str) -> Dict[str, int]:
        """Create G-Counter (Grow-only counter)."""
        if counter_id not in self.crdts:
            self.crdts[counter_id] = {"type": "g_counter", "counters": {}}
        
        counter = self.crdts[counter_id]
        if node_id not in counter["counters"]:
            counter["counters"][node_id] = 0
        
        return counter["counters"]
    
    def increment_g_counter(self, counter_id: str, node_id: str, amount: int = 1):
        """Increment G-Counter."""
        if counter_id in self.crdts:
            counter = self.crdts[counter_id]
            if node_id in counter["counters"]:
                counter["counters"][node_id] += amount
    
    def get_g_counter_value(self, counter_id: str) -> int:
        """Get G-Counter total value."""
        if counter_id in self.crdts:
            counter = self.crdts[counter_id]
            return sum(counter["counters"].values())
        return 0
    
    def merge_g_counter(self, counter_id: str, other_counters: Dict[str, int]):
        """Merge G-Counter with another counter."""
        if counter_id in self.crdts:
            counter = self.crdts[counter_id]
            for node_id, value in other_counters.items():
                current_value = counter["counters"].get(node_id, 0)
                counter["counters"][node_id] = max(current_value, value)
    
    def create_lww_register(self, register_id: str, initial_value: Any = None) -> Dict[str, Any]:
        """Create Last-Write-Wins Register."""
        if register_id not in self.crdts:
            self.crdts[register_id] = {
                "type": "lww_register",
                "value": initial_value,
                "timestamp": datetime.now(timezone.utc).timestamp(),
                "node_id": None
            }
        
        return self.crdts[register_id]
    
    def update_lww_register(self, register_id: str, value: Any, node_id: str):
        """Update Last-Write-Wins Register."""
        if register_id in self.crdts:
            register = self.crdts[register_id]
            timestamp = datetime.now(timezone.utc).timestamp()
            
            if timestamp > register["timestamp"]:
                register["value"] = value
                register["timestamp"] = timestamp
                register["node_id"] = node_id
    
    def merge_lww_register(self, register_id: str, other_value: Any, 
                          other_timestamp: float, other_node_id: str):
        """Merge Last-Write-Wins Register."""
        if register_id in self.crdts:
            register = self.crdts[register_id]
            
            if (other_timestamp > register["timestamp"] or 
                (other_timestamp == register["timestamp"] and other_node_id > register["node_id"])):
                register["value"] = other_value
                register["timestamp"] = other_timestamp
                register["node_id"] = other_node_id


class GlobalDataDistributionManager:
    """Manages global data distribution across regions."""
    
    def __init__(self):
        self.regions: Dict[str, DataRegion] = {}
        self.data_placements: Dict[str, DataPlacement] = {}
        self.conflict_resolution_rules: Dict[str, ConflictResolutionRule] = {}
        self.active_transactions: Dict[str, GlobalTransaction] = {}
        
        # Managers
        self.crdt_manager = CRDTManager()
        self.vector_clock = VectorClock("local")
        
        # Configuration
        self.default_consistency_model = ConsistencyModel.EVENTUAL
        self.default_replication_factor = 3
        self.conflict_resolution_enabled = True
        self.automatic_failover = True
        
    async def initialize(self):
        """Initialize global data distribution manager."""
        await self._load_regions()
        await self._load_placement_policies()
        await self._start_background_tasks()
        logger.info("Global data distribution manager initialized")
    
    async def _load_regions(self):
        """Load available data regions."""
        # Default regions
        self.regions["us-east-1"] = DataRegion(
            region_id="us-east-1",
            region_name="US East (Virginia)",
            location="Virginia, USA",
            compliance_zones=["SOC2", "FEDRAMP"],
            latency_ms=50.0,
            bandwidth_mbps=1000.0,
            storage_capacity_gb=1000000,
            compute_capacity=100.0,
            is_primary=True
        )
        
        self.regions["eu-west-1"] = DataRegion(
            region_id="eu-west-1",
            region_name="EU West (Ireland)",
            location="Dublin, Ireland",
            compliance_zones=["GDPR", "SOC2"],
            latency_ms=80.0,
            bandwidth_mbps=800.0,
            storage_capacity_gb=500000,
            compute_capacity=80.0
        )
        
        self.regions["ap-southeast-1"] = DataRegion(
            region_id="ap-southeast-1",
            region_name="Asia Pacific (Singapore)",
            location="Singapore",
            compliance_zones=["SOC2"],
            latency_ms=120.0,
            bandwidth_mbps=600.0,
            storage_capacity_gb=300000,
            compute_capacity=60.0
        )
        
        logger.info(f"Loaded {len(self.regions)} data regions")
    
    async def _load_placement_policies(self):
        """Load data placement policies."""
        # Default conflict resolution rules
        self.conflict_resolution_rules["user_data"] = ConflictResolutionRule(
            rule_id="user_data_lww",
            data_type="user_data",
            field_name="*",
            resolution_strategy="last_write_wins"
        )
        
        self.conflict_resolution_rules["counter_data"] = ConflictResolutionRule(
            rule_id="counter_data_merge",
            data_type="counter_data",
            field_name="*",
            resolution_strategy="merge"
        )
        
        logger.info("Data placement policies loaded")
    
    async def place_data(self, data_id: str, data_type: str, data_size_mb: float,
                        access_pattern: Optional[Dict[str, Any]] = None,
                        compliance_requirements: Optional[List[str]] = None,
                        consistency_model: Optional[ConsistencyModel] = None) -> DataPlacement:
        """Intelligently place data across global regions."""
        try:
            access_pattern = access_pattern or {}
            compliance_requirements = compliance_requirements or []
            consistency_model = consistency_model or self.default_consistency_model
            
            # Find suitable regions
            suitable_regions = self._find_suitable_regions(compliance_requirements, data_size_mb)
            
            if not suitable_regions:
                raise Exception("No suitable regions found for data placement")
            
            # Score regions based on access pattern and requirements
            scored_regions = self._score_regions(suitable_regions, access_pattern, data_size_mb)
            
            # Select primary and replica regions
            primary_region = scored_regions[0]["region_id"]
            replica_regions = [r["region_id"] for r in scored_regions[1:self.default_replication_factor]]
            
            # Determine replication strategy
            replication_strategy = self._determine_replication_strategy(consistency_model)
            
            # Create placement decision
            placement = DataPlacement(
                data_id=data_id,
                data_type=data_type,
                primary_region=primary_region,
                replica_regions=replica_regions,
                consistency_model=consistency_model,
                replication_strategy=replication_strategy,
                access_pattern=access_pattern,
                compliance_requirements=compliance_requirements,
                placement_score=scored_regions[0]["score"],
                placement_reason=f"Primary: {primary_region} (score: {scored_regions[0]['score']:.2f})"
            )
            
            self.data_placements[data_id] = placement
            
            logger.info(f"Data placed: {data_id} -> Primary: {primary_region}, Replicas: {replica_regions}")
            return placement
            
        except Exception as e:
            logger.error(f"Data placement failed for {data_id}: {e}")
            raise
    
    def _find_suitable_regions(self, compliance_requirements: Optional[List[str]], data_size_mb: float) -> List[DataRegion]:
        """Find regions that meet compliance and capacity requirements."""
        suitable = []
        
        for region in self.regions.values():
            if not region.is_active:
                continue
            
            # Check compliance
            if compliance_requirements and not region.is_compliant_for(compliance_requirements):
                continue
            
            # Check capacity (simplified)
            if region.storage_capacity_gb < data_size_mb / 1024:
                continue
            
            suitable.append(region)
        
        return suitable
    
    def _score_regions(self, regions: List[DataRegion], access_pattern: Dict[str, Any], 
                      data_size_mb: float) -> List[Dict[str, Any]]:
        """Score regions based on access pattern and requirements."""
        scored_regions = []
        
        for region in regions:
            # Base score from region capabilities
            latency_score = max(0, (200 - region.latency_ms) / 200)
            bandwidth_score = min(1.0, region.bandwidth_mbps / 1000)
            capacity_score = min(1.0, region.storage_capacity_gb / 1000000)
            
            # Access pattern scoring
            user_location_score = 0.5  # Default
            if "user_regions" in access_pattern:
                user_regions = access_pattern["user_regions"]
                if region.region_id in user_regions:
                    user_location_score = 1.0
                elif any(ur.startswith(region.region_id[:2]) for ur in user_regions):
                    user_location_score = 0.8
            
            # Primary region bonus
            primary_bonus = 0.2 if region.is_primary else 0.0
            
            # Calculate overall score
            overall_score = (
                latency_score * 0.3 +
                bandwidth_score * 0.2 +
                capacity_score * 0.2 +
                user_location_score * 0.2 +
                primary_bonus * 0.1
            )
            
            scored_regions.append({
                "region_id": region.region_id,
                "region": region,
                "score": overall_score,
                "latency_score": latency_score,
                "bandwidth_score": bandwidth_score,
                "user_location_score": user_location_score
            })
        
        # Sort by score (descending)
        scored_regions.sort(key=lambda x: x["score"], reverse=True)
        return scored_regions
    
    def _determine_replication_strategy(self, consistency_model: ConsistencyModel) -> ReplicationStrategy:
        """Determine replication strategy based on consistency model."""
        if consistency_model == ConsistencyModel.STRONG:
            return ReplicationStrategy.QUORUM_BASED
        elif consistency_model in [ConsistencyModel.CAUSAL, ConsistencyModel.MONOTONIC_READ]:
            return ReplicationStrategy.MASTER_MASTER
        else:
            return ReplicationStrategy.EVENTUAL_CONSISTENCY

    async def replicate_data(self, data_id: str, data: bytes,
                           metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Replicate data to all configured regions."""
        try:
            if data_id not in self.data_placements:
                raise Exception(f"No placement found for data: {data_id}")

            placement = self.data_placements[data_id]
            metadata = metadata or {}

            # Add vector clock for causal consistency
            if placement.consistency_model == ConsistencyModel.CAUSAL:
                self.vector_clock.tick()
                metadata["vector_clock"] = self.vector_clock.clock.copy()

            # Replicate to primary region
            primary_success = await self._replicate_to_region(
                placement.primary_region, data_id, data, metadata, is_primary=True
            )

            if not primary_success:
                raise Exception(f"Failed to replicate to primary region: {placement.primary_region}")

            # Replicate to replica regions
            replica_successes = []
            for replica_region in placement.replica_regions:
                success = await self._replicate_to_region(
                    replica_region, data_id, data, metadata, is_primary=False
                )
                replica_successes.append(success)

            # Check replication success based on strategy
            if placement.replication_strategy == ReplicationStrategy.QUORUM_BASED:
                required_replicas = len(placement.replica_regions) // 2 + 1
                successful_replicas = sum(replica_successes)

                if successful_replicas < required_replicas:
                    raise Exception(f"Quorum not achieved: {successful_replicas}/{required_replicas}")

            logger.info(f"Data replicated successfully: {data_id}")
            return True

        except Exception as e:
            logger.error(f"Data replication failed for {data_id}: {e}")
            return False

    async def _replicate_to_region(self, region_id: str, data_id: str, data: bytes,
                                 metadata: Dict[str, Any], is_primary: bool) -> bool:
        """Replicate data to specific region."""
        try:
            # In production, this would send data to the actual region
            # For now, simulate replication
            await asyncio.sleep(0.1)  # Simulate network latency

            logger.debug(f"Replicated {data_id} to {region_id} ({'primary' if is_primary else 'replica'})")
            return True

        except Exception as e:
            logger.error(f"Replication to {region_id} failed: {e}")
            return False

    async def read_data(self, data_id: str, consistency_level: Optional[ConsistencyModel] = None,
                       preferred_region: Optional[str] = None) -> Tuple[Optional[bytes], Dict[str, Any]]:
        """Read data with specified consistency guarantees."""
        try:
            if data_id not in self.data_placements:
                raise Exception(f"No placement found for data: {data_id}")

            placement = self.data_placements[data_id]
            consistency_level = consistency_level or placement.consistency_model

            # Determine read strategy
            if consistency_level == ConsistencyModel.STRONG:
                return await self._read_with_strong_consistency(data_id, placement)
            elif consistency_level == ConsistencyModel.CAUSAL:
                return await self._read_with_causal_consistency(data_id, placement)
            elif consistency_level == ConsistencyModel.MONOTONIC_READ:
                return await self._read_with_monotonic_consistency(data_id, placement)
            else:
                return await self._read_with_eventual_consistency(data_id, placement, preferred_region)

        except Exception as e:
            logger.error(f"Data read failed for {data_id}: {e}")
            return None, {}

    async def _read_with_strong_consistency(self, data_id: str, placement: DataPlacement) -> Tuple[Optional[bytes], Dict[str, Any]]:
        """Read with strong consistency (quorum read)."""
        # Read from majority of replicas
        required_reads = len(placement.replica_regions) // 2 + 2  # +1 for primary, +1 for majority

        read_results = []

        # Read from primary
        primary_result = await self._read_from_region(placement.primary_region, data_id)
        if primary_result[0] is not None:
            read_results.append(primary_result)

        # Read from replicas
        for replica_region in placement.replica_regions:
            if len(read_results) >= required_reads:
                break

            replica_result = await self._read_from_region(replica_region, data_id)
            if replica_result[0] is not None:
                read_results.append(replica_result)

        if len(read_results) < required_reads:
            raise Exception("Insufficient replicas for strong consistency read")

        # Return most recent version (simplified)
        return read_results[0]

    async def _read_with_causal_consistency(self, data_id: str, placement: DataPlacement) -> Tuple[Optional[bytes], Dict[str, Any]]:
        """Read with causal consistency."""
        # Read from any replica that satisfies causal ordering
        for region_id in [placement.primary_region] + placement.replica_regions:
            result = await self._read_from_region(region_id, data_id)

            if result[0] is not None:
                # Check causal ordering
                if "vector_clock" in result[1]:
                    other_clock = result[1]["vector_clock"]
                    comparison = self.vector_clock.compare(other_clock)

                    if comparison in ["AFTER", "EQUAL", "CONCURRENT"]:
                        return result
                else:
                    return result  # No vector clock, assume valid

        raise Exception("No causally consistent replica found")

    async def _read_with_monotonic_consistency(self, data_id: str, placement: DataPlacement) -> Tuple[Optional[bytes], Dict[str, Any]]:
        """Read with monotonic read consistency."""
        # Read from primary region for monotonic guarantees
        return await self._read_from_region(placement.primary_region, data_id)

    async def _read_with_eventual_consistency(self, data_id: str, placement: DataPlacement,
                                            preferred_region: Optional[str] = None) -> Tuple[Optional[bytes], Dict[str, Any]]:
        """Read with eventual consistency."""
        # Try preferred region first
        if preferred_region and preferred_region in [placement.primary_region] + placement.replica_regions:
            result = await self._read_from_region(preferred_region, data_id)
            if result[0] is not None:
                return result

        # Try primary region
        result = await self._read_from_region(placement.primary_region, data_id)
        if result[0] is not None:
            return result

        # Try replica regions
        for replica_region in placement.replica_regions:
            result = await self._read_from_region(replica_region, data_id)
            if result[0] is not None:
                return result

        raise Exception("Data not found in any region")

    async def _read_from_region(self, region_id: str, data_id: str) -> Tuple[Optional[bytes], Dict[str, Any]]:
        """Read data from specific region."""
        try:
            # In production, this would read from the actual region
            # For now, simulate read
            await asyncio.sleep(0.05)  # Simulate read latency

            # Simulate data and metadata
            data = b"simulated_data_content"
            metadata = {
                "region_id": region_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "size": len(data)
            }

            return data, metadata

        except Exception as e:
            logger.error(f"Read from {region_id} failed: {e}")
            return None, {}

    async def resolve_conflicts(self, data_id: str, conflicting_versions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Resolve conflicts between data versions."""
        try:
            if data_id not in self.data_placements:
                raise Exception(f"No placement found for data: {data_id}")

            placement = self.data_placements[data_id]

            # Find applicable conflict resolution rule
            resolution_rule = None
            for rule in self.conflict_resolution_rules.values():
                if rule.data_type == placement.data_type or rule.data_type == "*":
                    resolution_rule = rule
                    break

            if not resolution_rule:
                # Default to last-write-wins
                return self._resolve_last_write_wins(conflicting_versions)

            # Apply resolution strategy
            if resolution_rule.resolution_strategy == "last_write_wins":
                return self._resolve_last_write_wins(conflicting_versions)
            elif resolution_rule.resolution_strategy == "merge":
                return self._resolve_merge(conflicting_versions)
            elif resolution_rule.resolution_strategy == "custom":
                resolver_name = getattr(resolution_rule, 'custom_resolver', None) or 'default'
                return await self._resolve_custom(conflicting_versions, resolver_name)

            return conflicting_versions[0]  # Fallback

        except Exception as e:
            logger.error(f"Conflict resolution failed for {data_id}: {e}")
            return conflicting_versions[0] if conflicting_versions else {}

    def _resolve_last_write_wins(self, versions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Resolve conflicts using last-write-wins strategy."""
        if not versions:
            return {}

        # Sort by timestamp and return latest
        sorted_versions = sorted(versions, key=lambda v: v.get("timestamp", 0), reverse=True)
        return sorted_versions[0]

    def _resolve_merge(self, versions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Resolve conflicts by merging versions."""
        if not versions:
            return {}

        merged = {}

        # Merge all fields, preferring non-null values
        for version in versions:
            for key, value in version.items():
                if key not in merged or value is not None:
                    merged[key] = value

        return merged

    async def _resolve_custom(self, versions: List[Dict[str, Any]], resolver_name: str) -> Dict[str, Any]:
        """Resolve conflicts using custom resolver."""
        # Acknowledge parameter to avoid unused warning
        _ = resolver_name
        # Placeholder for custom conflict resolution
        # In production, this would call the specified resolver function
        return self._resolve_last_write_wins(versions)

    async def _start_background_tasks(self):
        """Start background maintenance tasks."""
        asyncio.create_task(self._consistency_maintenance_task())
        asyncio.create_task(self._region_health_monitoring_task())
        asyncio.create_task(self._data_placement_optimization_task())

    async def _consistency_maintenance_task(self):
        """Background task for maintaining data consistency."""
        while True:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes

                # Check for inconsistencies and resolve conflicts
                for data_id, placement in self.data_placements.items():
                    if placement.consistency_model != ConsistencyModel.EVENTUAL:
                        await self._check_data_consistency(data_id, placement)

            except Exception as e:
                logger.error(f"Consistency maintenance task error: {e}")

    async def _check_data_consistency(self, data_id: str, placement: DataPlacement):
        """Check and maintain data consistency."""
        # Acknowledge parameters to avoid unused warnings
        _ = data_id, placement
        # Placeholder for consistency checking
        # In production, this would compare data across regions

    async def _region_health_monitoring_task(self):
        """Background task for monitoring region health."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute

                for region_id, region in self.regions.items():
                    health = await self._check_region_health(region_id)
                    region.is_active = health

            except Exception as e:
                logger.error(f"Region health monitoring task error: {e}")

    async def _check_region_health(self, region_id: str) -> bool:
        """Check health of specific region."""
        # Acknowledge parameter to avoid unused warning
        _ = region_id
        # Placeholder for region health check
        return True

    async def _data_placement_optimization_task(self):
        """Background task for optimizing data placement."""
        while True:
            try:
                await asyncio.sleep(3600)  # Check every hour

                # Analyze access patterns and optimize placement
                for data_id, placement in self.data_placements.items():
                    await self._optimize_data_placement(data_id, placement)

            except Exception as e:
                logger.error(f"Data placement optimization task error: {e}")

    async def _optimize_data_placement(self, data_id: str, placement: DataPlacement):
        """Optimize data placement based on access patterns."""
        # Acknowledge parameters to avoid unused warnings
        _ = data_id, placement
        # Placeholder for placement optimization
        # In production, this would analyze access patterns and suggest migrations

    def get_global_status(self) -> Dict[str, Any]:
        """Get global data distribution status."""
        active_regions = sum(1 for r in self.regions.values() if r.is_active)
        total_placements = len(self.data_placements)

        consistency_breakdown = {}
        for placement in self.data_placements.values():
            model = placement.consistency_model.value
            consistency_breakdown[model] = consistency_breakdown.get(model, 0) + 1

        return {
            "total_regions": len(self.regions),
            "active_regions": active_regions,
            "total_data_placements": total_placements,
            "consistency_models": consistency_breakdown,
            "active_transactions": len(self.active_transactions),
            "conflict_resolution_rules": len(self.conflict_resolution_rules)
        }


# Global data distribution manager instance
global_data_distribution_manager = GlobalDataDistributionManager()
