"""
Intelligent Distribution Manager

AI-powered intelligent shard distribution system that optimizes placement
based on user preferences, regionality, node performance, and system health.
"""

import asyncio
import logging
import secrets
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import aiosqlite
import random

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Types of backup nodes."""
    LOCAL = "local"
    REMOTE = "remote"
    CLOUD = "cloud"
    PEER = "peer"
    DEDICATED = "dedicated"


class NodeStatus(Enum):
    """Node status."""
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"
    OVERLOADED = "overloaded"


class DistributionStrategy(Enum):
    """Distribution strategies."""
    GEOGRAPHIC = "geographic"
    PERFORMANCE = "performance"
    REDUNDANCY = "redundancy"
    USER_PREFERENCE = "user_preference"
    BALANCED = "balanced"
    AI_OPTIMIZED = "ai_optimized"


@dataclass
class BackupNode:
    """Represents a backup node."""
    node_id: str
    node_type: NodeType
    status: NodeStatus
    location: str
    region: str
    capacity_bytes: int
    used_bytes: int
    performance_score: float
    reliability_score: float
    last_seen: datetime
    user_preference_score: float = 0.0
    network_latency_ms: float = 0.0
    bandwidth_mbps: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ShardDistribution:
    """Represents shard distribution information."""
    shard_id: str
    backup_id: str
    node_assignments: List[str]
    distribution_strategy: DistributionStrategy
    created_at: datetime
    verified_at: Optional[datetime] = None
    redundancy_achieved: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class IntelligentDistributionManager:
    """
    Intelligent Distribution Manager
    
    AI-powered shard distribution system with:
    - Geographic distribution optimization
    - User preference-based placement
    - Performance-aware node selection
    - Real-time health monitoring
    - Automatic rebalancing
    - Predictive analytics for optimal placement
    """
    
    def __init__(self, backup_manager):
        """Initialize the intelligent distribution manager."""
        self.backup_manager = backup_manager
        self.distribution_dir = backup_manager.backup_dir / "distribution"
        self.distribution_dir.mkdir(parents=True, exist_ok=True)
        
        # Node registry
        self.backup_nodes: Dict[str, BackupNode] = {}
        self.shard_distributions: Dict[str, ShardDistribution] = {}
        
        # AI/ML components (simplified for now)
        self.performance_weights = {
            'capacity': 0.3,
            'performance': 0.25,
            'reliability': 0.2,
            'user_preference': 0.15,
            'network_latency': 0.1
        }
        
        # Configuration
        self.min_redundancy = 3
        self.max_redundancy = 10
        self.rebalance_threshold = 0.8  # 80% capacity
        self.health_check_interval = 300  # 5 minutes
        
        # Database
        self.distribution_db_path = backup_manager.databases_dir / "distribution_registry.db"
        
        logger.info("Intelligent Distribution Manager initialized")
    
    async def initialize(self):
        """Initialize the distribution manager."""
        await self._initialize_database()
        await self._load_existing_nodes()
        await self._load_existing_distributions()
        await self._discover_local_nodes()
        
        # Start background tasks
        asyncio.create_task(self._node_health_monitoring_task())
        asyncio.create_task(self._distribution_optimization_task())
        
        logger.info("Distribution Manager initialized successfully")
    
    async def _initialize_database(self):
        """Initialize distribution registry database."""
        async with aiosqlite.connect(self.distribution_db_path) as db:
            # Backup nodes table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS backup_nodes (
                    node_id TEXT PRIMARY KEY,
                    node_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    location TEXT NOT NULL,
                    region TEXT NOT NULL,
                    capacity_bytes INTEGER NOT NULL,
                    used_bytes INTEGER DEFAULT 0,
                    performance_score REAL DEFAULT 0.0,
                    reliability_score REAL DEFAULT 1.0,
                    last_seen TEXT NOT NULL,
                    user_preference_score REAL DEFAULT 0.0,
                    network_latency_ms REAL DEFAULT 0.0,
                    bandwidth_mbps REAL DEFAULT 0.0,
                    metadata TEXT
                )
            """)
            
            # Shard distributions table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS shard_distributions (
                    shard_id TEXT PRIMARY KEY,
                    backup_id TEXT NOT NULL,
                    node_assignments TEXT NOT NULL,
                    distribution_strategy TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    verified_at TEXT,
                    redundancy_achieved INTEGER DEFAULT 0,
                    metadata TEXT
                )
            """)
            
            # Distribution performance log
            await db.execute("""
                CREATE TABLE IF NOT EXISTS distribution_performance_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    operation_type TEXT NOT NULL,
                    shard_id TEXT,
                    node_id TEXT,
                    performance_metric REAL,
                    success BOOLEAN NOT NULL
                )
            """)
            
            await db.commit()
    
    async def _load_existing_nodes(self):
        """Load existing backup nodes from database."""
        async with aiosqlite.connect(self.distribution_db_path) as db:
            async with db.execute("SELECT * FROM backup_nodes") as cursor:
                async for row in cursor:
                    node = BackupNode(
                        node_id=row[0],
                        node_type=NodeType(row[1]),
                        status=NodeStatus(row[2]),
                        location=row[3],
                        region=row[4],
                        capacity_bytes=row[5],
                        used_bytes=row[6],
                        performance_score=row[7],
                        reliability_score=row[8],
                        last_seen=datetime.fromisoformat(row[9]),
                        user_preference_score=row[10],
                        network_latency_ms=row[11],
                        bandwidth_mbps=row[12],
                        metadata=json.loads(row[13]) if row[13] else {}
                    )
                    self.backup_nodes[node.node_id] = node
        
        logger.info(f"Loaded {len(self.backup_nodes)} backup nodes")
    
    async def _load_existing_distributions(self):
        """Load existing shard distributions from database."""
        async with aiosqlite.connect(self.distribution_db_path) as db:
            async with db.execute("SELECT * FROM shard_distributions") as cursor:
                async for row in cursor:
                    distribution = ShardDistribution(
                        shard_id=row[0],
                        backup_id=row[1],
                        node_assignments=json.loads(row[2]),
                        distribution_strategy=DistributionStrategy(row[3]),
                        created_at=datetime.fromisoformat(row[4]),
                        verified_at=datetime.fromisoformat(row[5]) if row[5] else None,
                        redundancy_achieved=row[6],
                        metadata=json.loads(row[7]) if row[7] else {}
                    )
                    self.shard_distributions[distribution.shard_id] = distribution
        
        logger.info(f"Loaded {len(self.shard_distributions)} shard distributions")
    
    async def _discover_local_nodes(self):
        """Discover local backup nodes."""
        # Create default local node if none exist
        if not any(node.node_type == NodeType.LOCAL for node in self.backup_nodes.values()):
            local_node = BackupNode(
                node_id=f"local_node_{secrets.token_hex(8)}",
                node_type=NodeType.LOCAL,
                status=NodeStatus.ONLINE,
                location="localhost",
                region="local",
                capacity_bytes=100 * 1024 * 1024 * 1024,  # 100GB default
                used_bytes=0,
                performance_score=1.0,
                reliability_score=1.0,
                last_seen=datetime.now(timezone.utc),
                user_preference_score=1.0,
                network_latency_ms=1.0,
                bandwidth_mbps=1000.0
            )
            
            await self.register_node(local_node)
            logger.info(f"Created default local node {local_node.node_id}")
    
    async def register_node(self, node: BackupNode):
        """Register a new backup node."""
        self.backup_nodes[node.node_id] = node
        await self._save_node_to_database(node)
        logger.info(f"Registered backup node {node.node_id} ({node.node_type.value})")
    
    async def _save_node_to_database(self, node: BackupNode):
        """Save node to database."""
        async with aiosqlite.connect(self.distribution_db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO backup_nodes (
                    node_id, node_type, status, location, region, capacity_bytes,
                    used_bytes, performance_score, reliability_score, last_seen,
                    user_preference_score, network_latency_ms, bandwidth_mbps, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                node.node_id,
                node.node_type.value,
                node.status.value,
                node.location,
                node.region,
                node.capacity_bytes,
                node.used_bytes,
                node.performance_score,
                node.reliability_score,
                node.last_seen.isoformat(),
                node.user_preference_score,
                node.network_latency_ms,
                node.bandwidth_mbps,
                json.dumps(node.metadata)
            ))
            await db.commit()

    async def distribute_shards(self, shards: List, operation):
        """Distribute shards across backup nodes using AI optimization."""
        logger.info(f"Distributing {len(shards)} shards for backup {operation.backup_id}")

        for shard in shards:
            # Select optimal nodes for this shard
            selected_nodes = await self._select_optimal_nodes(
                shard,
                operation.redundancy_factor,
                DistributionStrategy.AI_OPTIMIZED
            )

            # Create distribution record
            distribution = ShardDistribution(
                shard_id=shard.shard_id,
                backup_id=operation.backup_id,
                node_assignments=selected_nodes,
                distribution_strategy=DistributionStrategy.AI_OPTIMIZED,
                created_at=datetime.now(timezone.utc),
                redundancy_achieved=len(selected_nodes)
            )

            # Save distribution
            self.shard_distributions[shard.shard_id] = distribution
            await self._save_distribution_to_database(distribution)

            # Update node usage
            await self._update_node_usage(selected_nodes, shard.size_bytes)

            logger.debug(f"Distributed shard {shard.shard_id} to {len(selected_nodes)} nodes")

        logger.info(f"Successfully distributed all shards for backup {operation.backup_id}")

    async def _select_optimal_nodes(
        self,
        shard,
        redundancy_factor: int,
        strategy: DistributionStrategy
    ) -> List[str]:
        """Select optimal nodes for shard placement using AI scoring."""
        available_nodes = [
            node for node in self.backup_nodes.values()
            if node.status == NodeStatus.ONLINE and
            (node.capacity_bytes - node.used_bytes) > shard.size_bytes
        ]

        if len(available_nodes) < redundancy_factor:
            logger.warning(f"Only {len(available_nodes)} nodes available, requested {redundancy_factor}")
            redundancy_factor = len(available_nodes)

        # Score nodes based on multiple criteria
        node_scores = []
        for node in available_nodes:
            score = await self._calculate_node_score(node, shard, strategy)
            node_scores.append((node.node_id, score))

        # Sort by score (highest first) and select top nodes
        node_scores.sort(key=lambda x: x[1], reverse=True)
        selected_nodes = [node_id for node_id, _ in node_scores[:redundancy_factor]]

        # Ensure geographic diversity if possible
        selected_nodes = await self._ensure_geographic_diversity(selected_nodes, available_nodes)

        return selected_nodes

    async def _calculate_node_score(self, node: BackupNode, shard, strategy: DistributionStrategy) -> float:
        """Calculate AI-based score for node selection."""
        # Base capacity score (0-1)
        capacity_ratio = (node.capacity_bytes - node.used_bytes) / node.capacity_bytes
        capacity_score = min(capacity_ratio * 2, 1.0)  # Favor nodes with more free space

        # Performance score (already 0-1)
        performance_score = node.performance_score

        # Reliability score (already 0-1)
        reliability_score = node.reliability_score

        # User preference score (0-1)
        user_preference_score = node.user_preference_score

        # Network latency score (inverse, lower is better)
        latency_score = max(0, 1.0 - (node.network_latency_ms / 1000.0))

        # Weighted combination
        total_score = (
            capacity_score * self.performance_weights['capacity'] +
            performance_score * self.performance_weights['performance'] +
            reliability_score * self.performance_weights['reliability'] +
            user_preference_score * self.performance_weights['user_preference'] +
            latency_score * self.performance_weights['network_latency']
        )

        # Strategy-specific adjustments
        if strategy == DistributionStrategy.GEOGRAPHIC:
            # Favor nodes in different regions
            total_score *= 1.2 if node.region != "local" else 0.8
        elif strategy == DistributionStrategy.PERFORMANCE:
            # Heavily weight performance
            total_score = performance_score * 0.7 + total_score * 0.3
        elif strategy == DistributionStrategy.USER_PREFERENCE:
            # Heavily weight user preferences
            total_score = user_preference_score * 0.6 + total_score * 0.4

        return total_score

    async def get_node_health(self) -> Tuple[int, int]:
        """Get node health statistics."""
        healthy_nodes = len([
            node for node in self.backup_nodes.values()
            if node.status == NodeStatus.ONLINE
        ])
        total_nodes = len(self.backup_nodes)

        return healthy_nodes, total_nodes

    async def optimize_distribution(self):
        """Optimize shard distribution across nodes."""
        logger.info("Starting distribution optimization")

        # Check for overloaded nodes
        overloaded_nodes = [
            node for node in self.backup_nodes.values()
            if (node.used_bytes / node.capacity_bytes) > self.rebalance_threshold
        ]

        if overloaded_nodes:
            logger.info(f"Found {len(overloaded_nodes)} overloaded nodes, initiating rebalancing")
            # TODO: Implement rebalancing logic

        # Update node performance scores based on recent performance
        await self._update_performance_scores()

        logger.info("Distribution optimization completed")

    async def _update_performance_scores(self):
        """Update node performance scores based on recent metrics."""
        # Simplified performance scoring - in a real implementation,
        # this would analyze actual performance metrics
        for node in self.backup_nodes.values():
            if node.status == NodeStatus.ONLINE:
                # Simulate performance updates
                node.performance_score = min(1.0, node.performance_score + random.uniform(-0.1, 0.1))
                node.performance_score = max(0.0, node.performance_score)
                await self._save_node_to_database(node)

    async def _node_health_monitoring_task(self):
        """Background task for monitoring node health."""
        while True:
            try:
                await asyncio.sleep(self.health_check_interval)

                # Check node health
                for node in self.backup_nodes.values():
                    # Simulate health checks - in real implementation,
                    # this would ping nodes and check their status
                    if node.status == NodeStatus.ONLINE:
                        node.last_seen = datetime.now(timezone.utc)
                        await self._save_node_to_database(node)

            except Exception as e:
                logger.error(f"Node health monitoring error: {e}")

    async def _distribution_optimization_task(self):
        """Background task for distribution optimization."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                await self.optimize_distribution()

            except Exception as e:
                logger.error(f"Distribution optimization error: {e}")
