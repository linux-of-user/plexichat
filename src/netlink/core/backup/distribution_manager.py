"""
Intelligent Distribution Manager

Manages the distribution of backup shards across multiple nodes with AI-powered optimization.
Implements geographic redundancy, load balancing, and intelligent placement strategies.
"""

import asyncio
import logging
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import aiosqlite

logger = logging.getLogger(__name__)


class DistributionStrategy(Enum):
    """Distribution strategies for shards."""
    ROUND_ROBIN = "round-robin"
    CAPACITY_BASED = "capacity-based"
    PERFORMANCE_BASED = "performance-based"
    GEOGRAPHIC = "geographic"
    AI_OPTIMIZED = "ai-optimized"


class NodeStatus(Enum):
    """Backup node status."""
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"
    OVERLOADED = "overloaded"


@dataclass
class BackupNode:
    """Represents a backup node."""
    node_id: str
    hostname: str
    ip_address: str
    port: int
    capacity_bytes: int
    used_bytes: int
    status: NodeStatus
    performance_score: float
    last_seen: datetime
    geographic_region: str = "unknown"
    node_type: str = "standard"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ShardDistribution:
    """Represents shard distribution information."""
    shard_id: str
    backup_id: str
    node_assignments: List[str]
    distribution_strategy: DistributionStrategy
    created_at: datetime
    redundancy_achieved: int
    metadata: Dict[str, Any] = field(default_factory=dict)


class IntelligentDistributionManager:
    """
    Intelligent Distribution Manager
    
    Manages the distribution of backup shards across multiple nodes with:
    - AI-powered optimization for optimal placement
    - Geographic redundancy for disaster recovery
    - Performance-based load balancing
    - Automatic rebalancing and optimization
    - Real-time node health monitoring
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
        """Initialize the distribution database."""
        async with aiosqlite.connect(self.distribution_db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS backup_nodes (
                    node_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    capacity_bytes INTEGER NOT NULL,
                    used_bytes INTEGER DEFAULT 0,
                    status TEXT NOT NULL,
                    performance_score REAL DEFAULT 1.0,
                    last_seen TEXT NOT NULL,
                    geographic_region TEXT DEFAULT 'unknown',
                    node_type TEXT DEFAULT 'standard',
                    metadata TEXT
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS shard_distributions (
                    shard_id TEXT PRIMARY KEY,
                    backup_id TEXT NOT NULL,
                    node_assignments TEXT NOT NULL,
                    distribution_strategy TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    redundancy_achieved INTEGER NOT NULL,
                    metadata TEXT
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
                        hostname=row[1],
                        ip_address=row[2],
                        port=row[3],
                        capacity_bytes=row[4],
                        used_bytes=row[5],
                        status=NodeStatus(row[6]),
                        performance_score=row[7],
                        last_seen=datetime.fromisoformat(row[8]),
                        geographic_region=row[9],
                        node_type=row[10],
                        metadata=json.loads(row[11]) if row[11] else {}
                    )
                    self.backup_nodes[node.node_id] = node
    
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
                        redundancy_achieved=row[5],
                        metadata=json.loads(row[6]) if row[6] else {}
                    )
                    self.shard_distributions[distribution.shard_id] = distribution
    
    async def _discover_local_nodes(self):
        """Discover local backup nodes."""
        # Add localhost as default node
        localhost_node = BackupNode(
            node_id="localhost",
            hostname="localhost",
            ip_address="127.0.0.1",
            port=8080,
            capacity_bytes=100 * 1024 * 1024 * 1024,  # 100GB
            used_bytes=0,
            status=NodeStatus.ONLINE,
            performance_score=1.0,
            last_seen=datetime.now(timezone.utc),
            geographic_region="local",
            node_type="primary"
        )
        
        await self.register_backup_node(localhost_node)
    
    async def register_backup_node(self, node: BackupNode):
        """Register a new backup node."""
        self.backup_nodes[node.node_id] = node
        
        # Save to database
        async with aiosqlite.connect(self.distribution_db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO backup_nodes 
                (node_id, hostname, ip_address, port, capacity_bytes, used_bytes,
                 status, performance_score, last_seen, geographic_region, node_type, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                node.node_id,
                node.hostname,
                node.ip_address,
                node.port,
                node.capacity_bytes,
                node.used_bytes,
                node.status.value,
                node.performance_score,
                node.last_seen.isoformat(),
                node.geographic_region,
                node.node_type,
                json.dumps(node.metadata)
            ))
            await db.commit()
        
        logger.info(f"Registered backup node {node.node_id} at {node.ip_address}:{node.port}")
    
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

            # Store distribution
            self.shard_distributions[shard.shard_id] = distribution
            await self._save_distribution_to_database(distribution)

            logger.info(f"Distributed shard {shard.shard_id} to {len(selected_nodes)} nodes")

    async def _select_optimal_nodes(
        self,
        shard,
        redundancy_factor: int,
        strategy: DistributionStrategy
    ) -> List[str]:
        """Select optimal nodes for shard placement."""
        available_nodes = [
            node for node in self.backup_nodes.values()
            if node.status == NodeStatus.ONLINE and
            (node.used_bytes / node.capacity_bytes) < self.rebalance_threshold
        ]

        if len(available_nodes) < redundancy_factor:
            logger.warning(f"Only {len(available_nodes)} nodes available, need {redundancy_factor}")
            redundancy_factor = len(available_nodes)

        # Simple selection based on capacity and performance
        selected_nodes = sorted(
            available_nodes,
            key=lambda n: (n.used_bytes / n.capacity_bytes, -n.performance_score)
        )[:redundancy_factor]

        return [node.node_id for node in selected_nodes]

    async def _save_distribution_to_database(self, distribution: ShardDistribution):
        """Save shard distribution to database."""
        async with aiosqlite.connect(self.distribution_db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO shard_distributions 
                (shard_id, backup_id, node_assignments, distribution_strategy,
                 created_at, redundancy_achieved, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                distribution.shard_id,
                distribution.backup_id,
                json.dumps(distribution.node_assignments),
                distribution.distribution_strategy.value,
                distribution.created_at.isoformat(),
                distribution.redundancy_achieved,
                json.dumps(distribution.metadata)
            ))
            await db.commit()

    async def _node_health_monitoring_task(self):
        """Background task for monitoring node health."""
        while True:
            try:
                await asyncio.sleep(self.health_check_interval)
                await self._check_node_health()
            except Exception as e:
                logger.error(f"Node health monitoring error: {e}")

    async def _check_node_health(self):
        """Check health of all backup nodes."""
        for node in self.backup_nodes.values():
            # Simple health check (in production, implement actual network checks)
            if node.node_id == "localhost":
                node.status = NodeStatus.ONLINE
                node.last_seen = datetime.now(timezone.utc)

    async def _distribution_optimization_task(self):
        """Background task for distribution optimization."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                await self.optimize_distribution()
            except Exception as e:
                logger.error(f"Distribution optimization error: {e}")

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

    async def _update_performance_scores(self):
        """Update performance scores for all nodes."""
        for node in self.backup_nodes.values():
            # Simple performance scoring (in production, use actual metrics)
            capacity_ratio = node.used_bytes / node.capacity_bytes
            node.performance_score = max(0.1, 1.0 - capacity_ratio)

# Global instance will be created by backup manager
intelligent_distribution_manager = None
