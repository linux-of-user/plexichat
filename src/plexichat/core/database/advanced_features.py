#!/usr/bin/env python3
"""
Advanced Database Features

Implements advanced database capabilities:
- Database sharding
- Table partitioning
- Read replicas
- Performance monitoring
- Query optimization
- Connection pooling
"""

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from contextlib import asynccontextmanager

from plexichat.core.logging.unified_logging_manager import get_logger
from plexichat.shared.exceptions import DatabaseError

logger = get_logger(__name__)


class ShardStrategy(Enum):
    """Database sharding strategies."""
    HASH_BASED = "hash_based"
    RANGE_BASED = "range_based"
    DIRECTORY_BASED = "directory_based"
    CONSISTENT_HASH = "consistent_hash"


class PartitionType(Enum):
    """Database partition types."""
    RANGE = "range"
    HASH = "hash"
    LIST = "list"
    COMPOSITE = "composite"


@dataclass
class ShardConfig:
    """Shard configuration."""
    shard_id: str
    connection_string: str
    weight: float = 1.0
    is_active: bool = True
    is_read_only: bool = False
    max_connections: int = 10


@dataclass
class PartitionConfig:
    """Partition configuration."""
    partition_name: str
    table_name: str
    partition_type: PartitionType
    partition_key: str
    partition_value: Any
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class QueryMetrics:
    """Query performance metrics."""
    query_id: str
    query_text: str
    execution_time: float
    rows_affected: int
    timestamp: datetime = field(default_factory=datetime.now)
    shard_id: Optional[str] = None
    error: Optional[str] = None


class DatabaseShardManager:
    """Manages database sharding."""

    def __init__(self, strategy: ShardStrategy = ShardStrategy.HASH_BASED):
        self.strategy = strategy
        self.shards: Dict[str, ShardConfig] = {}
        self.shard_ring: List[str] = []  # For consistent hashing
        self.query_metrics: List[QueryMetrics] = []
        self.max_metrics = 10000

    def add_shard(self, shard_config: ShardConfig):
        """Add a new shard."""
        self.shards[shard_config.shard_id] = shard_config
        if shard_config.is_active:
            self._rebuild_shard_ring()

        logger.info(f"Added shard: {shard_config.shard_id}")

    def remove_shard(self, shard_id: str):
        """Remove a shard."""
        if shard_id in self.shards:
            del self.shards[shard_id]
            self._rebuild_shard_ring()
            logger.info(f"Removed shard: {shard_id}")

    def get_shard_for_key(self, key: str) -> str:
        """Get shard ID for a given key."""
        if not self.shard_ring:
            raise DatabaseError("No active shards available")

        if self.strategy == ShardStrategy.HASH_BASED:
            return self._hash_based_shard(key)
        elif self.strategy == ShardStrategy.CONSISTENT_HASH:
            return self._consistent_hash_shard(key)
        elif self.strategy == ShardStrategy.RANGE_BASED:
            return self._range_based_shard(key)
        else:
            return self.shard_ring[0]  # Default to first shard

    def get_read_shards(self) -> List[str]:
        """Get available shards for read operations."""
        return [
            shard_id for shard_id, config in self.shards.items()
            if config.is_active
        ]

    def get_write_shards(self) -> List[str]:
        """Get available shards for write operations."""
        return [
            shard_id for shard_id, config in self.shards.items()
            if config.is_active and not config.is_read_only
        ]

    def record_query_metrics(self, metrics: QueryMetrics):
        """Record query performance metrics."""
        self.query_metrics.append(metrics)

        # Keep only recent metrics
        if len(self.query_metrics) > self.max_metrics:
            self.query_metrics = self.query_metrics[-self.max_metrics:]

    def get_performance_stats(self, hours: int = 1) -> Dict[str, Any]:
        """Get performance statistics."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_metrics = [
            m for m in self.query_metrics
            if m.timestamp > cutoff_time
        ]

        if not recent_metrics:
            return {"total_queries": 0}

        total_queries = len(recent_metrics)
        successful_queries = [m for m in recent_metrics if m.error is None]
        failed_queries = [m for m in recent_metrics if m.error is not None]

        execution_times = [m.execution_time for m in successful_queries]

        stats = {
            "total_queries": total_queries,
            "successful_queries": len(successful_queries),
            "failed_queries": len(failed_queries),
            "success_rate": len(successful_queries) / total_queries * 100,
            "avg_execution_time": sum(execution_times) / len(execution_times) if execution_times else 0,
            "max_execution_time": max(execution_times) if execution_times else 0,
            "min_execution_time": min(execution_times) if execution_times else 0,
            "queries_per_minute": total_queries / (hours * 60),
            "shard_distribution": {}
        }

        # Shard distribution
        for metric in recent_metrics:
            if metric.shard_id:
                stats["shard_distribution"][metric.shard_id] = \
                    stats["shard_distribution"].get(metric.shard_id, 0) + 1

        return stats

    def _hash_based_shard(self, key: str) -> str:
        """Hash-based sharding."""
        hash_value = int(hashlib.md5(key.encode()).hexdigest(), 16)
        shard_index = hash_value % len(self.shard_ring)
        return self.shard_ring[shard_index]

    def _consistent_hash_shard(self, key: str) -> str:
        """Consistent hash-based sharding."""
        # Simplified consistent hashing
        hash_value = int(hashlib.md5(key.encode()).hexdigest(), 16)

        # Find the first shard with hash >= key hash
        for shard_id in sorted(self.shard_ring):
            shard_hash = int(hashlib.md5(shard_id.encode()).hexdigest(), 16)
            if shard_hash >= hash_value:
                return shard_id

        # Wrap around to first shard
        return sorted(self.shard_ring)[0]

    def _range_based_shard(self, key: str) -> str:
        """Range-based sharding (simplified)."""
        # This would typically use predefined ranges
        # For now, use alphabetical ranges
        first_char = key[0].lower() if key else 'a'

        if first_char <= 'm':
            return self.shard_ring[0] if len(self.shard_ring) > 0 else None
        else:
            return self.shard_ring[-1] if len(self.shard_ring) > 0 else None

    def _rebuild_shard_ring(self):
        """Rebuild the shard ring for consistent hashing."""
        self.shard_ring = [
            shard_id for shard_id, config in self.shards.items()
            if config.is_active
        ]


class DatabasePartitionManager:
    """Manages database partitioning."""

    def __init__(self):
        self.partitions: Dict[str, List[PartitionConfig]] = {}

    def create_partition(self, config: PartitionConfig) -> bool:
        """Create a new partition."""
        try:
            table_name = config.table_name
            if table_name not in self.partitions:
                self.partitions[table_name] = []

            self.partitions[table_name].append(config)

            # Generate partition creation SQL (example for PostgreSQL)
            sql = self._generate_partition_sql(config)
            logger.info(f"Created partition: {config.partition_name}")
            logger.debug(f"Partition SQL: {sql}")

            return True

        except Exception as e:
            logger.error(f"Failed to create partition {config.partition_name}: {e}")
            return False

    def get_partition_for_value(self, table_name: str, partition_key: str, value: Any) -> Optional[str]:
        """Get partition name for a given value."""
        if table_name not in self.partitions:
            return None

        for partition in self.partitions[table_name]:
            if partition.partition_key == partition_key:
                if self._value_matches_partition(value, partition):
                    return partition.partition_name

        return None

    def list_partitions(self, table_name: str) -> List[PartitionConfig]:
        """List all partitions for a table."""
        return self.partitions.get(table_name, [])

    def drop_partition(self, table_name: str, partition_name: str) -> bool:
        """Drop a partition."""
        if table_name in self.partitions:
            self.partitions[table_name] = [
                p for p in self.partitions[table_name]
                if p.partition_name != partition_name
            ]
            logger.info(f"Dropped partition: {partition_name}")
            return True
        return False

    def _generate_partition_sql(self, config: PartitionConfig) -> str:
        """Generate SQL for partition creation."""
        if config.partition_type == PartitionType.RANGE:
            return f"""
            CREATE TABLE {config.partition_name} PARTITION OF {config.table_name}
            FOR VALUES FROM ('{config.partition_value[0]}') TO ('{config.partition_value[1]}');
            """
        elif config.partition_type == PartitionType.HASH:
            return f"""
            CREATE TABLE {config.partition_name} PARTITION OF {config.table_name}
            FOR VALUES WITH (modulus {config.partition_value[0]}, remainder {config.partition_value[1]});
            """
        elif config.partition_type == PartitionType.LIST:
            values = "', '".join(str(v) for v in config.partition_value)
            return f"""
            CREATE TABLE {config.partition_name} PARTITION OF {config.table_name}
            FOR VALUES IN ('{values}');
            """
        else:
            return f"-- Partition type {config.partition_type} not implemented"

    def _value_matches_partition(self, value: Any, partition: PartitionConfig) -> bool:
        """Check if value matches partition criteria."""
        if partition.partition_type == PartitionType.RANGE:
            return partition.partition_value[0] <= value < partition.partition_value[1]
        elif partition.partition_type == PartitionType.LIST:
            return value in partition.partition_value
        elif partition.partition_type == PartitionType.HASH:
            hash_value = hash(str(value))
            modulus, remainder = partition.partition_value
            return hash_value % modulus == remainder
        return False


class ReadReplicaManager:
    """Manages read replicas."""

    def __init__(self):
        self.replicas: Dict[str, ShardConfig] = {}
        self.replica_weights: Dict[str, float] = {}
        self.health_status: Dict[str, bool] = {}

    def add_replica(self, replica_config: ShardConfig):
        """Add a read replica."""
        self.replicas[replica_config.shard_id] = replica_config
        self.replica_weights[replica_config.shard_id] = replica_config.weight
        self.health_status[replica_config.shard_id] = True

        logger.info(f"Added read replica: {replica_config.shard_id}")

    def get_read_replica(self) -> Optional[str]:
        """Get a read replica using weighted selection."""
        healthy_replicas = [
            replica_id for replica_id in self.replicas.keys()
            if self.health_status.get(replica_id, False)
        ]

        if not healthy_replicas:
            return None

        # Weighted random selection
        import random
        weights = [self.replica_weights[replica_id] for replica_id in healthy_replicas]
        return random.choices(healthy_replicas, weights=weights)[0]

    def check_replica_health(self, replica_id: str) -> bool:
        """Check replica health."""
        # Placeholder for actual health check
        # In production, this would ping the replica
        return True

    def update_replica_health(self):
        """Update health status for all replicas."""
        for replica_id in self.replicas.keys():
            self.health_status[replica_id] = self.check_replica_health(replica_id)


class PerformanceMonitor:
    """Database performance monitoring."""

    def __init__(self):
        self.slow_query_threshold = 1.0  # seconds
        self.slow_queries: List[QueryMetrics] = []
        self.connection_stats: Dict[str, Any] = {}

    async def monitor_query(self, query_func, query_text: str, shard_id: str = None):
        """Monitor query execution."""
        start_time = time.time()
        query_id = f"query_{int(start_time * 1000)}"

        try:
            result = await query_func()
            execution_time = time.time() - start_time

            metrics = QueryMetrics()
                query_id=query_id,
                query_text=query_text[:200],  # Truncate long queries
                execution_time=execution_time,
                rows_affected=getattr(result, 'rowcount', 0),
                shard_id=shard_id
            )

            # Record slow queries
            if execution_time > self.slow_query_threshold:
                self.slow_queries.append(metrics)
                logger.warning(f"Slow query detected: {execution_time:.3f}s - {query_text[:100]}")

            return result

        except Exception as e:
            execution_time = time.time() - start_time

            metrics = QueryMetrics()
                query_id=query_id,
                query_text=query_text[:200],
                execution_time=execution_time,
                rows_affected=0,
                shard_id=shard_id,
                error=str(e)
            )

            logger.error(f"Query failed: {e} - {query_text[:100]}")
            raise

    def get_slow_queries(self, limit: int = 50) -> List[QueryMetrics]:
        """Get recent slow queries."""
        return sorted(self.slow_queries, key=lambda x: x.execution_time, reverse=True)[:limit]

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary."""
        if not self.slow_queries:
            return {"slow_queries": 0}

        execution_times = [q.execution_time for q in self.slow_queries]

        return {
            "slow_queries": len(self.slow_queries),
            "avg_slow_query_time": sum(execution_times) / len(execution_times),
            "max_slow_query_time": max(execution_times),
            "slowest_query": max(self.slow_queries, key=lambda x: x.execution_time).query_text
        }


class AdvancedDatabaseManager:
    """Advanced database manager combining all features."""

    def __init__(self):
        self.shard_manager = DatabaseShardManager()
        self.partition_manager = DatabasePartitionManager()
        self.replica_manager = ReadReplicaManager()
        self.performance_monitor = PerformanceMonitor()

    async def execute_query(self, query: str, params: tuple = None, )
                          shard_key: str = None, is_read_only: bool = False):
        """Execute query with advanced features."""
        # Determine target shard
        if shard_key:
            shard_id = self.shard_manager.get_shard_for_key(shard_key)
        elif is_read_only:
            shard_id = self.replica_manager.get_read_replica()
            if not shard_id:
                # Fallback to read shards
                read_shards = self.shard_manager.get_read_shards()
                shard_id = read_shards[0] if read_shards else None
        else:
            write_shards = self.shard_manager.get_write_shards()
            shard_id = write_shards[0] if write_shards else None

        if not shard_id:
            raise DatabaseError("No available shards for query")

        # Execute with monitoring
        async def query_func():
            # Placeholder for actual query execution
            await asyncio.sleep(0.01)  # Simulate query execution
            return {"rowcount": 1, "result": "success"}

        return await self.performance_monitor.monitor_query()
            query_func, query, shard_id
        )

    def setup_sharding(self, shard_configs: List[ShardConfig]):
        """Setup database sharding."""
        for config in shard_configs:
            self.shard_manager.add_shard(config)

    def setup_partitioning(self, partition_configs: List[PartitionConfig]):
        """Setup table partitioning."""
        for config in partition_configs:
            self.partition_manager.create_partition(config)

    def setup_read_replicas(self, replica_configs: List[ShardConfig]):
        """Setup read replicas."""
        for config in replica_configs:
            self.replica_manager.add_replica(config)

    def get_database_stats(self) -> Dict[str, Any]:
        """Get comprehensive database statistics."""
        return {
            "sharding": {
                "total_shards": len(self.shard_manager.shards),
                "active_shards": len(self.shard_manager.get_read_shards()),
                "performance": self.shard_manager.get_performance_stats()
            },
            "partitioning": {
                "total_tables": len(self.partition_manager.partitions),
                "total_partitions": sum(len(partitions) for partitions in self.partition_manager.partitions.values())
            },
            "read_replicas": {
                "total_replicas": len(self.replica_manager.replicas),
                "healthy_replicas": sum(self.replica_manager.health_status.values())
            },
            "performance": self.performance_monitor.get_performance_summary()
        }


# Global advanced database manager
advanced_db_manager = AdvancedDatabaseManager()


def get_advanced_db_manager() -> AdvancedDatabaseManager:
    """Get the global advanced database manager."""
    return advanced_db_manager
