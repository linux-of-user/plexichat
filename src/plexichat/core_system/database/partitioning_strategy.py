"""
PlexiChat Data Partitioning Strategy

Advanced data partitioning implementation for scalable database architecture.
Supports time-based, hash-based, and range-based partitioning strategies
for large tables like messages, audit logs, and user data.

Features:
- Automatic partition creation and management
- Time-based partitioning for temporal data
- Hash-based partitioning for even distribution
- Range-based partitioning for ordered data
- Partition pruning for query optimization
- Automatic partition maintenance and cleanup
- Cross-database partitioning support
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime, timezone, timedelta
from enum import Enum
from dataclasses import dataclass, field
import hashlib
import calendar

from .enhanced_abstraction import AbstractDatabaseClient, DatabaseType

logger = logging.getLogger(__name__)


class PartitionType(Enum):
    """Types of partitioning strategies."""
    TIME_BASED = "time_based"
    HASH_BASED = "hash_based"
    RANGE_BASED = "range_based"
    LIST_BASED = "list_based"
    COMPOSITE = "composite"


class PartitionInterval(Enum):
    """Time-based partition intervals."""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"


@dataclass
class PartitionConfig:
    """Configuration for table partitioning."""
    table_name: str
    partition_type: PartitionType
    partition_column: str
    
    # Time-based partitioning
    interval: Optional[PartitionInterval] = None
    retention_period_days: Optional[int] = None
    
    # Hash-based partitioning
    hash_partitions: Optional[int] = None
    
    # Range-based partitioning
    range_values: Optional[List[Any]] = None
    
    # List-based partitioning
    list_values: Optional[Dict[str, List[Any]]] = None
    
    # General settings
    auto_create: bool = True
    auto_cleanup: bool = True
    partition_prefix: str = ""


@dataclass
class PartitionInfo:
    """Information about a database partition."""
    name: str
    table_name: str
    partition_type: PartitionType
    partition_key: str
    start_value: Optional[Any] = None
    end_value: Optional[Any] = None
    created_at: Optional[datetime] = None
    row_count: Optional[int] = None
    size_bytes: Optional[int] = None
    last_accessed: Optional[datetime] = None


class PartitionManager:
    """Manages database partitioning strategies."""
    
    def __init__(self):
        self.partition_configs: Dict[str, PartitionConfig] = {}
        self.partition_info: Dict[str, List[PartitionInfo]] = {}
        self.maintenance_interval = 3600  # 1 hour
        self._maintenance_task: Optional[asyncio.Task] = None
    
    def register_partition_config(self, config: PartitionConfig):
        """Register a partition configuration for a table."""
        self.partition_configs[config.table_name] = config
        logger.info(f"Registered partition config for table: {config.table_name}")
    
    async def create_partitions(self, client: AbstractDatabaseClient, table_name: str, 
                              periods: int = 12) -> List[str]:
        """Create partitions for a table."""
        if table_name not in self.partition_configs:
            raise ValueError(f"No partition config found for table: {table_name}")
        
        config = self.partition_configs[table_name]
        created_partitions = []
        
        if config.partition_type == PartitionType.TIME_BASED:
            created_partitions = await self._create_time_based_partitions(
                client, config, periods
            )
        elif config.partition_type == PartitionType.HASH_BASED:
            created_partitions = await self._create_hash_based_partitions(
                client, config
            )
        elif config.partition_type == PartitionType.RANGE_BASED:
            created_partitions = await self._create_range_based_partitions(
                client, config
            )
        
        return created_partitions
    
    async def _create_time_based_partitions(self, client: AbstractDatabaseClient, 
                                          config: PartitionConfig, periods: int) -> List[str]:
        """Create time-based partitions."""
        created_partitions = []
        database_type = getattr(client.config, 'type', DatabaseType.SQLITE)
        
        # Calculate partition dates
        now = datetime.now(timezone.utc)
        partition_dates = self._calculate_partition_dates(now, config.interval, periods)
        
        for start_date, end_date in partition_dates:
            partition_name = self._generate_time_partition_name(
                config.table_name, start_date, config.interval, config.partition_prefix
            )
            
            try:
                # Create partition based on database type
                if database_type == DatabaseType.POSTGRESQL:
                    sql = self._generate_postgresql_time_partition_sql(
                        config, partition_name, start_date, end_date
                    )
                elif database_type == DatabaseType.MYSQL:
                    sql = self._generate_mysql_time_partition_sql(
                        config, partition_name, start_date, end_date
                    )
                else:
                    # For databases that don't support native partitioning,
                    # create separate tables
                    sql = self._generate_table_based_partition_sql(
                        config, partition_name, start_date, end_date
                    )
                
                result = await client.execute_query(sql)
                
                if result.success:
                    created_partitions.append(partition_name)
                    
                    # Store partition info
                    partition_info = PartitionInfo(
                        name=partition_name,
                        table_name=config.table_name,
                        partition_type=config.partition_type,
                        partition_key=config.partition_column,
                        start_value=start_date,
                        end_value=end_date,
                        created_at=datetime.now(timezone.utc)
                    )
                    
                    if config.table_name not in self.partition_info:
                        self.partition_info[config.table_name] = []
                    self.partition_info[config.table_name].append(partition_info)
                    
                    logger.info(f"✅ Created time partition: {partition_name}")
                else:
                    logger.error(f"❌ Failed to create partition {partition_name}: {result.error}")
                    
            except Exception as e:
                logger.error(f"❌ Error creating partition {partition_name}: {e}")
        
        return created_partitions
    
    async def _create_hash_based_partitions(self, client: AbstractDatabaseClient, 
                                          config: PartitionConfig) -> List[str]:
        """Create hash-based partitions."""
        created_partitions = []
        database_type = getattr(client.config, 'type', DatabaseType.SQLITE)
        
        if not config.hash_partitions:
            raise ValueError("hash_partitions must be specified for hash-based partitioning")
        
        for i in range(config.hash_partitions):
            partition_name = f"{config.partition_prefix}{config.table_name}_hash_{i}"
            
            try:
                if database_type == DatabaseType.POSTGRESQL:
                    sql = f"""
                    CREATE TABLE {partition_name} PARTITION OF {config.table_name}
                    FOR VALUES WITH (MODULUS {config.hash_partitions}, REMAINDER {i})
                    """
                elif database_type == DatabaseType.MYSQL:
                    # MySQL hash partitioning is defined on the main table
                    if i == 0:  # Only create the partitioning scheme once
                        sql = f"""
                        ALTER TABLE {config.table_name}
                        PARTITION BY HASH({config.partition_column})
                        PARTITIONS {config.hash_partitions}
                        """
                    else:
                        continue  # Skip individual partition creation for MySQL
                else:
                    # Create separate tables for hash partitions
                    sql = f"""
                    CREATE TABLE {partition_name} AS 
                    SELECT * FROM {config.table_name} WHERE 1=0
                    """
                
                result = await client.execute_query(sql)
                
                if result.success:
                    created_partitions.append(partition_name)
                    logger.info(f"✅ Created hash partition: {partition_name}")
                else:
                    logger.error(f"❌ Failed to create hash partition {partition_name}: {result.error}")
                    
            except Exception as e:
                logger.error(f"❌ Error creating hash partition {partition_name}: {e}")
        
        return created_partitions
    
    async def _create_range_based_partitions(self, client: AbstractDatabaseClient, 
                                           config: PartitionConfig) -> List[str]:
        """Create range-based partitions."""
        created_partitions = []
        
        if not config.range_values:
            raise ValueError("range_values must be specified for range-based partitioning")
        
        database_type = getattr(client.config, 'type', DatabaseType.SQLITE)
        
        for i, range_value in enumerate(config.range_values):
            partition_name = f"{config.partition_prefix}{config.table_name}_range_{i}"
            
            try:
                start_value = config.range_values[i-1] if i > 0 else None
                end_value = range_value
                
                if database_type == DatabaseType.POSTGRESQL:
                    if start_value is not None:
                        sql = f"""
                        CREATE TABLE {partition_name} PARTITION OF {config.table_name}
                        FOR VALUES FROM ('{start_value}') TO ('{end_value}')
                        """
                    else:
                        sql = f"""
                        CREATE TABLE {partition_name} PARTITION OF {config.table_name}
                        FOR VALUES FROM (MINVALUE) TO ('{end_value}')
                        """
                else:
                    # Create separate tables with constraints
                    if start_value is not None:
                        constraint = f"{config.partition_column} >= '{start_value}' AND {config.partition_column} < '{end_value}'"
                    else:
                        constraint = f"{config.partition_column} < '{end_value}'"
                    
                    sql = f"""
                    CREATE TABLE {partition_name} AS 
                    SELECT * FROM {config.table_name} WHERE {constraint} AND 1=0
                    """
                
                result = await client.execute_query(sql)
                
                if result.success:
                    created_partitions.append(partition_name)
                    logger.info(f"✅ Created range partition: {partition_name}")
                else:
                    logger.error(f"❌ Failed to create range partition {partition_name}: {result.error}")
                    
            except Exception as e:
                logger.error(f"❌ Error creating range partition {partition_name}: {e}")
        
        return created_partitions
    
    def _calculate_partition_dates(self, base_date: datetime, interval: PartitionInterval, 
                                 periods: int) -> List[Tuple[datetime, datetime]]:
        """Calculate partition date ranges."""
        dates = []
        current_date = base_date.replace(hour=0, minute=0, second=0, microsecond=0)
        
        # Adjust to start of period
        if interval == PartitionInterval.WEEKLY:
            current_date = current_date - timedelta(days=current_date.weekday())
        elif interval == PartitionInterval.MONTHLY:
            current_date = current_date.replace(day=1)
        elif interval == PartitionInterval.QUARTERLY:
            quarter_start_month = ((current_date.month - 1) // 3) * 3 + 1
            current_date = current_date.replace(month=quarter_start_month, day=1)
        elif interval == PartitionInterval.YEARLY:
            current_date = current_date.replace(month=1, day=1)
        
        for _ in range(periods):
            if interval == PartitionInterval.DAILY:
                end_date = current_date + timedelta(days=1)
            elif interval == PartitionInterval.WEEKLY:
                end_date = current_date + timedelta(weeks=1)
            elif interval == PartitionInterval.MONTHLY:
                if current_date.month == 12:
                    end_date = current_date.replace(year=current_date.year + 1, month=1)
                else:
                    end_date = current_date.replace(month=current_date.month + 1)
            elif interval == PartitionInterval.QUARTERLY:
                end_month = current_date.month + 3
                if end_month > 12:
                    end_date = current_date.replace(year=current_date.year + 1, month=end_month - 12)
                else:
                    end_date = current_date.replace(month=end_month)
            elif interval == PartitionInterval.YEARLY:
                end_date = current_date.replace(year=current_date.year + 1)
            
            dates.append((current_date, end_date))
            current_date = end_date
        
        return dates
    
    def _generate_time_partition_name(self, table_name: str, date: datetime, 
                                    interval: PartitionInterval, prefix: str = "") -> str:
        """Generate partition name for time-based partitioning."""
        if interval == PartitionInterval.DAILY:
            suffix = date.strftime("%Y%m%d")
        elif interval == PartitionInterval.WEEKLY:
            suffix = f"{date.year}w{date.isocalendar()[1]:02d}"
        elif interval == PartitionInterval.MONTHLY:
            suffix = date.strftime("%Y%m")
        elif interval == PartitionInterval.QUARTERLY:
            quarter = (date.month - 1) // 3 + 1
            suffix = f"{date.year}q{quarter}"
        elif interval == PartitionInterval.YEARLY:
            suffix = str(date.year)
        else:
            suffix = date.strftime("%Y%m%d")
        
        return f"{prefix}{table_name}_{suffix}"
    
    def _generate_postgresql_time_partition_sql(self, config: PartitionConfig, 
                                              partition_name: str, start_date: datetime, 
                                              end_date: datetime) -> str:
        """Generate PostgreSQL time partition SQL."""
        return f"""
        CREATE TABLE {partition_name} PARTITION OF {config.table_name}
        FOR VALUES FROM ('{start_date.isoformat()}') TO ('{end_date.isoformat()}')
        """
    
    def _generate_mysql_time_partition_sql(self, config: PartitionConfig, 
                                         partition_name: str, start_date: datetime, 
                                         end_date: datetime) -> str:
        """Generate MySQL time partition SQL."""
        # MySQL partitioning is typically defined on the main table
        return f"""
        ALTER TABLE {config.table_name}
        PARTITION BY RANGE (TO_DAYS({config.partition_column}))
        (PARTITION {partition_name} VALUES LESS THAN (TO_DAYS('{end_date.date()}')))
        """
    
    def _generate_table_based_partition_sql(self, config: PartitionConfig, 
                                           partition_name: str, start_date: datetime, 
                                           end_date: datetime) -> str:
        """Generate table-based partition SQL for databases without native partitioning."""
        return f"""
        CREATE TABLE {partition_name} AS 
        SELECT * FROM {config.table_name} 
        WHERE {config.partition_column} >= '{start_date.isoformat()}' 
        AND {config.partition_column} < '{end_date.isoformat()}'
        AND 1=0
        """
    
    async def cleanup_old_partitions(self, client: AbstractDatabaseClient, 
                                   table_name: str) -> List[str]:
        """Clean up old partitions based on retention policy."""
        if table_name not in self.partition_configs:
            return []
        
        config = self.partition_configs[table_name]
        if not config.retention_period_days or not config.auto_cleanup:
            return []
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=config.retention_period_days)
        dropped_partitions = []
        
        partitions = self.partition_info.get(table_name, [])
        
        for partition in partitions:
            if (partition.end_value and 
                isinstance(partition.end_value, datetime) and 
                partition.end_value < cutoff_date):
                
                try:
                    drop_sql = f"DROP TABLE {partition.name}"
                    result = await client.execute_query(drop_sql)
                    
                    if result.success:
                        dropped_partitions.append(partition.name)
                        partitions.remove(partition)
                        logger.info(f"✅ Dropped old partition: {partition.name}")
                    else:
                        logger.error(f"❌ Failed to drop partition {partition.name}: {result.error}")
                        
                except Exception as e:
                    logger.error(f"❌ Error dropping partition {partition.name}: {e}")
        
        return dropped_partitions
    
    async def get_partition_statistics(self, client: AbstractDatabaseClient, 
                                     table_name: str) -> Dict[str, Any]:
        """Get statistics for table partitions."""
        if table_name not in self.partition_info:
            return {"error": "No partition info found"}
        
        partitions = self.partition_info[table_name]
        
        stats = {
            "table_name": table_name,
            "total_partitions": len(partitions),
            "partition_type": partitions[0].partition_type.value if partitions else "unknown",
            "partitions": []
        }
        
        for partition in partitions:
            partition_stats = {
                "name": partition.name,
                "start_value": partition.start_value.isoformat() if isinstance(partition.start_value, datetime) else partition.start_value,
                "end_value": partition.end_value.isoformat() if isinstance(partition.end_value, datetime) else partition.end_value,
                "created_at": partition.created_at.isoformat() if partition.created_at else None,
                "row_count": partition.row_count,
                "size_bytes": partition.size_bytes
            }
            stats["partitions"].append(partition_stats)
        
        return stats
    
    def get_partition_for_value(self, table_name: str, value: Any) -> Optional[str]:
        """Get the appropriate partition name for a given value."""
        if table_name not in self.partition_configs:
            return None
        
        config = self.partition_configs[table_name]
        partitions = self.partition_info.get(table_name, [])
        
        if config.partition_type == PartitionType.TIME_BASED:
            if isinstance(value, datetime):
                for partition in partitions:
                    if (partition.start_value <= value < partition.end_value):
                        return partition.name
        
        elif config.partition_type == PartitionType.HASH_BASED:
            if config.hash_partitions:
                hash_value = int(hashlib.md5(str(value).encode()).hexdigest(), 16)
                partition_index = hash_value % config.hash_partitions
                return f"{config.partition_prefix}{table_name}_hash_{partition_index}"
        
        return None


# Global partition manager instance
partition_manager = PartitionManager()
