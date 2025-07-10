"""
PlexiChat Enhanced Database Abstraction Layer

Advanced multi-database abstraction supporting:
- SQL databases (PostgreSQL, MySQL, SQLite, SQL Server, Oracle)
- NoSQL databases (MongoDB, Redis, Cassandra, DynamoDB, CouchDB)
- Time-series databases (InfluxDB, TimescaleDB)
- Graph databases (Neo4j, ArangoDB)
- Search engines (Elasticsearch, OpenSearch)
- Data Lakehouse (MinIO + Apache Iceberg/Delta Lake)
- Vector databases (Pinecone, Weaviate, Chroma)

Features:
- Unified query interface across all database types
- Automatic connection pooling and failover
- Data partitioning and sharding strategies
- Real-time analytics and streaming
- ACID transactions where supported
- Eventual consistency handling for NoSQL
- Automatic schema migration and evolution
"""

import asyncio
import logging
import os
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Union, AsyncGenerator, Callable
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from contextlib import asynccontextmanager
import json

logger = logging.getLogger(__name__)


class DatabaseType(Enum):
    """Enhanced database type enumeration."""
    # SQL Databases
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    SQLITE = "sqlite"
    SQLSERVER = "sqlserver"
    ORACLE = "oracle"
    
    # NoSQL Document Databases
    MONGODB = "mongodb"
    COUCHDB = "couchdb"
    DYNAMODB = "dynamodb"
    
    # Key-Value Stores
    REDIS = "redis"
    MEMCACHED = "memcached"
    
    # Column-Family
    CASSANDRA = "cassandra"
    SCYLLADB = "scylladb"
    HBASE = "hbase"
    
    # Time-Series
    INFLUXDB = "influxdb"
    TIMESCALEDB = "timescaledb"
    PROMETHEUS = "prometheus"
    
    # Graph Databases
    NEO4J = "neo4j"
    ARANGODB = "arangodb"
    
    # Search Engines
    ELASTICSEARCH = "elasticsearch"
    OPENSEARCH = "opensearch"
    SOLR = "solr"
    
    # Vector Databases
    PINECONE = "pinecone"
    WEAVIATE = "weaviate"
    CHROMA = "chroma"
    
    # Data Lakehouse
    MINIO_ICEBERG = "minio_iceberg"
    MINIO_DELTA = "minio_delta"
    
    # Analytics
    CLICKHOUSE = "clickhouse"
    DRUID = "druid"


class QueryType(Enum):
    """Query operation types."""
    SELECT = "select"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    AGGREGATE = "aggregate"
    SEARCH = "search"
    GRAPH_TRAVERSE = "graph_traverse"
    TIME_SERIES = "time_series"
    VECTOR_SEARCH = "vector_search"


@dataclass
class DatabaseConfig:
    """Enhanced database configuration."""
    type: DatabaseType
    name: str
    host: str = "localhost"
    port: Optional[int] = None
    database: str = "plexichat"
    username: str = "plexichat"
    password: str = ""
    
    # Connection settings
    ssl_enabled: bool = True
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 3600
    
    # Advanced settings
    encryption_enabled: bool = True
    compression_enabled: bool = False
    read_preference: str = "primary"  # For MongoDB
    consistency_level: str = "eventual"  # For NoSQL
    
    # Partitioning and sharding
    partitioning_enabled: bool = False
    partition_key: Optional[str] = None
    shard_count: int = 1
    
    # Performance settings
    cache_enabled: bool = True
    cache_ttl: int = 300
    batch_size: int = 1000
    
    # Monitoring
    metrics_enabled: bool = True
    slow_query_threshold: float = 1.0
    
    # Custom options
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class QueryResult:
    """Unified query result."""
    data: Any
    count: int = 0
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    cursor: Optional[str] = None  # For pagination


class AbstractDatabaseClient(ABC):
    """Abstract base class for all database clients."""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.connection = None
        self.is_connected = False
        self.metrics = {
            "queries_executed": 0,
            "total_execution_time": 0.0,
            "errors": 0,
            "connections_created": 0
        }
    
    @abstractmethod
    async def connect(self) -> bool:
        """Establish database connection."""
        pass
    
    @abstractmethod
    async def disconnect(self) -> bool:
        """Close database connection."""
        pass
    
    @abstractmethod
    async def execute_query(self, query: str, params: Dict[str, Any] = None, 
                          query_type: QueryType = QueryType.SELECT) -> QueryResult:
        """Execute a database query."""
        pass
    
    @abstractmethod
    async def execute_batch(self, queries: List[Dict[str, Any]]) -> List[QueryResult]:
        """Execute multiple queries in batch."""
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Check database health status."""
        pass
    
    @abstractmethod
    async def get_schema_info(self) -> Dict[str, Any]:
        """Get database schema information."""
        pass
    
    # Optional methods for specific database types
    async def create_index(self, table: str, columns: List[str], 
                          index_type: str = "btree") -> bool:
        """Create database index."""
        raise NotImplementedError("Index creation not supported")
    
    async def partition_table(self, table: str, partition_key: str, 
                            partition_type: str = "range") -> bool:
        """Partition a table."""
        raise NotImplementedError("Table partitioning not supported")
    
    async def stream_data(self, query: str, params: Dict[str, Any] = None) -> AsyncGenerator:
        """Stream large result sets."""
        raise NotImplementedError("Data streaming not supported")


class DatabaseClientFactory:
    """Factory for creating database clients."""
    
    _clients: Dict[DatabaseType, type] = {}
    
    @classmethod
    def register_client(cls, db_type: DatabaseType, client_class: type):
        """Register a database client class."""
        cls._clients[db_type] = client_class
    
    @classmethod
    def create_client(cls, config: DatabaseConfig) -> AbstractDatabaseClient:
        """Create a database client instance."""
        if config.type not in cls._clients:
            raise ValueError(f"Unsupported database type: {config.type}")
        
        client_class = cls._clients[config.type]
        return client_class(config)
    
    @classmethod
    def get_supported_types(cls) -> List[DatabaseType]:
        """Get list of supported database types."""
        return list(cls._clients.keys())


class EnhancedDatabaseManager:
    """Enhanced database manager with multi-database support."""
    
    def __init__(self):
        self.clients: Dict[str, AbstractDatabaseClient] = {}
        self.configs: Dict[str, DatabaseConfig] = {}
        self.factory = DatabaseClientFactory()
        self.default_client: Optional[str] = None
        
        # Load balancing and failover
        self.read_replicas: Dict[str, List[str]] = {}
        self.write_masters: Dict[str, str] = {}
        
        # Connection pooling
        self.connection_pools: Dict[str, Any] = {}
        
        # Metrics and monitoring
        self.global_metrics = {
            "total_queries": 0,
            "total_errors": 0,
            "average_response_time": 0.0,
            "active_connections": 0
        }
    
    async def add_database(self, name: str, config: DatabaseConfig, 
                          is_default: bool = False) -> bool:
        """Add a database configuration."""
        try:
            # Create client
            client = self.factory.create_client(config)
            
            # Test connection
            if await client.connect():
                self.clients[name] = client
                self.configs[name] = config
                
                if is_default or self.default_client is None:
                    self.default_client = name
                
                logger.info(f"✅ Database '{name}' ({config.type.value}) added successfully")
                return True
            else:
                logger.error(f"❌ Failed to connect to database '{name}'")
                return False
                
        except Exception as e:
            logger.error(f"❌ Failed to add database '{name}': {e}")
            return False
    
    async def execute_query(self, query: str, params: Dict[str, Any] = None,
                          database: Optional[str] = None, 
                          query_type: QueryType = QueryType.SELECT) -> QueryResult:
        """Execute query on specified or default database."""
        db_name = database or self.default_client
        if not db_name or db_name not in self.clients:
            raise ValueError(f"Database '{db_name}' not found")
        
        client = self.clients[db_name]
        
        # Route read queries to replicas if available
        if query_type == QueryType.SELECT and db_name in self.read_replicas:
            replica_clients = [self.clients[r] for r in self.read_replicas[db_name] 
                             if r in self.clients]
            if replica_clients:
                client = replica_clients[0]  # Simple round-robin
        
        # Apply query optimization for SELECT queries
        optimized_query = query
        try:
            from .query_optimizer import sql_analyzer, performance_monitor

            if query_type == QueryType.SELECT and query.strip().upper().startswith('SELECT'):
                analysis = sql_analyzer.analyze_query(query)

                # Apply optimizations if beneficial
                if analysis.complexity_score > 3.0 or analysis.uses_select_star or analysis.has_wildcards:
                    optimization = sql_analyzer.optimize_query(query)
                    if optimization.optimization_applied:
                        optimized_query = optimization.optimized_query
                        logger.debug(f"Query optimized: {optimization.optimization_applied}")
        except ImportError:
            logger.debug("Query optimizer not available")
        except Exception as opt_e:
            logger.warning(f"Query optimization failed: {opt_e}")

        start_time = datetime.now()
        try:
            result = await client.execute_query(optimized_query, params, query_type)
            execution_time = (datetime.now() - start_time).total_seconds()
            execution_time_ms = execution_time * 1000

            # Record performance metrics
            try:
                from .query_optimizer import performance_monitor
                performance_monitor.record_query_execution(
                    optimized_query, execution_time_ms,
                    getattr(result, 'row_count', 0),
                    getattr(result, 'row_count', 0)
                )
            except ImportError:
                pass

            # Update global metrics
            self.global_metrics["total_queries"] += 1
            self._update_average_response_time(execution_time)

            return result

        except Exception as e:
            self.global_metrics["total_errors"] += 1
            logger.error(f"Query execution failed on '{db_name}': {e}")
            raise
    
    def _update_average_response_time(self, execution_time: float):
        """Update average response time metric."""
        current_avg = self.global_metrics["average_response_time"]
        total_queries = self.global_metrics["total_queries"]
        
        if total_queries == 1:
            self.global_metrics["average_response_time"] = execution_time
        else:
            # Exponential moving average
            alpha = 0.1
            self.global_metrics["average_response_time"] = (
                alpha * execution_time + (1 - alpha) * current_avg
            )


# Global instance
enhanced_db_manager = EnhancedDatabaseManager()


async def initialize_enhanced_database_system():
    """Initialize the complete enhanced database system."""
    logger.info("🚀 Initializing PlexiChat Enhanced Database System...")

    try:
        # Import and register all database clients
        from .nosql_clients import MongoDBClient, RedisClient
        from .analytics_clients import ClickHouseClient, TimescaleDBClient
        from .lakehouse import MinIOLakehouseClient

        # Register additional SQL clients if needed
        # PostgreSQL and MySQL clients would be registered here

        # Initialize performance optimization system
        from .performance_integration import performance_optimizer
        logger.info("🔧 Performance optimization system initialized")

        # Initialize data ingestion service
        from ...services.data_ingestion_service import data_ingestion_service
        await data_ingestion_service.start()

        # Initialize ETL pipeline service
        from ...services.etl_pipeline_service import etl_pipeline_service
        await etl_pipeline_service.start()

        # Set up default database configurations
        await _setup_default_databases()

        # Set up default ETL pipelines
        await _setup_default_pipelines()

        # Start performance monitoring if enabled
        if os.getenv("PLEXICHAT_AUTO_OPTIMIZATION", "false").lower() == "true":
            asyncio.create_task(_start_performance_monitoring())

        logger.info("✅ Enhanced Database System initialized successfully")
        return True

    except Exception as e:
        logger.error(f"❌ Enhanced Database System initialization failed: {e}")
        return False


async def _setup_default_databases():
    """Set up default database configurations."""
    try:
        # Default SQLite database (existing)
        sqlite_config = DatabaseConfig(
            type=DatabaseType.SQLITE,
            name="default",
            database="data/plexichat.db"
        )
        await enhanced_db_manager.add_database("default", sqlite_config, is_default=True)

        # MongoDB for document storage (optional)
        if "PLEXICHAT_MONGODB_URL" in os.environ:
            mongo_config = DatabaseConfig(
                type=DatabaseType.MONGODB,
                name="mongodb",
                host=os.getenv("PLEXICHAT_MONGODB_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_MONGODB_PORT", "27017")),
                database=os.getenv("PLEXICHAT_MONGODB_DB", "plexichat"),
                username=os.getenv("PLEXICHAT_MONGODB_USER", ""),
                password=os.getenv("PLEXICHAT_MONGODB_PASS", "")
            )
            await enhanced_db_manager.add_database("mongodb", mongo_config)

        # Redis for caching (optional)
        if "PLEXICHAT_REDIS_URL" in os.environ:
            redis_config = DatabaseConfig(
                type=DatabaseType.REDIS,
                name="redis",
                host=os.getenv("PLEXICHAT_REDIS_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_REDIS_PORT", "6379")),
                database=int(os.getenv("PLEXICHAT_REDIS_DB", "0")),
                password=os.getenv("PLEXICHAT_REDIS_PASS", "")
            )
            await enhanced_db_manager.add_database("redis", redis_config)

        # ClickHouse for analytics (optional)
        if "PLEXICHAT_CLICKHOUSE_URL" in os.environ:
            clickhouse_config = DatabaseConfig(
                type=DatabaseType.CLICKHOUSE,
                name="analytics",
                host=os.getenv("PLEXICHAT_CLICKHOUSE_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_CLICKHOUSE_PORT", "9000")),
                database=os.getenv("PLEXICHAT_CLICKHOUSE_DB", "plexichat"),
                username=os.getenv("PLEXICHAT_CLICKHOUSE_USER", "default"),
                password=os.getenv("PLEXICHAT_CLICKHOUSE_PASS", "")
            )
            await enhanced_db_manager.add_database("analytics", clickhouse_config)

        # MinIO Lakehouse (optional)
        if "PLEXICHAT_MINIO_URL" in os.environ:
            lakehouse_config = DatabaseConfig(
                type=DatabaseType.MINIO_ICEBERG,
                name="lakehouse",
                options={
                    "endpoint": os.getenv("PLEXICHAT_MINIO_ENDPOINT", "localhost:9000"),
                    "access_key": os.getenv("PLEXICHAT_MINIO_ACCESS_KEY", "minioadmin"),
                    "secret_key": os.getenv("PLEXICHAT_MINIO_SECRET_KEY", "minioadmin"),
                    "bucket_name": os.getenv("PLEXICHAT_MINIO_BUCKET", "plexichat-lakehouse"),
                    "secure": os.getenv("PLEXICHAT_MINIO_SECURE", "false").lower() == "true"
                }
            )
            await enhanced_db_manager.add_database("lakehouse", lakehouse_config)

        logger.info("✅ Default databases configured")

    except Exception as e:
        logger.error(f"❌ Failed to setup default databases: {e}")


async def _setup_default_pipelines():
    """Set up default ETL pipelines."""
    try:
        from ...services.etl_pipeline_service import etl_pipeline_service, PipelineConfig, PipelineType

        # User activity aggregation pipeline
        user_activity_pipeline = PipelineConfig(
            name="user_activity_aggregation",
            pipeline_type=PipelineType.SCHEDULED,
            description="Aggregate user activity data for analytics",
            source_type="lakehouse",
            source_config={
                "query": """
                SELECT
                    user_id,
                    event_type,
                    DATE(timestamp) as event_date,
                    COUNT(*) as event_count
                FROM raw_user_events
                WHERE timestamp >= current_date() - INTERVAL 1 DAY
                GROUP BY user_id, event_type, DATE(timestamp)
                """
            },
            target_type="analytics_warehouse",
            target_config={
                "table": "user_activity_daily"
            },
            schedule_cron="0 1 * * *",  # Run daily at 1 AM
            transformations=[
                {
                    "type": "enrich",
                    "enrichment_type": "timestamp"
                }
            ]
        )
        etl_pipeline_service.register_pipeline(user_activity_pipeline)

        # Message analytics pipeline
        message_analytics_pipeline = PipelineConfig(
            name="message_analytics",
            pipeline_type=PipelineType.SCHEDULED,
            description="Process message data for analytics",
            source_type="database",
            source_config={
                "database": "default",
                "query": """
                SELECT
                    channel_id,
                    user_id,
                    created_at,
                    LENGTH(content) as message_length,
                    CASE WHEN content LIKE '%@%' THEN 1 ELSE 0 END as has_mention
                FROM messages
                WHERE created_at >= datetime('now', '-1 day')
                """
            },
            target_type="analytics_warehouse",
            target_config={
                "table": "message_analytics_daily"
            },
            schedule_cron="0 2 * * *",  # Run daily at 2 AM
            transformations=[
                {
                    "type": "aggregate",
                    "group_by": ["channel_id"],
                    "aggregations": {
                        "message_count": "count",
                        "avg_message_length": "avg",
                        "total_mentions": "sum"
                    }
                }
            ]
        )
        etl_pipeline_service.register_pipeline(message_analytics_pipeline)

        logger.info("✅ Default ETL pipelines configured")

    except Exception as e:
        logger.error(f"❌ Failed to setup default pipelines: {e}")


async def shutdown_enhanced_database_system():
    """Shutdown the enhanced database system."""
    logger.info("🛑 Shutting down Enhanced Database System...")

    try:
        # Stop services
        from ...services.data_ingestion_service import data_ingestion_service
        from ...services.etl_pipeline_service import etl_pipeline_service

        await data_ingestion_service.stop()
        await etl_pipeline_service.stop()

        # Disconnect all database clients
        for name, client in enhanced_db_manager.clients.items():
            await client.disconnect()

        logger.info("✅ Enhanced Database System shutdown complete")

    except Exception as e:
        logger.error(f"❌ Enhanced Database System shutdown failed: {e}")


# Convenience functions for the enhanced system
async def get_database_client(name: str) -> Optional[AbstractDatabaseClient]:
    """Get a database client by name."""
    return enhanced_db_manager.clients.get(name)


async def execute_analytics_query(query: str, params: Dict[str, Any] = None) -> QueryResult:
    """Execute query on analytics database."""
    return await enhanced_db_manager.execute_query(
        query, params, database="analytics", query_type=QueryType.SELECT
    )


async def ingest_user_event(user_id: str, event_type: str, data: Dict[str, Any] = None):
    """Convenience function to ingest user events."""
    from ...services.data_ingestion_service import data_ingestion_service
    return await data_ingestion_service.ingest_user_event(user_id, event_type, data=data)


async def ingest_api_request(method: str, endpoint: str, user_id: str = None,
                           response_code: int = None, response_time: float = None):
    """Convenience function to ingest API requests."""
    from ...services.data_ingestion_service import data_ingestion_service
    return await data_ingestion_service.ingest_api_request(
        method, endpoint, user_id, response_code, response_time
    )


async def run_etl_pipeline(pipeline_name: str, trigger_data: Dict[str, Any] = None):
    """Convenience function to run ETL pipeline."""
    from ...services.etl_pipeline_service import etl_pipeline_service
    return await etl_pipeline_service.execute_pipeline(pipeline_name, trigger_data)


async def _start_performance_monitoring():
    """Start background performance monitoring and optimization."""
    from .performance_integration import performance_optimizer

    logger.info("🔍 Starting automatic performance monitoring...")

    while True:
        try:
            # Wait for optimization interval
            interval_hours = int(os.getenv("PLEXICHAT_OPTIMIZATION_INTERVAL_HOURS", "24"))
            await asyncio.sleep(interval_hours * 3600)

            # Analyze and optimize all databases
            for db_name in enhanced_db_manager.clients.keys():
                try:
                    logger.info(f"🔍 Analyzing performance for database: {db_name}")

                    # Analyze performance
                    report = await performance_optimizer.analyze_database_performance(db_name)

                    # Auto-optimize if performance is poor
                    if report.performance_score < 70:
                        logger.warning(f"⚠️ Performance degradation detected in {db_name} (Score: {report.performance_score}/100)")

                        # Run automatic optimization
                        tasks = await performance_optimizer.optimize_database_performance(
                            db_name, auto_apply=True
                        )

                        logger.info(f"✅ Applied {len(tasks)} optimizations to {db_name}")
                    else:
                        logger.info(f"✅ Database {db_name} performance is good (Score: {report.performance_score}/100)")

                except Exception as e:
                    logger.error(f"❌ Performance monitoring failed for {db_name}: {e}")

        except Exception as e:
            logger.error(f"❌ Performance monitoring error: {e}")
            await asyncio.sleep(3600)  # Wait 1 hour before retrying


async def optimize_database_performance(database_name: str, auto_apply: bool = False):
    """Convenience function to optimize database performance."""
    from .performance_integration import performance_optimizer
    return await performance_optimizer.optimize_database_performance(database_name, auto_apply)


async def get_database_performance_report(database_name: str):
    """Convenience function to get database performance report."""
    from .performance_integration import performance_optimizer
    return await performance_optimizer.analyze_database_performance(database_name)
