import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Coroutine, Any as TypingAny

try:

    import redis.asyncio as redis  # type: ignore

except ImportError:

    redis = None
from motor.motor_asyncio import AsyncIOMotorClient  # type: ignore

from ...core.config import get_config
from ...core.logging import get_logger

# Import unified cache integration
try:
    from ...core.caching.unified_cache_integration import cache_get, cache_set, cache_delete, CacheKeyBuilder
    CACHE_AVAILABLE = True
except ImportError:
    import types
    async def cache_get(key: str, default=None):
        return default
    async def _always_true(*args, **kwargs):
        return True
    cache_set = _always_true
    cache_delete = _always_true
    CACHE_AVAILABLE = False
    CacheKeyBuilder = None
# Comment out or remove problematic imports for missing symbols
# try:
#     from ...features.channels.repositories.channel_repository import ChannelRepository
# except ImportError:
ChannelRepository = None

# try:
#     from ...features.channels.repositories.permission_overwrite_repository import PermissionOverwriteRepository
# except ImportError:
PermissionOverwriteRepository = None

# try:
#     from ...features.channels.repositories.role_repository import RoleRepository
# except ImportError:
RoleRepository = None

# try:
#     from ...features.security import distributed_key_manager, quantum_encryption
# except ImportError:
distributed_key_manager = None
quantum_encryption = None

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine  # type: ignore
from sqlalchemy.pool import StaticPool  # type: ignore
from sqlalchemy import text  # type: ignore
from plexichat.features.security.database_encryption import setup_database_encryption, encryption_manager
import sqlalchemy

"""
Consolidated Database Manager - Single Source of Truth

Replaces all previous database management systems with a unified,
comprehensive solution supporting all database types and advanced features.
"""

# SQLAlchemy imports
# Database-specific imports
try:
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

try:
    MOTOR_AVAILABLE = True
except ImportError:
    MOTOR_AVAILABLE = False
    AsyncIOMotorClient = None

# PlexiChat imports
logger = get_logger(__name__)


class DatabaseType(Enum):
    """Supported database types."""
    # SQL Databases
    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MARIADB = "mariadb"
    ORACLE = "oracle"
    MSSQL = "mssql"
    COCKROACHDB = "cockroachdb"

    # NoSQL Databases
    MONGODB = "mongodb"
    CASSANDRA = "cassandra"
    COUCHDB = "couchdb"
    DYNAMODB = "dynamodb"
    FIRESTORE = "firestore"
    ARANGODB = "arangodb"

    # Cache/In-Memory Databases
    REDIS = "redis"
    MEMCACHED = "memcached"

    # Analytics/Time-Series Databases
    CLICKHOUSE = "clickhouse"
    TIMESCALEDB = "timescaledb"
    INFLUXDB = "influxdb"

    # Graph Databases
    NEO4J = "neo4j"

    # Search Engines
    ELASTICSEARCH = "elasticsearch"
    OPENSEARCH = "opensearch"
    SOLR = "solr"

    # Data Warehouses
    SNOWFLAKE = "snowflake"
    BIGQUERY = "bigquery"
    REDSHIFT = "redshift"

    # Object Storage/Lakehouse
    MINIO = "minio"
    S3 = "s3"

    # Vector Databases
    PINECONE = "pinecone"
    WEAVIATE = "weaviate"
    CHROMA = "chroma"


class DatabaseRole(Enum):
    """Database role in cluster."""
    PRIMARY = "primary"
    REPLICA = "replica"
    ANALYTICS = "analytics"
    CACHE = "cache"
    BACKUP = "backup"


class ConnectionStatus(Enum):
    """Database connection status."""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    ERROR = "error"
    MAINTENANCE = "maintenance"


@dataclass
class DatabaseConfig:
    """Database configuration."""
    type: DatabaseType
    name: str
    host: str = "localhost"
    port: int = 5432
    database: str = "plexichat"
    username: str = ""
    password: str = ""
    role: DatabaseRole = DatabaseRole.PRIMARY
    ssl_enabled: bool = True
    encryption_enabled: bool = True
    connection_pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 3600
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DatabaseMetrics:
    """Database performance metrics."""
    queries_executed: int = 0
    total_execution_time: float = 0.0
    average_response_time: float = 0.0
    errors: int = 0
    active_connections: int = 0
    peak_connections: int = 0
    last_query_time: Optional[datetime] = None
    uptime_seconds: float = 0.0


class ConsolidatedDatabaseManager:
    """
    Consolidated Database Manager - Single Source of Truth

    Replaces all previous database management systems with a unified,
    comprehensive solution supporting all database types and advanced features.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # Handle config safely
        if config:
            self.config = config
        else:
            try:
                config_obj = get_config()
                if hasattr(config_obj, 'get'):
                    self.config = config_obj.get("database", {})  # type: ignore
                elif hasattr(config_obj, 'database'):
                    self.config = getattr(config_obj, 'database', {})
                else:
                    self.config = {}
            except Exception:
                self.config = {}
        self.initialized = False

        # Database configurations and connections
        self.database_configs: Dict[str, DatabaseConfig] = {}
        self.engines: Dict[str, Union[AsyncEngine, Any]] = {}
        self.sessions: Dict[str, Any] = {}
        self.connection_pools: Dict[str, Any] = {}

        # Connection status and metrics
        self.connection_status: Dict[str, ConnectionStatus] = {}
        self.connection_metrics: Dict[str, DatabaseMetrics] = {}

        # Security and encryption
        self.encryption_manager = None
        self.key_manager = None

        # Advanced features
        self.migration_manager = None
        self.backup_integration = None
        self.performance_monitor = None
        self.global_distribution = None

        # Performance monitoring
        self._performance_monitor = None
        self._query_cache = {}
        self._cache_stats = {'hits': 0, 'misses': 0}

        # Load balancing and failover
        self.read_replicas: Dict[str, List[str]] = {}
        self.write_masters: Dict[str, str] = {}
        self.health_check_interval = 30

        # Global metrics
        self.global_metrics = {
            "total_queries": 0,
            "total_errors": 0,
            "average_response_time": 0.0,
            "active_connections": 0,
            "databases_connected": 0
        }

        # Repository registry for new channel system
        self.repositories = {}
        self._register_default_repositories()

        logger.info("Consolidated Database Manager initialized")

    async def initialize(self, config: Optional[Dict[str, Any]] = None) -> bool:
        """Initialize the consolidated database system."""
        try:
            if config:
                self.config.update(config)

            # Initialize security components
            await self._initialize_security()

            # Initialize advanced components
            await self._initialize_components()

            # Load default database configurations
            await self._load_default_configurations()

            # Initialize performance monitoring
            await self._initialize_performance_monitoring()

            # Start background tasks
            asyncio.create_task(self._health_check_task())
            asyncio.create_task(self._metrics_collection_task())

            self.initialized = True
            logger.info(" Consolidated Database Manager fully initialized")
            return True

        except Exception as e:
            logger.error(f" Database manager initialization failed: {e}")
            return False

    def _register_default_repositories(self):
        """Register default repositories for the channel system."""
        try:
            # Register channel system repositories if available
            if ChannelRepository:
                self.register_repository("channel", ChannelRepository)
            if RoleRepository:
                self.register_repository("role", RoleRepository)
            if PermissionOverwriteRepository:
                self.register_repository("permission_overwrite", PermissionOverwriteRepository)
            logger.info(" Default repositories registered successfully")
        except ImportError as e:
            logger.warning(f" Some repositories not available yet: {e}")
        except Exception as e:
            logger.error(f" Failed to register default repositories: {e}")

    def register_repository(self, name: str, repository_class):
        """Register a repository class with the database manager."""
        try:
            self.repositories[name] = repository_class
            logger.debug(f"Registered repository: {name} -> {repository_class.__name__}")
            return True
        except Exception as e:
            logger.error(f"Failed to register repository {name}: {e}")
            return False

    def get_repository(self, name: str, session_factory=None):
        """Get a repository instance by name."""
        try:
            if name not in self.repositories:
                raise ValueError(f"Repository '{name}' not registered")

            repository_class = self.repositories[name]
            return repository_class(session_factory)

        except Exception as e:
            logger.error(f"Failed to get repository {name}: {e}")
            return None

    def list_repositories(self) -> list:
        """List all registered repositories."""
        return list(self.repositories.keys())

    async def _initialize_security(self) -> None:
        """Initialize security and encryption components."""
        try:
            # Initialize encryption manager
            self.encryption_manager = encryption_manager
            if hasattr(self.encryption_manager, 'initialize'):
                await self.encryption_manager.initialize()  # type: ignore

            # Initialize key manager
            self.key_manager = distributed_key_manager
            if hasattr(self.key_manager, 'initialize'):
                await self.key_manager.initialize()  # type: ignore

            logger.info("Database security components initialized")

        except Exception as e:
            logger.error(f"Security initialization failed: {e}")
            # Continue without encryption if not available

    async def _initialize_components(self) -> None:
        """Initialize advanced database components."""
        try:
            # Initialize migration manager
            # Placeholder: Replace with actual import or implementation
            self.migration_manager = None  # zero_downtime_migration_manager
            # if self.migration_manager:
            #     await self.migration_manager.initialize()

            # Initialize global data distribution
            self.global_distribution = None  # global_data_distribution_manager
            # if self.global_distribution:
            #     await self.global_distribution.initialize()

            # Initialize backup integration
            self.backup_integration = None  # get_unified_backup_manager()

            logger.info("Advanced database components initialized")

        except Exception as e:
            logger.error(f"Component initialization failed: {e}")
            # Continue with basic functionality

    async def _load_default_configurations(self) -> None:
        """Load default database configurations."""
        # Default SQLite configuration - store in data folder
        sqlite_config = DatabaseConfig(
            type=DatabaseType.SQLITE,
            name="default",
            database="data/plexichat.db",
            role=DatabaseRole.PRIMARY
        )
        await self.add_database("default", sqlite_config, is_default=True)

        # Load additional configurations from environment
        await self._load_environment_configurations()

    async def _load_environment_configurations(self) -> None:
        """Load database configurations from environment variables."""
        # PostgreSQL configuration
        if os.getenv("PLEXICHAT_POSTGRES_URL"):
            postgres_config = DatabaseConfig(
                type=DatabaseType.POSTGRESQL,
                name="postgres",
                host=os.getenv("PLEXICHAT_POSTGRES_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_POSTGRES_PORT", "5432")),
                database=os.getenv("PLEXICHAT_POSTGRES_DB", "plexichat"),
                username=os.getenv("PLEXICHAT_POSTGRES_USER", ""),
                password=os.getenv("PLEXICHAT_POSTGRES_PASS", ""),
                role=DatabaseRole.PRIMARY
            )
            await self.add_database("postgres", postgres_config)

        # MongoDB configuration
        if os.getenv("PLEXICHAT_MONGODB_URL"):
            mongo_config = DatabaseConfig(
                type=DatabaseType.MONGODB,
                name="mongodb",
                host=os.getenv("PLEXICHAT_MONGODB_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_MONGODB_PORT", "27017")),
                database=os.getenv("PLEXICHAT_MONGODB_DB", "plexichat"),
                username=os.getenv("PLEXICHAT_MONGODB_USER", ""),
                password=os.getenv("PLEXICHAT_MONGODB_PASS", ""),
                role=DatabaseRole.PRIMARY
            )
            await self.add_database("mongodb", mongo_config)

        # Redis configuration
        if os.getenv("PLEXICHAT_REDIS_URL"):
            redis_config = DatabaseConfig(
                type=DatabaseType.REDIS,
                name="redis",
                host=os.getenv("PLEXICHAT_REDIS_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_REDIS_PORT", "6379")),
                password=os.getenv("PLEXICHAT_REDIS_PASS", ""),
                role=DatabaseRole.CACHE
            )
            await self.add_database("redis", redis_config)

        # MySQL configuration
        if os.getenv("PLEXICHAT_MYSQL_URL"):
            mysql_config = DatabaseConfig(
                type=DatabaseType.MYSQL,
                name="mysql",
                host=os.getenv("PLEXICHAT_MYSQL_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_MYSQL_PORT", "3306")),
                database=os.getenv("PLEXICHAT_MYSQL_DB", "plexichat"),
                username=os.getenv("PLEXICHAT_MYSQL_USER", ""),
                password=os.getenv("PLEXICHAT_MYSQL_PASS", ""),
                role=DatabaseRole.PRIMARY
            )
            await self.add_database("mysql", mysql_config)

        # MariaDB configuration
        if os.getenv("PLEXICHAT_MARIADB_URL"):
            mariadb_config = DatabaseConfig(
                type=DatabaseType.MARIADB,
                name="mariadb",
                host=os.getenv("PLEXICHAT_MARIADB_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_MARIADB_PORT", "3306")),
                database=os.getenv("PLEXICHAT_MARIADB_DB", "plexichat"),
                username=os.getenv("PLEXICHAT_MARIADB_USER", ""),
                password=os.getenv("PLEXICHAT_MARIADB_PASS", ""),
                role=DatabaseRole.PRIMARY
            )
            await self.add_database("mariadb", mariadb_config)

        # ClickHouse configuration
        if os.getenv("PLEXICHAT_CLICKHOUSE_URL"):
            clickhouse_config = DatabaseConfig(
                type=DatabaseType.CLICKHOUSE,
                name="clickhouse",
                host=os.getenv("PLEXICHAT_CLICKHOUSE_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_CLICKHOUSE_PORT", "8123")),
                database=os.getenv("PLEXICHAT_CLICKHOUSE_DB", "plexichat"),
                username=os.getenv("PLEXICHAT_CLICKHOUSE_USER", ""),
                password=os.getenv("PLEXICHAT_CLICKHOUSE_PASS", ""),
                role=DatabaseRole.ANALYTICS
            )
            await self.add_database("clickhouse", clickhouse_config)

        # TimescaleDB configuration
        if os.getenv("PLEXICHAT_TIMESCALEDB_URL"):
            timescaledb_config = DatabaseConfig(
                type=DatabaseType.TIMESCALEDB,
                name="timescaledb",
                host=os.getenv("PLEXICHAT_TIMESCALEDB_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_TIMESCALEDB_PORT", "5432")),
                database=os.getenv("PLEXICHAT_TIMESCALEDB_DB", "plexichat"),
                username=os.getenv("PLEXICHAT_TIMESCALEDB_USER", ""),
                password=os.getenv("PLEXICHAT_TIMESCALEDB_PASS", ""),
                role=DatabaseRole.ANALYTICS
            )
            await self.add_database("timescaledb", timescaledb_config)

        # Cassandra configuration
        if os.getenv("PLEXICHAT_CASSANDRA_URL"):
            cassandra_config = DatabaseConfig(
                type=DatabaseType.CASSANDRA,
                name="cassandra",
                host=os.getenv("PLEXICHAT_CASSANDRA_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_CASSANDRA_PORT", "9042")),
                database=os.getenv("PLEXICHAT_CASSANDRA_KEYSPACE", "plexichat"),
                username=os.getenv("PLEXICHAT_CASSANDRA_USER", ""),
                password=os.getenv("PLEXICHAT_CASSANDRA_PASS", ""),
                role=DatabaseRole.PRIMARY
            )
            await self.add_database("cassandra", cassandra_config)

        # Elasticsearch configuration
        if os.getenv("PLEXICHAT_ELASTICSEARCH_URL"):
            elasticsearch_config = DatabaseConfig(
                type=DatabaseType.ELASTICSEARCH,
                name="elasticsearch",
                host=os.getenv("PLEXICHAT_ELASTICSEARCH_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_ELASTICSEARCH_PORT", "9200")),
                database=os.getenv("PLEXICHAT_ELASTICSEARCH_INDEX", "plexichat"),
                username=os.getenv("PLEXICHAT_ELASTICSEARCH_USER", ""),
                password=os.getenv("PLEXICHAT_ELASTICSEARCH_PASS", ""),
                role=DatabaseRole.ANALYTICS
            )
            await self.add_database("elasticsearch", elasticsearch_config)

        # Neo4j configuration
        if os.getenv("PLEXICHAT_NEO4J_URL"):
            neo4j_config = DatabaseConfig(
                type=DatabaseType.NEO4J,
                name="neo4j",
                host=os.getenv("PLEXICHAT_NEO4J_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_NEO4J_PORT", "7687")),
                database=os.getenv("PLEXICHAT_NEO4J_DB", "neo4j"),
                username=os.getenv("PLEXICHAT_NEO4J_USER", ""),
                password=os.getenv("PLEXICHAT_NEO4J_PASS", ""),
                role=DatabaseRole.ANALYTICS
            )
            await self.add_database("neo4j", neo4j_config)

        # InfluxDB configuration
        if os.getenv("PLEXICHAT_INFLUXDB_URL"):
            influxdb_config = DatabaseConfig(
                type=DatabaseType.INFLUXDB,
                name="influxdb",
                host=os.getenv("PLEXICHAT_INFLUXDB_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_INFLUXDB_PORT", "8086")),
                database=os.getenv("PLEXICHAT_INFLUXDB_BUCKET", "plexichat"),
                username=os.getenv("PLEXICHAT_INFLUXDB_ORG", ""),
                password=os.getenv("PLEXICHAT_INFLUXDB_TOKEN", ""),
                role=DatabaseRole.ANALYTICS
            )
            await self.add_database("influxdb", influxdb_config)

    async def add_database(self, name: str, config: DatabaseConfig, is_default: bool = False) -> bool:
        """Add a database configuration and establish connection."""
        try:
            self.database_configs[name] = config

            # Create database engine/connection based on type
            if config.type == DatabaseType.SQLITE:
                # Ensure data directory exists
                from pathlib import Path
                db_path = Path(config.database)
                db_path.parent.mkdir(parents=True, exist_ok=True)

                engine = create_async_engine(
                    f"sqlite+aiosqlite:///{config.database}",
                    poolclass=StaticPool,
                    connect_args={"check_same_thread": False}
                )
                self.engines[name] = engine
                # Enforce encryption hooks only for sync engines
                if isinstance(engine, sqlalchemy.engine.Engine):
                    setup_database_encryption(engine)
                else:
                    logger.warning(f"Encryption hooks not applied: {name} is not a sync SQLAlchemy engine.")

            elif config.type == DatabaseType.POSTGRESQL:
                connection_string = f"postgresql+asyncpg://{config.username}:{config.password}@{config.host}:{config.port}/{config.database}"
                engine = create_async_engine(
                    connection_string,
                    pool_size=config.connection_pool_size,
                    max_overflow=config.max_overflow,
                    pool_timeout=config.pool_timeout,
                    pool_recycle=config.pool_recycle
                )
                self.engines[name] = engine
                # Enforce encryption hooks only for sync engines
                if isinstance(engine, sqlalchemy.engine.Engine):
                    setup_database_encryption(engine)
                else:
                    logger.warning(f"Encryption hooks not applied: {name} is not a sync SQLAlchemy engine.")

            elif config.type == DatabaseType.MONGODB:
                if AsyncIOMotorClient is not None:
                    connection_string = f"mongodb://{config.username}:{config.password}@{config.host}:{config.port}/{config.database}"
                    client = AsyncIOMotorClient(connection_string)
                    self.engines[name] = client
                else:
                    logger.warning(f"MongoDB support not available for {name}")
                    return False

            elif config.type == DatabaseType.REDIS:
                if redis is not None:
                    client = redis.Redis(
                        host=config.host,
                        port=config.port,
                        password=config.password,
                        decode_responses=True
                    )
                    self.engines[name] = client
                else:
                    logger.warning(f"Redis support not available for {name}")
                    return False

            elif config.type == DatabaseType.MYSQL:
                try:
                    connection_string = f"mysql+aiomysql://{config.username}:{config.password}@{config.host}:{config.port}/{config.database}"
                    engine = create_async_engine(
                        connection_string,
                        pool_size=config.connection_pool_size,
                        max_overflow=config.max_overflow,
                        pool_timeout=config.pool_timeout,
                        pool_recycle=config.pool_recycle
                    )
                    self.engines[name] = engine
                except ImportError:
                    logger.warning(f"MySQL support not available for {name} (aiomysql not installed)")
                    return False

            elif config.type == DatabaseType.MARIADB:
                try:
                    # MariaDB uses same driver as MySQL
                    connection_string = f"mysql+aiomysql://{config.username}:{config.password}@{config.host}:{config.port}/{config.database}"
                    engine = create_async_engine(
                        connection_string,
                        pool_size=config.connection_pool_size,
                        max_overflow=config.max_overflow,
                        pool_timeout=config.pool_timeout,
                        pool_recycle=config.pool_recycle
                    )
                    self.engines[name] = engine
                except ImportError:
                    logger.warning(f"MariaDB support not available for {name} (aiomysql not installed)")
                    return False

            elif config.type == DatabaseType.CLICKHOUSE:
                try:
                    # ClickHouse connection
                    connection_string = f"clickhouse+asynch://{config.username}:{config.password}@{config.host}:{config.port}/{config.database}"
                    engine = create_async_engine(connection_string)
                    self.engines[name] = engine
                except ImportError:
                    logger.warning(f"ClickHouse support not available for {name} (asynch not installed)")
                    return False

            elif config.type == DatabaseType.TIMESCALEDB:
                # TimescaleDB uses PostgreSQL driver
                connection_string = f"postgresql+asyncpg://{config.username}:{config.password}@{config.host}:{config.port}/{config.database}"
                engine = create_async_engine(
                    connection_string,
                    pool_size=config.connection_pool_size,
                    max_overflow=config.max_overflow,
                    pool_timeout=config.pool_timeout,
                    pool_recycle=config.pool_recycle
                )
                self.engines[name] = engine

            elif config.type == DatabaseType.CASSANDRA:
                try:
                    from cassandra.cluster import Cluster
                    from cassandra.auth import PlainTextAuthProvider

                    auth_provider = PlainTextAuthProvider(username=config.username, password=config.password)
                    cluster = Cluster([config.host], port=config.port, auth_provider=auth_provider)
                    session = cluster.connect()
                    self.engines[name] = session
                except ImportError:
                    logger.warning(f"Cassandra support not available for {name} (cassandra-driver not installed)")
                    return False

            elif config.type == DatabaseType.ELASTICSEARCH:
                try:
                    from elasticsearch import AsyncElasticsearch

                    client = AsyncElasticsearch(
                        [{'host': config.host, 'port': config.port}],
                        http_auth=(config.username, config.password) if config.username else None
                    )
                    self.engines[name] = client
                except ImportError:
                    logger.warning(f"Elasticsearch support not available for {name} (elasticsearch not installed)")
                    return False

            elif config.type == DatabaseType.NEO4J:
                try:
                    from neo4j import AsyncGraphDatabase

                    uri = f"bolt://{config.host}:{config.port}"
                    driver = AsyncGraphDatabase.driver(uri, auth=(config.username, config.password))
                    self.engines[name] = driver
                except ImportError:
                    logger.warning(f"Neo4j support not available for {name} (neo4j not installed)")
                    return False

            elif config.type == DatabaseType.INFLUXDB:
                try:
                    from influxdb_client.client.influxdb_client_async import InfluxDBClientAsync

                    client = InfluxDBClientAsync(
                        url=f"http://{config.host}:{config.port}",
                        token=config.password,  # InfluxDB uses token instead of password
                        org=config.username     # InfluxDB uses org instead of username
                    )
                    self.engines[name] = client
                except ImportError:
                    logger.warning(f"InfluxDB support not available for {name} (influxdb-client not installed)")
                    return False

            else:
                logger.warning(f"Unsupported database type: {config.type}")
                return False

            # Initialize metrics
            self.connection_metrics[name] = DatabaseMetrics()
            self.connection_status[name] = ConnectionStatus.CONNECTING

            # Test connection
            await self._test_connection(name)

            if is_default:
                self.default_database = name

            logger.info(f" Database '{name}' ({config.type.value}) added successfully")
            return True

        except Exception as e:
            logger.error(f" Failed to add database '{name}': {e}")
            self.connection_status[name] = ConnectionStatus.ERROR
            return False

    async def _test_connection(self, name: str) -> bool:
        """Test database connection."""
        try:
            config = self.database_configs[name]
            engine = self.engines[name]

            # SQL Databases (SQLAlchemy-based)
            if config.type in [DatabaseType.SQLITE, DatabaseType.POSTGRESQL, DatabaseType.MYSQL,
                              DatabaseType.MARIADB, DatabaseType.TIMESCALEDB, DatabaseType.CLICKHOUSE]:
                async with engine.begin() as conn:
                    await conn.execute(text("SELECT 1"))

            # NoSQL Databases
            elif config.type == DatabaseType.MONGODB:
                if hasattr(engine, 'admin'):
                    await engine.admin.command('ping')  # type: ignore
                else:
                    # Alternative ping for MongoDB
                    await engine.server_info()  # type: ignore

            elif config.type == DatabaseType.CASSANDRA:
                # Test Cassandra connection
                if hasattr(engine, 'execute'):
                    engine.execute("SELECT now() FROM system.local")

            # Cache Databases
            elif config.type == DatabaseType.REDIS:
                if hasattr(engine, 'ping'):
                    await engine.ping()  # type: ignore
                else:
                    # Alternative ping for Redis
                    await engine.execute_command('PING')  # type: ignore

            # Search Engines
            elif config.type == DatabaseType.ELASTICSEARCH:
                if hasattr(engine, 'ping'):
                    await engine.ping()
                elif hasattr(engine, 'info'):
                    await engine.info()

            # Graph Databases
            elif config.type == DatabaseType.NEO4J:
                if hasattr(engine, 'verify_connectivity'):
                    await engine.verify_connectivity()

            # Time Series Databases
            elif config.type == DatabaseType.INFLUXDB:
                if hasattr(engine, 'ping'):
                    await engine.ping()
                elif hasattr(engine, 'health'):
                    await engine.health()

            else:
                logger.warning(f"Connection test not implemented for {config.type}")
                # Assume connection is working if no test is available
                pass

            self.connection_status[name] = ConnectionStatus.CONNECTED
            self.global_metrics["databases_connected"] += 1
            return True

        except Exception as e:
            logger.error(f"Connection test failed for '{name}': {e}")
            self.connection_status[name] = ConnectionStatus.ERROR
            return False

    async def _initialize_performance_monitoring(self):
        """Initialize performance monitoring system."""
        try:
            from .performance_monitor import DatabasePerformanceMonitor

            monitor_config = self.config.get('monitoring', {})
            self._performance_monitor = DatabasePerformanceMonitor(monitor_config)

            if monitor_config.get('enabled', True):
                await self._performance_monitor.start_monitoring()
                logger.info("Database performance monitoring enabled")

        except Exception as e:
            logger.warning(f"Performance monitoring initialization failed: {e}")

    async def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None, database: Optional[str] = None, use_cache: bool = True) -> Dict[str, Any]:
        """Execute a database query with unified interface, caching, and performance monitoring."""
        start_time = time.time()
        database = database or getattr(self, 'default_database', 'default')

        # Check query cache first
        cache_key = None
        cache_hit = False
        if use_cache and query.strip().upper().startswith('SELECT'):
            cache_key = hash(f"{query}{params}")
            if cache_key in self._query_cache:
                self._cache_stats['hits'] += 1
                cache_hit = True
                result = self._query_cache[cache_key]

                # Record cache hit in performance monitor
                if self._performance_monitor:
                    execution_time = time.time() - start_time
                    self._performance_monitor.record_query_execution(query, execution_time)

                return result
            else:
                self._cache_stats['misses'] += 1

        # Generate cache key for SELECT queries
        cache_key = None
        if use_cache and CACHE_AVAILABLE and query.strip().upper().startswith('SELECT'):
            import hashlib
            query_hash = hashlib.md5(f"{query}:{params}".encode()).hexdigest()
            # Ensure database is str, not None
            table = database if database is not None else "default"
            if CACHE_AVAILABLE and CacheKeyBuilder is not None:
                cache_key = CacheKeyBuilder.query_key(table, query_hash)

                # Try to get from cache
                cached_result = await cache_get(cache_key)
                if cached_result is not None:
                    logger.debug(f"Cache hit for query: {query[:50]}...")
                    return cached_result

        try:
            if database not in self.engines:
                raise Exception(f"Database '{database}' not configured")

            config = self.database_configs[database]
            engine = self.engines[database]
            params = params or {}

            result = None

            # SQL Databases (SQLAlchemy-based)
            if config.type in [DatabaseType.SQLITE, DatabaseType.POSTGRESQL, DatabaseType.MYSQL,
                              DatabaseType.MARIADB, DatabaseType.TIMESCALEDB, DatabaseType.CLICKHOUSE]:
                async with engine.begin() as conn:
                    result_obj = await conn.execute(text(query), params)
                    if result_obj.returns_rows:
                        rows = result_obj.fetchall()
                        result = {"rows": [dict(row._mapping) for row in rows], "rowcount": len(rows)}
                    else:
                        result = {"rowcount": result_obj.rowcount}

            elif config.type == DatabaseType.MONGODB:
                # Parse MongoDB query (simplified)
                query_obj = json.loads(query)
                # Access MongoDB collection safely
                db = getattr(engine, config.database, None)
                if db is None:
                    db = engine[config.database]  # type: ignore
                collection = db[query_obj.get("collection", "default")]

                if query_obj.get("operation") == "find":
                    cursor = collection.find(query_obj.get("filter", {}))
                    rows = await cursor.to_list(length=None)
                    result = {"rows": rows, "rowcount": len(rows)}
                elif query_obj.get("operation") == "insert":
                    insert_result = await collection.insert_one(query_obj.get("document", {}))
                    result = {"inserted_id": str(insert_result.inserted_id), "rowcount": 1}

            elif config.type == DatabaseType.REDIS:
                # Parse Redis command (simplified)
                parts = query.split()
                command = parts[0].upper()

                if command == "GET":
                    if hasattr(engine, 'get'):
                        value = await engine.get(parts[1])  # type: ignore
                    else:
                        value = await engine.execute_command('GET', parts[1])  # type: ignore
                    result = {"value": value}
                elif command == "SET":
                    if hasattr(engine, 'set'):
                        await engine.set(parts[1], parts[2])  # type: ignore
                    else:
                        await engine.execute_command('SET', parts[1], parts[2])  # type: ignore
                    result = {"status": "OK"}

            elif config.type == DatabaseType.CASSANDRA:
                # Execute Cassandra CQL query
                if hasattr(engine, 'execute'):
                    rows = engine.execute(query)
                    result = {"rows": [dict(row._asdict()) for row in rows], "rowcount": len(rows)}
                else:
                    result = {"error": "Cassandra execution not supported"}

            elif config.type == DatabaseType.ELASTICSEARCH:
                # Parse Elasticsearch query (simplified)
                try:
                    query_obj = json.loads(query)
                    index = query_obj.get("index", "_all")
                    body = query_obj.get("body", {})

                    if query_obj.get("operation") == "search":
                        response = await engine.search(index=index, body=body)
                        hits = response.get("hits", {}).get("hits", [])
                        result = {"rows": hits, "rowcount": len(hits)}
                    elif query_obj.get("operation") == "index":
                        response = await engine.index(index=index, body=body)
                        result = {"id": response.get("_id"), "status": "indexed"}
                except json.JSONDecodeError:
                    result = {"error": "Invalid Elasticsearch query format"}

            elif config.type == DatabaseType.NEO4J:
                # Execute Cypher query
                async with engine.session() as session:
                    cypher_result = await session.run(query, params)
                    records = await cypher_result.data()
                    result = {"rows": records, "rowcount": len(records)}

            elif config.type == DatabaseType.INFLUXDB:
                # Execute InfluxDB query
                try:
                    query_api = engine.query_api()
                    tables = await query_api.query(query)
                    rows = []
                    for table in tables:
                        for record in table.records:
                            rows.append(record.values)
                    result = {"rows": rows, "rowcount": len(rows)}
                except Exception as e:
                    result = {"error": f"InfluxDB query failed: {str(e)}"}

            else:
                result = {"error": f"Query execution not implemented for {config.type}"}

            # Update metrics
            execution_time = time.time() - start_time
            self._update_metrics(database, execution_time, success=True)

            # Cache the result if it was a SELECT query
            if cache_key and result:
                await cache_set(cache_key, {"success": True, "result": result, "execution_time": execution_time}, ttl=300)
                logger.debug(f"Cached query result: {query[:50]}...")

            return {"success": True, "result": result, "execution_time": execution_time}

        except Exception as e:
            execution_time = time.time() - start_time
            self._update_metrics(database or 'unknown', execution_time, success=False)
            logger.error(f"Query execution failed on '{database}': {e}")
            return {"success": False, "error": str(e), "execution_time": execution_time}

    def _format_last_query_time(self, last_query_time) -> Optional[str]:
        """Helper method to safely format last query time."""
        return last_query_time.isoformat() if last_query_time is not None else None

    def _update_metrics(self, database: str, execution_time: float, success: bool = True):
        """Update database metrics."""
        if database in self.connection_metrics:
            metrics = self.connection_metrics[database]
            metrics.queries_executed += 1
            metrics.total_execution_time += execution_time
            metrics.average_response_time = metrics.total_execution_time / metrics.queries_executed
            metrics.last_query_time = datetime.now(timezone.utc)

            if not success:
                metrics.errors += 1

            # Update global metrics
            self.global_metrics["total_queries"] += 1
            if not success:
                self.global_metrics["total_errors"] += 1

            # Update global average response time
            total_queries = self.global_metrics["total_queries"]
            if total_queries == 1:
                self.global_metrics["average_response_time"] = execution_time
            else:
                alpha = 0.1  # Exponential moving average
                current_avg = self.global_metrics["average_response_time"]
                self.global_metrics["average_response_time"] = alpha * execution_time + (1 - alpha) * current_avg

    async def _health_check_task(self):
        """Background task for database health monitoring."""
        while True:
            try:
                await asyncio.sleep(self.health_check_interval)

                for name in list(self.engines.keys()):
                    try:
                        await self._test_connection(name)
                    except Exception as e:
                        logger.warning(f"Health check failed for '{name}': {e}")
                        self.connection_status[name] = ConnectionStatus.ERROR

            except Exception as e:
                logger.error(f"Health check task error: {e}")
                await asyncio.sleep(60)  # Wait before retrying

    async def _metrics_collection_task(self):
        """Background task for metrics collection."""
        while True:
            try:
                await asyncio.sleep(60)  # Collect metrics every minute

                # Update connection counts
                connected_count = sum(1 for status in self.connection_status.values() if status == ConnectionStatus.CONNECTED)
                self.global_metrics["databases_connected"] = connected_count

                # Log metrics summary
                if self.global_metrics["total_queries"] > 0:
                    logger.debug(f"Database metrics: {self.global_metrics}")

            except Exception as e:
                logger.error(f"Metrics collection error: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive database system status."""
        return {
            "initialized": self.initialized,
            "databases": {
                name: {
                    "type": config.type.value,
                    "role": config.role.value,
                    "status": self.connection_status.get(name, ConnectionStatus.DISCONNECTED).value,
                    "metrics": {
                        "queries_executed": self.connection_metrics[name].queries_executed,
                        "average_response_time": self.connection_metrics[name].average_response_time,
                        "errors": self.connection_metrics[name].errors,
                        "last_query": self._format_last_query_time(self.connection_metrics[name].last_query_time)
                    } if name in self.connection_metrics else {}
                }
                for name, config in self.database_configs.items()
            },
            "global_metrics": self.global_metrics,
            "features": {
                "encryption_enabled": self.encryption_manager is not None,
                "migration_manager": self.migration_manager is not None,
                "backup_integration": self.backup_integration is not None,
                "global_distribution": self.global_distribution is not None
            }
        }

    async def close_all_connections(self):
        """Close all database connections."""
        for name, engine in self.engines.items():
            try:
                if hasattr(engine, 'dispose'):
                    await engine.dispose()
                elif hasattr(engine, 'close'):
                    await engine.close()  # type: ignore
                logger.info(f"Closed connection to '{name}'")
            except Exception as e:
                logger.error(f"Error closing connection to '{name}': {e}")

        self.engines.clear()
        self.connection_status.clear()
        logger.info("All database connections closed")

    async def __aenter__(self):
        """Async context manager entry."""
        if not self.initialized:
            await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # Acknowledge unused parameters
        _ = exc_type, exc_val, exc_tb
        """Async context manager exit."""
        await self.close_all_connections()


# Global instance - Single Source of Truth
database_manager = ConsolidatedDatabaseManager()


# Convenience functions for backward compatibility
async def initialize_database_system(config: Optional[dict] = None) -> bool:
    """Initialize the consolidated database system."""
    return await database_manager.initialize(config)


async def get_database_manager() -> ConsolidatedDatabaseManager:
    """Get the consolidated database manager instance."""
    if not database_manager.initialized:
        await database_manager.initialize()
    return database_manager


# Export main components
__all__ = [
    "ConsolidatedDatabaseManager",
    "database_manager",
    "DatabaseType",
    "DatabaseRole",
    "DatabaseConfig",
    "DatabaseMetrics",
    "ConnectionStatus",
    "initialize_database_system",
    "get_database_manager"
]
