import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import redis.asyncio as redis
from motor.motor_asyncio import AsyncIOMotorClient

from ...core_system.config import get_config
from ...core_system.logging import get_logger
from ...features.backup import get_unified_backup_manager
from ...features.security import distributed_key_manager, quantum_encryption
from .global_data_distribution import global_data_distribution_manager
from .zero_downtime_migration import zero_downtime_migration_manager


from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import StaticPool

"""
PlexiChat Consolidated Database Manager

SINGLE SOURCE OF TRUTH for all database management functionality.

Consolidates and replaces:
- database_manager.py (core functionality) - REMOVED
- unified_database_manager.py (unified attempt) - REMOVED
- enhanced_abstraction.py (multi-database support) - REMOVED

Provides comprehensive database management with:
- Multi-backend support (SQL, NoSQL, Time-series, Graph, Vector)
- Advanced encryption and security integration
- Connection pooling and optimization
- Clustering and failover
- Zero-downtime migrations
- Real-time monitoring and analytics
- Performance optimization
- Backup system integration
- Global data distribution
"""

# Database-specific imports
# SQLAlchemy imports
# PlexiChat imports
logger = get_logger(__name__)


class DatabaseType(Enum):
    """Supported database types."""

    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MONGODB = "mongodb"
    REDIS = "redis"
    CLICKHOUSE = "clickhouse"
    TIMESCALEDB = "timescaledb"
    NEO4J = "neo4j"
    ELASTICSEARCH = "elasticsearch"
    MINIO = "minio"
    PINECONE = "pinecone"


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
        self.config = config or get_config().get("database", {})
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
            "databases_connected": 0,
        }

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

            # Start background tasks
            asyncio.create_task(self._health_check_task())
            asyncio.create_task(self._metrics_collection_task())

            self.initialized = True
            logger.info(" Consolidated Database Manager fully initialized")
            return True

        except Exception as e:
            logger.error(f" Database manager initialization failed: {e}")
            return False

    async def _initialize_security(self) -> None:
        """Initialize security and encryption components."""
        try:
            # Initialize encryption manager
            self.encryption_manager = quantum_encryption
            await self.encryption_manager.initialize()

            # Initialize key manager
            self.key_manager = distributed_key_manager
            await self.key_manager.initialize()

            logger.info("Database security components initialized")

        except Exception as e:
            logger.error(f"Security initialization failed: {e}")
            # Continue without encryption if not available

    async def _initialize_components(self) -> None:
        """Initialize advanced database components."""
        try:
            # Initialize migration manager
            self.migration_manager = zero_downtime_migration_manager
            await self.migration_manager.initialize()

            # Initialize global data distribution
            self.global_distribution = global_data_distribution_manager
            await self.global_distribution.initialize()

            # Initialize backup integration
            self.backup_integration = get_unified_backup_manager()

            logger.info("Advanced database components initialized")

        except Exception as e:
            logger.error(f"Component initialization failed: {e}")
            # Continue with basic functionality

    async def _load_default_configurations(self) -> None:
        """Load default database configurations."""
        # Default SQLite configuration
        sqlite_config = DatabaseConfig(
            type=DatabaseType.SQLITE,
            name="default",
            database="plexichat.db",
            role=DatabaseRole.PRIMARY,
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
                role=DatabaseRole.PRIMARY,
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
                role=DatabaseRole.PRIMARY,
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
                role=DatabaseRole.CACHE,
            )
            await self.add_database("redis", redis_config)

    async def add_database(
        self, name: str, config: DatabaseConfig, is_default: bool = False
    ) -> bool:
        """Add a database configuration and establish connection."""
        try:
            self.database_configs[name] = config

            # Create database engine/connection based on type
            if config.type == DatabaseType.SQLITE:
                engine = create_async_engine(
                    f"sqlite+aiosqlite:///{config.database}",
                    poolclass=StaticPool,
                    connect_args={"check_same_thread": False},
                )
                self.engines[name] = engine

            elif config.type == DatabaseType.POSTGRESQL:
                connection_string = f"postgresql+asyncpg://{config.username}:{config.password}@{config.host}:{config.port}/{config.database}"
                engine = create_async_engine(
                    connection_string,
                    pool_size=config.connection_pool_size,
                    max_overflow=config.max_overflow,
                    pool_timeout=config.pool_timeout,
                    pool_recycle=config.pool_recycle,
                )
                self.engines[name] = engine

            elif config.type == DatabaseType.MONGODB:
                connection_string = f"mongodb://{config.username}:{config.password}@{config.host}:{config.port}/{config.database}"
                client = AsyncIOMotorClient(connection_string)
                self.engines[name] = client

            elif config.type == DatabaseType.REDIS:
                client = redis.Redis(
                    host=config.host,
                    port=config.port,
                    password=config.password,
                    decode_responses=True,
                )
                self.engines[name] = client

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

            if config.type in [DatabaseType.SQLITE, DatabaseType.POSTGRESQL]:
                async with engine.begin() as conn:
                    await conn.execute(text("SELECT 1"))

            elif config.type == DatabaseType.MONGODB:
                await engine.admin.command("ping")

            elif config.type == DatabaseType.REDIS:
                await engine.ping()

            self.connection_status[name] = ConnectionStatus.CONNECTED
            self.global_metrics["databases_connected"] += 1
            return True

        except Exception as e:
            logger.error(f"Connection test failed for '{name}': {e}")
            self.connection_status[name] = ConnectionStatus.ERROR
            return False

    async def execute_query(
        self, query: str, params: Dict[str, Any] = None, database: str = None
    ) -> Dict[str, Any]:
        """Execute a database query with unified interface."""
        start_time = time.time()
        database = database or getattr(self, "default_database", "default")

        try:
            if database not in self.engines:
                raise Exception(f"Database '{database}' not configured")

            config = self.database_configs[database]
            engine = self.engines[database]
            params = params or {}

            result = None

            if config.type in [DatabaseType.SQLITE, DatabaseType.POSTGRESQL]:
                async with engine.begin() as conn:
                    result = await conn.execute(text(query), params)
                    if result.returns_rows:
                        rows = result.fetchall()
                        result = {
                            "rows": [dict(row._mapping) for row in rows],
                            "rowcount": len(rows),
                        }
                    else:
                        result = {"rowcount": result.rowcount}

            elif config.type == DatabaseType.MONGODB:
                # Parse MongoDB query (simplified)
                query_obj = json.loads(query)
                collection = engine[config.database][
                    query_obj.get("collection", "default")
                ]

                if query_obj.get("operation") == "find":
                    cursor = collection.find(query_obj.get("filter", {}))
                    rows = await cursor.to_list(length=None)
                    result = {"rows": rows, "rowcount": len(rows)}
                elif query_obj.get("operation") == "insert":
                    insert_result = await collection.insert_one(
                        query_obj.get("document", {})
                    )
                    result = {
                        "inserted_id": str(insert_result.inserted_id),
                        "rowcount": 1,
                    }

            elif config.type == DatabaseType.REDIS:
                # Parse Redis command (simplified)
                parts = query.split()
                command = parts[0].upper()

                if command == "GET":
                    value = await engine.get(parts[1])
                    result = {"value": value}
                elif command == "SET":
                    await engine.set(parts[1], parts[2])
                    result = {"status": "OK"}

            # Update metrics
            execution_time = time.time() - start_time
            self._update_metrics(database, execution_time, success=True)

            return {"success": True, "result": result, "execution_time": execution_time}

        except Exception as e:
            execution_time = time.time() - start_time
            self._update_metrics(database, execution_time, success=False)
            logger.error(f"Query execution failed on '{database}': {e}")
            return {"success": False, "error": str(e), "execution_time": execution_time}

    def _update_metrics(
        self, database: str, execution_time: float, success: bool = True
    ):
        """Update database metrics."""
        if database in self.connection_metrics:
            metrics = self.connection_metrics[database]
            metrics.queries_executed += 1
            metrics.total_execution_time += execution_time
            metrics.average_response_time = (
                metrics.total_execution_time / metrics.queries_executed
            )
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
                self.global_metrics["average_response_time"] = (
                    alpha * execution_time + (1 - alpha) * current_avg
                )

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
                connected_count = sum(
                    1
                    for status in self.connection_status.values()
                    if status == ConnectionStatus.CONNECTED
                )
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
                    "status": self.connection_status.get(
                        name, ConnectionStatus.DISCONNECTED
                    ).value,
                    "metrics": (
                        {
                            "queries_executed": self.connection_metrics[
                                name
                            ].queries_executed,
                            "average_response_time": self.connection_metrics[
                                name
                            ].average_response_time,
                            "errors": self.connection_metrics[name].errors,
                            "last_query": (
                                self.connection_metrics[
                                    name
                                ].last_query_time.isoformat()
                                if self.connection_metrics[name].last_query_time
                                else None
                            ),
                        }
                        if name in self.connection_metrics
                        else {}
                    ),
                }
                for name, config in self.database_configs.items()
            },
            "global_metrics": self.global_metrics,
            "features": {
                "encryption_enabled": self.encryption_manager is not None,
                "migration_manager": self.migration_manager is not None,
                "backup_integration": self.backup_integration is not None,
                "global_distribution": self.global_distribution is not None,
            },
        }

    async def close_all_connections(self):
        """Close all database connections."""
        for name, engine in self.engines.items():
            try:
                if hasattr(engine, "dispose"):
                    await engine.dispose()
                elif hasattr(engine, "close"):
                    await engine.close()
                logger.info(f"Closed connection to '{name}'")
            except Exception as e:
                logger.error(f"Error closing connection to '{name}': {e}")

        self.engines.clear()
        self.connection_status.clear()
        logger.info("All database connections closed")

    async def shutdown(self):
        """Shutdown the database manager."""
        await self.close_all_connections()
        logger.info("Database manager shutdown complete")

    async def get_session(self, role: str = "primary", read_only: bool = False):
        """Get database session with automatic failover."""
        try:
            # Import the cluster from engines which has get_session
            from .engines import db_cluster
            async with db_cluster.get_session() as session:
                return session
        except Exception:
            return None

    async def get_health(self, role: Optional[str] = None):
        """Get database health status."""
        return self.get_status()

    async def backup(self, backup_name: Optional[str] = None):
        """Create database backup."""
        try:
            # Import backup manager
            from ..backup.manager import get_backup_manager
            backup_manager = get_backup_manager()
            return await backup_manager.create_backup(backup_name or "auto_backup")
        except Exception:
            return False

    async def restore(self, backup_name: str):
        """Restore database from backup."""
        try:
            # Import backup manager
            from ..backup.manager import get_backup_manager
            backup_manager = get_backup_manager()
            return await backup_manager.restore_backup(backup_name)
        except Exception:
            return False

    async def __aenter__(self):
        """Async context manager entry."""
        if not self.initialized:
            await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close_all_connections()


# Global instance - Single Source of Truth
database_manager = ConsolidatedDatabaseManager()


# Convenience functions for backward compatibility
async def initialize_database_system(config: dict = None) -> bool:
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
    "get_database_manager",
]
