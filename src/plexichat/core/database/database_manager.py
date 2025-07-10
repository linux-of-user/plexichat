"""
NetLink Core Database Manager

Unified database management system with multi-backend support,
encryption, clustering, and advanced features.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Union, Type
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from contextlib import asynccontextmanager
import time

from sqlalchemy import create_engine, text, MetaData, inspect
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool, NullPool, StaticPool
from sqlmodel import SQLModel, Session, select
import redis.asyncio as redis
from motor.motor_asyncio import AsyncIOMotorClient

from .config import DatabaseConfig, DatabaseType, DatabaseRole
from .exceptions import DatabaseError, ConnectionError

# Import enhanced database components
try:
    from .zero_downtime_migration import zero_downtime_migration_manager
    from .global_data_distribution import global_data_distribution_manager
    ENHANCED_DATABASE_AVAILABLE = True
except ImportError:
    ENHANCED_DATABASE_AVAILABLE = False

logger = logging.getLogger(__name__)


class ConnectionStatus(Enum):
    """Database connection status."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"
    MAINTENANCE = "maintenance"


@dataclass
class DatabaseMetrics:
    """Database performance metrics."""
    connection_count: int = 0
    active_queries: int = 0
    total_queries: int = 0
    average_query_time: float = 0.0
    error_count: int = 0
    last_error: Optional[str] = None
    uptime_seconds: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    disk_usage_mb: float = 0.0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class QueryResult:
    """Database query result."""
    success: bool
    data: Any = None
    error: Optional[str] = None
    execution_time: float = 0.0
    rows_affected: int = 0
    query_id: Optional[str] = None


class DatabaseManager:
    """
    Unified database manager with comprehensive features.
    
    Features:
    - Multi-database engine support (PostgreSQL, MySQL, SQLite, MongoDB)
    - Automatic connection management and pooling
    - Query optimization and caching
    - Performance monitoring and metrics
    - Error handling and recovery
    - Transaction management
    - Schema management and migrations
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.databases: Dict[str, DatabaseConfig] = {}
        self.engines: Dict[str, Any] = {}
        self.sessions: Dict[str, sessionmaker] = {}
        self.connection_status: Dict[str, ConnectionStatus] = {}
        self.metrics: Dict[str, DatabaseMetrics] = {}
        
        # Redis cache for query results
        self.redis_client: Optional[redis.Redis] = None
        self.cache_enabled = self.config.get("cache_enabled", True)
        self.cache_ttl = self.config.get("cache_ttl", 300)  # 5 minutes
        
        # Query optimization
        self.query_cache: Dict[str, Any] = {}
        self.prepared_statements: Dict[str, Any] = {}
        
        # Performance monitoring
        self.query_history: List[Dict[str, Any]] = []
        self.max_history_size = self.config.get("max_history_size", 1000)
        
        self.initialized = False
        self.start_time = time.time()
    
    async def initialize(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the database manager."""
        if self.initialized:
            return

        try:
            # Initialize enhanced database components if available
            if ENHANCED_DATABASE_AVAILABLE:
                await self._initialize_enhanced_features()

            if config:
                self.config.update(config)
            
            # Initialize Redis cache if enabled
            if self.cache_enabled:
                await self._initialize_cache()
            
            # Load database configurations
            await self._load_database_configs()
            
            # Initialize database engines
            await self._initialize_engines()
            
            # Start monitoring tasks
            asyncio.create_task(self._metrics_collection_loop())
            asyncio.create_task(self._health_check_loop())
            asyncio.create_task(self._cleanup_loop())
            
            self.initialized = True
            logger.info("✅ Database Manager initialized")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize Database Manager: {e}")
            raise DatabaseError(f"Initialization failed: {e}")
    
    async def add_database(self, name: str, config: DatabaseConfig) -> bool:
        """Add a new database configuration."""
        try:
            self.databases[name] = config
            
            # Initialize engine for this database
            await self._initialize_engine(name, config)
            
            # Test connection
            if await self._test_connection(name):
                self.connection_status[name] = ConnectionStatus.CONNECTED
                self.metrics[name] = DatabaseMetrics()
                logger.info(f"✅ Database '{name}' added successfully")
                return True
            else:
                self.connection_status[name] = ConnectionStatus.ERROR
                logger.error(f"❌ Failed to connect to database '{name}'")
                return False
                
        except Exception as e:
            logger.error(f"❌ Failed to add database '{name}': {e}")
            self.connection_status[name] = ConnectionStatus.ERROR
            return False
    
    async def remove_database(self, name: str) -> bool:
        """Remove a database configuration."""
        try:
            if name in self.engines:
                # Close connections
                engine = self.engines[name]
                if hasattr(engine, 'dispose'):
                    await engine.dispose()
                del self.engines[name]
            
            # Clean up
            self.databases.pop(name, None)
            self.sessions.pop(name, None)
            self.connection_status.pop(name, None)
            self.metrics.pop(name, None)
            
            logger.info(f"✅ Database '{name}' removed")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to remove database '{name}': {e}")
            return False
    
    @asynccontextmanager
    async def get_session(self, database_name: str = "default"):
        """Get database session with automatic cleanup."""
        if database_name not in self.sessions:
            raise DatabaseError(f"Database '{database_name}' not found")
        
        config = self.databases[database_name]
        session_factory = self.sessions[database_name]
        
        # Update metrics
        if database_name in self.metrics:
            self.metrics[database_name].connection_count += 1
        
        try:
            if config.type == DatabaseType.MONGODB:
                # MongoDB session
                yield self.engines[database_name]
            else:
                # SQL session
                if config.async_enabled:
                    async with session_factory() as session:
                        yield session
                else:
                    with session_factory() as session:
                        yield session
                        
        except Exception as e:
            logger.error(f"❌ Database session error for '{database_name}': {e}")
            if database_name in self.metrics:
                self.metrics[database_name].error_count += 1
                self.metrics[database_name].last_error = str(e)
            raise DatabaseError(f"Session error: {e}")
        finally:
            # Update metrics
            if database_name in self.metrics:
                self.metrics[database_name].connection_count -= 1
    
    async def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None,
                          database_name: str = "default", cache_key: Optional[str] = None) -> QueryResult:
        """Execute a database query with caching and metrics."""
        start_time = time.time()
        query_id = f"query_{int(start_time * 1000)}"
        
        try:
            # Check cache first
            if cache_key and self.cache_enabled:
                cached_result = await self._get_cached_result(cache_key)
                if cached_result:
                    return QueryResult(
                        success=True,
                        data=cached_result,
                        execution_time=time.time() - start_time,
                        query_id=query_id
                    )
            
            # Execute query
            async with self.get_session(database_name) as session:
                if isinstance(session, AsyncSession):
                    result = await session.execute(text(query), params or {})
                    await session.commit()
                else:
                    result = session.execute(text(query), params or {})
                    session.commit()
                
                # Process result
                if result.returns_rows:
                    data = result.fetchall()
                    rows_affected = len(data)
                else:
                    data = None
                    rows_affected = result.rowcount
                
                execution_time = time.time() - start_time
                
                # Cache result if requested
                if cache_key and self.cache_enabled and data:
                    await self._cache_result(cache_key, data)
                
                # Update metrics
                await self._update_query_metrics(database_name, execution_time, True)
                
                # Store query history
                self._add_to_history({
                    "query_id": query_id,
                    "database": database_name,
                    "query": query[:200],  # Truncate for storage
                    "params": params,
                    "execution_time": execution_time,
                    "rows_affected": rows_affected,
                    "success": True,
                    "timestamp": datetime.now(timezone.utc)
                })
                
                return QueryResult(
                    success=True,
                    data=data,
                    execution_time=execution_time,
                    rows_affected=rows_affected,
                    query_id=query_id
                )
                
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = str(e)
            
            # Update metrics
            await self._update_query_metrics(database_name, execution_time, False)
            
            # Store error in history
            self._add_to_history({
                "query_id": query_id,
                "database": database_name,
                "query": query[:200],
                "params": params,
                "execution_time": execution_time,
                "error": error_msg,
                "success": False,
                "timestamp": datetime.now(timezone.utc)
            })
            
            logger.error(f"❌ Query execution failed: {error_msg}")
            return QueryResult(
                success=False,
                error=error_msg,
                execution_time=execution_time,
                query_id=query_id
            )
    
    async def create_tables(self, models: List[Type[SQLModel]], database_name: str = "default"):
        """Create database tables from SQLModel models."""
        try:
            engine = self.engines[database_name]
            
            # Create tables
            for model in models:
                model.metadata.create_all(engine)
            
            logger.info(f"✅ Created tables for {len(models)} models in '{database_name}'")
            
        except Exception as e:
            logger.error(f"❌ Failed to create tables in '{database_name}': {e}")
            raise DatabaseError(f"Table creation failed: {e}")
    
    async def drop_tables(self, models: List[Type[SQLModel]], database_name: str = "default"):
        """Drop database tables (use with caution)."""
        try:
            engine = self.engines[database_name]
            
            # Drop tables
            for model in models:
                model.metadata.drop_all(engine)
            
            logger.warning(f"⚠️ Dropped tables for {len(models)} models in '{database_name}'")
            
        except Exception as e:
            logger.error(f"❌ Failed to drop tables in '{database_name}': {e}")
            raise DatabaseError(f"Table drop failed: {e}")
    
    async def get_database_info(self, database_name: str = "default") -> Dict[str, Any]:
        """Get database information and statistics."""
        try:
            config = self.databases[database_name]
            engine = self.engines[database_name]
            metrics = self.metrics.get(database_name, DatabaseMetrics())
            
            # Get database-specific information
            info = {
                "name": database_name,
                "type": config.type.value,
                "status": self.connection_status.get(database_name, ConnectionStatus.DISCONNECTED).value,
                "metrics": {
                    "connection_count": metrics.connection_count,
                    "total_queries": metrics.total_queries,
                    "average_query_time": metrics.average_query_time,
                    "error_count": metrics.error_count,
                    "uptime_seconds": time.time() - self.start_time
                }
            }
            
            # Add database-specific details
            if config.type in [DatabaseType.POSTGRESQL, DatabaseType.MYSQL, DatabaseType.SQLITE]:
                inspector = inspect(engine)
                info["tables"] = inspector.get_table_names()
                info["schema_version"] = await self._get_schema_version(database_name)
            
            return info
            
        except Exception as e:
            logger.error(f"❌ Failed to get database info for '{database_name}': {e}")
            return {"error": str(e)}
    
    async def get_performance_metrics(self, database_name: str = "default") -> Dict[str, Any]:
        """Get detailed performance metrics for a database."""
        try:
            metrics = self.metrics.get(database_name, DatabaseMetrics())
            
            # Calculate additional metrics
            recent_queries = [
                q for q in self.query_history
                if q["database"] == database_name and 
                (datetime.now(timezone.utc) - q["timestamp"]).total_seconds() < 3600
            ]
            
            successful_queries = [q for q in recent_queries if q["success"]]
            failed_queries = [q for q in recent_queries if not q["success"]]
            
            return {
                "database": database_name,
                "current_connections": metrics.connection_count,
                "total_queries": metrics.total_queries,
                "queries_last_hour": len(recent_queries),
                "successful_queries_last_hour": len(successful_queries),
                "failed_queries_last_hour": len(failed_queries),
                "average_query_time": metrics.average_query_time,
                "error_rate": len(failed_queries) / max(len(recent_queries), 1),
                "uptime_seconds": metrics.uptime_seconds,
                "memory_usage_mb": metrics.memory_usage_mb,
                "cpu_usage_percent": metrics.cpu_usage_percent,
                "last_error": metrics.last_error,
                "last_updated": metrics.last_updated.isoformat()
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to get performance metrics for '{database_name}': {e}")
            return {"error": str(e)}
    
    async def shutdown(self):
        """Gracefully shutdown the database manager."""
        try:
            # Close all database connections
            for name, engine in self.engines.items():
                if hasattr(engine, 'dispose'):
                    await engine.dispose()
                logger.info(f"🔌 Closed database connection: {name}")
            
            # Close Redis connection
            if self.redis_client:
                await self.redis_client.close()
            
            logger.info("✅ Database Manager shutdown complete")
            
        except Exception as e:
            logger.error(f"❌ Error during Database Manager shutdown: {e}")
    
    async def _initialize_cache(self):
        """Initialize Redis cache."""
        try:
            redis_url = self.config.get("redis_url", "redis://localhost:6379")
            self.redis_client = redis.from_url(redis_url)
            
            # Test connection
            await self.redis_client.ping()
            logger.info("✅ Redis cache initialized")
            
        except Exception as e:
            logger.warning(f"⚠️ Redis cache initialization failed: {e}")
            self.cache_enabled = False
    
    async def _load_database_configs(self):
        """Load database configurations."""
        # Default SQLite database
        default_config = DatabaseConfig(
            name="default",
            type=DatabaseType.SQLITE,
            host="",
            port=0,
            database="data/netlink.db",
            username="",
            password="",
            options={"check_same_thread": False}
        )
        
        self.databases["default"] = default_config
        logger.info("📋 Database configurations loaded")
    
    async def _initialize_engines(self):
        """Initialize database engines."""
        for name, config in self.databases.items():
            await self._initialize_engine(name, config)
    
    async def _initialize_engine(self, name: str, config: DatabaseConfig):
        """Initialize a single database engine."""
        try:
            connection_string = config.get_connection_string()
            
            # Engine configuration
            engine_kwargs = {
                "echo": config.options.get("echo", False),
                "pool_pre_ping": True,
                "pool_recycle": 3600
            }
            
            # Database-specific configuration
            if config.type == DatabaseType.SQLITE:
                engine_kwargs.update({
                    "poolclass": StaticPool,
                    "connect_args": {"check_same_thread": False}
                })
            elif config.type in [DatabaseType.POSTGRESQL, DatabaseType.MYSQL]:
                engine_kwargs.update({
                    "poolclass": QueuePool,
                    "pool_size": 20,
                    "max_overflow": 30
                })
            
            # Create engine
            if config.async_enabled and config.type != DatabaseType.SQLITE:
                # Async engine
                async_url = connection_string.replace("postgresql://", "postgresql+asyncpg://")
                async_url = async_url.replace("mysql://", "mysql+aiomysql://")
                self.engines[name] = create_async_engine(async_url, **engine_kwargs)
                
                # Async session factory
                self.sessions[name] = sessionmaker(
                    bind=self.engines[name],
                    class_=AsyncSession,
                    expire_on_commit=False
                )
            else:
                # Sync engine
                self.engines[name] = create_engine(connection_string, **engine_kwargs)
                
                # Sync session factory
                self.sessions[name] = sessionmaker(
                    bind=self.engines[name],
                    class_=Session,
                    expire_on_commit=False
                )
            
            logger.info(f"✅ Database engine initialized: {name}")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize engine for '{name}': {e}")
            raise
    
    async def _test_connection(self, name: str) -> bool:
        """Test database connection."""
        try:
            config = self.databases[name]
            engine = self.engines[name]
            
            if config.type == DatabaseType.SQLITE:
                with engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
            elif config.type == DatabaseType.POSTGRESQL:
                if config.async_enabled:
                    async with engine.begin() as conn:
                        await conn.execute(text("SELECT version()"))
                else:
                    with engine.connect() as conn:
                        conn.execute(text("SELECT version()"))
            elif config.type == DatabaseType.MYSQL:
                if config.async_enabled:
                    async with engine.begin() as conn:
                        await conn.execute(text("SELECT VERSION()"))
                else:
                    with engine.connect() as conn:
                        conn.execute(text("SELECT VERSION()"))
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Connection test failed for '{name}': {e}")
            return False
    
    async def _get_cached_result(self, cache_key: str) -> Optional[Any]:
        """Get cached query result."""
        if not self.redis_client:
            return None
        
        try:
            cached_data = await self.redis_client.get(f"query:{cache_key}")
            if cached_data:
                import pickle
                return pickle.loads(cached_data)
        except Exception as e:
            logger.warning(f"⚠️ Cache retrieval failed: {e}")
        
        return None
    
    async def _cache_result(self, cache_key: str, data: Any):
        """Cache query result."""
        if not self.redis_client:
            return
        
        try:
            import pickle
            cached_data = pickle.dumps(data)
            await self.redis_client.setex(f"query:{cache_key}", self.cache_ttl, cached_data)
        except Exception as e:
            logger.warning(f"⚠️ Cache storage failed: {e}")
    
    async def _update_query_metrics(self, database_name: str, execution_time: float, success: bool):
        """Update query performance metrics."""
        if database_name not in self.metrics:
            self.metrics[database_name] = DatabaseMetrics()
        
        metrics = self.metrics[database_name]
        metrics.total_queries += 1
        
        if success:
            # Update average query time
            if metrics.average_query_time == 0:
                metrics.average_query_time = execution_time
            else:
                metrics.average_query_time = (metrics.average_query_time + execution_time) / 2
        else:
            metrics.error_count += 1
        
        metrics.last_updated = datetime.now(timezone.utc)
    
    def _add_to_history(self, query_info: Dict[str, Any]):
        """Add query to history with size limit."""
        self.query_history.append(query_info)
        
        # Maintain history size limit
        if len(self.query_history) > self.max_history_size:
            self.query_history = self.query_history[-self.max_history_size:]
    
    async def _get_schema_version(self, database_name: str) -> Optional[str]:
        """Get database schema version."""
        try:
            result = await self.execute_query(
                "SELECT version FROM schema_migrations ORDER BY applied_at DESC LIMIT 1",
                database_name=database_name
            )
            
            if result.success and result.data:
                return result.data[0][0]
        except:
            pass
        
        return None
    
    async def _metrics_collection_loop(self):
        """Collect database metrics periodically."""
        while True:
            try:
                await asyncio.sleep(60)  # Collect every minute
                await self._collect_system_metrics()
            except Exception as e:
                logger.error(f"❌ Metrics collection error: {e}")
                await asyncio.sleep(60)
    
    async def _health_check_loop(self):
        """Perform health checks on all databases."""
        while True:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds
                for name in self.databases.keys():
                    if await self._test_connection(name):
                        self.connection_status[name] = ConnectionStatus.CONNECTED
                    else:
                        self.connection_status[name] = ConnectionStatus.ERROR
            except Exception as e:
                logger.error(f"❌ Health check error: {e}")
                await asyncio.sleep(30)
    
    async def _cleanup_loop(self):
        """Clean up old data periodically."""
        while True:
            try:
                await asyncio.sleep(3600)  # Clean up every hour
                
                # Clean up old query history
                cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)
                self.query_history = [
                    q for q in self.query_history
                    if q["timestamp"] > cutoff_time
                ]
                
            except Exception as e:
                logger.error(f"❌ Cleanup error: {e}")
                await asyncio.sleep(3600)
    
    async def _collect_system_metrics(self):
        """Collect system-level metrics."""
        try:
            import psutil
            
            for name in self.databases.keys():
                if name in self.metrics:
                    metrics = self.metrics[name]
                    metrics.memory_usage_mb = psutil.virtual_memory().used / 1024 / 1024
                    metrics.cpu_usage_percent = psutil.cpu_percent()
                    metrics.uptime_seconds = time.time() - self.start_time
                    
        except ImportError:
            # psutil not available
            pass
        except Exception as e:
            logger.error(f"❌ System metrics collection failed: {e}")

    async def _initialize_enhanced_features(self):
        """Initialize enhanced database features."""
        try:
            logger.info("🚀 Initializing enhanced database features...")

            # Initialize zero-downtime migration manager
            await zero_downtime_migration_manager.initialize()
            logger.info("✅ Zero-downtime migration manager initialized")

            # Initialize global data distribution manager
            await global_data_distribution_manager.initialize()
            logger.info("✅ Global data distribution manager initialized")

            logger.info("🎉 Enhanced database features initialized successfully!")

        except Exception as e:
            logger.error(f"❌ Failed to initialize enhanced database features: {e}")

    def get_enhanced_status(self) -> Dict[str, Any]:
        """Get enhanced database status."""
        base_status = self.get_status()

        if not ENHANCED_DATABASE_AVAILABLE:
            return {**base_status, "enhanced_features": {"available": False}}

        try:
            # Get zero-downtime migration status
            migration_status = {
                "active_migrations": len(zero_downtime_migration_manager.active_migrations),
                "migration_history": len(zero_downtime_migration_manager.migration_history)
            }

            # Get global distribution status
            distribution_status = global_data_distribution_manager.get_global_status()

            enhanced_status = {
                **base_status,
                "enhanced_features": {
                    "available": True,
                    "zero_downtime_migrations": migration_status,
                    "global_data_distribution": distribution_status
                }
            }

            return enhanced_status

        except Exception as e:
            logger.error(f"Failed to get enhanced status: {e}")
            return {**base_status, "enhanced_features": {"error": str(e)}}


# Global instance
database_manager = DatabaseManager()
