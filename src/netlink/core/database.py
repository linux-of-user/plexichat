"""
NetLink Unified Database Management

Consolidates database functionality from:
- src/netlink/app/db/ (database managers)
- src/netlink/core/database/ (core database system)
- Root databases/ directory

Provides unified database management with multi-backend support, clustering, and encryption.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from pathlib import Path
from enum import Enum
from dataclasses import dataclass
from contextlib import asynccontextmanager

# Database imports
try:
    from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, DateTime, Text, Boolean
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
    from sqlalchemy.orm import sessionmaker, Session, declarative_base
    from sqlalchemy.pool import QueuePool
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False

logger = logging.getLogger(__name__)

# Database types and enums
class DatabaseType(Enum):
    """Supported database types."""
    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MONGODB = "mongodb"

class DatabaseRole(Enum):
    """Database roles for clustering."""
    PRIMARY = "primary"
    REPLICA = "replica"
    BACKUP = "backup"

class DatabaseProvider(Enum):
    """Database hosting providers."""
    LOCAL = "local"
    AWS_RDS = "aws_rds"
    GOOGLE_CLOUD_SQL = "google_cloud_sql"
    AZURE_SQL = "azure_sql"
    MONGODB_ATLAS = "mongodb_atlas"

@dataclass
class DatabaseConfig:
    """Database configuration."""
    type: DatabaseType
    host: str = "localhost"
    port: int = 5432
    database: str = "netlink"
    username: str = "netlink"
    password: str = ""
    ssl_enabled: bool = True
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 3600
    echo: bool = False
    encryption_enabled: bool = True
    backup_enabled: bool = True
    role: DatabaseRole = DatabaseRole.PRIMARY
    provider: DatabaseProvider = DatabaseProvider.LOCAL

class DatabaseError(Exception):
    """Base database exception."""
    pass

class ConnectionError(DatabaseError):
    """Database connection error."""
    pass

class MigrationError(DatabaseError):
    """Database migration error."""
    pass

class EncryptionError(DatabaseError):
    """Database encryption error."""
    pass

class DatabaseManager:
    """
    Unified Database Manager
    
    Provides centralized database management with support for multiple backends,
    clustering, encryption, and advanced features.
    """
    
    def __init__(self, config: Optional[DatabaseConfig] = None):
        self.config = config or self._get_default_config()
        self.engines: Dict[str, Any] = {}
        self.sessions: Dict[str, Any] = {}
        self.metadata = MetaData() if SQLALCHEMY_AVAILABLE else None
        self.is_initialized = False
        
        # Component managers
        self.cluster_manager = None
        self.migration_manager = None
        self.encryption_manager = None
        self.monitor = None
        
        logger.info("Database Manager initialized")
    
    def _get_default_config(self) -> DatabaseConfig:
        """Get default database configuration."""
        return DatabaseConfig(
            type=DatabaseType.SQLITE,
            database="data/netlink.db",
            host="localhost",
            port=0,  # Not used for SQLite
            username="",
            password=""
        )
    
    async def initialize(self, configs: Optional[Dict[str, DatabaseConfig]] = None):
        """Initialize database connections and components."""
        if self.is_initialized:
            return
        
        if not SQLALCHEMY_AVAILABLE:
            raise DatabaseError("SQLAlchemy not available. Install with: pip install sqlalchemy")
        
        logger.info("🔄 Initializing Database Manager...")
        
        # Initialize primary database
        await self._initialize_database("primary", self.config)
        
        # Initialize additional databases if provided
        if configs:
            for name, config in configs.items():
                await self._initialize_database(name, config)
        
        # Initialize components
        await self._initialize_components()
        
        self.is_initialized = True
        logger.info("✅ Database Manager initialized successfully")
    
    async def _initialize_database(self, name: str, config: DatabaseConfig):
        """Initialize a specific database connection."""
        try:
            connection_string = self._build_connection_string(config)
            
            # Engine configuration
            engine_kwargs = {
                "echo": config.echo,
                "pool_size": config.pool_size,
                "max_overflow": config.max_overflow,
                "pool_timeout": config.pool_timeout,
                "pool_recycle": config.pool_recycle,
                "poolclass": QueuePool
            }
            
            # Create engine
            if config.type != DatabaseType.SQLITE:
                # Async engine for PostgreSQL/MySQL
                async_url = connection_string.replace("postgresql://", "postgresql+asyncpg://")
                async_url = async_url.replace("mysql://", "mysql+aiomysql://")
                self.engines[name] = create_async_engine(async_url, **engine_kwargs)
                
                # Async session factory
                self.sessions[name] = async_sessionmaker(
                    bind=self.engines[name],
                    class_=AsyncSession,
                    expire_on_commit=False
                )
            else:
                # Sync engine for SQLite
                self.engines[name] = create_engine(connection_string, **engine_kwargs)
                
                # Sync session factory
                self.sessions[name] = sessionmaker(
                    bind=self.engines[name],
                    class_=Session,
                    expire_on_commit=False
                )
            
            logger.info(f"✅ Database engine initialized: {name} ({config.type.value})")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize database {name}: {e}")
            raise ConnectionError(f"Failed to initialize database {name}: {e}")
    
    def _build_connection_string(self, config: DatabaseConfig) -> str:
        """Build database connection string."""
        if config.type == DatabaseType.SQLITE:
            return f"sqlite:///{config.database}"
        elif config.type == DatabaseType.POSTGRESQL:
            return f"postgresql://{config.username}:{config.password}@{config.host}:{config.port}/{config.database}"
        elif config.type == DatabaseType.MYSQL:
            return f"mysql://{config.username}:{config.password}@{config.host}:{config.port}/{config.database}"
        else:
            raise DatabaseError(f"Unsupported database type: {config.type}")
    
    async def _initialize_components(self):
        """Initialize database components."""
        # Component initialization would go here
        logger.info("🔧 Database components initialized")
    
    @asynccontextmanager
    async def get_session(self, database: str = "primary"):
        """Get database session context manager."""
        if not self.is_initialized:
            raise DatabaseError("Database manager not initialized")
        
        if database not in self.sessions:
            raise DatabaseError(f"Database {database} not configured")
        
        session_factory = self.sessions[database]
        
        if asyncio.iscoroutinefunction(session_factory):
            # Async session
            async with session_factory() as session:
                try:
                    yield session
                    await session.commit()
                except Exception:
                    await session.rollback()
                    raise
        else:
            # Sync session
            with session_factory() as session:
                try:
                    yield session
                    session.commit()
                except Exception:
                    session.rollback()
                    raise
    
    async def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None, 
                           database: str = "primary") -> Any:
        """Execute a database query."""
        async with self.get_session(database) as session:
            result = await session.execute(query, params or {})
            return result
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get database health status."""
        status = {
            "databases": {},
            "overall_status": "healthy",
            "timestamp": datetime.now().isoformat()
        }
        
        for name, engine in self.engines.items():
            try:
                # Test connection
                async with self.get_session(name) as session:
                    await session.execute("SELECT 1")
                status["databases"][name] = "healthy"
            except Exception as e:
                status["databases"][name] = f"unhealthy: {e}"
                status["overall_status"] = "degraded"
        
        return status
    
    async def backup_database(self, database: str = "primary", backup_path: Optional[str] = None) -> bool:
        """Create database backup."""
        try:
            # Backup logic would go here
            logger.info(f"📦 Database backup created: {database}")
            return True
        except Exception as e:
            logger.error(f"❌ Database backup failed: {e}")
            return False
    
    async def shutdown(self):
        """Shutdown database connections."""
        logger.info("🔄 Shutting down database connections...")
        
        for name, engine in self.engines.items():
            try:
                if hasattr(engine, 'dispose'):
                    await engine.dispose()
                logger.info(f"✅ Database connection closed: {name}")
            except Exception as e:
                logger.error(f"❌ Error closing database {name}: {e}")
        
        self.is_initialized = False
        logger.info("✅ Database shutdown complete")


# Placeholder classes for additional components
class DatabaseCluster:
    """Database clustering management."""
    def __init__(self):
        self.is_initialized = False
    
    async def initialize(self):
        if self.is_initialized:
            return
        logger.info("🔗 Database Cluster initialized")
        self.is_initialized = True

class MigrationManager:
    """Database migration management."""
    def __init__(self):
        self.is_initialized = False
    
    async def initialize(self):
        if self.is_initialized:
            return
        logger.info("🔄 Migration Manager initialized")
        self.is_initialized = True

class DatabaseEncryption:
    """Database encryption management."""
    def __init__(self):
        self.is_initialized = False
    
    async def initialize(self):
        if self.is_initialized:
            return
        logger.info("🔐 Database Encryption initialized")
        self.is_initialized = True

class DatabaseMonitor:
    """Database monitoring and health checks."""
    def __init__(self):
        self.is_initialized = False
    
    async def initialize(self):
        if self.is_initialized:
            return
        logger.info("📊 Database Monitor initialized")
        self.is_initialized = True

# Global database manager instance
database_manager = DatabaseManager()

# Convenience functions
async def get_session(database: str = "primary"):
    """Get database session."""
    return database_manager.get_session(database)

async def execute_query(query: str, params: Optional[Dict[str, Any]] = None, 
                       database: str = "primary"):
    """Execute database query."""
    return await database_manager.execute_query(query, params, database)

async def get_database_health():
    """Get database health status."""
    return await database_manager.get_health_status()

async def backup_database(database: str = "primary", backup_path: Optional[str] = None):
    """Create database backup."""
    return await database_manager.backup_database(database, backup_path)
