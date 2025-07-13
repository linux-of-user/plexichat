"""
Multi-database engine support with automatic failover and load balancing.
Supports PostgreSQL, MySQL, SQLite, and MongoDB with clustering.
"""

import asyncio
import logging
import random
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool, QueuePool
from sqlmodel import Session

try:
    import redis.asyncio as redis  # type: ignore
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

try:
    from motor.motor_asyncio import AsyncIOMotorClient  # type: ignore
    MOTOR_AVAILABLE = True
except ImportError:
    MOTOR_AVAILABLE = False
    AsyncIOMotorClient = None

try:
    import pymongo  # type: ignore
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False
    pymongo = None

try:
    from plexichat.core.config.settings import settings  # type: ignore
except ImportError:
    # Fallback configuration if settings module is not available
    import os
    class Settings:
        def __init__(self):
            self.DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./plexichat.db")
            self.REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
            self.MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
            self.DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "20"))
            self.DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "30"))
            self.DB_ECHO = os.getenv("DB_ECHO", "false").lower() == "true"
    settings = Settings()

logger = logging.getLogger(__name__)

class DatabaseType(str, Enum):
    """Supported database types."""
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    SQLITE = "sqlite"
    MONGODB = "mongodb"

class DatabaseRole(str, Enum):
    """Database role types."""
    PRIMARY = "primary"
    REPLICA = "replica"
    ANALYTICS = "analytics"

@dataclass
class DatabaseConfig:
    """Database configuration."""
    name: str
    type: DatabaseType
    role: DatabaseRole
    url: str
    pool_size: int = 20
    max_overflow: int = 30
    pool_timeout: int = 30
    pool_recycle: int = 3600
    echo: bool = False
    weight: int = 100  # For load balancing
    priority: int = 1  # Higher priority = preferred
    health_check_interval: int = 30
    max_retries: int = 3
    retry_delay: int = 1

class DatabaseCluster:
    """Database cluster manager with failover and load balancing."""
    
    def __init__(self):
        self.databases: Dict[str, DatabaseConfig] = {}
        self.engines: Dict[str, Any] = {}
        self.sessions: Dict[str, sessionmaker] = {}
        self.health_status: Dict[str, bool] = {}
        self.last_health_check: Dict[str, float] = {}
        self.connection_counts: Dict[str, int] = {}
        self.error_counts: Dict[str, int] = {}
        self._lock = asyncio.Lock()
        
        # Initialize from settings
        self._load_database_configs()
        self._initialize_engines()
        
        # Start health monitoring
        asyncio.create_task(self._health_monitor())
    
    def _load_database_configs(self):
        """Load database configurations from settings."""
        # Primary database
        if settings.DATABASE_URL:
            db_type = self._detect_database_type(settings.DATABASE_URL)
            self.databases["primary"] = DatabaseConfig(
                name="primary",
                type=db_type,
                role=DatabaseRole.PRIMARY,
                url=settings.DATABASE_URL,
                pool_size=getattr(settings, 'DB_POOL_SIZE', 20),
                max_overflow=getattr(settings, 'DB_MAX_OVERFLOW', 30),
                echo=getattr(settings, 'DB_ECHO', False)
            )
        
        # Read replicas
        replica_urls = getattr(settings, 'DATABASE_REPLICA_URLS', [])
        for i, url in enumerate(replica_urls):
            db_type = self._detect_database_type(url)
            self.databases[f"replica_{i}"] = DatabaseConfig(
                name=f"replica_{i}",
                type=db_type,
                role=DatabaseRole.REPLICA,
                url=url,
                pool_size=getattr(settings, 'DB_REPLICA_POOL_SIZE', 10),
                weight=80  # Lower weight for replicas
            )
        
        # Analytics database
        analytics_url = getattr(settings, 'ANALYTICS_DATABASE_URL', None)
        if analytics_url:
            db_type = self._detect_database_type(analytics_url)
            self.databases["analytics"] = DatabaseConfig(
                name="analytics",
                type=db_type,
                role=DatabaseRole.ANALYTICS,
                url=analytics_url,
                pool_size=getattr(settings, 'ANALYTICS_DB_POOL_SIZE', 5)
            )
    
    def _detect_database_type(self, url: str) -> DatabaseType:
        """Detect database type from URL."""
        if url.startswith('postgresql'):
            return DatabaseType.POSTGRESQL
        elif url.startswith('mysql'):
            return DatabaseType.MYSQL
        elif url.startswith('sqlite'):
            return DatabaseType.SQLITE
        elif url.startswith('mongodb'):
            return DatabaseType.MONGODB
        else:
            raise ValueError(f"Unsupported database URL: {url}")
    
    def _initialize_engines(self):
        """Initialize database engines."""
        for name, config in self.databases.items():
            try:
                if config.type == DatabaseType.MONGODB:
                    # MongoDB client
                    if AsyncIOMotorClient is not None:
                        self.engines[name] = AsyncIOMotorClient(config.url)
                    else:
                        logger.warning(f"MongoDB support not available for {name}")
                        continue
                else:
                    # SQL databases
                    engine_kwargs = {
                        'echo': config.echo,
                        'pool_size': config.pool_size,
                        'max_overflow': config.max_overflow,
                        'pool_timeout': config.pool_timeout,
                        'pool_recycle': config.pool_recycle,
                        'poolclass': QueuePool if config.type != DatabaseType.SQLITE else NullPool
                    }
                    
                    # Async engine for better performance
                    if config.url.startswith('sqlite'):
                        # SQLite doesn't support async
                        self.engines[name] = create_engine(config.url, **engine_kwargs)
                    else:
                        # Convert to async URL
                        async_url = config.url.replace('postgresql://', 'postgresql+asyncpg://')
                        async_url = async_url.replace('mysql://', 'mysql+aiomysql://')
                        self.engines[name] = create_async_engine(async_url, **engine_kwargs)
                    
                    # Create session factory
                    if config.url.startswith('sqlite'):
                        self.sessions[name] = sessionmaker(
                            bind=self.engines[name],
                            class_=Session,
                            expire_on_commit=False
                        )
                    else:
                        self.sessions[name] = sessionmaker(
                            bind=self.engines[name],
                            class_=AsyncSession,
                            expire_on_commit=False
                        )
                
                self.health_status[name] = True
                self.connection_counts[name] = 0
                self.error_counts[name] = 0
                logger.info(f"Initialized database engine: {name} ({config.type})")
                
            except Exception as e:
                logger.error(f"Failed to initialize database {name}: {e}")
                self.health_status[name] = False
    
    async def _health_monitor(self):
        """Monitor database health continuously."""
        while True:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds
                
                for name, config in self.databases.items():
                    if time.time() - self.last_health_check.get(name, 0) > config.health_check_interval:
                        await self._check_database_health(name)
                        
            except Exception as e:
                logger.error(f"Health monitor error: {e}")
    
    async def _check_database_health(self, name: str):
        """Check health of a specific database."""
        try:
            config = self.databases[name]
            engine = self.engines[name]
            
            if config.type == DatabaseType.MONGODB:
                # MongoDB health check
                await engine.admin.command('ping')
            else:
                # SQL database health check
                if hasattr(engine, 'execute'):
                    # Async engine
                    async with engine.begin() as conn:
                        await conn.execute("SELECT 1")
                else:
                    # Sync engine
                    with engine.connect() as conn:
                        conn.execute("SELECT 1")
            
            if not self.health_status[name]:
                logger.info(f"Database {name} is back online")
            
            self.health_status[name] = True
            self.error_counts[name] = 0
            self.last_health_check[name] = time.time()
            
        except Exception as e:
            logger.error(f"Database {name} health check failed: {e}")
            self.health_status[name] = False
            self.error_counts[name] += 1
    
    def get_healthy_databases(self, role: Optional[DatabaseRole] = None) -> List[str]:
        """Get list of healthy databases, optionally filtered by role."""
        healthy = []
        for name, config in self.databases.items():
            if self.health_status.get(name, False):
                if role is None or config.role == role:
                    healthy.append(name)
        return healthy
    
    def select_database(self, role: DatabaseRole = DatabaseRole.PRIMARY, 
                       read_only: bool = False) -> Optional[str]:
        """Select best database for operation using load balancing."""
        if read_only and role == DatabaseRole.PRIMARY:
            # Try to use replica for read operations
            replicas = self.get_healthy_databases(DatabaseRole.REPLICA)
            if replicas:
                return self._weighted_selection(replicas)
        
        # Get databases for the specified role
        candidates = self.get_healthy_databases(role)
        if not candidates:
            # Fallback to primary if no replicas available
            if role == DatabaseRole.REPLICA:
                candidates = self.get_healthy_databases(DatabaseRole.PRIMARY)
            
            if not candidates:
                logger.error(f"No healthy databases available for role: {role}")
                return None
        
        return self._weighted_selection(candidates)
    
    def _weighted_selection(self, candidates: List[str]) -> str:
        """Select database using weighted random selection."""
        if len(candidates) == 1:
            return candidates[0]
        
        # Calculate weights based on configuration and current load
        weights = []
        for name in candidates:
            config = self.databases[name]
            base_weight = config.weight
            
            # Reduce weight based on current connections and errors
            load_factor = 1.0 - (self.connection_counts.get(name, 0) / (config.pool_size * 2))
            error_factor = 1.0 - (self.error_counts.get(name, 0) / 10)
            
            final_weight = base_weight * load_factor * error_factor
            weights.append(max(final_weight, 1))  # Minimum weight of 1
        
        # Weighted random selection
        total_weight = sum(weights)
        r = random.uniform(0, total_weight)
        
        cumulative = 0
        for i, weight in enumerate(weights):
            cumulative += weight
            if r <= cumulative:
                return candidates[i]
        
        return candidates[-1]  # Fallback
    
    @asynccontextmanager
    async def get_session(self, role: DatabaseRole = DatabaseRole.PRIMARY,
                         read_only: bool = False):
        """Get database session with automatic failover."""
        db_name = self.select_database(role, read_only)
        if not db_name:
            raise RuntimeError("No healthy database available")
        
        config = self.databases[db_name]
        session_factory = self.sessions[db_name]
        
        # Track connection
        async with self._lock:
            self.connection_counts[db_name] += 1
        
        try:
            if config.type == DatabaseType.MONGODB:
                # MongoDB session
                yield self.engines[db_name]
            else:
                # SQL session
                if hasattr(session_factory, '__call__'):
                    # Async session
                    async with session_factory() as session:
                        yield session
                else:
                    # Sync session
                    with session_factory() as session:
                        yield session
                        
        except Exception as e:
            # Track error
            async with self._lock:
                self.error_counts[db_name] += 1
            
            logger.error(f"Database session error on {db_name}: {e}")
            
            # Mark database as unhealthy if too many errors
            if self.error_counts[db_name] > 5:
                self.health_status[db_name] = False
                logger.warning(f"Marking database {db_name} as unhealthy due to errors")
            
            raise
        finally:
            # Release connection
            async with self._lock:
                self.connection_counts[db_name] -= 1
    
    async def execute_query(self, query: str, params: Optional[Dict] = None,
                           role: DatabaseRole = DatabaseRole.PRIMARY,
                           read_only: bool = False) -> Any:
        """Execute query with automatic database selection."""
        async with self.get_session(role, read_only) as session:
            if hasattr(session, 'execute'):
                # SQL database
                result = await session.execute(query, params or {})
                return result
            else:
                # MongoDB - would need different handling
                raise NotImplementedError("MongoDB query execution not implemented")
    
    def get_cluster_status(self) -> Dict[str, Any]:
        """Get cluster status information."""
        status = {
            'total_databases': len(self.databases),
            'healthy_databases': len([h for h in self.health_status.values() if h]),
            'databases': {}
        }
        
        for name, config in self.databases.items():
            status['databases'][name] = {
                'type': config.type,
                'role': config.role,
                'healthy': self.health_status.get(name, False),
                'connections': self.connection_counts.get(name, 0),
                'errors': self.error_counts.get(name, 0),
                'last_health_check': self.last_health_check.get(name, 0)
            }
        
        return status

# Global database cluster instance
db_cluster = DatabaseCluster()

# Convenience functions for backward compatibility
async def get_session():
    """Get primary database session."""
    async with db_cluster.get_session() as session:
        yield session

async def get_read_session():
    """Get read-only database session (uses replica if available)."""
    async with db_cluster.get_session(read_only=True) as session:
        yield session

async def get_analytics_session():
    """Get analytics database session."""
    async with db_cluster.get_session(DatabaseRole.ANALYTICS) as session:
        yield session
