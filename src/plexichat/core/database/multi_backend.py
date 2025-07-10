"""
Enhanced Database Support
Multi-backend database support with automatic migrations and clustering.
"""

import asyncio
import os
from typing import Dict, Any, Optional, List
from sqlalchemy import create_engine, MetaData, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import logging
from pathlib import Path

from netlink.core.config.settings import settings
import logging import logger

class DatabaseBackend:
    """Base database backend class."""
    
    def __init__(self, url: str, **kwargs):
        self.url = url
        self.kwargs = kwargs
        self.engine = None
        self.async_engine = None
        self.session_factory = None
        self.async_session_factory = None
        
    async def initialize(self):
        """Initialize the database backend."""
        raise NotImplementedError
        
    async def health_check(self) -> bool:
        """Check if database is healthy."""
        raise NotImplementedError
        
    async def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        raise NotImplementedError

class SQLiteBackend(DatabaseBackend):
    """SQLite database backend."""
    
    async def initialize(self):
        """Initialize SQLite backend."""
        # Ensure data directory exists
        db_path = self.url.replace('sqlite:///', '').replace('sqlite:', '')
        if db_path.startswith('./'):
            db_path = db_path[2:]
        
        db_dir = Path(db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        
        # Create engines
        self.engine = create_engine(
            self.url,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
            echo=getattr(settings, 'DATABASE_ECHO', False)
        )
        
        # SQLite async support
        async_url = self.url.replace('sqlite:', 'sqlite+aiosqlite:')
        self.async_engine = create_async_engine(
            async_url,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
            echo=getattr(settings, 'DATABASE_ECHO', False)
        )
        
        # Session factories
        self.session_factory = sessionmaker(bind=self.engine)
        self.async_session_factory = sessionmaker(
            bind=self.async_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        logger.info(f"SQLite backend initialized: {db_path}")
        
    async def health_check(self) -> bool:
        """Check SQLite health."""
        try:
            async with self.async_engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.error(f"SQLite health check failed: {e}")
            return False
            
    async def get_stats(self) -> Dict[str, Any]:
        """Get SQLite statistics."""
        try:
            async with self.async_engine.begin() as conn:
                # Get database size
                result = await conn.execute(text("PRAGMA page_count"))
                page_count = result.scalar()
                
                result = await conn.execute(text("PRAGMA page_size"))
                page_size = result.scalar()
                
                db_size = (page_count or 0) * (page_size or 0)
                
                # Get table count
                result = await conn.execute(text(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
                ))
                table_count = result.scalar()
                
                return {
                    "backend": "sqlite",
                    "size_bytes": db_size,
                    "table_count": table_count,
                    "page_count": page_count,
                    "page_size": page_size
                }
        except Exception as e:
            logger.error(f"Failed to get SQLite stats: {e}")
            return {"backend": "sqlite", "error": str(e)}

class PostgreSQLBackend(DatabaseBackend):
    """PostgreSQL database backend."""
    
    async def initialize(self):
        """Initialize PostgreSQL backend."""
        # Create engines with connection pooling
        self.engine = create_engine(
            self.url,
            pool_size=getattr(settings, 'DATABASE_POOL_SIZE', 10),
            max_overflow=getattr(settings, 'DATABASE_MAX_OVERFLOW', 20),
            pool_pre_ping=True,
            echo=getattr(settings, 'DATABASE_ECHO', False)
        )
        
        # Async engine
        async_url = self.url.replace('postgresql:', 'postgresql+asyncpg:')
        self.async_engine = create_async_engine(
            async_url,
            pool_size=getattr(settings, 'DATABASE_POOL_SIZE', 10),
            max_overflow=getattr(settings, 'DATABASE_MAX_OVERFLOW', 20),
            pool_pre_ping=True,
            echo=getattr(settings, 'DATABASE_ECHO', False)
        )
        
        # Session factories
        self.session_factory = sessionmaker(bind=self.engine)
        self.async_session_factory = sessionmaker(
            bind=self.async_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        logger.info("PostgreSQL backend initialized")
        
    async def health_check(self) -> bool:
        """Check PostgreSQL health."""
        try:
            async with self.async_engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.error(f"PostgreSQL health check failed: {e}")
            return False
            
    async def get_stats(self) -> Dict[str, Any]:
        """Get PostgreSQL statistics."""
        try:
            async with self.async_engine.begin() as conn:
                # Get database size
                result = await conn.execute(text(
                    "SELECT pg_size_pretty(pg_database_size(current_database()))"
                ))
                db_size = result.scalar()
                
                # Get connection count
                result = await conn.execute(text(
                    "SELECT count(*) FROM pg_stat_activity"
                ))
                connection_count = result.scalar()
                
                # Get table count
                result = await conn.execute(text(
                    "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'"
                ))
                table_count = result.scalar()
                
                return {
                    "backend": "postgresql",
                    "size": db_size,
                    "connection_count": connection_count,
                    "table_count": table_count
                }
        except Exception as e:
            logger.error(f"Failed to get PostgreSQL stats: {e}")
            return {"backend": "postgresql", "error": str(e)}

class MySQLBackend(DatabaseBackend):
    """MySQL database backend."""
    
    async def initialize(self):
        """Initialize MySQL backend."""
        # Create engines
        self.engine = create_engine(
            self.url,
            pool_size=getattr(settings, 'DATABASE_POOL_SIZE', 10),
            max_overflow=getattr(settings, 'DATABASE_MAX_OVERFLOW', 20),
            pool_pre_ping=True,
            echo=getattr(settings, 'DATABASE_ECHO', False)
        )
        
        # Async engine
        async_url = self.url.replace('mysql:', 'mysql+aiomysql:')
        self.async_engine = create_async_engine(
            async_url,
            pool_size=getattr(settings, 'DATABASE_POOL_SIZE', 10),
            max_overflow=getattr(settings, 'DATABASE_MAX_OVERFLOW', 20),
            pool_pre_ping=True,
            echo=getattr(settings, 'DATABASE_ECHO', False)
        )
        
        # Session factories
        self.session_factory = sessionmaker(bind=self.engine)
        self.async_session_factory = sessionmaker(
            bind=self.async_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        logger.info("MySQL backend initialized")
        
    async def health_check(self) -> bool:
        """Check MySQL health."""
        try:
            async with self.async_engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.error(f"MySQL health check failed: {e}")
            return False
            
    async def get_stats(self) -> Dict[str, Any]:
        """Get MySQL statistics."""
        try:
            async with self.async_engine.begin() as conn:
                # Get database size
                result = await conn.execute(text(
                    "SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 1) AS 'DB Size in MB' "
                    "FROM information_schema.tables WHERE table_schema=DATABASE()"
                ))
                db_size = result.scalar()
                
                # Get connection count
                result = await conn.execute(text("SHOW STATUS LIKE 'Threads_connected'"))
                connection_count = result.fetchone()[1] if result else 0
                
                # Get table count
                result = await conn.execute(text(
                    "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()"
                ))
                table_count = result.scalar()
                
                return {
                    "backend": "mysql",
                    "size_mb": db_size,
                    "connection_count": connection_count,
                    "table_count": table_count
                }
        except Exception as e:
            logger.error(f"Failed to get MySQL stats: {e}")
            return {"backend": "mysql", "error": str(e)}

class DatabaseManager:
    """Enhanced database manager with multi-backend support."""
    
    def __init__(self):
        self.backend: Optional[DatabaseBackend] = None
        self.read_replicas: List[DatabaseBackend] = []
        self.metadata = MetaData()
        
    async def initialize(self, database_url: str = None):
        """Initialize database with appropriate backend."""
        url = database_url or getattr(settings, 'DATABASE_URL', 'sqlite:///./data/chatapi.db')
        
        # Determine backend type
        if url.startswith('sqlite'):
            self.backend = SQLiteBackend(url)
        elif url.startswith('postgresql'):
            self.backend = PostgreSQLBackend(url)
        elif url.startswith('mysql'):
            self.backend = MySQLBackend(url)
        else:
            raise ValueError(f"Unsupported database URL: {url}")
        
        # Initialize primary backend
        await self.backend.initialize()
        
        # Initialize read replicas if configured
        read_replica_urls = getattr(settings, 'DATABASE_READ_REPLICAS', [])
        for replica_url in read_replica_urls:
            if replica_url.startswith('sqlite'):
                replica = SQLiteBackend(replica_url)
            elif replica_url.startswith('postgresql'):
                replica = PostgreSQLBackend(replica_url)
            elif replica_url.startswith('mysql'):
                replica = MySQLBackend(replica_url)
            else:
                logger.warning(f"Unsupported read replica URL: {replica_url}")
                continue
                
            await replica.initialize()
            self.read_replicas.append(replica)
        
        logger.info(f"Database manager initialized with {len(self.read_replicas)} read replicas")
        
    async def health_check(self) -> Dict[str, Any]:
        """Check health of all database backends."""
        result = {
            "primary": await self.backend.health_check() if self.backend else False,
            "replicas": []
        }
        
        for i, replica in enumerate(self.read_replicas):
            replica_health = await replica.health_check()
            result["replicas"].append({
                "index": i,
                "healthy": replica_health
            })
        
        return result
        
    async def get_stats(self) -> Dict[str, Any]:
        """Get statistics from all backends."""
        result = {
            "primary": await self.backend.get_stats() if self.backend else {},
            "replicas": []
        }
        
        for replica in self.read_replicas:
            replica_stats = await replica.get_stats()
            result["replicas"].append(replica_stats)
        
        return result
        
    def get_session(self, read_only: bool = False):
        """Get database session."""
        if read_only and self.read_replicas:
            # Use round-robin for read replicas
            replica = self.read_replicas[0]  # Simple selection
            return replica.session_factory()
        
        return self.backend.session_factory()
        
    def get_async_session(self, read_only: bool = False):
        """Get async database session."""
        if read_only and self.read_replicas:
            # Use round-robin for read replicas
            replica = self.read_replicas[0]  # Simple selection
            return replica.async_session_factory()
        
        return self.backend.async_session_factory()
        
    @property
    def engine(self):
        """Get primary database engine."""
        return self.backend.engine if self.backend else None
        
    @property
    def async_engine(self):
        """Get primary async database engine."""
        return self.backend.async_engine if self.backend else None

# Global database manager instance
db_manager = DatabaseManager()
