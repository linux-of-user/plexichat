"""
PlexiChat Unified Database Engines - SINGLE SOURCE OF TRUTH

Consolidates database engine management from:
- infrastructure/database/db_engines.py - INTEGRATED
- core/database/db_manager.py engine components - ENHANCED

Provides unified interface for all database engines and connections.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass
from enum import Enum

# Import database libraries with fallbacks
try:
    import asyncpg
    import aiosqlite
    import aiomysql
    import motor.motor_asyncio
    import redis.asyncio as redis
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, AsyncEngine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from sqlalchemy import text
except ImportError:
    asyncpg = None
    aiosqlite = None
    aiomysql = None
    motor = None
    redis = None
    create_async_engine = None
    AsyncSession = None
    AsyncEngine = None
    sessionmaker = None
    StaticPool = None
    text = None

# Import from existing db_manager
from .db_manager import DatabaseType, DatabaseRole, ConnectionStatus

logger = logging.getLogger(__name__)


@dataclass
class EngineConfig:
    """Unified engine configuration."""
    engine_type: DatabaseType
    host: str = "localhost"
    port: Optional[int] = None
    database: str = "plexichat"
    username: str = ""
    password: str = ""
    ssl_enabled: bool = True
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 3600
    options: Dict[str, Any] = None

    def __post_init__(self):
        if self.options is None:
            self.options = {}

        # Set default ports if not specified
        if self.port is None:
            port_defaults = {
                DatabaseType.POSTGRESQL: 5432,
                DatabaseType.MYSQL: 3306,
                DatabaseType.MONGODB: 27017,
                DatabaseType.REDIS: 6379,
                DatabaseType.SQLITE: None,
            }
            self.port = port_defaults.get(self.engine_type)


class DatabaseEngine(ABC):
    """Abstract base class for database engines."""

    def __init__(self, config: EngineConfig):
        self.config = config
        self.connection = None
        self.is_connected = False

    @abstractmethod
    async def connect(self) -> bool:
        """Connect to the database."""
        pass

    @abstractmethod
    async def disconnect(self) -> bool:
        """Disconnect from the database."""
        pass

    @abstractmethod
    async def execute(self, query: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Execute a query."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the database is healthy."""
        pass


class SQLiteEngine(DatabaseEngine):
    """SQLite database engine."""

    async def connect(self) -> bool:
        """Connect to SQLite database."""
        try:
            if not aiosqlite:
                logger.error("aiosqlite not available")
                return False

            # For SQLAlchemy async engine
            if create_async_engine:
                self.connection = create_async_engine(
                    f"sqlite+aiosqlite:///{self.config.database}",
                    poolclass=StaticPool,
                    connect_args={"check_same_thread": False}
                )
            else:
                # Direct aiosqlite connection
                self.connection = await aiosqlite.connect(self.config.database)

            self.is_connected = True
            logger.info(f"Connected to SQLite database: {self.config.database}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to SQLite: {e}")
            return False

    async def disconnect(self) -> bool:
        """Disconnect from SQLite."""
        try:
            if self.connection:
                if hasattr(self.connection, 'dispose'):
                    await self.connection.dispose()
                elif hasattr(self.connection, 'close'):
                    await self.connection.close()
                self.connection = None
            self.is_connected = False
            return True
        except Exception as e:
            logger.error(f"Error disconnecting from SQLite: {e}")
            return False

    async def execute(self, query: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Execute SQLite query."""
        try:
            if not self.is_connected:
                await self.connect()

            if hasattr(self.connection, 'execute'):
                # SQLAlchemy engine
                async with self.connection.begin() as conn:
                    result = await conn.execute(text(query), params or {})
                    return result
            else:
                # Direct aiosqlite
                async with self.connection.execute(query, params or {}) as cursor:
                    return await cursor.fetchall()

        except Exception as e:
            logger.error(f"SQLite query execution failed: {e}")
            raise

    async def health_check(self) -> bool:
        """Check SQLite health using abstraction layer."""
        try:
            from plexichat.core.database import database_manager
            return await database_manager.health_check()
        except Exception:
            return False


class PostgreSQLEngine(DatabaseEngine):
    """PostgreSQL database engine."""

    async def connect(self) -> bool:
        """Connect to PostgreSQL database."""
        try:
            if create_async_engine:
                # SQLAlchemy async engine
                connection_string = (
                    f"postgresql+asyncpg://{self.config.username}:{self.config.password}"
                    f"@{self.config.host}:{self.config.port}/{self.config.database}"
                )
                self.connection = create_async_engine(
                    connection_string,
                    pool_size=self.config.pool_size,
                    max_overflow=self.config.max_overflow,
                    pool_timeout=self.config.pool_timeout,
                    pool_recycle=self.config.pool_recycle
                )
            elif asyncpg:
                # Direct asyncpg connection
                self.connection = await asyncpg.connect(
                    host=self.config.host,
                    port=self.config.port,
                    database=self.config.database,
                    user=self.config.username,
                    password=self.config.password
                )
            else:
                logger.error("No PostgreSQL driver available")
                return False

            self.is_connected = True
            logger.info(f"Connected to PostgreSQL: {self.config.host}:{self.config.port}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            return False

    async def disconnect(self) -> bool:
        """Disconnect from PostgreSQL."""
        try:
            if self.connection:
                if hasattr(self.connection, 'dispose'):
                    await self.connection.dispose()
                elif hasattr(self.connection, 'close'):
                    await self.connection.close()
                self.connection = None
            self.is_connected = False
            return True
        except Exception as e:
            logger.error(f"Error disconnecting from PostgreSQL: {e}")
            return False

    async def execute(self, query: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Execute PostgreSQL query."""
        try:
            if not self.is_connected:
                await self.connect()

            if hasattr(self.connection, 'execute'):
                # SQLAlchemy engine
                async with self.connection.begin() as conn:
                    result = await conn.execute(text(query), params or {})
                    return result
            else:
                # Direct asyncpg
                return await self.connection.fetch(query, *(params.values() if params else []))

        except Exception as e:
            logger.error(f"PostgreSQL query execution failed: {e}")
            raise

    async def health_check(self) -> bool:
        """Check PostgreSQL health using abstraction layer."""
        try:
            from plexichat.core.database import database_manager
            return await database_manager.health_check()
        except Exception:
            return False


class MongoDBEngine(DatabaseEngine):
    """MongoDB database engine."""

    async def connect(self) -> bool:
        """Connect to MongoDB database."""
        try:
            if not motor:
                logger.error("motor not available")
                return False

            connection_string = f"mongodb://{self.config.host}:{self.config.port}"
            if self.config.username and self.config.password:
                connection_string = (
                    f"mongodb://{self.config.username}:{self.config.password}"
                    f"@{self.config.host}:{self.config.port}"
                )

            self.connection = motor.motor_asyncio.AsyncIOMotorClient(connection_string)
            self.database = self.connection[self.config.database]

            # Test connection
            await self.connection.admin.command('ping')

            self.is_connected = True
            logger.info(f"Connected to MongoDB: {self.config.host}:{self.config.port}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            return False

    async def disconnect(self) -> bool:
        """Disconnect from MongoDB."""
        try:
            if self.connection:
                self.connection.close()
                self.connection = None
            self.is_connected = False
            return True
        except Exception as e:
            logger.error(f"Error disconnecting from MongoDB: {e}")
            return False

    async def execute(self, query: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Execute MongoDB operation."""
        try:
            if not self.is_connected:
                await self.connect()

            # MongoDB operations are different - this is a placeholder
            # In practice, you'd use collection.find(), collection.insert_one(), etc.
            return {"status": "MongoDB operation placeholder"}

        except Exception as e:
            logger.error(f"MongoDB operation failed: {e}")
            raise

    async def health_check(self) -> bool:
        """Check MongoDB health."""
        try:
            await self.connection.admin.command('ping')
            return True
        except Exception:
            return False


class UnifiedEngineManager:
    """
    Unified Database Engine Manager - SINGLE SOURCE OF TRUTH

    Consolidates all database engine management functionality.
    """

    def __init__(self):
        self.engines: Dict[str, DatabaseEngine] = {}
        self.engine_classes = {
            DatabaseType.SQLITE: SQLiteEngine,
            DatabaseType.POSTGRESQL: PostgreSQLEngine,
            DatabaseType.MONGODB: MongoDBEngine,
            # Add more engines as needed
        }

    async def create_engine(self, name: str, config: EngineConfig) -> bool:
        """Create and register a database engine."""
        try:
            engine_class = self.engine_classes.get(config.engine_type)
            if not engine_class:
                logger.error(f"Unsupported database type: {config.engine_type}")
                return False

            engine = engine_class(config)
            success = await engine.connect()

            if success:
                self.engines[name] = engine
                logger.info(f"Engine '{name}' created successfully")
                return True
            else:
                logger.error(f"Failed to create engine '{name}'")
                return False

        except Exception as e:
            logger.error(f"Error creating engine '{name}': {e}")
            return False

    async def get_engine(self, name: str) -> Optional[DatabaseEngine]:
        """Get a database engine by name."""
        return self.engines.get(name)

    async def remove_engine(self, name: str) -> bool:
        """Remove and disconnect a database engine."""
        try:
            if name in self.engines:
                await self.engines[name].disconnect()
                del self.engines[name]
                logger.info(f"Engine '{name}' removed")
                return True
            return False
        except Exception as e:
            logger.error(f"Error removing engine '{name}': {e}")
            return False

    async def health_check_all(self) -> Dict[str, bool]:
        """Check health of all engines."""
        results = {}
        for name, engine in self.engines.items():
            try:
                results[name] = await engine.health_check()
            except Exception as e:
                logger.error(f"Health check failed for engine '{name}': {e}")
                results[name] = False
        return results

    async def shutdown(self) -> bool:
        """Shutdown all engines."""
        try:
            for name in list(self.engines.keys()):
                await self.remove_engine(name)
            logger.info("All engines shut down successfully")
            return True
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
            return False


# Global unified engine manager instance
unified_engine_manager = UnifiedEngineManager()

# Backward compatibility exports
engine_manager = unified_engine_manager

__all__ = [
    'UnifiedEngineManager',
    'unified_engine_manager',
    'engine_manager',  # Backward compatibility
    'DatabaseEngine',
    'SQLiteEngine',
    'PostgreSQLEngine',
    'MongoDBEngine',
    'EngineConfig',
]
