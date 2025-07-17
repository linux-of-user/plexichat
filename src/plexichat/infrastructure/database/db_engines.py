"""
PlexiChat Database Engines

Multiple database engine support and management.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass
from enum import Enum

try:
    import asyncpg
    import aiosqlite
    import aiomysql
    import motor.motor_asyncio
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
except ImportError:
    asyncpg = None
    aiosqlite = None
    aiomysql = None
    motor = None
    create_async_engine = None
    AsyncSession = None
    sessionmaker = None

try:
    from plexichat.app.logger_config import get_logger
    from plexichat.core.config import settings
except ImportError:
    get_logger = lambda name: logging.getLogger(name)
    settings = {}

logger = get_logger(__name__)

class DatabaseType(Enum):
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    SQLITE = "sqlite"
    MONGODB = "mongodb"
    REDIS = "redis"

@dataclass
class DatabaseConfig:
    """Database configuration."""
    engine_type: DatabaseType
    host: str = "localhost"
    port: int = 5432
    database: str = "plexichat"
    username: str = ""
    password: str = ""
    ssl: bool = False
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    connection_timeout: int = 10
    options: Dict[str, Any] = None

    def __post_init__(self):
        if self.options is None:
            self.options = {}

class DatabaseEngine(ABC):
    """Abstract base class for database engines."""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.connection = None
        self.pool = None
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
    async def execute(self, query: str, params: Optional[Dict] = None) -> Any:
        """Execute a query."""
        pass
    
    @abstractmethod
    async def fetch_one(self, query: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Fetch one record."""
        pass
    
    @abstractmethod
    async def fetch_all(self, query: str, params: Optional[Dict] = None) -> List[Dict]:
        """Fetch all records."""
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check."""
        pass

class PostgreSQLEngine(DatabaseEngine):
    """PostgreSQL database engine."""
    
    async def connect(self) -> bool:
        """Connect to PostgreSQL."""
        try:
            if not asyncpg:
                raise ImportError("asyncpg not available")
            
            connection_string = (
                f"postgresql://{self.config.username}:{self.config.password}@"
                f"{self.config.host}:{self.config.port}/{self.config.database}"
            )
            
            self.pool = await asyncpg.create_pool(
                connection_string,
                min_size=1,
                max_size=self.config.pool_size,
                command_timeout=self.config.connection_timeout
            )
            
            self.is_connected = True
            logger.info("Connected to PostgreSQL database")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from PostgreSQL."""
        try:
            if self.pool:
                await self.pool.close()
                self.pool = None
            
            self.is_connected = False
            logger.info("Disconnected from PostgreSQL database")
            return True
            
        except Exception as e:
            logger.error(f"Failed to disconnect from PostgreSQL: {e}")
            return False
    
    async def execute(self, query: str, params: Optional[Dict] = None) -> Any:
        """Execute a PostgreSQL query."""
        try:
            if not self.pool:
                raise RuntimeError("Not connected to database")
            
            async with self.pool.acquire() as connection:
                if params:
                    return await connection.execute(query, *params.values())
                else:
                    return await connection.execute(query)
                    
        except Exception as e:
            logger.error(f"Failed to execute query: {e}")
            raise
    
    async def fetch_one(self, query: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Fetch one record from PostgreSQL."""
        try:
            if not self.pool:
                raise RuntimeError("Not connected to database")
            
            async with self.pool.acquire() as connection:
                if params:
                    row = await connection.fetchrow(query, *params.values())
                else:
                    row = await connection.fetchrow(query)
                
                return dict(row) if row else None
                
        except Exception as e:
            logger.error(f"Failed to fetch record: {e}")
            raise
    
    async def fetch_all(self, query: str, params: Optional[Dict] = None) -> List[Dict]:
        """Fetch all records from PostgreSQL."""
        try:
            if not self.pool:
                raise RuntimeError("Not connected to database")
            
            async with self.pool.acquire() as connection:
                if params:
                    rows = await connection.fetch(query, *params.values())
                else:
                    rows = await connection.fetch(query)
                
                return [dict(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Failed to fetch records: {e}")
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform PostgreSQL health check."""
        try:
            if not self.pool:
                return {"healthy": False, "error": "Not connected"}
            
            async with self.pool.acquire() as connection:
                result = await connection.fetchval("SELECT 1")
                
                return {
                    "healthy": True,
                    "engine": "postgresql",
                    "version": connection.get_server_version(),
                    "pool_size": self.pool.get_size(),
                    "test_query": result == 1
                }
                
        except Exception as e:
            return {"healthy": False, "error": str(e)}

class SQLiteEngine(DatabaseEngine):
    """SQLite database engine."""
    
    async def connect(self) -> bool:
        """Connect to SQLite."""
        try:
            if not aiosqlite:
                raise ImportError("aiosqlite not available")
            
            self.connection = await aiosqlite.connect(
                self.config.database,
                timeout=self.config.connection_timeout
            )
            
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
                await self.connection.close()
                self.connection = None
            
            self.is_connected = False
            logger.info("Disconnected from SQLite database")
            return True
            
        except Exception as e:
            logger.error(f"Failed to disconnect from SQLite: {e}")
            return False
    
    async def execute(self, query: str, params: Optional[Dict] = None) -> Any:
        """Execute a SQLite query."""
        try:
            if not self.connection:
                raise RuntimeError("Not connected to database")
            
            if params:
                cursor = await self.connection.execute(query, tuple(params.values()))
            else:
                cursor = await self.connection.execute(query)
            
            await self.connection.commit()
            return cursor.rowcount
            
        except Exception as e:
            logger.error(f"Failed to execute query: {e}")
            raise
    
    async def fetch_one(self, query: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Fetch one record from SQLite."""
        try:
            if not self.connection:
                raise RuntimeError("Not connected to database")
            
            self.connection.row_factory = aiosqlite.Row
            
            if params:
                cursor = await self.connection.execute(query, tuple(params.values()))
            else:
                cursor = await self.connection.execute(query)
            
            row = await cursor.fetchone()
            return dict(row) if row else None
            
        except Exception as e:
            logger.error(f"Failed to fetch record: {e}")
            raise
    
    async def fetch_all(self, query: str, params: Optional[Dict] = None) -> List[Dict]:
        """Fetch all records from SQLite."""
        try:
            if not self.connection:
                raise RuntimeError("Not connected to database")
            
            self.connection.row_factory = aiosqlite.Row
            
            if params:
                cursor = await self.connection.execute(query, tuple(params.values()))
            else:
                cursor = await self.connection.execute(query)
            
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Failed to fetch records: {e}")
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform SQLite health check."""
        try:
            if not self.connection:
                return {"healthy": False, "error": "Not connected"}
            
            cursor = await self.connection.execute("SELECT 1")
            result = await cursor.fetchone()
            
            return {
                "healthy": True,
                "engine": "sqlite",
                "database_file": self.config.database,
                "test_query": result[0] == 1 if result else False
            }
            
        except Exception as e:
            return {"healthy": False, "error": str(e)}

class DatabaseEngineManager:
    """Manager for multiple database engines."""
    
    def __init__(self):
        self.engines: Dict[str, DatabaseEngine] = {}
        self.primary_engine: Optional[str] = None
    
    def add_engine(self, name: str, engine: DatabaseEngine) -> None:
        """Add a database engine."""
        self.engines[name] = engine
        
        if self.primary_engine is None:
            self.primary_engine = name
    
    def get_engine(self, name: Optional[str] = None) -> Optional[DatabaseEngine]:
        """Get a database engine."""
        if name is None:
            name = self.primary_engine
        
        return self.engines.get(name)
    
    async def connect_all(self) -> Dict[str, bool]:
        """Connect all engines."""
        results = {}
        
        for name, engine in self.engines.items():
            try:
                results[name] = await engine.connect()
            except Exception as e:
                logger.error(f"Failed to connect engine {name}: {e}")
                results[name] = False
        
        return results
    
    async def disconnect_all(self) -> Dict[str, bool]:
        """Disconnect all engines."""
        results = {}
        
        for name, engine in self.engines.items():
            try:
                results[name] = await engine.disconnect()
            except Exception as e:
                logger.error(f"Failed to disconnect engine {name}: {e}")
                results[name] = False
        
        return results
    
    async def health_check_all(self) -> Dict[str, Dict[str, Any]]:
        """Health check all engines."""
        results = {}
        
        for name, engine in self.engines.items():
            try:
                results[name] = await engine.health_check()
            except Exception as e:
                logger.error(f"Health check failed for engine {name}: {e}")
                results[name] = {"healthy": False, "error": str(e)}
        
        return results

# Factory function
def create_engine(config: DatabaseConfig) -> DatabaseEngine:
    """Create a database engine based on configuration."""
    if config.engine_type == DatabaseType.POSTGRESQL:
        return PostgreSQLEngine(config)
    elif config.engine_type == DatabaseType.SQLITE:
        return SQLiteEngine(config)
    else:
        raise ValueError(f"Unsupported database type: {config.engine_type}")

# Global engine manager
engine_manager = DatabaseEngineManager()

# Initialize default engines based on configuration
def initialize_engines():
    """Initialize database engines from configuration."""
    try:
        db_config = settings.get('database', {})
        
        # Primary database
        primary_config = DatabaseConfig(
            engine_type=DatabaseType(db_config.get('type', 'sqlite')),
            host=db_config.get('host', 'localhost'),
            port=db_config.get('port', 5432),
            database=db_config.get('database', 'plexichat.db'),
            username=db_config.get('username', ''),
            password=db_config.get('password', ''),
            ssl=db_config.get('ssl', False),
            pool_size=db_config.get('pool_size', 10)
        )
        
        primary_engine = create_engine(primary_config)
        engine_manager.add_engine('primary', primary_engine)
        
        logger.info(f"Initialized primary database engine: {primary_config.engine_type.value}")
        
    except Exception as e:
        logger.error(f"Failed to initialize database engines: {e}")

# Initialize on import
initialize_engines()

__all__ = [
    'DatabaseType', 'DatabaseConfig', 'DatabaseEngine',
    'PostgreSQLEngine', 'SQLiteEngine', 'DatabaseEngineManager',
    'create_engine', 'engine_manager'
]
