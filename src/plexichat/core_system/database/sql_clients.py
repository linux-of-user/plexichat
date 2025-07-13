"""
PlexiChat SQL Database Clients

Specialized implementations for different SQL databases with database-specific
optimizations, features, and performance enhancements.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import asyncpg  # type: ignore
except ImportError:
    asyncpg = None

try:
    import aiomysql  # type: ignore
except ImportError:
    aiomysql = None

try:
    import aiosqlite  # type: ignore
except ImportError:
    aiosqlite = None

try:
    from .enhanced_abstraction import (  # type: ignore
        AbstractDatabaseClient,
        DatabaseConfig,
        DatabaseType,
        QueryResult,
    )
    ENHANCED_ABSTRACTION_AVAILABLE = True
except ImportError:
    ENHANCED_ABSTRACTION_AVAILABLE = False
    # Create placeholder classes
    class AbstractDatabaseClient:
        def __init__(self, config):
            self.config = config
        async def execute_query(self, query, params=None):
            return {"success": True, "data": []}

    class DatabaseConfig:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

    class QueryResult:
        def __init__(self, data=None, count=0, execution_time=0.0, metadata=None, success=True, **kwargs):
            self.data = data or []
            self.count = count
            self.execution_time = execution_time
            self.metadata = metadata or {}
            self.success = success
            # Accept any additional keyword arguments
            for key, value in kwargs.items():
                setattr(self, key, value)

    class DatabaseType:
        POSTGRESQL = "postgresql"
        MYSQL = "mysql"
        SQLITE = "sqlite"

logger = logging.getLogger(__name__)


class PostgreSQLClient(AbstractDatabaseClient):  # type: ignore
    """PostgreSQL-specific database client with advanced features."""
    
    def __init__(self, config: DatabaseConfig):
        super().__init__(config)
        self.pool = None
        self.connection_params = self._build_connection_params()
    
    def _build_connection_params(self) -> Dict[str, Any]:
        """Build PostgreSQL connection parameters."""
        params = {
            "host": self.config.host,
            "port": self.config.port,
            "database": self.config.name,
            "user": self.config.username,
            "password": self.config.password,
            "min_size": 5,
            "max_size": self.config.pool_size or 20,
            "command_timeout": 60,
            "server_settings": {
                "application_name": "PlexiChat",
                "timezone": "UTC"
            }
        }
        
        # Add SSL configuration if specified
        if hasattr(self.config, 'ssl_mode'):
            params["ssl"] = self.config.ssl_mode
        
        return params
    
    async def connect(self) -> bool:
        """Connect to PostgreSQL database."""
        if not asyncpg:
            logger.error("asyncpg not installed. Install with: pip install asyncpg")
            return False
        
        try:
            self.pool = await asyncpg.create_pool(**self.connection_params)
            logger.info(f"✅ Connected to PostgreSQL: {self.config.host}:{self.config.port}/{self.config.name}")
            return True
        except Exception as e:
            logger.error(f"❌ PostgreSQL connection failed: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from PostgreSQL."""
        try:
            if self.pool:
                await self.pool.close()
                self.pool = None
            logger.info("✅ Disconnected from PostgreSQL")
            return True
        except Exception as e:
            logger.error(f"❌ PostgreSQL disconnect failed: {e}")
            return False
    
    async def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> QueryResult:
        """Execute PostgreSQL query with optimizations."""
        if not self.pool:
            raise RuntimeError("Not connected to PostgreSQL")
        
        start_time = datetime.now(timezone.utc)
        
        try:
            async with self.pool.acquire() as connection:
                # Convert named parameters to positional for asyncpg
                if params:
                    # Simple parameter substitution for demonstration
                    for key, value in params.items():
                        query = query.replace(f"${key}", f"${list(params.keys()).index(key) + 1}")
                    result = await connection.fetch(query, *params.values())
                else:
                    result = await connection.fetch(query)
                
                # Convert asyncpg records to dictionaries
                data = [dict(record) for record in result]
                
                execution_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                
                return QueryResult(
                    success=True,
                    data=data,
                    row_count=len(data),
                    execution_time_ms=execution_time,
                    query=query
                )
        
        except Exception as e:
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            logger.error(f"PostgreSQL query failed: {e}")
            
            return QueryResult(
                success=False,
                data=[],
                row_count=0,
                execution_time_ms=execution_time,
                error=str(e),
                query=query
            )
    
    async def execute_transaction(self, queries: List[str], params_list: Optional[List[Dict[str, Any]]] = None) -> List[QueryResult]:
        """Execute multiple queries in a PostgreSQL transaction."""
        if not self.pool:
            raise RuntimeError("Not connected to PostgreSQL")
        
        results = []
        
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                for i, query in enumerate(queries):
                    params = params_list[i] if params_list and i < len(params_list) else None
                    
                    try:
                        if params:
                            for key, value in params.items():
                                query = query.replace(f"${key}", f"${list(params.keys()).index(key) + 1}")
                            result = await connection.fetch(query, *params.values())
                        else:
                            result = await connection.fetch(query)
                        
                        data = [dict(record) for record in result]
                        results.append(QueryResult(
                            success=True,
                            data=data,
                            row_count=len(data),
                            query=query
                        ))
                    
                    except Exception as e:
                        results.append(QueryResult(
                            success=False,
                            data=[],
                            row_count=0,
                            error=str(e),
                            query=query
                        ))
                        raise  # Rollback transaction
        
        return results
    
    async def get_table_info(self, table_name: str) -> Dict[str, Any]:
        """Get PostgreSQL-specific table information."""
        query = """
        SELECT 
            column_name,
            data_type,
            is_nullable,
            column_default,
            character_maximum_length
        FROM information_schema.columns
        WHERE table_name = $1
        ORDER BY ordinal_position
        """
        
        result = await self.execute_query(query, {"1": table_name})
        return {
            "table_name": table_name,
            "columns": result.data if result.success else [],
            "database_type": "postgresql"
        }


class MySQLClient(AbstractDatabaseClient):  # type: ignore
    """MySQL-specific database client with optimizations."""
    
    def __init__(self, config: DatabaseConfig):
        super().__init__(config)
        self.pool = None
    
    async def connect(self) -> bool:
        """Connect to MySQL database."""
        if not aiomysql:
            logger.error("aiomysql not installed. Install with: pip install aiomysql")
            return False
        
        try:
            self.pool = await aiomysql.create_pool(
                host=self.config.host,
                port=self.config.port,
                user=self.config.username,
                password=self.config.password,
                db=self.config.name,
                minsize=5,
                maxsize=self.config.pool_size or 20,
                autocommit=True,
                charset='utf8mb4'
            )
            logger.info(f"✅ Connected to MySQL: {self.config.host}:{self.config.port}/{self.config.name}")
            return True
        except Exception as e:
            logger.error(f"❌ MySQL connection failed: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from MySQL."""
        try:
            if self.pool:
                self.pool.close()
                await self.pool.wait_closed()
                self.pool = None
            logger.info("✅ Disconnected from MySQL")
            return True
        except Exception as e:
            logger.error(f"❌ MySQL disconnect failed: {e}")
            return False
    
    async def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> QueryResult:
        """Execute MySQL query."""
        if not self.pool:
            raise RuntimeError("Not connected to MySQL")
        
        start_time = datetime.now(timezone.utc)
        
        try:
            async with self.pool.acquire() as connection:
                dict_cursor = getattr(aiomysql, 'DictCursor', None) if aiomysql else None
                async with connection.cursor(dict_cursor) as cursor:
                    if params:
                        # Convert named parameters to MySQL format
                        mysql_query = query
                        mysql_params = []
                        for key, value in params.items():
                            mysql_query = mysql_query.replace(f"%{key}", "%s")
                            mysql_params.append(value)
                        await cursor.execute(mysql_query, mysql_params)
                    else:
                        await cursor.execute(query)
                    
                    result = await cursor.fetchall()
                    
                    execution_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                    
                    return QueryResult(
                        success=True,
                        data=result or [],
                        row_count=len(result) if result else 0,
                        execution_time_ms=execution_time,
                        query=query
                    )
        
        except Exception as e:
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            logger.error(f"MySQL query failed: {e}")
            
            return QueryResult(
                success=False,
                data=[],
                row_count=0,
                execution_time_ms=execution_time,
                error=str(e),
                query=query
            )
    
    async def execute_transaction(self, queries: List[str], params_list: Optional[List[Dict[str, Any]]] = None) -> List[QueryResult]:
        """Execute multiple queries in a MySQL transaction."""
        if not self.pool:
            raise RuntimeError("Not connected to MySQL")
        
        results = []
        
        async with self.pool.acquire() as connection:
            try:
                await connection.begin()
                
                for i, query in enumerate(queries):
                    params = params_list[i] if params_list and i < len(params_list) else None
                    
                    dict_cursor = getattr(aiomysql, 'DictCursor', None) if aiomysql else None
                    async with connection.cursor(dict_cursor) as cursor:
                        if params:
                            mysql_query = query
                            mysql_params = []
                            for key, value in params.items():
                                mysql_query = mysql_query.replace(f"%{key}", "%s")
                                mysql_params.append(value)
                            await cursor.execute(mysql_query, mysql_params)
                        else:
                            await cursor.execute(query)
                        
                        result = await cursor.fetchall()
                        results.append(QueryResult(
                            success=True,
                            data=result or [],
                            row_count=len(result) if result else 0,
                            query=query
                        ))
                
                await connection.commit()
            
            except Exception as e:
                await connection.rollback()
                results.append(QueryResult(
                    success=False,
                    data=[],
                    row_count=0,
                    error=str(e),
                    query="TRANSACTION"
                ))
        
        return results


class SQLiteClient(AbstractDatabaseClient):  # type: ignore
    """SQLite-specific database client with optimizations."""
    
    def __init__(self, config: DatabaseConfig):
        super().__init__(config)
        self.connection = None
        self.db_path = self._extract_db_path()
    
    def _extract_db_path(self) -> str:
        """Extract database path from URL."""
        if self.config.url.startswith("sqlite:///"):
            return self.config.url[10:]  # Remove "sqlite:///"
        return self.config.url
    
    async def connect(self) -> bool:
        """Connect to SQLite database."""
        if not aiosqlite:
            logger.error("aiosqlite not installed. Install with: pip install aiosqlite")
            return False
        
        try:
            self.connection = await aiosqlite.connect(self.db_path)
            self.connection.row_factory = aiosqlite.Row
            
            # Enable WAL mode for better concurrency
            await self.connection.execute("PRAGMA journal_mode=WAL")
            await self.connection.execute("PRAGMA synchronous=NORMAL")
            await self.connection.execute("PRAGMA cache_size=10000")
            await self.connection.execute("PRAGMA temp_store=MEMORY")
            
            logger.info(f"✅ Connected to SQLite: {self.db_path}")
            return True
        except Exception as e:
            logger.error(f"❌ SQLite connection failed: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from SQLite."""
        try:
            if self.connection:
                await self.connection.close()
                self.connection = None
            logger.info("✅ Disconnected from SQLite")
            return True
        except Exception as e:
            logger.error(f"❌ SQLite disconnect failed: {e}")
            return False
    
    async def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> QueryResult:
        """Execute SQLite query."""
        if not self.connection:
            raise RuntimeError("Not connected to SQLite")
        
        start_time = datetime.now(timezone.utc)
        
        try:
            if params:
                cursor = await self.connection.execute(query, params)
            else:
                cursor = await self.connection.execute(query)
            
            rows = await cursor.fetchall()
            data = [dict(row) for row in rows]
            
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            return QueryResult(
                success=True,
                data=data,
                row_count=len(data),
                execution_time_ms=execution_time,
                query=query
            )
        
        except Exception as e:
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            logger.error(f"SQLite query failed: {e}")
            
            return QueryResult(
                success=False,
                data=[],
                row_count=0,
                execution_time_ms=execution_time,
                error=str(e),
                query=query
            )
    
    async def execute_transaction(self, queries: List[str], params_list: Optional[List[Dict[str, Any]]] = None) -> List[QueryResult]:
        """Execute multiple queries in a SQLite transaction."""
        if not self.connection:
            raise RuntimeError("Not connected to SQLite")
        
        results = []
        
        try:
            await self.connection.execute("BEGIN")
            
            for i, query in enumerate(queries):
                params = params_list[i] if params_list and i < len(params_list) else None
                
                if params:
                    cursor = await self.connection.execute(query, params)
                else:
                    cursor = await self.connection.execute(query)
                
                rows = await cursor.fetchall()
                data = [dict(row) for row in rows]
                
                results.append(QueryResult(
                    success=True,
                    data=data,
                    row_count=len(data),
                    query=query
                ))
            
            await self.connection.execute("COMMIT")
        
        except Exception as e:
            await self.connection.execute("ROLLBACK")
            results.append(QueryResult(
                success=False,
                data=[],
                row_count=0,
                error=str(e),
                query="TRANSACTION"
            ))
        
        return results
