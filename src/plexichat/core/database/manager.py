"""
PlexiChat Database Manager

Unified database management system with support for multiple database types,
connection pooling, transactions, and performance optimization.
"""

import asyncio
import logging
import inspect
from typing import Any, Dict, List, Optional, Set, AsyncContextManager
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum

try:
    from plexichat.core.unified_config import get_config
    from plexichat.core.auth.permissions import check_permission, format_permission, DBOperation, ResourceType, PermissionError
    config = get_config("database")
except ImportError:
    # This fallback is for when the module is used in a context where the full app isn't available.
    config = None
    # Define dummy classes and functions for type hinting and to avoid runtime errors.
    def check_permission(required, user_permissions): pass
    def format_permission(rt, op, rn): return ""
    class DBOperation(Enum): READ="read"; WRITE="write"; DELETE="delete"; EXECUTE_RAW="execute_raw"
    class ResourceType(Enum): TABLE="table"; DATABASE="db"
    class PermissionError(Exception): pass


logger = logging.getLogger(__name__)


class DatabaseType(Enum):
    """Supported database types."""
    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MARIADB = "mariadb"


@dataclass
class DatabaseConfig:
    """Database configuration."""
    db_type: str = "sqlite"
    host: str = "localhost"
    port: int = 5432
    name: str = "plexichat"
    username: str = ""
    password: str = ""
    path: str = "data/plexichat.db"
    pool_size: int = 10
    max_overflow: int = 20
    echo: bool = False
    backup_enabled: bool = True
    backup_interval_hours: int = 6


class DatabaseSession:
    """
    Database session wrapper with fine-grained access control.
    """
    
    def __init__(self, connection, user_permissions: Optional[Set[str]] = None):
        self.connection = connection
        self._transaction = None
        self.user_permissions = user_permissions

    def _check_permission(self, operation: DBOperation, resource_name: str):
        """Checks if the user has permission to perform the operation on the resource."""
        # If no permissions are passed, we assume system-level access and allow the operation.
        if self.user_permissions is None:
            return

        required_permission = format_permission(ResourceType.TABLE, operation, resource_name)
        check_permission(required_permission, self.user_permissions)

    async def execute(self, query: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Execute a raw SQL query. Requires special permission."""
        if self.user_permissions is not None:
            required_permission = format_permission(ResourceType.DATABASE, DBOperation.EXECUTE_RAW, "any")
            check_permission(required_permission, self.user_permissions)

        try:
            return await self.connection.execute(query, params or {})
        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            raise
    
    async def fetchall(self, query: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Fetch all results from a query. Requires raw execution permission."""
        result = await self.execute(query, params)
        return [dict(row) for row in await result.fetchall()]
    
    async def fetchone(self, query: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Fetch one result from a query. Requires raw execution permission."""
        result = await self.execute(query, params)
        row = await result.fetchone()
        return dict(row) if row else None
    
    async def insert(self, table: str, data: Dict[str, Any]) -> Any:
        """Insert data into a table after a permission check."""
        self._check_permission(DBOperation.WRITE, table)
        columns = ", ".join(data.keys())
        placeholders = ", ".join([f":{key}" for key in data.keys()])
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        return await self.connection.execute(query, data)
    
    async def update(self, table: str, data: Dict[str, Any], where: Dict[str, Any]) -> Any:
        """Update data in a table after a permission check."""
        self._check_permission(DBOperation.WRITE, table)
        set_clause = ", ".join([f"{key} = :{key}" for key in data.keys()])
        where_clause = " AND ".join([f"{key} = :where_{key}" for key in where.keys()])
        query = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
        params = {**data, **{f"where_{k}": v for k, v in where.items()}}
        return await self.connection.execute(query, params)
    
    async def delete(self, table: str, where: Dict[str, Any]) -> Any:
        """Delete data from a table after a permission check."""
        self._check_permission(DBOperation.DELETE, table)
        where_clause = " AND ".join([f"{key} = :{key}" for key in where.keys()])
        query = f"DELETE FROM {table} WHERE {where_clause}"
        return await self.connection.execute(query, where)
    
    async def commit(self):
        """Commit the current transaction."""
        if self._transaction:
            try:
                commit_method = getattr(self._transaction, 'commit', None)
                if commit_method and callable(commit_method):
                    result = commit_method()
                    if inspect.iscoroutine(result):
                        await result
            except Exception as e:
                logger.error(f"Failed to commit transaction: {e}")

    async def rollback(self):
        """Rollback the current transaction."""
        if self._transaction:
            try:
                rollback_method = getattr(self._transaction, 'rollback', None)
                if rollback_method and callable(rollback_method):
                    result = rollback_method()
                    if inspect.iscoroutine(result):
                        await result
            except Exception as e:
                logger.error(f"Failed to rollback transaction: {e}")

    async def close(self):
        """Close the session."""
        if self.connection:
            try:
                close_method = getattr(self.connection, 'close', None)
                if close_method and callable(close_method):
                    result = close_method()
                    if inspect.iscoroutine(result):
                        await result
            except Exception as e:
                logger.error(f"Failed to close connection: {e}")


class DatabaseManager:
    """Unified database manager."""
    
    def __init__(self, config: Optional[DatabaseConfig] = None):
        self.config = config or self._get_default_config()
        self.engine = None
        self.session_factory = None
        self._initialized = False
        self.logger = logging.getLogger(__name__)
    
    def _get_default_config(self) -> DatabaseConfig:
        """Get default database configuration."""
        if config and hasattr(config, 'database'):
            db_config = config.database
            return DatabaseConfig(
                db_type=getattr(db_config, 'db_type', 'sqlite'),
                host=getattr(db_config, 'host', 'localhost'),
                port=getattr(db_config, 'port', 5432),
                name=getattr(db_config, 'name', 'plexichat'),
                username=getattr(db_config, 'username', ''),
                password=getattr(db_config, 'password', ''),
                path=getattr(db_config, 'path', 'data/plexichat.db'),
                pool_size=getattr(db_config, 'pool_size', 10),
                max_overflow=getattr(db_config, 'max_overflow', 20),
                echo=getattr(db_config, 'echo', False),
            )
        return DatabaseConfig()
    
    async def initialize(self) -> bool:
        """Initialize the database manager."""
        if self._initialized:
            return True
        
        try:
            self.logger.info(f"Initializing database manager with {self.config.db_type}")
            
            # Create database engine based on type
            if self.config.db_type == "sqlite":
                await self._initialize_sqlite()
            elif self.config.db_type in ["postgresql", "postgres"]:
                await self._initialize_postgresql()
            elif self.config.db_type == "mysql":
                await self._initialize_mysql()
            else:
                raise ValueError(f"Unsupported database type: {self.config.db_type}")
            
            await self.ensure_table_exists(
                "plugin_data",
                {
                    "plugin_name": "TEXT",
                    "key": "TEXT",
                    "value": "TEXT",
                    "PRIMARY KEY": "(plugin_name, key)",
                },
            )
            self._initialized = True
            self.logger.info("Database manager initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database manager: {e}")
            return False
    
    async def _initialize_sqlite(self):
        """Initialize SQLite database."""
        try:
            try:
                import aiosqlite
            except ImportError:
                self.logger.error("aiosqlite not available. Install with: pip install aiosqlite")
                raise

            import os

            # Ensure directory exists
            db_dir = os.path.dirname(self.config.path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)

            # Test connection
            async with aiosqlite.connect(self.config.path) as conn:
                await conn.execute("SELECT 1")

            self.logger.info(f"SQLite database initialized at {self.config.path}")

        except Exception as e:
            self.logger.error(f"SQLite initialization failed: {e}")
            raise
    
    async def _initialize_postgresql(self):
        """Initialize PostgreSQL database."""
        try:
            try:
                # Import asyncpg conditionally
                asyncpg = __import__('asyncpg')
            except ImportError:
                self.logger.error("asyncpg not available. Install with: pip install asyncpg")
                raise

            # Test connection
            conn = await asyncpg.connect(
                host=self.config.host,
                port=self.config.port,
                database=self.config.name,
                user=self.config.username,
                password=self.config.password
            )
            await conn.close()

            self.logger.info(f"PostgreSQL database initialized at {self.config.host}:{self.config.port}")

        except Exception as e:
            self.logger.error(f"PostgreSQL initialization failed: {e}")
            raise
    
    async def _initialize_mysql(self):
        """Initialize MySQL database."""
        try:
            try:
                import aiomysql
            except ImportError:
                self.logger.error("aiomysql not available. Install with: pip install aiomysql")
                raise

            # Test connection
            conn = await aiomysql.connect(
                host=self.config.host,
                port=self.config.port,
                db=self.config.name,
                user=self.config.username,
                password=self.config.password
            )
            conn.close()

            self.logger.info(f"MySQL database initialized at {self.config.host}:{self.config.port}")

        except Exception as e:
            self.logger.error(f"MySQL initialization failed: {e}")
            raise
    
    @asynccontextmanager
    async def get_session(self, user_permissions: Optional[Set[str]] = None) -> AsyncContextManager[DatabaseSession]:
        """Get a database session, optionally with user permissions for access control."""
        if not self._initialized:
            await self.initialize()

        session: Optional[DatabaseSession] = None
        try:
            if self.config.db_type == "sqlite":
                session = await self._get_sqlite_session(user_permissions)
            elif self.config.db_type in ["postgresql", "postgres"]:
                session = await self._get_postgresql_session(user_permissions)
            elif self.config.db_type == "mysql":
                session = await self._get_mysql_session(user_permissions)
            else:
                raise ValueError(f"Unsupported database type: {self.config.db_type}")

            yield session
        except Exception as e:
            if session is not None:
                await session.rollback()
            raise
        finally:
            if session is not None:
                await session.close()

    async def _get_sqlite_session(self, user_permissions: Optional[Set[str]] = None) -> DatabaseSession:
        """Get SQLite session."""
        try:
            import aiosqlite
        except ImportError:
            raise ImportError("aiosqlite not available")

        conn = await aiosqlite.connect(self.config.path)
        conn.row_factory = aiosqlite.Row
        return DatabaseSession(conn, user_permissions)

    async def _get_postgresql_session(self, user_permissions: Optional[Set[str]] = None) -> DatabaseSession:
        """Get PostgreSQL session."""
        try:
            # Import asyncpg conditionally
            asyncpg = __import__('asyncpg')
        except ImportError:
            raise ImportError("asyncpg not available")

        conn = await asyncpg.connect(
            host=self.config.host,
            port=self.config.port,
            database=self.config.name,
            user=self.config.username,
            password=self.config.password
        )
        return DatabaseSession(conn, user_permissions)

    async def _get_mysql_session(self, user_permissions: Optional[Set[str]] = None) -> DatabaseSession:
        """Get MySQL session."""
        try:
            import aiomysql
        except ImportError:
            raise ImportError("aiomysql not available")

        conn = await aiomysql.connect(
            host=self.config.host,
            port=self.config.port,
            db=self.config.name,
            user=self.config.username,
            password=self.config.password
        )
        return DatabaseSession(conn, user_permissions)
    
    async def ensure_table_exists(self, table_name: str, schema: Dict[str, str]) -> bool:
        """Ensure a table exists with the given schema."""
        try:
            async with self.get_session() as session:
                # Check if table exists
                if self.config.db_type == "sqlite":
                    check_query = "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
                    result = await session.fetchone(check_query, {"name": table_name})
                else:
                    check_query = "SELECT table_name FROM information_schema.tables WHERE table_name = :name"
                    result = await session.fetchone(check_query, {"name": table_name})
                
                if not result:
                    # Create table
                    columns = ", ".join([f"{col} {dtype}" for col, dtype in schema.items()])
                    create_query = f"CREATE TABLE {table_name} ({columns})"
                    await session.execute(create_query)
                    await session.commit()
                    self.logger.info(f"Created table: {table_name}")
                
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to ensure table {table_name} exists: {e}")
            return False
    
    async def health_check(self) -> bool:
        """Check database health."""
        try:
            async with self.get_session() as session:
                await session.execute("SELECT 1")
                return True
        except Exception as e:
            self.logger.error(f"Database health check failed: {e}")
            return False


# Global database manager instance
database_manager = DatabaseManager()


# Convenience functions
def get_session(user_permissions: Optional[Set[str]] = None):
    """Get a database session, optionally with user permissions."""
    return database_manager.get_session(user_permissions)


async def execute_query(query: str, params: Optional[Dict[str, Any]] = None, user_permissions: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
    """Execute a query and return results. Requires raw execution permissions."""
    async with database_manager.get_session(user_permissions=user_permissions) as session:
        return await session.fetchall(query, params)


async def execute_transaction(operations: List[Dict[str, Any]], user_permissions: Optional[Set[str]] = None) -> bool:
    """Execute multiple operations in a transaction, with permission checks."""
    try:
        async with database_manager.get_session(user_permissions=user_permissions) as session:
            for op in operations:
                op_type = op.get('type')
                if op_type == 'query':
                    await session.execute(op['query'], op.get('params'))
                elif op_type == 'insert':
                    await session.insert(op['table'], op['data'])
                elif op_type == 'update':
                    await session.update(op['table'], op['data'], op['where'])
                elif op_type == 'delete':
                    await session.delete(op['table'], op['where'])

            await session.commit()
            return True
    except Exception as e:
        logger.error(f"Transaction failed: {e}")
        return False
