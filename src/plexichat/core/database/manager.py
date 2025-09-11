"""
PlexiChat Database Manager

Unified database management system with support for multiple database types,
connection pooling, transactions, and performance optimization.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
import inspect
from typing import (
    Any,
    Protocol,
    runtime_checkable,
)

# Unified logging imports
from plexichat.core.logging import LogCategory, get_logger

try:
    from plexichat.core.config_manager import get_config

    config = get_config("database")
except ImportError:
    # This fallback is for when the module is used in a context where the full app isn't available.
    config = None

# Try to import permission classes, with fallbacks
try:
    from plexichat.core.auth.permissions import (  # type: ignore
        DBOperation,
        ResourceType,
        check_permission,
        format_permission,
    )
    from plexichat.core.auth.permissions import (
        PermissionError as AuthPermissionError,
    )

    # Type aliases to avoid naming conflicts
    DatabasePermissionError = AuthPermissionError
    DatabaseOperation = DBOperation
    DatabaseResourceType = ResourceType

    local_check_permission = check_permission
    local_format_permission = format_permission

except ImportError:
    # Define dummy classes and functions for type hinting and to avoid runtime errors.

    def check_permission(required: str, user_permissions: set[str]) -> None:
        """Fallback permission check - always allows."""
        pass

    def format_permission(rt: "DatabaseResourceType", op: "DatabaseOperation", rn: str = "any") -> str:
        """Fallback permission formatting."""
        return f"{rt.value}:{op.value}:{rn}"

    class DatabaseOperation(Enum):
        READ = "read"
        WRITE = "write"
        DELETE = "delete"
        EXECUTE_RAW = "execute_raw"

    class DatabaseResourceType(Enum):
        TABLE = "table"
        DATABASE = "db"

    class DatabasePermissionError(Exception):
        """Fallback permission error."""
        pass


logger = get_logger(__name__)


@runtime_checkable
class DatabaseConnection(Protocol):
    """Protocol for database connections."""

    async def execute(self, query: str, params: dict[str, Any] | None = None) -> Any:
        """Execute a query."""
        ...

    async def close(self) -> None:
        """Close the connection."""
        ...

    async def commit(self) -> None:
        """Commit the connection transaction."""
        ...

    async def rollback(self) -> None:
        """Rollback the connection transaction."""
        ...


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

    def __init__(self, connection: DatabaseConnection, user_permissions: set[str] | None = None):
        self.connection = connection
        self._transaction = None
        self.user_permissions = user_permissions
        self._in_transaction = False

    def _check_permission(self, operation: DatabaseOperation, resource_name: str) -> None:
        """Checks if the user has permission to perform the operation on the resource."""
        # If no permissions are passed, we assume system-level access and allow the operation.
        if self.user_permissions is None:
            return

        required_permission = local_format_permission(
            DatabaseResourceType.TABLE, operation, resource_name
        )
        try:
            local_check_permission(required_permission, self.user_permissions)
        except Exception as e:
            raise DatabasePermissionError(f"Permission denied: {required_permission}") from e

    async def execute(self, query: str, params: dict[str, Any] | None = None) -> Any:
        """Execute a raw SQL query. Requires special permission."""
        if self.user_permissions is not None:
            required_permission = local_format_permission(
                DatabaseResourceType.DATABASE, DatabaseOperation.EXECUTE_RAW, "any"
            )
            try:
                local_check_permission(required_permission, self.user_permissions)
            except Exception as e:
                raise DatabasePermissionError(f"Permission denied: {required_permission}") from e

        try:
            return await self.connection.execute(query, params or {})
        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            raise

    async def fetchall(
        self, query: str, params: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """Fetch all results from a query. Requires raw execution permission."""
        result = await self.execute(query, params)
        return [dict(row) for row in await result.fetchall()]

    async def fetchone(
        self, query: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any] | None:
        """Fetch one result from a query. Requires raw execution permission."""
        result = await self.execute(query, params)
        row = await result.fetchone()
        return dict(row) if row else None

    async def insert(self, table: str, data: dict[str, Any]) -> Any:
        """Insert data into a table after a permission check."""
        self._check_permission(DatabaseOperation.WRITE, table)
        columns = ", ".join(data.keys())
        placeholders = ", ".join(["?" for _ in data])
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        # Convert dict values to tuple for compatibility with database connections
        values = tuple(data.values())
        return await self.connection.execute(query, values)

    async def update(
        self, table: str, data: dict[str, Any], where: dict[str, Any]
    ) -> Any:
        """Update data in a table after a permission check."""
        self._check_permission(DatabaseOperation.WRITE, table)
        set_clause = ", ".join([f"{key} = :{key}" for key in data])
        where_clause = " AND ".join([f"{key} = :where_{key}" for key in where])
        query = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
        params = {**data, **{f"where_{k}": v for k, v in where.items()}}
        return await self.connection.execute(query, params)

    async def delete(self, table: str, where: dict[str, Any]) -> Any:
        """Delete data from a table after a permission check."""
        self._check_permission(DatabaseOperation.DELETE, table)
        where_clause = " AND ".join([f"{key} = :{key}" for key in where])
        query = f"DELETE FROM {table} WHERE {where_clause}"
        return await self.connection.execute(query, where)

    async def commit(self) -> None:
        """Commit the current transaction."""
        if self.connection:
            try:
                # For aiosqlite, commit the connection
                commit_method = getattr(self.connection, "commit", None)
                if commit_method and callable(commit_method):
                    result = commit_method()
                    if inspect.iscoroutine(result):
                        await result
                    logger.debug(
                        "Transaction committed successfully",
                        extra={"category": LogCategory.DATABASE},
                    )
                else:
                    logger.warning(
                        "Connection does not have commit method",
                        extra={"category": LogCategory.DATABASE},
                    )
            except Exception as e:
                logger.error(
                    f"Failed to commit transaction: {e}"
                )
                raise

    async def rollback(self) -> None:
        """Rollback the current transaction."""
        if self.connection:
            try:
                # For aiosqlite, rollback the connection
                rollback_method = getattr(self.connection, "rollback", None)
                if rollback_method and callable(rollback_method):
                    result = rollback_method()
                    if inspect.iscoroutine(result):
                        await result
                    logger.debug(
                        "Transaction rolled back successfully",
                        extra={"category": LogCategory.DATABASE},
                    )
                else:
                    logger.warning(
                        "Connection does not have rollback method",
                        extra={"category": LogCategory.DATABASE},
                    )
            except Exception as e:
                logger.error(
                    f"Failed to rollback transaction: {e}",
                    extra={"category": LogCategory.DATABASE},
                )
                raise

    async def close(self) -> None:
        """Close the session."""
        if self.connection:
            try:
                close_method = getattr(self.connection, "close", None)
                if close_method and callable(close_method):
                    result = close_method()
                    if inspect.iscoroutine(result):
                        await result
            except Exception as e:
                logger.error(
                    f"Failed to close connection: {e}"
                )


class DatabaseManager:
    """Unified database manager."""

    def __init__(self, config: DatabaseConfig | None = None):
        self.config = config or self._get_default_config()
        self.engine = None
        self.session_factory = None
        self._initialized = False
        self.logger = get_logger(__name__)

    def _get_default_config(self) -> DatabaseConfig:
        """Get default database configuration."""
        if config and hasattr(config, "database"):
            db_config = config.database
            return DatabaseConfig(
                db_type=getattr(db_config, "db_type", "sqlite"),
                host=getattr(db_config, "host", "localhost"),
                port=getattr(db_config, "port", 5432),
                name=getattr(db_config, "name", "plexichat"),
                username=getattr(db_config, "username", ""),
                password=getattr(db_config, "password", ""),
                path=getattr(db_config, "path", "data/plexichat.db"),
                pool_size=getattr(db_config, "pool_size", 10),
                max_overflow=getattr(db_config, "max_overflow", 20),
                echo=getattr(db_config, "echo", False),
            )
        return DatabaseConfig()

    async def initialize(self) -> bool:
        """Initialize the database manager."""
        if self._initialized:
            return True

        try:
            self.logger.info(
                f"Initializing database manager with {self.config.db_type}"
            )

            # Create database engine based on type
            if self.config.db_type == "sqlite":
                await self._initialize_sqlite()
            elif self.config.db_type in ["postgresql", "postgres"]:
                await self._initialize_postgresql()
            elif self.config.db_type == "mysql":
                await self._initialize_mysql()
            else:
                raise ValueError(f"Unsupported database type: {self.config.db_type}")

            # Mark as initialized before creating tables to avoid circular dependency
            self._initialized = True

            # Create essential tables after initialization
            await self._create_essential_tables()

            # Create all standard tables from models
            try:
                from plexichat.core.database.models import create_tables

                await create_tables()
                self.logger.info(
                    "All standard tables created successfully",
                    extra={"category": LogCategory.DATABASE},
                )
            except Exception as e:
                self.logger.error(
                    f"Failed to create standard tables: {e}",
                    extra={"category": LogCategory.DATABASE},
                )
                raise

            self.logger.info(
                "Database manager initialized successfully",
                extra={"category": LogCategory.DATABASE},
            )
            return True

        except Exception as e:
            self.logger.error(
                f"Failed to initialize database manager: {e}"
            )
            self._initialized = False  # Reset on failure
            return False

    async def _initialize_sqlite(self) -> None:
        """Initialize SQLite database."""
        try:
            try:
                import aiosqlite
            except ImportError:
                self.logger.error(
                    "aiosqlite not available. Install with: pip install aiosqlite",
                    extra={"category": LogCategory.DATABASE},
                )
                raise

            import os

            # Ensure directory exists
            db_dir = os.path.dirname(self.config.path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)

            # Test connection
            async with aiosqlite.connect(self.config.path) as conn:
                await conn.execute("SELECT 1")

            self.logger.info(
                f"SQLite database initialized at {self.config.path}",
                extra={"category": LogCategory.DATABASE},
            )

        except Exception as e:
            self.logger.error(
                f"SQLite initialization failed: {e}"
            )
            raise

    async def _initialize_postgresql(self) -> None:
        """Initialize PostgreSQL database."""
        try:
            try:
                # Import asyncpg conditionally
                asyncpg = __import__("asyncpg")
            except ImportError:
                self.logger.error(
                    "asyncpg not available. Install with: pip install asyncpg",
                    extra={"category": LogCategory.DATABASE},
                )
                raise

            # Test connection
            conn = await asyncpg.connect(
                host=self.config.host,
                port=self.config.port,
                database=self.config.name,
                user=self.config.username,
                password=self.config.password,
            )
            await conn.close()

            self.logger.info(
                f"PostgreSQL database initialized at {self.config.host}:{self.config.port}",
                extra={"category": LogCategory.DATABASE},
            )

        except Exception as e:
            self.logger.error(
                f"PostgreSQL initialization failed: {e}"
            )
            raise

    async def _initialize_mysql(self) -> None:
        """Initialize MySQL database."""
        try:
            try:
                import aiomysql
            except ImportError:
                self.logger.error(
                    "aiomysql not available. Install with: pip install aiomysql",
                    extra={"category": LogCategory.DATABASE},
                )
                raise

            # Test connection
            conn = await aiomysql.connect(
                host=self.config.host,
                port=self.config.port,
                db=self.config.name,
                user=self.config.username,
                password=self.config.password,
            )
            conn.close()

            self.logger.info(
                f"MySQL database initialized at {self.config.host}:{self.config.port}",
                extra={"category": LogCategory.DATABASE},
            )

        except Exception as e:
            self.logger.error(
                f"MySQL initialization failed: {e}"
            )
            raise

    async def _create_essential_tables(self) -> None:
        """Create essential tables after database initialization."""
        try:
            # Create plugin_data table
            await self.ensure_table_exists(
                "plugin_data",
                {
                    "plugin_name": "TEXT",
                    "key": "TEXT",
                    "value": "TEXT",
                    "PRIMARY KEY": "(plugin_name, key)",
                },
            )

            # Create message_threads table
            await self.ensure_table_exists(
                "message_threads",
                {
                    "id": "TEXT PRIMARY KEY",
                    "parent_message_id": "TEXT",
                    "title": "TEXT NOT NULL",
                    "creator_id": "TEXT NOT NULL",
                    "created_at": "TEXT NOT NULL",
                    "updated_at": "TEXT NOT NULL",
                    "reply_count": "INTEGER DEFAULT 0",
                    "is_archived": "BOOLEAN DEFAULT FALSE",
                },
            )

            # Create thread_replies table
            await self.ensure_table_exists(
                "thread_replies",
                {
                    "id": "TEXT PRIMARY KEY",
                    "thread_id": "TEXT NOT NULL",
                    "message_content": "TEXT NOT NULL",
                    "user_id": "TEXT NOT NULL",
                    "created_at": "TEXT NOT NULL",
                    "is_edited": "BOOLEAN DEFAULT FALSE",
                },
            )
        except Exception as e:
            self.logger.error(
                f"Failed to create essential tables: {e}"
            )
            raise

    @asynccontextmanager
    async def get_session(
        self, user_permissions: set[str] | None = None
    ) -> AsyncGenerator[DatabaseSession, None]:
        """Get a database session, optionally with user permissions for access control."""
        if not self._initialized:
            await self.initialize()

        session: DatabaseSession | None = None
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

            # If we get here, no exception was raised - commit the transaction
            logger.debug(
                "Committing transaction on successful exit",
                extra={"category": LogCategory.DATABASE},
            )
            await session.commit()

        except Exception as e:
            # Exception occurred - rollback the transaction
            if session is not None:
                logger.debug(
                    f"Rolling back transaction due to exception: {type(e).__name__}: {e}",
                    extra={"category": LogCategory.DATABASE},
                )
                await session.rollback()
            raise
        finally:
            if session is not None:
                await session.close()

    async def _get_sqlite_session(
        self, user_permissions: set[str] | None = None
    ) -> DatabaseSession:
        """Get SQLite session."""
        try:
            import aiosqlite
        except ImportError:
            raise ImportError("aiosqlite not available")

        conn = await aiosqlite.connect(self.config.path)
        conn.row_factory = aiosqlite.Row
        return DatabaseSession(conn, user_permissions)

    async def _get_postgresql_session(
        self, user_permissions: set[str] | None = None
    ) -> DatabaseSession:
        """Get PostgreSQL session."""
        try:
            # Import asyncpg conditionally
            asyncpg = __import__("asyncpg")
        except ImportError:
            raise ImportError("asyncpg not available")

        conn = await asyncpg.connect(
            host=self.config.host,
            port=self.config.port,
            database=self.config.name,
            user=self.config.username,
            password=self.config.password,
        )
        return DatabaseSession(conn, user_permissions)

    async def _get_mysql_session(
        self, user_permissions: set[str] | None = None
    ) -> DatabaseSession:
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
            password=self.config.password,
        )
        return DatabaseSession(conn, user_permissions)

    async def table_exists(self, table_name: str) -> bool:
        """Check if a table exists."""
        try:
            async with self.get_session() as session:
                if self.config.db_type == "sqlite":
                    result = await session.fetchone(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                        (table_name,)
                    )
                else:
                    # PostgreSQL/MySQL
                    result = await session.fetchone(
                        "SELECT table_name FROM information_schema.tables WHERE table_name = ?",
                        (table_name,)
                    )
                return result is not None
        except Exception as e:
            self.logger.error(
                f"Failed to check if table exists: {e}",
                extra={"category": LogCategory.DATABASE},
            )
            return False

    async def ensure_table_exists(self, table_name: str, schema: dict[str, str]) -> bool:
        """Ensure a table exists with the given schema."""
        try:
            if await self.table_exists(table_name):
                return True

            # Create table
            columns = []
            primary_keys = []

            for column_name, column_type in schema.items():
                if column_name.upper() == "PRIMARY KEY":
                    primary_keys.append(column_type)
                else:
                    columns.append(f"{column_name} {column_type}")

            if primary_keys:
                columns.append(f"PRIMARY KEY {primary_keys[0]}")

            create_sql = f"CREATE TABLE {table_name} ({', '.join(columns)})"

            async with self.get_session() as session:
                await session.execute(create_sql)

            self.logger.info(
                f"Created table: {table_name}",
                extra={"category": LogCategory.DATABASE},
            )
            return True

        except Exception as e:
            self.logger.error(
                f"Failed to create table {table_name}: {e}",
                extra={"category": LogCategory.DATABASE},
            )
            return False

    async def execute_query(
        self, query: str, params: dict[str, Any] | None = None
    ) -> Any:
        """Execute a query and return the result."""
        async with self.get_session() as session:
            return await session.execute(query, params)

    async def execute_transaction(
        self, queries: list[dict[str, Any]]
    ) -> list[Any]:
        """Execute multiple queries in a transaction."""
        results = []
        async with self.get_session() as session:
            for query_dict in queries:
                query = query_dict.get("query", "")
                params = query_dict.get("params")
                result = await session.execute(query, params)
                results.append(result)

        return results

    async def get_connection_info(self) -> dict[str, Any]:
        """Get database connection information."""
        return {
            "db_type": self.config.db_type,
            "host": self.config.host if self.config.db_type != "sqlite" else None,
            "port": self.config.port if self.config.db_type != "sqlite" else None,
            "database": self.config.name if self.config.db_type != "sqlite" else self.config.path,
            "initialized": self._initialized,
        }


# Global database manager instance
database_manager = DatabaseManager()

# Convenience functions that use the global manager
async def execute_query(query: str, params: dict[str, Any] | None = None) -> Any:
    """Execute a query using the global database manager."""
    return await database_manager.execute_query(query, params)


async def execute_transaction(queries: list[dict[str, Any]]) -> list[Any]:
    """Execute multiple queries in a transaction using the global database manager."""
    return await database_manager.execute_transaction(queries)


# Exports
__all__ = [
    "DatabaseConfig",
    "DatabaseConnection",
    "DatabaseManager",
    "DatabaseOperation",
    "DatabasePermissionError",
    "DatabaseResourceType",
    "DatabaseSession",
    "DatabaseType",
    "database_manager",
    "execute_query",
    "execute_transaction",
]
