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
import re
from typing import Any

# Unified logging imports
from plexichat.core.logging import get_logger

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
        PermissionError,
        ResourceType,
        check_permission,
        format_permission,
    )
except ImportError:
    # Define dummy classes and functions for type hinting and to avoid runtime errors.

    def check_permission(required: str, user_permissions: set[str]) -> None:
        """Fallback permission check - always allows."""
        pass

    def format_permission(rt, op, rn: str = "any") -> str:
        """Fallback permission formatting."""
        return f"{rt}:{op}:{rn}"

    class DBOperation(Enum):
        READ = "read"
        WRITE = "write"

    class ResourceType(Enum):
        DATABASE = "database"

    class PermissionError(Exception):
        pass


logger = get_logger(__name__)


class DatabaseConfig:
    """Database configuration class."""

    def __init__(self, db_url: str = "sqlite:///:memory:", **kwargs):
        self.db_url = db_url
        self.pool_size = kwargs.get("pool_size", 10)
        self.echo = kwargs.get("echo", False)


@dataclass
class ConnectionMetrics:
    """Database connection metrics."""

    total_connections: int = 0
    active_connections: int = 0
    failed_connections: int = 0
    avg_query_time: float = 0.0


class DatabaseSession:
    """Database session wrapper with permission checking."""

    def __init__(self, connection: Any, user_permissions: set[str]):
        self.connection = connection
        self.user_permissions = user_permissions

    def _check_permission(self, operation: DBOperation, resource_name: str) -> None:
        """Check if user has permission for database operation."""
        required_permission = format_permission(
            ResourceType.DATABASE, operation, resource_name
        )
        check_permission(required_permission, self.user_permissions)

    async def execute(
        self, query: str, params: dict[str, Any] | tuple | list | None = None
    ) -> Any:
        """Execute a query with permission checking."""
        # Extract table/resource from query for permission check

        # Simple heuristic to extract table name from query
        words = query.strip().split()
        if len(words) > 2 and words[0].upper() in [
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
        ]:
            operation = (
                DBOperation.WRITE if words[0].upper() != "SELECT" else DBOperation.READ
            )
            # Try to extract table name
            if words[0].upper() == "SELECT":
                try:
                    from_idx = [i for i, w in enumerate(words) if w.upper() == "FROM"][
                        0
                    ]
                    table_name = words[from_idx + 1].strip(";")
                except (IndexError, ValueError):
                    table_name = "unknown"
            elif words[0].upper() == "INSERT":
                try:
                    into_idx = [i for i, w in enumerate(words) if w.upper() == "INTO"][
                        0
                    ]
                    table_name = words[into_idx + 1].strip(";")
                except (IndexError, ValueError):
                    table_name = "unknown"
            elif words[0].upper() in ["UPDATE", "DELETE"]:
                try:
                    table_name = words[1].strip(";")
                except IndexError:
                    table_name = "unknown"
            else:
                table_name = "unknown"

            required_permission = format_permission(
                ResourceType.DATABASE, operation, table_name
            )
            check_permission(required_permission, self.user_permissions)

        # Convert tuple/list params to dict for compatibility
        if isinstance(params, (tuple, list)):
            params_dict = {}
            param_counter = 0

            def replace_placeholder(match):
                nonlocal param_counter
                key = f"param_{param_counter}"
                if param_counter < len(params):
                    params_dict[key] = params[param_counter]
                param_counter += 1
                return f":{key}"

            query = re.sub(r"\?", replace_placeholder, query)
            params = params_dict

        try:
            return await self.connection.execute(query, params or {})
        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            raise

    async def fetchall(
        self, query: str, params: dict[str, Any] | tuple | list | None = None
    ) -> list[dict[str, Any]]:
        """Fetch all results from a query. Requires raw execution permission."""
        result = await self.execute(query, params)
        return [dict(row) for row in await result.fetchall()]

    async def fetchone(
        self, query: str, params: dict[str, Any] | tuple | list | None = None
    ) -> dict[str, Any] | None:
        """Fetch one result from a query. Requires raw execution permission."""
        result = await self.execute(query, params)
        row = await result.fetchone()
        return dict(row) if row else None

    async def insert(self, table: str, data: dict[str, Any]) -> Any:
        """Insert data into a table after a permission check."""
        self._check_permission(DBOperation.WRITE, table)
        columns = ", ".join(data.keys())
        placeholders = ", ".join([f":{key}" for key in data])
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        return await self.execute(query, data)

    async def update(
        self, table: str, data: dict[str, Any], where: dict[str, Any]
    ) -> Any:
        """Update data in a table after permission check."""
        self._check_permission(DBOperation.WRITE, table)
        set_clause = ", ".join([f"{key} = :{key}" for key in data])
        where_clause = " AND ".join([f"{key} = :where_{key}" for key in where])
        where_params = {f"where_{key}": value for key, value in where.items()}
        all_params = {**data, **where_params}
        query = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
        return await self.execute(query, all_params)

    async def delete(self, table: str, where: dict[str, Any]) -> Any:
        """Delete data from a table after permission check."""
        self._check_permission(DBOperation.WRITE, table)
        where_clause = " AND ".join([f"{key} = :{key}" for key in where])
        query = f"DELETE FROM {table} WHERE {where_clause}"
        return await self.execute(query, where)

    async def commit(self) -> None:
        """Commit the current transaction."""
        if hasattr(self.connection, "commit"):
            await self.connection.commit()

    async def rollback(self) -> None:
        """Rollback the current transaction."""
        if hasattr(self.connection, "rollback"):
            await self.connection.rollback()

    async def close(self) -> None:
        """Close the database connection."""
        if hasattr(self.connection, "close"):
            await self.connection.close()


class DatabaseManager:
    """Unified database manager with support for multiple database types."""

    def __init__(self, config: DatabaseConfig | None = None):
        self.config = config or DatabaseConfig()
        self.pool = None
        self.metrics = ConnectionMetrics()
        self.is_connected = False

    async def connect(self) -> None:
        """Initialize database connection/pool."""
        try:
            # This is a placeholder - actual implementation would depend on the database type
            # For SQLite/PostgreSQL/MySQL, you'd use appropriate async drivers
            logger.info(f"Connecting to database: {self.config.db_url}")
            self.is_connected = True
            self.metrics.total_connections += 1
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            self.metrics.failed_connections += 1
            raise

    async def disconnect(self) -> None:
        """Close database connections."""
        try:
            if self.pool:
                # Close connection pool
                pass
            self.is_connected = False
            logger.info("Database disconnected")
        except Exception as e:
            logger.error(f"Error disconnecting from database: {e}")

    @asynccontextmanager
    async def get_session(
        self, user_permissions: set[str] | None = None
    ) -> AsyncGenerator[DatabaseSession, None]:
        """Get a database session with optional permission checking."""
        if not self.is_connected:
            await self.connect()

        permissions = user_permissions or set()

        # This would be replaced with actual database connection logic
        # For now, using a placeholder connection object
        connection = None  # Would be actual database connection

        session = DatabaseSession(connection, permissions)
        self.metrics.active_connections += 1

        try:
            yield session
        finally:
            await session.close()
            self.metrics.active_connections -= 1

    async def execute_transaction(
        self, operations: list[callable], user_permissions: set[str] | None = None
    ) -> list[Any]:
        """Execute multiple operations in a single transaction."""
        results = []
        async with self.get_session(user_permissions) as session:
            try:
                for operation in operations:
                    if inspect.iscoroutinefunction(operation):
                        result = await operation(session)
                    else:
                        result = operation(session)
                    results.append(result)

                await session.commit()
                return results
            except Exception as e:
                await session.rollback()
                logger.error(f"Transaction failed: {e}")
                raise

    def get_metrics(self) -> ConnectionMetrics:
        """Get current database metrics."""
        return self.metrics

    async def health_check(self) -> bool:
        """Perform a health check on the database connection."""
        try:
            async with self.get_session() as session:
                # Simple query to test connection
                await session.execute("SELECT 1")
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False


# Global database manager instance
database_manager = DatabaseManager()


# Convenience functions
async def get_database_session(
    user_permissions: set[str] | None = None,
) -> AsyncGenerator[DatabaseSession, None]:
    """Get a database session from the global manager."""
    async with database_manager.get_session(user_permissions) as session:
        yield session


async def execute_query(
    query: str,
    params: dict[str, Any] | None = None,
    user_permissions: set[str] | None = None,
) -> Any:
    """Execute a single query using the global database manager."""
    async with get_database_session(user_permissions) as session:
        return await session.execute(query, params)


async def fetch_all(
    query: str,
    params: dict[str, Any] | None = None,
    user_permissions: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Fetch all results from a query using the global database manager."""
    async with get_database_session(user_permissions) as session:
        return await session.fetchall(query, params)


async def fetch_one(
    query: str,
    params: dict[str, Any] | None = None,
    user_permissions: set[str] | None = None,
) -> dict[str, Any] | None:
    """Fetch one result from a query using the global database manager."""
    async with get_database_session(user_permissions) as session:
        return await session.fetchone(query, params)
