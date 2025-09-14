"""
Database Connection Management

Connection pooling and management utilities.
"""

import asyncio
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from plexichat.core.logging import get_logger

logger = get_logger(__name__)


@runtime_checkable
class ConnectionProtocol(Protocol):
    """Protocol for database connections."""

    async def execute(
        self, query: str, params: dict[str, Any] | tuple | None = None
    ) -> Any:
        """Execute a query."""
        ...

    async def close(self) -> None:
        """Close the connection."""
        ...


@dataclass
class ConnectionConfig:
    """Database connection configuration."""

    max_connections: int = 10
    min_connections: int = 1
    connection_timeout: int = 30
    idle_timeout: int = 300
    retry_attempts: int = 3
    retry_delay: float = 1.0


class DatabaseConnection:
    """Database connection wrapper."""

    def __init__(
        self, connection: ConnectionProtocol, config: ConnectionConfig | None = None
    ):
        self.connection = connection
        self.config = config or ConnectionConfig()
        self.is_active = True
        self.last_used = asyncio.get_event_loop().time()
        self.logger = get_logger(__name__)

    async def execute(
        self, query: str, params: dict[str, Any] | tuple | None = None
    ) -> Any:
        """Execute a query on this connection."""
        self.last_used = asyncio.get_event_loop().time()

        if params:
            return await self.connection.execute(query, params)
        else:
            return await self.connection.execute(query)

    async def close(self) -> None:
        """Close the connection."""
        if self.connection and self.is_active:
            await self.connection.close()
            self.is_active = False

    def is_expired(self) -> bool:
        """Check if connection has expired."""
        current_time = asyncio.get_event_loop().time()
        return (current_time - self.last_used) > self.config.idle_timeout


class ConnectionPool:
    """Database connection pool."""

    def __init__(self, config: ConnectionConfig | None = None):
        self.config = config or ConnectionConfig()
        self.connections: list[DatabaseConnection] = []
        self.active_connections = 0
        self.lock = asyncio.Lock()
        self.logger = get_logger(__name__)

    async def get_connection(self) -> DatabaseConnection | None:
        """Get a connection from the pool."""
        async with self.lock:
            # Try to reuse an existing connection
            for conn in self.connections:
                if conn.is_active and not conn.is_expired():
                    return conn

            # Remove expired connections
            expired = [conn for conn in self.connections if conn.is_expired()]
            for conn in expired:
                await conn.close()
                self.connections.remove(conn)
                self.active_connections -= 1

            # Create new connection if under limit
            if self.active_connections < self.config.max_connections:
                conn = await self._create_connection()
                if conn:
                    self.connections.append(conn)
                    self.active_connections += 1
                    return conn

            # No connections available
            self.logger.warning("No database connections available")
            return None

    async def _create_connection(self) -> DatabaseConnection | None:
        """Create a new database connection."""
        # This would be implemented based on the database type
        # For now, return None as a placeholder
        return None

    async def return_connection(self, connection: DatabaseConnection) -> None:
        """Return a connection to the pool."""
        # Connection is automatically returned when not in use
        pass

    async def close_all(self) -> None:
        """Close all connections in the pool."""
        async with self.lock:
            for conn in self.connections:
                await conn.close()
            self.connections.clear()
            self.active_connections = 0

    async def health_check(self) -> dict[str, Any]:
        """Get pool health information."""
        async with self.lock:
            active = sum(1 for conn in self.connections if conn.is_active)
            expired = sum(1 for conn in self.connections if conn.is_expired())

            return {
                "total_connections": len(self.connections),
                "active_connections": active,
                "expired_connections": expired,
                "max_connections": self.config.max_connections,
                "pool_utilization": (
                    active / self.config.max_connections
                    if self.config.max_connections > 0
                    else 0
                ),
            }


# Global connection pool
connection_pool = ConnectionPool()


__all__ = [
    "ConnectionConfig",
    "ConnectionPool",
    "ConnectionProtocol",
    "DatabaseConnection",
    "connection_pool",
]
