"""
PlexiChat Database Abstraction Layer

Provides a unified interface for database operations across different database types.
Supports SQLite, PostgreSQL, MySQL, and other databases through a common API.
"""

from typing import TYPE_CHECKING

from plexichat.core.database.connection import (
    ConnectionPool,
    ConnectionProtocol,
    DatabaseConnection,
)
from plexichat.core.database.manager import (
    DatabaseConfig,
    DatabaseManager,
    DatabaseOperation,
    DatabasePermissionError,
    DatabaseResourceType,
    DatabaseSession,
    DatabaseType,
    database_manager,
    execute_query,
    execute_transaction,
)
from plexichat.core.database.migrations import create_migration, run_migrations
from plexichat.core.database.models import (
    BaseModel,
    SchemaDict,
    create_tables,
    drop_tables,
)
from plexichat.core.database.session import get_session

if TYPE_CHECKING:
    from plexichat.core.database.manager import (
        DatabaseConnection as DatabaseConnectionProtocol,
    )


# Initialize database system
async def initialize_database_system() -> None:
    """Initialize the database system."""
    await database_manager.initialize()


# Export main components
__all__ = [
    # Core manager
    "database_manager",
    "DatabaseManager",
    "DatabaseConfig",
    "DatabaseType",
    "DatabaseOperation",
    "DatabaseResourceType",
    "DatabasePermissionError",
    # Session management
    "get_session",
    "DatabaseSession",
    # Operations
    "execute_query",
    "execute_transaction",
    # Models
    "BaseModel",
    "SchemaDict",
    "create_tables",
    "drop_tables",
    # Migrations
    "run_migrations",
    "create_migration",
    # Connection
    "DatabaseConnection",
    "ConnectionProtocol",
    "ConnectionPool",
    # Initialization
    "initialize_database_system",
]
