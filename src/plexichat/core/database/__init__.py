"""
PlexiChat Database Abstraction Layer

Provides a unified interface for database operations across different database types.
Supports SQLite, PostgreSQL, MySQL, and other databases through a common API.
"""

from plexichat.core.database.connection import ConnectionPool, DatabaseConnection
from plexichat.core.database.manager import (
    DatabaseManager,
    database_manager,
    execute_query,
    execute_transaction,
)
from plexichat.core.database.migrations import create_migration, run_migrations
from plexichat.core.database.models import BaseModel, create_tables, drop_tables
from plexichat.core.database.session import DatabaseSession, get_session


# Initialize database system
async def initialize_database_system():
    """Initialize the database system."""
    await database_manager.initialize()


# Export main components
__all__ = [
    # Core manager
    "database_manager",
    "DatabaseManager",
    # Session management
    "get_session",
    "DatabaseSession",
    # Operations
    "execute_query",
    "execute_transaction",
    # Models
    "BaseModel",
    "create_tables",
    "drop_tables",
    # Migrations
    "run_migrations",
    "create_migration",
    # Connection
    "DatabaseConnection",
    "ConnectionPool",
    # Initialization
    "initialize_database_system",
]
