"""
Database Manager Module - MODERN ARCHITECTURE

This module provides a unified interface to the database management system.
It re-exports the main database manager and related components from db_manager.py
to maintain backward compatibility with existing imports.

Uses shared components for consistent error handling and type definitions.
"""

# Import shared components (NEW ARCHITECTURE)
from ...shared.exceptions import DatabaseError, PlexiChatError
from ...shared.types import ConfigDict, DatabaseRow, DatabaseRows, QueryResult
from ...shared.constants import DEFAULT_DATABASE_URL, DATABASE_POOL_SIZE

# Re-export everything from db_manager to maintain compatibility
try:
    from .db_manager import (
        # Main database manager class
        ConsolidatedDatabaseManager,
        database_manager,

        # Configuration and types
        DatabaseConfig,
        DatabaseType,
        DatabaseRole,
        DatabaseMetrics,
        ConnectionStatus,

        # Initialization functions
        initialize_database_system,
        get_database_manager,
    )
except ImportError:
    # Fallback definitions
    ConsolidatedDatabaseManager = None
    database_manager = None
    DatabaseConfig = None
    DatabaseType = None
    DatabaseRole = None
    DatabaseMetrics = None
    ConnectionStatus = None
    initialize_database_system = lambda: None
    get_database_manager = lambda: None

# Create specific database exceptions using shared base
class ConnectionError(DatabaseError):
    """Database connection errors."""
pass

class MigrationError(DatabaseError):
    """Database migration errors."""
pass

class EncryptionError(DatabaseError):
    """Database encryption errors."""
pass

class TransactionError(DatabaseError):
    """Database transaction errors."""
pass

class SchemaError(DatabaseError):
    """Database schema errors."""
pass

# Backward compatibility aliases
DatabaseManager = ConsolidatedDatabaseManager

# Export the main instance
__all__ = [
    "ConsolidatedDatabaseManager",
    "DatabaseManager",
    "database_manager",
    "DatabaseConfig",
    "DatabaseType",
    "DatabaseRole",
    "DatabaseMetrics",
    "ConnectionStatus",
    "initialize_database_system",
    "get_database_manager",
    "DatabaseError",
    "ConnectionError",
    "MigrationError",
    "EncryptionError",
]
