"""
PlexiChat Unified Database System
================================

This module consolidates all database functionality into a single, unified system.
Replaces multiple database modules with a comprehensive, feature-rich solution.

Features:
- Database clustering with automatic failover and load balancing
- Encrypted database connections and data-at-rest encryption
- Advanced migration system with rollback capabilities
- Connection pooling and performance optimization
- External database hosting support (AWS RDS, Google Cloud SQL, etc.)
- Real-time monitoring and health checks
- Backup and recovery integration
"""

from typing import Optional

# Import consolidated database components
from .manager_database import (
    ConnectionStatus,
    ConsolidatedDatabaseManager,
    DatabaseConfig,
    DatabaseMetrics,
    DatabaseRole,
    DatabaseType,
    database_manager,
    get_database_manager,
    initialize_database_system,
)

# Note: Consolidated from database_manager.py, unified_database_manager.py, enhanced_abstraction.py
# Legacy imports maintained for backward compatibility
DatabaseManager = ConsolidatedDatabaseManager  # Alias for backward compatibility

# Database configuration and types
# Import database models and schemas
# Import database utilities
__version__ = "3.0.0"
__all__ = [
    # Consolidated database management (SINGLE SOURCE OF TRUTH)
    "ConsolidatedDatabaseManager",
    "database_manager",
    "DatabaseManager",  # Backward compatibility alias

    # Database configuration and types
    "DatabaseConfig",
    "DatabaseType",
    "DatabaseRole",
    "DatabaseMetrics",
    "ConnectionStatus",

    # Initialization functions
    "initialize_database_system",
    "get_database_manager",

    # Legacy functions
    "initialize_database_system_legacy",
    "shutdown_database_system",
    "get_session",
    "execute_query",
    "get_database_health",
    "backup_database",
    "restore_database"
]

# Database system constants
DATABASE_SYSTEM_VERSION = "3.0.0"
SUPPORTED_DATABASES = ["postgresql", "mysql", "sqlite", "mongodb"]
ENCRYPTION_REQUIRED = True
CLUSTERING_ENABLED = True
MONITORING_ENABLED = True

# Default database configuration
DEFAULT_DATABASE_CONFIG = {
    "type": "sqlite",
    "encryption": {
        "enabled": True,
        "algorithm": "AES-256-GCM",
        "key_rotation_hours": 24
    },
    "connection_pool": {
        "min_connections": 5,
        "max_connections": 50,
        "connection_timeout": 30,
        "idle_timeout": 300
    },
    "clustering": {
        "enabled": False,
        "auto_failover": True,
        "health_check_interval": 30,
        "replica_lag_threshold": 1000
    },
    "monitoring": {
        "enabled": True,
        "metrics_collection": True,
        "performance_tracking": True,
        "alert_thresholds": {
            "connection_usage": 0.8,
            "query_time": 5.0,
            "error_rate": 0.05
        }
    },
    "backup": {
        "enabled": True,
        "automatic_backups": True,
        "backup_interval_hours": 6,
        "retention_days": 30
    }
}

# Database feature matrix
DATABASE_FEATURES = {
    "postgresql": {
        "transactions": True,
        "json_support": True,
        "full_text_search": True,
        "arrays": True,
        "clustering": True,
        "encryption": True,
        "async_support": True
    },
    "mysql": {
        "transactions": True,
        "json_support": True,
        "full_text_search": True,
        "arrays": False,
        "clustering": True,
        "encryption": True,
        "async_support": True
    },
    "sqlite": {
        "transactions": True,
        "json_support": True,
        "full_text_search": True,
        "arrays": False,
        "clustering": False,
        "encryption": True,
        "async_support": False
    },
    "mongodb": {
        "transactions": True,
        "json_support": True,
        "full_text_search": True,
        "arrays": True,
        "clustering": True,
        "encryption": True,
        "async_support": True
    }
}

# Legacy compatibility functions
async def initialize_database_system_legacy(config: Optional[dict] = None) -> bool:
    """Legacy database initialization function."""
    try:
        return await initialize_database_system(config or {})
    except Exception as e:
        import logging
        logging.error(f"Legacy database initialization failed: {e}")
        return False

async def shutdown_database_system():
    """Legacy database shutdown function."""
    try:
        if database_manager:
            await database_manager.shutdown()
    except Exception as e:
        import logging
        logging.error(f"Legacy database shutdown failed: {e}")

async def get_session(role: str = "primary", read_only: bool = False):
    """Legacy session getter."""
    if database_manager:
        return await database_manager.get_session(role, read_only)
    return None

async def execute_query(query: str, params: Optional[dict] = None, role: str = "primary"):
    """Legacy query executor."""
    if database_manager:
        return await database_manager.execute_query(query, params or {}, role)
    return None

async def get_database_health():
    """Legacy health checker."""
    if database_manager:
        return await database_manager.get_health()
    return {"status": "unknown"}

async def backup_database(backup_name: Optional[str] = None):
    """Legacy backup function."""
    if database_manager:
        return await database_manager.backup(backup_name)
    return False

async def restore_database(backup_name: str):
    """Legacy restore function."""
    if database_manager:
        return await database_manager.restore(backup_name)
    return False
