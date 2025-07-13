"""
PlexiChat Core Database System - Unified Database Management

Consolidates all database components into a single, comprehensive module
with multi-backend support, encryption, clustering, and advanced features.

This unified system replaces and consolidates:
- src/plexichat/app/db/
- src/plexichat/app/core/database/
- src/plexichat/core/external_database.py

Features:
- Multi-database engine support (PostgreSQL, MySQL, SQLite, MongoDB)
- Database clustering with automatic failover and load balancing
- Encrypted database connections and data-at-rest encryption
- Advanced migration system with rollback capabilities
- Connection pooling and performance optimization
- External database hosting support (AWS RDS, Google Cloud SQL, etc.)
- Real-time monitoring and health checks
- Backup and recovery integration
"""

# Import consolidated database components
from .manager_database import (  # <-- Add this line
    ConsolidatedDatabaseManager, database_manager, DatabaseType, DatabaseRole,
    DatabaseConfig, DatabaseMetrics, ConnectionStatus, initialize_database_system,
    get_database_manager
)
# Note: Consolidated from database_manager.py, unified_database_manager.py, enhanced_abstraction.py
# Legacy imports maintained for backward compatibility
DatabaseManager = ConsolidatedDatabaseManager  # Alias for backward compatibility

# Import database models and schemas
from .models import *
from .schemas import *

# Import database utilities
from .utils import DatabaseUtils, db_utils
from .backup_integration import DatabaseBackupIntegration, db_backup
from .monitor import DatabaseMonitor, database_monitor  # <-- Add this line
from .migration import MigrationManager, migration_manager  # <-- Add this line
from .cluster import DatabaseCluster, db_cluster  # <-- Add this line

# Database configuration and types
from .config import DatabaseConfig, DatabaseType, DatabaseRole, DatabaseProvider
from .exceptions import DatabaseError, ConnectionError, MigrationError, EncryptionError

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
    
    # Exceptions
    "DatabaseError",
    "ConnectionError",
    "MigrationError",
    "EncryptionError"
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

# External database providers
EXTERNAL_PROVIDERS = {
    "aws_rds": {
        "name": "Amazon RDS",
        "supported_engines": ["postgresql", "mysql"],
        "features": ["clustering", "encryption", "backup", "monitoring"],
        "connection_string_format": "postgresql://{user}:{password}@{host}:{port}/{database}"
    },
    "google_cloud_sql": {
        "name": "Google Cloud SQL",
        "supported_engines": ["postgresql", "mysql"],
        "features": ["clustering", "encryption", "backup", "monitoring"],
        "connection_string_format": "postgresql://{user}:{password}@{host}:{port}/{database}"
    },
    "azure_database": {
        "name": "Azure Database",
        "supported_engines": ["postgresql", "mysql"],
        "features": ["clustering", "encryption", "backup", "monitoring"],
        "connection_string_format": "postgresql://{user}:{password}@{host}:{port}/{database}"
    },
    "supabase": {
        "name": "Supabase",
        "supported_engines": ["postgresql"],
        "features": ["clustering", "encryption", "backup", "monitoring", "realtime"],
        "connection_string_format": "postgresql://{user}:{password}@{host}:{port}/{database}"
    },
    "planetscale": {
        "name": "PlanetScale",
        "supported_engines": ["mysql"],
        "features": ["clustering", "encryption", "backup", "monitoring", "branching"],
        "connection_string_format": "mysql://{user}:{password}@{host}:{port}/{database}"
    }
}

# Database security levels
SECURITY_LEVELS = {
    "BASIC": {
        "encryption_at_rest": False,
        "encryption_in_transit": True,
        "connection_encryption": True,
        "audit_logging": False
    },
    "ENHANCED": {
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "connection_encryption": True,
        "audit_logging": True
    },
    "GOVERNMENT": {
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "connection_encryption": True,
        "audit_logging": True,
        "field_level_encryption": True,
        "key_rotation": True
    },
    "MILITARY": {
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "connection_encryption": True,
        "audit_logging": True,
        "field_level_encryption": True,
        "key_rotation": True,
        "quantum_resistant": True,
        "zero_knowledge": True
    }
}

# Default security level
DEFAULT_SECURITY_LEVEL = "GOVERNMENT"

# Performance optimization settings
PERFORMANCE_SETTINGS = {
    "query_optimization": {
        "enable_query_cache": True,
        "cache_size_mb": 256,
        "cache_ttl_seconds": 300,
        "enable_prepared_statements": True
    },
    "connection_optimization": {
        "enable_connection_pooling": True,
        "pool_pre_ping": True,
        "pool_recycle_seconds": 3600,
        "enable_connection_validation": True
    },
    "index_optimization": {
        "auto_create_indexes": True,
        "analyze_query_patterns": True,
        "suggest_missing_indexes": True,
        "monitor_index_usage": True
    }
}

# Monitoring and alerting configuration
MONITORING_CONFIG = {
    "metrics": {
        "connection_count": True,
        "query_performance": True,
        "error_rates": True,
        "throughput": True,
        "latency": True,
        "resource_usage": True
    },
    "alerts": {
        "high_connection_usage": {
            "threshold": 0.8,
            "severity": "warning"
        },
        "slow_queries": {
            "threshold": 5.0,
            "severity": "warning"
        },
        "high_error_rate": {
            "threshold": 0.05,
            "severity": "critical"
        },
        "connection_failures": {
            "threshold": 3,
            "severity": "critical"
        }
    },
    "reporting": {
        "daily_reports": True,
        "weekly_summaries": True,
        "performance_trends": True,
        "capacity_planning": True
    }
}

# Migration system configuration
MIGRATION_CONFIG = {
    "auto_migrate": False,
    "backup_before_migration": True,
    "rollback_on_failure": True,
    "validate_migrations": True,
    "migration_timeout_seconds": 300,
    "concurrent_migrations": False
}

# Backup integration configuration
BACKUP_CONFIG = {
    "integration_enabled": True,
    "backup_database_schema": True,
    "backup_database_data": True,
    "backup_encryption": True,
    "backup_compression": True,
    "backup_verification": True,
    "restore_testing": True
}

# Note: initialize_database_system is now provided by the consolidated manager
# Legacy function maintained for backward compatibility
async def initialize_database_system_legacy(config: dict = None) -> bool:
    """
    Legacy initialization function - use database_manager.initialize() instead.

    Args:
        config: Optional configuration dictionary

    Returns:
        bool: True if initialization successful
    """
    try:
        return await database_manager.initialize(config)
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"❌ Failed to initialize database system: {e}")
        return False

async def shutdown_database_system():
    """Gracefully shutdown the database system."""
    try:
        # Shutdown components in reverse order
        await db_backup.shutdown()
        await database_monitor.shutdown()
        await connection_pool.shutdown()
        # await database_encryption.shutdown()  # Removed: database_encryption is not defined
        await migration_manager.shutdown()
        await db_cluster.shutdown()
        await database_manager.shutdown()
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"❌ Error during database system shutdown: {e}")

# Convenience functions for common operations
async def get_session(role: str = "primary", read_only: bool = False):
    """Get database session with automatic failover."""
    return await db_cluster.get_session(role, read_only)

async def execute_query(query: str, params: dict = None, role: str = "primary"):
    """Execute a database query with automatic failover."""
    return await database_manager.execute_query(query, params, role)

async def get_database_health():
    """Get current database health status."""
    return await database_monitor.get_health_status()

async def backup_database(backup_name: str = None):
    """Trigger database backup."""
    return await db_backup.create_backup(backup_name)

async def restore_database(backup_name: str):
    """Restore database from backup."""
    return await db_backup.restore_backup(backup_name)
