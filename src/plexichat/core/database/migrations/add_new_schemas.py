"""
Database Migration: Add New Schemas

This migration adds the new schemas for client settings, plugin permissions,
cluster nodes, and backup metadata with proper indexing and constraints.
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from plexichat.core.database.manager import database_manager
from plexichat.core.database.models import (
    CLIENT_SETTINGS_SCHEMA,
    PLUGIN_PERMISSIONS_SCHEMA,
    CLUSTER_NODES_SCHEMA,
    BACKUP_METADATA_SCHEMA
)

logger = logging.getLogger(__name__)

# Migration metadata
MIGRATION_VERSION = "001_add_new_schemas"
MIGRATION_DATE = "2024-01-01"
MIGRATION_DESCRIPTION = "Add client settings, plugin permissions, cluster nodes, and backup metadata schemas"

# Tables to be created in this migration
NEW_TABLES = {
    "client_settings": CLIENT_SETTINGS_SCHEMA,
    "plugin_permissions": PLUGIN_PERMISSIONS_SCHEMA,
    "cluster_nodes": CLUSTER_NODES_SCHEMA,
    "backup_metadata": BACKUP_METADATA_SCHEMA,
}

# Indexes for performance optimization
INDEXES = {
    "client_settings": [
        ("idx_client_settings_user_id", ["user_id"]),
        ("idx_client_settings_user_key", ["user_id", "setting_key"], True),  # Unique composite
        ("idx_client_settings_created_at", ["created_at"]),
        ("idx_client_settings_size", ["size_bytes"]),
    ],
    "plugin_permissions": [
        ("idx_plugin_permissions_plugin_id", ["plugin_id"]),
        ("idx_plugin_permissions_permission", ["permission"]),
        ("idx_plugin_permissions_approved", ["is_approved"]),
        ("idx_plugin_permissions_plugin_perm", ["plugin_id", "permission"], True),  # Unique composite
        ("idx_plugin_permissions_requested_at", ["requested_at"]),
    ],
    "cluster_nodes": [
        ("idx_cluster_nodes_node_id", ["node_id"], True),  # Unique
        ("idx_cluster_nodes_hostname", ["hostname"]),
        ("idx_cluster_nodes_ip_address", ["ip_address"]),
        ("idx_cluster_nodes_status", ["status"]),
        ("idx_cluster_nodes_type", ["node_type"]),
        ("idx_cluster_nodes_leader", ["is_leader"]),
        ("idx_cluster_nodes_heartbeat", ["last_heartbeat"]),
    ],
    "backup_metadata": [
        ("idx_backup_metadata_backup_id", ["backup_id"], True),  # Unique
        ("idx_backup_metadata_node_id", ["node_id"]),
        ("idx_backup_metadata_status", ["status"]),
        ("idx_backup_metadata_type", ["backup_type"]),
        ("idx_backup_metadata_started_at", ["started_at"]),
        ("idx_backup_metadata_completed_at", ["completed_at"]),
        ("idx_backup_metadata_retention", ["retention_days"]),
        ("idx_backup_metadata_verified", ["verified"]),
    ],
}

# Foreign key constraints
FOREIGN_KEYS = {
    "client_settings": [
        ("fk_client_settings_user_id", "user_id", "users", "id", "CASCADE", "CASCADE"),
    ],
    "plugin_permissions": [
        ("fk_plugin_permissions_plugin_id", "plugin_id", "plugins", "id", "CASCADE", "CASCADE"),
    ],
    "backup_metadata": [
        ("fk_backup_metadata_node_id", "node_id", "cluster_nodes", "node_id", "SET NULL", "CASCADE"),
    ],
}

# Check constraints for data validation
CHECK_CONSTRAINTS = {
    "client_settings": [
        ("chk_client_settings_value_type", "value_type IN ('json', 'string', 'number', 'boolean', 'binary')"),
        ("chk_client_settings_size_positive", "size_bytes >= 0"),
        ("chk_client_settings_key_not_empty", "LENGTH(setting_key) > 0"),
    ],
    "plugin_permissions": [
        ("chk_plugin_permissions_permission_not_empty", "LENGTH(permission) > 0"),
        ("chk_plugin_permissions_approval_logic", 
         "(is_approved = FALSE AND approved_by IS NULL AND approved_at IS NULL) OR "
         "(is_approved = TRUE AND approved_by IS NOT NULL AND approved_at IS NOT NULL)"),
    ],
    "cluster_nodes": [
        ("chk_cluster_nodes_node_type", "node_type IN ('networking', 'endpoint', 'general', 'backup', 'compute')"),
        ("chk_cluster_nodes_status", "status IN ('online', 'offline', 'maintenance', 'error', 'starting', 'stopping')"),
        ("chk_cluster_nodes_port_range", "port IS NULL OR (port > 0 AND port <= 65535)"),
    ],
    "backup_metadata": [
        ("chk_backup_metadata_status", "status IN ('pending', 'running', 'completed', 'failed', 'cancelled', 'verifying')"),
        ("chk_backup_metadata_type", "backup_type IN ('full', 'incremental', 'differential', 'snapshot')"),
        ("chk_backup_metadata_size_positive", "size_bytes >= 0"),
        ("chk_backup_metadata_retention_positive", "retention_days > 0"),
        ("chk_backup_metadata_completion_logic",
         "(status = 'completed' AND completed_at IS NOT NULL) OR "
         "(status != 'completed' AND (completed_at IS NULL OR completed_at >= started_at))"),
    ],
}


class MigrationError(Exception):
    """Custom exception for migration errors."""
    pass


async def create_migration_tracking_table():
    """Create table to track applied migrations."""
    migration_schema = {
        "id": "TEXT PRIMARY KEY",
        "version": "TEXT UNIQUE NOT NULL",
        "description": "TEXT",
        "applied_at": "TEXT NOT NULL",
        "rollback_sql": "TEXT",
        "checksum": "TEXT",
        "metadata": "TEXT DEFAULT '{}'"
    }
    
    success = await database_manager.ensure_table_exists("schema_migrations", migration_schema)
    if not success:
        raise MigrationError("Failed to create migration tracking table")
    
    # Create index on version for fast lookups
    async with database_manager.get_session() as session:
        try:
            await session.execute(
                "CREATE INDEX IF NOT EXISTS idx_schema_migrations_version ON schema_migrations(version)"
            )
            await session.commit()
        except Exception as e:
            logger.warning(f"Could not create migration index: {e}")


async def is_migration_applied(version: str) -> bool:
    """Check if a migration has already been applied."""
    try:
        async with database_manager.get_session() as session:
            result = await session.fetchone(
                "SELECT version FROM schema_migrations WHERE version = :version",
                {"version": version}
            )
            return result is not None
    except Exception:
        # If table doesn't exist or query fails, assume migration not applied
        return False


async def record_migration(version: str, description: str, rollback_sql: str):
    """Record that a migration has been applied."""
    async with database_manager.get_session() as session:
        await session.insert("schema_migrations", {
            "id": f"migration_{version}_{int(datetime.now(timezone.utc).timestamp())}",
            "version": version,
            "description": description,
            "applied_at": datetime.now(timezone.utc).isoformat(),
            "rollback_sql": rollback_sql,
            "metadata": "{}"
        })
        await session.commit()


async def create_table_with_constraints(table_name: str, schema: Dict[str, str]) -> List[str]:
    """Create table with all constraints and return rollback SQL."""
    rollback_statements = []
    
    async with database_manager.get_session() as session:
        try:
            # Create the base table
            columns = ", ".join([f"{col} {dtype}" for col, dtype in schema.items()])
            create_query = f"CREATE TABLE {table_name} ({columns})"
            await session.execute(create_query)
            rollback_statements.append(f"DROP TABLE IF EXISTS {table_name}")
            
            logger.info(f"Created table: {table_name}")
            
            # Add indexes
            if table_name in INDEXES:
                for index_name, columns, *unique in INDEXES[table_name]:
                    is_unique = unique[0] if unique else False
                    unique_clause = "UNIQUE " if is_unique else ""
                    columns_str = ", ".join(columns)
                    
                    index_query = f"CREATE {unique_clause}INDEX {index_name} ON {table_name}({columns_str})"
                    await session.execute(index_query)
                    rollback_statements.append(f"DROP INDEX IF EXISTS {index_name}")
                    
                    logger.info(f"Created index: {index_name}")
            
            # Add foreign key constraints (if supported by database)
            if table_name in FOREIGN_KEYS:
                for fk_name, local_col, ref_table, ref_col, on_delete, on_update in FOREIGN_KEYS[table_name]:
                    try:
                        # Note: SQLite has limited FK support, PostgreSQL/MySQL have full support
                        if database_manager.config.db_type != "sqlite":
                            fk_query = (
                                f"ALTER TABLE {table_name} ADD CONSTRAINT {fk_name} "
                                f"FOREIGN KEY ({local_col}) REFERENCES {ref_table}({ref_col}) "
                                f"ON DELETE {on_delete} ON UPDATE {on_update}"
                            )
                            await session.execute(fk_query)
                            rollback_statements.append(f"ALTER TABLE {table_name} DROP CONSTRAINT {fk_name}")
                            logger.info(f"Added foreign key: {fk_name}")
                    except Exception as e:
                        logger.warning(f"Could not add foreign key {fk_name}: {e}")
            
            # Add check constraints (if supported)
            if table_name in CHECK_CONSTRAINTS:
                for check_name, check_condition in CHECK_CONSTRAINTS[table_name]:
                    try:
                        if database_manager.config.db_type != "sqlite":
                            check_query = f"ALTER TABLE {table_name} ADD CONSTRAINT {check_name} CHECK ({check_condition})"
                            await session.execute(check_query)
                            rollback_statements.append(f"ALTER TABLE {table_name} DROP CONSTRAINT {check_name}")
                            logger.info(f"Added check constraint: {check_name}")
                    except Exception as e:
                        logger.warning(f"Could not add check constraint {check_name}: {e}")
            
            await session.commit()
            return rollback_statements
            
        except Exception as e:
            await session.rollback()
            logger.error(f"Failed to create table {table_name}: {e}")
            raise MigrationError(f"Failed to create table {table_name}: {e}")


async def validate_table_data(table_name: str) -> bool:
    """Validate data in newly created table."""
    try:
        async with database_manager.get_session() as session:
            # Check table exists and is accessible
            count_result = await session.fetchone(f"SELECT COUNT(*) as count FROM {table_name}")
            count = count_result['count'] if count_result else 0
            
            logger.info(f"Table {table_name} validated successfully with {count} rows")
            return True
            
    except Exception as e:
        logger.error(f"Table validation failed for {table_name}: {e}")
        return False


async def run_migration() -> bool:
    """Run the migration to add new schemas."""
    try:
        # Initialize database manager
        if not await database_manager.initialize():
            raise MigrationError("Failed to initialize database manager")
        
        # Create migration tracking table
        await create_migration_tracking_table()
        
        # Check if migration already applied
        if await is_migration_applied(MIGRATION_VERSION):
            logger.info(f"Migration {MIGRATION_VERSION} already applied, skipping")
            return True
        
        logger.info(f"Starting migration: {MIGRATION_VERSION}")
        
        all_rollback_statements = []
        
        # Create each new table with constraints
        for table_name, schema in NEW_TABLES.items():
            logger.info(f"Creating table: {table_name}")
            
            # Check if table already exists
            async with database_manager.get_session() as session:
                if database_manager.config.db_type == "sqlite":
                    check_query = "SELECT name FROM sqlite_master WHERE type='table' AND name=:name"
                else:
                    check_query = "SELECT table_name FROM information_schema.tables WHERE table_name = :name"
                
                existing = await session.fetchone(check_query, {"name": table_name})
                
                if existing:
                    logger.warning(f"Table {table_name} already exists, skipping creation")
                    continue
            
            rollback_statements = await create_table_with_constraints(table_name, schema)
            all_rollback_statements.extend(rollback_statements)
            
            # Validate the created table
            if not await validate_table_data(table_name):
                raise MigrationError(f"Table validation failed for {table_name}")
        
        # Record successful migration
        rollback_sql = "; ".join(reversed(all_rollback_statements))
        await record_migration(MIGRATION_VERSION, MIGRATION_DESCRIPTION, rollback_sql)
        
        logger.info(f"Migration {MIGRATION_VERSION} completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        return False


async def rollback_migration() -> bool:
    """Rollback the migration."""
    try:
        # Check if migration was applied
        if not await is_migration_applied(MIGRATION_VERSION):
            logger.info(f"Migration {MIGRATION_VERSION} not applied, nothing to rollback")
            return True
        
        logger.info(f"Rolling back migration: {MIGRATION_VERSION}")
        
        async with database_manager.get_session() as session:
            # Get rollback SQL
            result = await session.fetchone(
                "SELECT rollback_sql FROM schema_migrations WHERE version = :version",
                {"version": MIGRATION_VERSION}
            )
            
            if not result or not result['rollback_sql']:
                logger.error("No rollback SQL found for migration")
                return False
            
            rollback_sql = result['rollback_sql']
            
            # Execute rollback statements
            for statement in rollback_sql.split(';'):
                statement = statement.strip()
                if statement:
                    try:
                        await session.execute(statement)
                        logger.info(f"Executed rollback: {statement}")
                    except Exception as e:
                        logger.warning(f"Rollback statement failed (may be expected): {statement} - {e}")
            
            # Remove migration record
            await session.delete("schema_migrations", {"version": MIGRATION_VERSION})
            await session.commit()
        
        logger.info(f"Migration {MIGRATION_VERSION} rolled back successfully")
        return True
        
    except Exception as e:
        logger.error(f"Rollback failed: {e}")
        return False


async def verify_migration() -> bool:
    """Verify that the migration was applied correctly."""
    try:
        logger.info("Verifying migration...")
        
        # Check that all tables exist
        for table_name in NEW_TABLES.keys():
            async with database_manager.get_session() as session:
                if database_manager.config.db_type == "sqlite":
                    check_query = "SELECT name FROM sqlite_master WHERE type='table' AND name=:name"
                else:
                    check_query = "SELECT table_name FROM information_schema.tables WHERE table_name = :name"
                
                result = await session.fetchone(check_query, {"name": table_name})
                if not result:
                    logger.error(f"Table {table_name} not found after migration")
                    return False
        
        # Check that indexes exist
        for table_name, indexes in INDEXES.items():
            for index_name, _, *_ in indexes:
                async with database_manager.get_session() as session:
                    try:
                        if database_manager.config.db_type == "sqlite":
                            check_query = "SELECT name FROM sqlite_master WHERE type='index' AND name=:name"
                        else:
                            check_query = "SELECT indexname FROM pg_indexes WHERE indexname = :name"
                        
                        result = await session.fetchone(check_query, {"name": index_name})
                        if not result:
                            logger.warning(f"Index {index_name} not found (may not be supported)")
                    except Exception as e:
                        logger.warning(f"Could not verify index {index_name}: {e}")
        
        # Verify migration is recorded
        if not await is_migration_applied(MIGRATION_VERSION):
            logger.error("Migration not recorded in schema_migrations table")
            return False
        
        logger.info("Migration verification completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Migration verification failed: {e}")
        return False


# CLI interface functions
async def main():
    """Main function for running migration from command line."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python add_new_schemas.py [up|down|verify]")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == "up":
        success = await run_migration()
        sys.exit(0 if success else 1)
    elif command == "down":
        success = await rollback_migration()
        sys.exit(0 if success else 1)
    elif command == "verify":
        success = await verify_migration()
        sys.exit(0 if success else 1)
    else:
        print("Invalid command. Use: up, down, or verify")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
