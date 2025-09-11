"""
Database Migration: Add New Schemas

This migration adds the new schemas for client settings, plugin permissions,
cluster nodes, and backup metadata with proper indexing and constraints.
"""

import asyncio
import logging
from typing import Any

from plexichat.core.database.manager import database_manager
from plexichat.core.database.models import (
    BACKUP_METADATA_SCHEMA,
    CLIENT_SETTINGS_SCHEMA,
    CLUSTER_NODES_SCHEMA,
    PLUGIN_PERMISSIONS_SCHEMA,
)

from .base import Migration

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
        (
            "idx_client_settings_user_key",
            ["user_id", "setting_key"],
            True,
        ),  # Unique composite
        ("idx_client_settings_created_at", ["created_at"]),
        ("idx_client_settings_size", ["size_bytes"]),
    ],
    "plugin_permissions": [
        ("idx_plugin_permissions_plugin_id", ["plugin_id"]),
        ("idx_plugin_permissions_permission", ["permission"]),
        ("idx_plugin_permissions_approved", ["is_approved"]),
        (
            "idx_plugin_permissions_plugin_perm",
            ["plugin_id", "permission"],
            True,
        ),  # Unique composite
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
        (
            "fk_plugin_permissions_plugin_id",
            "plugin_id",
            "plugins",
            "id",
            "CASCADE",
            "CASCADE",
        ),
    ],
    "backup_metadata": [
        (
            "fk_backup_metadata_node_id",
            "node_id",
            "cluster_nodes",
            "node_id",
            "SET NULL",
            "CASCADE",
        ),
    ],
}

# Check constraints for data validation
CHECK_CONSTRAINTS = {
    "client_settings": [
        (
            "chk_client_settings_value_type",
            "value_type IN ('json', 'string', 'number', 'boolean', 'binary')",
        ),
        ("chk_client_settings_size_positive", "size_bytes >= 0"),
        ("chk_client_settings_key_not_empty", "LENGTH(setting_key) > 0"),
    ],
    "plugin_permissions": [
        ("chk_plugin_permissions_permission_not_empty", "LENGTH(permission) > 0"),
        (
            "chk_plugin_permissions_approval_logic",
            "(is_approved = FALSE AND approved_by IS NULL AND approved_at IS NULL) OR "
            "(is_approved = TRUE AND approved_by IS NOT NULL AND approved_at IS NOT NULL)",
        ),
    ],
    "cluster_nodes": [
        (
            "chk_cluster_nodes_node_type",
            "node_type IN ('networking', 'endpoint', 'general', 'backup', 'compute')",
        ),
        (
            "chk_cluster_nodes_status",
            "status IN ('online', 'offline', 'maintenance', 'error', 'starting', 'stopping')",
        ),
        (
            "chk_cluster_nodes_port_range",
            "port IS NULL OR (port > 0 AND port <= 65535)",
        ),
    ],
    "backup_metadata": [
        (
            "chk_backup_metadata_status",
            "status IN ('pending', 'running', 'completed', 'failed', 'cancelled', 'verifying')",
        ),
        (
            "chk_backup_metadata_type",
            "backup_type IN ('full', 'incremental', 'differential', 'snapshot')",
        ),
        ("chk_backup_metadata_size_positive", "size_bytes >= 0"),
        ("chk_backup_metadata_retention_positive", "retention_days > 0"),
        (
            "chk_backup_metadata_completion_logic",
            "(status = 'completed' AND completed_at IS NOT NULL) OR "
            "(status != 'completed' AND (completed_at IS NULL OR completed_at >= started_at))",
        ),
    ],
}


async def create_migration_tracking_table():
    """Create table to track applied migrations."""
    migration_schema = {
        "id": "TEXT PRIMARY KEY",
        "version": "TEXT UNIQUE NOT NULL",
        "description": "TEXT",
        "applied_at": "TEXT NOT NULL",
        "rollback_sql": "TEXT",
        "checksum": "TEXT",
        "metadata": "TEXT DEFAULT '{}'",
    }

    success = await database_manager.ensure_table_exists(
        "schema_migrations", migration_schema
    )
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


class AddNewSchemasMigration(Migration):
    MIGRATION_VERSION = "001_add_new_schemas"
    MIGRATION_DESCRIPTION = "Add client settings, plugin permissions, cluster nodes, and backup metadata schemas"

    def _get_tables(self) -> dict[str, dict[str, Any]]:
        def convert_schema(schema_dict: dict[str, str]) -> dict[str, Any]:
            columns = []
            unique_constraints = []
            for col, dtype_str in schema_dict.items():
                parts = dtype_str.split()
                col_type = parts[0]
                nullable = "NOT NULL" not in parts
                pk = "PRIMARY KEY" in parts
                default = None
                if "DEFAULT" in parts:
                    default_idx = parts.index("DEFAULT")
                    if default_idx + 1 < len(parts):
                        default = parts[default_idx + 1].strip("'\"")
                columns.append((col, col_type, nullable, default, pk))
            # Add unique constraints from INDEXES where unique=True
            table_name = list(NEW_TABLES.keys())[
                list(NEW_TABLES.values()).index(schema_dict)
            ]
            for idx_name, cols, is_unique in INDEXES.get(table_name, []):
                if is_unique:
                    unique_constraints.append(cols)
            return {"columns": columns, "unique_constraints": unique_constraints}

        tables = {}
        for table, schema in NEW_TABLES.items():
            tables[table] = convert_schema(schema)
        return tables

    def _get_indexes(self) -> dict[str, list[tuple[str, list[str], bool]]]:
        return INDEXES

    def _get_foreign_keys(self) -> dict[str, list[tuple[str, str, str, str, str, str]]]:
        return FOREIGN_KEYS

    def _get_check_constraints(self) -> dict[str, list[tuple[str, str]]]:
        return CHECK_CONSTRAINTS

    async def up(self):
        await super().up()

    async def down(self):
        await super().down()


# CLI interface functions
async def main():
    """Main function for running migration from command line."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python add_new_schemas.py [up|down|verify]")
        sys.exit(1)

    command = sys.argv[1].lower()
    migration = AddNewSchemasMigration()

    if command == "up":
        success = await migration.up()
        sys.exit(0 if success else 1)
    elif command == "down":
        success = await migration.down()
        sys.exit(0 if success else 1)
    elif command == "verify":
        success = await migration.verify()
        sys.exit(0 if success else 1)
    else:
        print("Invalid command. Use: up, down, or verify")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
