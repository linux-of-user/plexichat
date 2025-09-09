"""
Database migration for plugin permission management.

This migration adds tables for:
- Plugin permissions management
- Plugin audit logging
- Plugin settings and configuration
- Plugin approved modules
- Client settings storage

Migration ID: 001_add_plugin_permissions
Created: 2024-01-01
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)
from .base import Migration


class AddPluginPermissionsMigration(Migration):
    MIGRATION_VERSION = "001_add_plugin_permissions"
    MIGRATION_DESCRIPTION = "Add Plugin Permissions"

    def _get_tables(self) -> Dict[str, Dict[str, Any]]:
        # Extract and convert dialect-specific schemas to base format
        tables = {}
        # plugin_permissions from model
        plugin_permissions_schema = PLUGIN_PERMISSIONS_SCHEMA

        def convert_schema(schema_dict: Dict[str, str]) -> Dict[str, Any]:
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
            return {"columns": columns, "unique_constraints": unique_constraints}

        tables["plugin_permissions"] = convert_schema(plugin_permissions_schema)
        # client_settings from model
        tables["client_settings"] = convert_schema(CLIENT_SETTINGS_SCHEMA)
        # plugin_audit_events (extracted from old CREATE)
        tables["plugin_audit_events"] = {
            "columns": [
                ("id", "INTEGER", False, None, True),
                ("event_id", "TEXT", False, None, False),
                ("plugin_name", "TEXT", False, None, False),
                ("event_type", "TEXT", False, None, False),
                ("threat_level", "TEXT", False, None, False),
                ("description", "TEXT", False, None, False),
                ("timestamp", "TIMESTAMP", False, None, False),
                ("details", "TEXT", True, None, False),
                ("resolved", "BOOLEAN", True, "FALSE", False),
                ("resolved_by", "TEXT", True, None, False),
                ("resolved_at", "TIMESTAMP", True, None, False),
                ("created_at", "TIMESTAMP", False, "CURRENT_TIMESTAMP", False),
            ],
            "unique_constraints": [["event_id"]],
        }
        # plugin_settings
        tables["plugin_settings"] = {
            "columns": [
                ("id", "INTEGER", False, None, True),
                ("plugin_name", "TEXT", False, None, False),
                ("is_enabled", "BOOLEAN", True, "FALSE", False),
                ("is_quarantined", "BOOLEAN", True, "FALSE", False),
                ("configuration", "TEXT", True, None, False),
                ("security_policy", "TEXT", True, None, False),
                ("last_enabled_at", "TIMESTAMP", True, None, False),
                ("last_disabled_at", "TIMESTAMP", True, None, False),
                ("enabled_by", "TEXT", True, None, False),
                ("disabled_by", "TEXT", True, None, False),
                ("quarantine_reason", "TEXT", True, None, False),
                ("quarantined_by", "TEXT", True, None, False),
                ("quarantined_at", "TIMESTAMP", True, None, False),
                ("created_at", "TIMESTAMP", False, "CURRENT_TIMESTAMP", False),
                ("updated_at", "TIMESTAMP", False, "CURRENT_TIMESTAMP", False),
            ],
            "unique_constraints": [["plugin_name"]],
        }
        # plugin_approved_modules
        tables["plugin_approved_modules"] = {
            "columns": [
                ("id", "INTEGER", False, None, True),
                ("plugin_name", "TEXT", False, None, False),
                ("module_name", "TEXT", False, None, False),
                ("approved_by", "TEXT", False, None, False),
                ("approved_at", "TIMESTAMP", False, None, False),
                ("expires_at", "TIMESTAMP", True, None, False),
                ("is_active", "BOOLEAN", True, "TRUE", False),
                ("created_at", "TIMESTAMP", False, "CURRENT_TIMESTAMP", False),
            ],
            "unique_constraints": [["plugin_name", "module_name"]],
        }
        return tables

    def _get_indexes(self) -> Dict[str, List[Tuple[str, List[str], bool]]]:
        indexes = {
            "plugin_permissions": [
                ("idx_plugin_permissions_plugin_name", ["plugin_name"], False),
                ("idx_plugin_permissions_status", ["status"], False),
                ("idx_plugin_permissions_approved_by", ["approved_by"], False),
                ("idx_plugin_permissions_expires", ["expires_at"], False),
                ("idx_plugin_permissions_requested", ["requested_at"], False),
            ],
            "plugin_audit_events": [
                ("idx_plugin_audit_events_plugin_name", ["plugin_name"], False),
                ("idx_plugin_audit_events_timestamp", ["timestamp"], False),
                ("idx_plugin_audit_events_event_type", ["event_type"], False),
                ("idx_plugin_audit_events_threat_level", ["threat_level"], False),
                ("idx_plugin_audit_events_resolved", ["resolved"], False),
            ],
            "plugin_settings": [
                ("idx_plugin_settings_enabled", ["is_enabled"], False),
                ("idx_plugin_settings_quarantined", ["is_quarantined"], False),
                ("idx_plugin_settings_updated", ["updated_at"], False),
            ],
            "plugin_approved_modules": [
                ("idx_plugin_approved_modules_plugin", ["plugin_name"], False),
                ("idx_plugin_approved_modules_active", ["is_active"], False),
                ("idx_plugin_approved_modules_expires", ["expires_at"], False),
            ],
            "client_settings": [
                ("idx_client_settings_user_id", ["user_id"], False),
                ("idx_client_settings_type", ["setting_type"], False),
                ("idx_client_settings_updated", ["updated_at"], False),
            ],
        }
        return indexes

    def _get_foreign_keys(self) -> Dict[str, List[Tuple[str, str, str, str, str, str]]]:
        return {}  # No FKs in this migration

    def _get_check_constraints(self) -> Dict[str, List[Tuple[str, str]]]:
        return {}  # No check constraints in this migration

    async def up(self):
        await super().up()

    async def down(self):
        await super().down()


async def apply_migration(database_manager) -> bool:
    """Apply the plugin permissions migration."""
    migration = PluginPermissionsMigration(database_manager)

    # Check if already applied
    if await migration.is_applied():
        logger.info(f"Migration {migration.MIGRATION_NAME} already applied, skipping")
        return True

    # Apply the migration
    return await migration.upgrade()


async def rollback_migration(database_manager) -> bool:
    """Rollback the plugin permissions migration."""
    migration = PluginPermissionsMigration(database_manager)

    # Check if applied
    if not await migration.is_applied():
        logger.info(
            f"Migration {migration.MIGRATION_NAME} not applied, nothing to rollback"
        )
        return True

    # Rollback the migration
    return await migration.downgrade()


# Convenience functions for direct usage
async def run_upgrade(database_manager):
    """Run the upgrade migration."""
    return await apply_migration(database_manager)


async def run_downgrade(database_manager):
    """Run the downgrade migration."""
    return await rollback_migration(database_manager)


if __name__ == "__main__":
    # Allow running migration directly for testing
    import os
    import sys

    # Add parent directory to path for imports
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../.."))

    from plexichat.core.database.manager import database_manager

    async def main():
        """Main function for direct execution."""
        if len(sys.argv) > 1 and sys.argv[1] == "downgrade":
            success = await rollback_migration(database_manager)
            print(f"Migration rollback {'succeeded' if success else 'failed'}")
        else:
            success = await apply_migration(database_manager)
            print(f"Migration {'succeeded' if success else 'failed'}")

    asyncio.run(main())
