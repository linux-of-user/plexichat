"""
Database migration for plugin permission management.

This migration adds tables for:
- Plugin permissions management
- Plugin audit logging
- Client settings storage

Migration ID: 001_add_plugin_permissions
Created: 2024-01-01
"""

import asyncio
import logging
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class PluginPermissionsMigration:
    """Migration for plugin permissions and related tables."""
    
    MIGRATION_ID = "001_add_plugin_permissions"
    MIGRATION_NAME = "Add Plugin Permissions"
    VERSION = "1.0.0"
    
    def __init__(self, database_manager):
        self.db = database_manager
        self.logger = logging.getLogger(__name__)
    
    async def upgrade(self) -> bool:
        """Apply the migration - create tables and indexes."""
        try:
            self.logger.info(f"Starting migration: {self.MIGRATION_NAME}")
            
            # Create plugin_permissions table
            await self._create_plugin_permissions_table()
            
            # Create plugin_audit table
            await self._create_plugin_audit_table()
            
            # Create client_settings table
            await self._create_client_settings_table()
            
            # Create indexes for performance
            await self._create_indexes()
            
            # Record migration in migrations table
            await self._record_migration()
            
            self.logger.info(f"Migration {self.MIGRATION_NAME} completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Migration {self.MIGRATION_NAME} failed: {e}")
            await self.downgrade()  # Attempt rollback
            return False
    
    async def downgrade(self) -> bool:
        """Rollback the migration - drop tables and indexes."""
        try:
            self.logger.info(f"Rolling back migration: {self.MIGRATION_NAME}")
            
            # Drop tables in reverse order (due to foreign keys)
            await self._drop_table("plugin_audit")
            await self._drop_table("plugin_permissions")
            await self._drop_table("client_settings")
            
            # Remove migration record
            await self._remove_migration_record()
            
            self.logger.info(f"Migration {self.MIGRATION_NAME} rolled back successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Migration rollback {self.MIGRATION_NAME} failed: {e}")
            return False
    
    async def _create_plugin_permissions_table(self):
        """Create the plugin_permissions table."""
        if self.db.config.db_type == "sqlite":
            query = """
            CREATE TABLE IF NOT EXISTS plugin_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plugin_id TEXT NOT NULL,
                permission_name TEXT NOT NULL,
                granted_by_user_id TEXT NOT NULL,
                granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(plugin_id, permission_name)
            )
            """
        elif self.db.config.db_type in ["postgresql", "postgres"]:
            query = """
            CREATE TABLE IF NOT EXISTS plugin_permissions (
                id SERIAL PRIMARY KEY,
                plugin_id VARCHAR(255) NOT NULL,
                permission_name VARCHAR(255) NOT NULL,
                granted_by_user_id VARCHAR(255) NOT NULL,
                granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP WITH TIME ZONE NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(plugin_id, permission_name)
            )
            """
        elif self.db.config.db_type == "mysql":
            query = """
            CREATE TABLE IF NOT EXISTS plugin_permissions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                plugin_id VARCHAR(255) NOT NULL,
                permission_name VARCHAR(255) NOT NULL,
                granted_by_user_id VARCHAR(255) NOT NULL,
                granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY unique_plugin_permission (plugin_id, permission_name)
            )
            """
        
        async with self.db.get_session() as session:
            await session.execute(query)
            await session.commit()
        
        self.logger.info("Created plugin_permissions table")
    
    async def _create_plugin_audit_table(self):
        """Create the plugin_audit table."""
        if self.db.config.db_type == "sqlite":
            query = """
            CREATE TABLE IF NOT EXISTS plugin_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plugin_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                user_id TEXT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT NULL,
                ip_address TEXT NULL,
                user_agent TEXT NULL,
                success BOOLEAN DEFAULT TRUE,
                error_message TEXT NULL
            )
            """
        elif self.db.config.db_type in ["postgresql", "postgres"]:
            query = """
            CREATE TABLE IF NOT EXISTS plugin_audit (
                id SERIAL PRIMARY KEY,
                plugin_id VARCHAR(255) NOT NULL,
                action_type VARCHAR(100) NOT NULL,
                user_id VARCHAR(255) NULL,
                timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                details JSONB NULL,
                ip_address INET NULL,
                user_agent TEXT NULL,
                success BOOLEAN DEFAULT TRUE,
                error_message TEXT NULL
            )
            """
        elif self.db.config.db_type == "mysql":
            query = """
            CREATE TABLE IF NOT EXISTS plugin_audit (
                id INT AUTO_INCREMENT PRIMARY KEY,
                plugin_id VARCHAR(255) NOT NULL,
                action_type VARCHAR(100) NOT NULL,
                user_id VARCHAR(255) NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details JSON NULL,
                ip_address VARCHAR(45) NULL,
                user_agent TEXT NULL,
                success BOOLEAN DEFAULT TRUE,
                error_message TEXT NULL
            )
            """
        
        async with self.db.get_session() as session:
            await session.execute(query)
            await session.commit()
        
        self.logger.info("Created plugin_audit table")
    
    async def _create_client_settings_table(self):
        """Create the client_settings table."""
        if self.db.config.db_type == "sqlite":
            query = """
            CREATE TABLE IF NOT EXISTS client_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                setting_key TEXT NOT NULL,
                setting_value TEXT NULL,
                setting_type TEXT DEFAULT 'text' CHECK (setting_type IN ('text', 'image', 'json', 'binary')),
                file_path TEXT NULL,
                file_size INTEGER NULL,
                mime_type TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, setting_key)
            )
            """
        elif self.db.config.db_type in ["postgresql", "postgres"]:
            query = """
            CREATE TABLE IF NOT EXISTS client_settings (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                setting_key VARCHAR(255) NOT NULL,
                setting_value TEXT NULL,
                setting_type VARCHAR(20) DEFAULT 'text' CHECK (setting_type IN ('text', 'image', 'json', 'binary')),
                file_path TEXT NULL,
                file_size BIGINT NULL,
                mime_type VARCHAR(255) NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, setting_key)
            )
            """
        elif self.db.config.db_type == "mysql":
            query = """
            CREATE TABLE IF NOT EXISTS client_settings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                setting_key VARCHAR(255) NOT NULL,
                setting_value TEXT NULL,
                setting_type ENUM('text', 'image', 'json', 'binary') DEFAULT 'text',
                file_path TEXT NULL,
                file_size BIGINT NULL,
                mime_type VARCHAR(255) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY unique_user_setting (user_id, setting_key)
            )
            """
        
        async with self.db.get_session() as session:
            await session.execute(query)
            await session.commit()
        
        self.logger.info("Created client_settings table")
    
    async def _create_indexes(self):
        """Create indexes for performance optimization."""
        indexes = [
            # Plugin permissions indexes
            ("idx_plugin_permissions_plugin_id", "plugin_permissions", ["plugin_id"]),
            ("idx_plugin_permissions_granted_by", "plugin_permissions", ["granted_by_user_id"]),
            ("idx_plugin_permissions_active", "plugin_permissions", ["is_active"]),
            ("idx_plugin_permissions_expires", "plugin_permissions", ["expires_at"]),
            
            # Plugin audit indexes
            ("idx_plugin_audit_plugin_id", "plugin_audit", ["plugin_id"]),
            ("idx_plugin_audit_timestamp", "plugin_audit", ["timestamp"]),
            ("idx_plugin_audit_action_type", "plugin_audit", ["action_type"]),
            ("idx_plugin_audit_user_id", "plugin_audit", ["user_id"]),
            
            # Client settings indexes
            ("idx_client_settings_user_id", "client_settings", ["user_id"]),
            ("idx_client_settings_type", "client_settings", ["setting_type"]),
            ("idx_client_settings_updated", "client_settings", ["updated_at"]),
        ]
        
        async with self.db.get_session() as session:
            for index_name, table_name, columns in indexes:
                try:
                    if self.db.config.db_type == "sqlite":
                        # SQLite syntax
                        columns_str = ", ".join(columns)
                        query = f"CREATE INDEX IF NOT EXISTS {index_name} ON {table_name} ({columns_str})"
                    elif self.db.config.db_type in ["postgresql", "postgres"]:
                        # PostgreSQL syntax
                        columns_str = ", ".join(columns)
                        query = f"CREATE INDEX IF NOT EXISTS {index_name} ON {table_name} ({columns_str})"
                    elif self.db.config.db_type == "mysql":
                        # MySQL syntax
                        columns_str = ", ".join(columns)
                        query = f"CREATE INDEX {index_name} ON {table_name} ({columns_str})"
                    
                    await session.execute(query)
                    self.logger.debug(f"Created index: {index_name}")
                    
                except Exception as e:
                    # Index might already exist, log but don't fail
                    self.logger.debug(f"Index {index_name} creation skipped: {e}")
            
            await session.commit()
        
        self.logger.info("Created performance indexes")
    
    async def _ensure_migrations_table(self):
        """Ensure the migrations tracking table exists."""
        if self.db.config.db_type == "sqlite":
            query = """
            CREATE TABLE IF NOT EXISTS migrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                migration_id TEXT UNIQUE NOT NULL,
                migration_name TEXT NOT NULL,
                version TEXT NOT NULL,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                rollback_sql TEXT NULL
            )
            """
        elif self.db.config.db_type in ["postgresql", "postgres"]:
            query = """
            CREATE TABLE IF NOT EXISTS migrations (
                id SERIAL PRIMARY KEY,
                migration_id VARCHAR(255) UNIQUE NOT NULL,
                migration_name VARCHAR(255) NOT NULL,
                version VARCHAR(50) NOT NULL,
                applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                rollback_sql TEXT NULL
            )
            """
        elif self.db.config.db_type == "mysql":
            query = """
            CREATE TABLE IF NOT EXISTS migrations (
                id INT AUTO_INCREMENT PRIMARY KEY,
                migration_id VARCHAR(255) UNIQUE NOT NULL,
                migration_name VARCHAR(255) NOT NULL,
                version VARCHAR(50) NOT NULL,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                rollback_sql TEXT NULL
            )
            """
        
        async with self.db.get_session() as session:
            await session.execute(query)
            await session.commit()
    
    async def _record_migration(self):
        """Record this migration in the migrations table."""
        await self._ensure_migrations_table()
        
        async with self.db.get_session() as session:
            await session.insert("migrations", {
                "migration_id": self.MIGRATION_ID,
                "migration_name": self.MIGRATION_NAME,
                "version": self.VERSION,
                "applied_at": datetime.utcnow().isoformat(),
                "rollback_sql": None  # Could store rollback SQL for complex migrations
            })
            await session.commit()
    
    async def _remove_migration_record(self):
        """Remove this migration record from the migrations table."""
        try:
            async with self.db.get_session() as session:
                await session.delete("migrations", {"migration_id": self.MIGRATION_ID})
                await session.commit()
        except Exception as e:
            self.logger.debug(f"Could not remove migration record: {e}")
    
    async def _drop_table(self, table_name: str):
        """Drop a table if it exists."""
        try:
            async with self.db.get_session() as session:
                if self.db.config.db_type == "sqlite":
                    query = f"DROP TABLE IF EXISTS {table_name}"
                elif self.db.config.db_type in ["postgresql", "postgres"]:
                    query = f"DROP TABLE IF EXISTS {table_name} CASCADE"
                elif self.db.config.db_type == "mysql":
                    query = f"DROP TABLE IF EXISTS {table_name}"
                
                await session.execute(query)
                await session.commit()
                self.logger.info(f"Dropped table: {table_name}")
        except Exception as e:
            self.logger.debug(f"Could not drop table {table_name}: {e}")
    
    async def is_applied(self) -> bool:
        """Check if this migration has already been applied."""
        try:
            await self._ensure_migrations_table()
            async with self.db.get_session() as session:
                result = await session.fetchone(
                    "SELECT id FROM migrations WHERE migration_id = :migration_id",
                    {"migration_id": self.MIGRATION_ID}
                )
                return result is not None
        except Exception:
            return False


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
        logger.info(f"Migration {migration.MIGRATION_NAME} not applied, nothing to rollback")
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
    import sys
    import os
    
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