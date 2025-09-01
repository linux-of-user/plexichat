"""
Database Migrations

Migration system for database schema changes.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from plexichat.core.database.manager import database_manager

logger = logging.getLogger(__name__)


class Migration:
    """Database migration."""
    
    def __init__(self, version: str, description: str, up_sql: str, down_sql: str = ""):
        self.version = version
        self.description = description
        self.up_sql = up_sql
        self.down_sql = down_sql
        self.created_at = datetime.now(timezone.utc)
    
    async def apply(self) -> bool:
        """Apply the migration."""
        try:
            async with database_manager.get_session() as session:
                await session.execute(self.up_sql)
                await session.commit()
                
                # Record migration
                await session.insert("migrations", {
                    "version": self.version,
                    "description": self.description,
                    "applied_at": self.created_at.isoformat()
                })
                await session.commit()
                
                logger.info(f"Applied migration {self.version}: {self.description}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to apply migration {self.version}: {e}")
            return False
    
    async def rollback(self) -> bool:
        """Rollback the migration."""
        if not self.down_sql:
            logger.warning(f"No rollback SQL for migration {self.version}")
            return False
        
        try:
            async with database_manager.get_session() as session:
                await session.execute(self.down_sql)
                await session.commit()
                
                # Remove migration record
                await session.delete("migrations", {"version": self.version})
                await session.commit()
                
                logger.info(f"Rolled back migration {self.version}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to rollback migration {self.version}: {e}")
            return False


class MigrationManager:
    """Manages database migrations."""
    
    def __init__(self):
        self.migrations: List[Migration] = []
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self) -> bool:
        """Initialize migration system."""
        try:
            # Create migrations table
            await database_manager.ensure_table_exists("migrations", {
                "version": "TEXT PRIMARY KEY",
                "description": "TEXT NOT NULL",
                "applied_at": "TEXT NOT NULL"
            })
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize migration system: {e}")
            return False
    
    def add_migration(self, migration: Migration):
        """Add a migration."""
        self.migrations.append(migration)
        self.migrations.sort(key=lambda m: m.version)
    
    async def get_applied_migrations(self) -> List[str]:
        """Get list of applied migration versions."""
        try:
            async with database_manager.get_session() as session:
                result = await session.fetchall("SELECT version FROM migrations ORDER BY version")
                return [row["version"] for row in result]
        except Exception:
            return []
    
    async def get_pending_migrations(self) -> List[Migration]:
        """Get list of pending migrations."""
        applied = await self.get_applied_migrations()
        return [m for m in self.migrations if m.version not in applied]
    
    async def run_migrations(self) -> bool:
        """Run all pending migrations."""
        await self.initialize()
        
        pending = await self.get_pending_migrations()
        if not pending:
            self.logger.info("No pending migrations")
            return True
        
        self.logger.info(f"Running {len(pending)} pending migrations")
        
        for migration in pending:
            success = await migration.apply()
            if not success:
                self.logger.error(f"Migration {migration.version} failed, stopping")
                return False
        
        self.logger.info("All migrations completed successfully")
        return True
    
    async def rollback_migration(self, version: str) -> bool:
        """Rollback a specific migration."""
        migration = next((m for m in self.migrations if m.version == version), None)
        if not migration:
            self.logger.error(f"Migration {version} not found")
            return False
        
        return await migration.rollback()


# Global migration manager
migration_manager = MigrationManager()


# Convenience functions
async def run_migrations() -> bool:
    """Run all pending migrations."""
    return await migration_manager.run_migrations()


def create_migration(version: str, description: str, up_sql: str, down_sql: str = "") -> Migration:
    """Create a new migration."""
    migration = Migration(version, description, up_sql, down_sql)
    migration_manager.add_migration(migration)
    return migration


# Built-in migrations
create_migration(
    "001_initial_schema",
    "Create initial database schema",
    """
    -- This migration is handled by the models.py create_tables() function
    SELECT 1;
    """,
    """
    DROP TABLE IF EXISTS events;
    DROP TABLE IF EXISTS plugins;
    DROP TABLE IF EXISTS sessions;
    DROP TABLE IF EXISTS channels;
    DROP TABLE IF EXISTS messages;
    DROP TABLE IF EXISTS users;
    """
)

create_migration(
    "002_add_typing_status_table",
    "Add typing status table for persistent typing indicators",
    """
    CREATE TABLE IF NOT EXISTS typing_status (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        channel_id TEXT NOT NULL,
        started_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        metadata TEXT DEFAULT '{}'
    );
    CREATE INDEX IF NOT EXISTS idx_typing_status_user_channel ON typing_status(user_id, channel_id);
    CREATE INDEX IF NOT EXISTS idx_typing_status_expires_at ON typing_status(expires_at);
    """,
    """
    DROP TABLE IF EXISTS typing_status;
    """
)


__all__ = [
    "Migration",
    "MigrationManager", 
    "migration_manager",
    "run_migrations",
    "create_migration",
# Import additional typing optimization migrations
try:
    from plexichat.core.database.migrations_typing_optimization import *
except ImportError:
    pass  # Migrations will be loaded when the module is available
]
