"""
import os
import time
PlexiChat Unified Database Migrations - SINGLE SOURCE OF TRUTH

Consolidates migration management from:
- infrastructure/database/db_migrations.py - INTEGRATED
- core/database/db_zero_downtime_migration.py - ENHANCED

Provides unified interface for all database migrations and schema management.
"""

import asyncio
import logging
import hashlib
import json
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum

# Import from existing modules
from .db_manager import DatabaseType
from .unified_engines import unified_engine_manager

logger = logging.getLogger(__name__)


class MigrationStatus(Enum):
    """Migration execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class MigrationStrategy(Enum):
    """Migration strategies for different scenarios."""
    SIMPLE = "simple"              # Basic up/down migration
    EXPAND_CONTRACT = "expand_contract"  # Add new, migrate data, remove old
    DUAL_WRITE = "dual_write"      # Write to both old and new schemas
    SHADOW_TABLE = "shadow_table"  # Create shadow table, sync, swap
    ONLINE_DDL = "online_ddl"      # Use database-specific online DDL
    BLUE_GREEN = "blue_green"      # Complete database switch


@dataclass
class Migration:
    """Database migration definition."""
    version: str
    name: str
    description: str
    up_sql: str
    down_sql: str
    database_type: DatabaseType
    strategy: MigrationStrategy = MigrationStrategy.SIMPLE
    checksum: str = ""
    created_at: Optional[datetime] = None
    dependencies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

        # Calculate checksum if not provided
        if not self.checksum:
            content = f"{self.version}{self.up_sql}{self.down_sql}"
            self.checksum = hashlib.sha256(content.encode()).hexdigest()


@dataclass
class MigrationExecution:
    """Migration execution record."""
    migration_version: str
    status: MigrationStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    execution_time_seconds: float = 0.0
    rollback_available: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


class MigrationRepository:
    """Repository for managing migration records."""

    def __init__(self, engine_name: str = "default"):
        self.engine_name = engine_name
        self.table_name = "plexichat_migrations"

    async def initialize(self) -> bool:
        """Initialize migration tracking table."""
        try:
            engine = await unified_engine_manager.get_engine(self.engine_name)
            if not engine:
                logger.error(f"Engine '{self.engine_name}' not found")
                return False

            # Create migrations table using abstraction layer
            from plexichat.core.database import database_manager

            # Define table schema using abstraction layer
            table_schema = {
                "table_name": self.table_name,
                "columns": {
                    "version": {"type": "VARCHAR", "length": 255, "primary_key": True},
                    "name": {"type": "VARCHAR", "length": 255, "nullable": False},
                    "description": {"type": "TEXT"},
                    "checksum": {"type": "VARCHAR", "length": 64, "nullable": False},
                    "strategy": {"type": "VARCHAR", "length": 50, "nullable": False},
                    "status": {"type": "VARCHAR", "length": 50, "nullable": False},
                    "started_at": {"type": "TIMESTAMP", "nullable": False},
                    "completed_at": {"type": "TIMESTAMP"},
                    "execution_time_seconds": {"type": "REAL", "default": 0.0},
                    "error_message": {"type": "TEXT"},
                    "rollback_available": {"type": "BOOLEAN", "default": True},
                    "metadata": {"type": "TEXT"}
                }
            }

            # Create migration tracking table using execute_query
            create_table_sql = """
                CREATE TABLE IF NOT EXISTS migration_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    execution_time REAL,
                    success BOOLEAN DEFAULT TRUE,
                    error_message TEXT
                )
            """
            await database_manager.execute_query(create_table_sql)
            logger.info("Migration tracking table initialized")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize migration repository: {e}")
            return False

    async def record_migration_start(self, migration: Migration) -> bool:
        """Record the start of a migration."""
        try:
            engine = await unified_engine_manager.get_engine(self.engine_name)
            if not engine:
                return False

            insert_sql = f"""
            INSERT INTO {self.table_name}
            (version, name, description, checksum, strategy, status, started_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """

            params = {
                'version': migration.version,
                'name': migration.name,
                'description': migration.description,
                'checksum': migration.checksum,
                'strategy': migration.strategy.value,
                'status': MigrationStatus.RUNNING.value,
                'started_at': datetime.now(),
                'metadata': json.dumps(migration.metadata)
            }

            await engine.execute(insert_sql, params)
            return True

        except Exception as e:
            logger.error(f"Failed to record migration start: {e}")
            return False

    async def record_migration_completion(self, version: str, success: bool,
                                        execution_time: float, error: Optional[str] = None) -> bool:
        """Record the completion of a migration."""
        try:
            engine = await unified_engine_manager.get_engine(self.engine_name)
            if not engine:
                return False

            status = MigrationStatus.COMPLETED if success else MigrationStatus.FAILED

            update_sql = f"""
            UPDATE {self.table_name}
            SET status = ?, completed_at = ?, execution_time_seconds = ?, error_message = ?
            WHERE version = ?
            """

            params = {
                'status': status.value,
                'completed_at': datetime.now(),
                'execution_time_seconds': execution_time,
                'error_message': error,
                'version': version
            }

            await engine.execute(update_sql, params)
            return True

        except Exception as e:
            logger.error(f"Failed to record migration completion: {e}")
            return False

    async def get_applied_migrations(self) -> List[str]:
        """Get list of applied migration versions."""
        try:
            engine = await unified_engine_manager.get_engine(self.engine_name)
            if not engine:
                return []

            query_sql = f"""
            SELECT version FROM {self.table_name}
            WHERE status = ?
            ORDER BY started_at
            """

            result = await engine.execute(query_sql, {'status': MigrationStatus.COMPLETED.value})

            # Extract versions from result (format depends on engine type)
            if hasattr(result, 'fetchall'):
                rows = await result.fetchall()
                return [row[0] for row in rows]
            elif isinstance(result, list):
                return [row[0] for row in result]
            else:
                return []

        except Exception as e:
            logger.error(f"Failed to get applied migrations: {e}")
            return []

    async def get_migration_status(self, version: str) -> Optional[MigrationExecution]:
        """Get the status of a specific migration."""
        try:
            engine = await unified_engine_manager.get_engine(self.engine_name)
            if not engine:
                return None

            query_sql = f"""
            SELECT * FROM {self.table_name} WHERE version = ?
            """

            result = await engine.execute(query_sql, {'version': version})

            # Parse result (format depends on engine type)
            # This is a simplified implementation
            return None

        except Exception as e:
            logger.error(f"Failed to get migration status: {e}")
            return None


class UnifiedMigrationManager:
    """
    Unified Migration Manager - SINGLE SOURCE OF TRUTH

    Consolidates all database migration functionality.
    """

    def __init__(self, engine_name: str = "default"):
        self.engine_name = engine_name
        self.repository = MigrationRepository(engine_name)
        self.migrations: Dict[str, Migration] = {}
        self.migration_directory = Path("migrations")

    async def initialize(self) -> bool:
        """Initialize the migration manager."""
        try:
            # Initialize repository
            success = await self.repository.initialize()
            if not success:
                return False

            # Load migrations from directory
            await self.load_migrations()

            logger.info("Migration manager initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize migration manager: {e}")
            return False

    async def load_migrations(self) -> bool:
        """Load migrations from the migrations directory."""
        try:
            if not self.migration_directory.exists():
                self.migration_directory.mkdir(parents=True, exist_ok=True)
                logger.info(f"Created migrations directory: {self.migration_directory}")
                return True

            # Load .sql files as migrations
            for migration_file in self.migration_directory.glob("*.sql"):
                await self._load_migration_file(migration_file)

            logger.info(f"Loaded {len(self.migrations)} migrations")
            return True

        except Exception as e:
            logger.error(f"Failed to load migrations: {e}")
            return False

    async def _load_migration_file(self, file_path: Path) -> bool:
        """Load a single migration file."""
        try:
            content = file_path.read_text(encoding='utf-8')

            # Parse migration file (simplified format)
            # Expected format: version_name.sql with -- UP and -- DOWN sections
            lines = content.split('\n')

            version = file_path.stem
            name = version.replace('_', ' ').title()
            description = f"Migration {version}"
            up_sql = ""
            down_sql = ""

            current_section = None
            for line in lines:
                line = line.strip()
                if line.startswith('-- UP'):
                    current_section = 'up'
                elif line.startswith('-- DOWN'):
                    current_section = 'down'
                elif line.startswith('--'):
                    # Comment line, extract metadata
                    if 'DESCRIPTION:' in line:
                        description = line.split('DESCRIPTION:')[1].strip()
                elif current_section == 'up':
                    up_sql += line + '\n'
                elif current_section == 'down':
                    down_sql += line + '\n'

            migration = Migration(
                version=version,
                name=name,
                description=description,
                up_sql=up_sql.strip(),
                down_sql=down_sql.strip(),
                database_type=DatabaseType.SQLITE  # Default, should be configurable
            )

            self.migrations[version] = migration
            return True

        except Exception as e:
            logger.error(f"Failed to load migration file {file_path}: {e}")
            return False

    async def get_pending_migrations(self) -> List[Migration]:
        """Get list of pending migrations."""
        try:
            applied_versions = await self.repository.get_applied_migrations()
            pending = []

            # Sort migrations by version
            sorted_versions = sorted(self.migrations.keys())

            for version in sorted_versions:
                if version not in applied_versions:
                    pending.append(self.migrations[version])

            return pending

        except Exception as e:
            logger.error(f"Failed to get pending migrations: {e}")
            return []

    async def apply_migration(self, migration: Migration) -> bool:
        """Apply a single migration."""
        start_time = datetime.now()  # Define start_time before try block
        try:
            logger.info(f"Applying migration {migration.version}: {migration.name}")

            # Record migration start
            await self.repository.record_migration_start(migration)

            # Get database engine
            engine = await unified_engine_manager.get_engine(self.engine_name)
            if not engine:
                raise Exception(f"Engine '{self.engine_name}' not found")

            # Execute migration SQL
            await engine.execute(migration.up_sql)

            # Calculate execution time
            execution_time = (datetime.now() - start_time).total_seconds()

            # Record successful completion
            await self.repository.record_migration_completion(
                migration.version, True, execution_time
            )

            logger.info(f"Migration {migration.version} applied successfully in {execution_time:.2f}s")
            return True

        except Exception as e:
            # Record failure
            execution_time = (datetime.now() - start_time).total_seconds()
            await self.repository.record_migration_completion(
                migration.version, False, execution_time, str(e)
            )

            logger.error(f"Failed to apply migration {migration.version}: {e}")
            return False

    async def rollback_migration(self, version: str) -> bool:
        """Rollback a specific migration."""
        try:
            migration = self.migrations.get(version)
            if not migration:
                logger.error(f"Migration {version} not found")
                return False

            if not migration.down_sql:
                logger.error(f"Migration {version} has no rollback SQL")
                return False

            logger.info(f"Rolling back migration {version}: {migration.name}")

            # Get database engine
            engine = await unified_engine_manager.get_engine(self.engine_name)
            if not engine:
                raise Exception(f"Engine '{self.engine_name}' not found")

            # Execute rollback SQL
            await engine.execute(migration.down_sql)

            # Update migration status
            # TODO: Add rollback status tracking

            logger.info(f"Migration {version} rolled back successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to rollback migration {version}: {e}")
            return False

    async def apply_all_pending(self) -> bool:
        """Apply all pending migrations."""
        try:
            pending = await self.get_pending_migrations()

            if not pending:
                logger.info("No pending migrations")
                return True

            logger.info(f"Applying {len(pending)} pending migrations")

            for migration in pending:
                success = await self.apply_migration(migration)
                if not success:
                    logger.error(f"Migration {migration.version} failed, stopping")
                    return False

            logger.info("All pending migrations applied successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to apply pending migrations: {e}")
            return False


# Global unified migration manager instance
unified_migration_manager = UnifiedMigrationManager()

# Backward compatibility exports
migration_manager = unified_migration_manager

__all__ = [
    'UnifiedMigrationManager',
    'unified_migration_manager',
    'migration_manager',  # Backward compatibility
    'Migration',
    'MigrationExecution',
    'MigrationStatus',
    'MigrationStrategy',
    'MigrationRepository',
]
