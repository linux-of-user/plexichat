import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from plexichat.core.database.multi_backend import db_manager  # type: ignore

"""
Database Migration System
Automatic database migrations with version control and rollback support.
"""

try:
    MULTI_BACKEND_AVAILABLE = True
except ImportError:
    MULTI_BACKEND_AVAILABLE = False
    # Create placeholder db_manager
    class MockDBManager:
        def __init__(self):
            # Mock async_engine
            class MockAsyncEngine:
                def begin(self):
                    return self
                async def __aenter__(self):
                    return self
                async def __aexit__(self, exc_type, exc_val, exc_tb):
                    pass
                async def execute(self, query, params=None):
                    # Acknowledge parameters to avoid unused warnings
                    _ = query, params
                    # Mock result with fetchall method
                    class MockResult:
                        def fetchall(self):
                            return []
                    return MockResult()

            # Mock backend
            class MockBackend:
                def __init__(self):
                    self.url = "sqlite:///mock.db"

            self.async_engine = MockAsyncEngine()
            self.backend = MockBackend()

        async def execute_query(self, query, params=None):
            # Acknowledge parameters to avoid unused warnings
            _ = query, params
            # Mock implementation
            return {"success": True, "data": []}
    db_manager = MockDBManager()

logger = logging.getLogger(__name__)

class Migration:
    """Represents a single database migration."""
    
    def __init__(self, version: str, name: str, up_sql: str, down_sql: Optional[str] = None):
        self.version = version
        self.name = name
        self.up_sql = up_sql
        self.down_sql = down_sql
        self.timestamp = datetime.now(timezone.utc)
    
    def __str__(self):
        return f"Migration {self.version}: {self.name}"

class MigrationManager:
    """Manages database migrations with automatic execution and rollback."""
    
    def __init__(self):
        self.migrations: List[Migration] = []
        self.migrations_dir = from pathlib import Path
Path("migrations")
        self.migrations_dir.mkdir(exist_ok=True)
        
    async def initialize(self):
        """Initialize migration system."""
        await self._ensure_migration_table()
        await self._load_migrations()
        
    async def _ensure_migration_table(self):
        """Ensure migration tracking table exists."""
        try:
            async with db_manager.async_engine.begin() as conn:
                # Create migrations table if it doesn't exist
                create_table_sql = """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    id INTEGER PRIMARY KEY,
                    version VARCHAR(255) NOT NULL UNIQUE,
                    name VARCHAR(255) NOT NULL,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    checksum VARCHAR(255)
                )
                """
                
                # Adjust for different database backends
                if 'postgresql' in str(db_manager.backend.url):
                    create_table_sql = create_table_sql.replace('INTEGER PRIMARY KEY', 'SERIAL PRIMARY KEY')
                elif 'mysql' in str(db_manager.backend.url):
                    create_table_sql = create_table_sql.replace('INTEGER PRIMARY KEY', 'INT AUTO_INCREMENT PRIMARY KEY')
                    create_table_sql = create_table_sql.replace('TIMESTAMP DEFAULT CURRENT_TIMESTAMP', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
                
                await conn.execute(text(create_table_sql))
                logger.info("Migration table ensured")
                
        except Exception as e:
            logger.error(f"Failed to create migration table: {e}")
            raise
    
    async def _load_migrations(self):
        """Load migrations from files and code."""
        # Load from migration files
        for migration_file in sorted(self.migrations_dir.glob("*.sql")):
            await self._load_migration_file(migration_file)
        
        # Load built-in migrations
        await self._load_builtin_migrations()
        
        # Sort migrations by version
        self.migrations.sort(key=lambda m: m.version)
        
    async def _load_migration_file(self, file_path: Path):
        """Load migration from SQL file."""
        try:
            content = file_path.read_text()
            
            # Parse migration file format
            # Expected format: version_name.sql with -- UP and -- DOWN sections
            lines = content.split('\n')
            up_sql = []
            down_sql = []
            current_section = None
            
            for line in lines:
                line = line.strip()
                if line.startswith('-- UP'):
                    current_section = 'up'
                elif line.startswith('-- DOWN'):
                    current_section = 'down'
                elif line and not line.startswith('--'):
                    if current_section == 'up':
                        up_sql.append(line)
                    elif current_section == 'down':
                        down_sql.append(line)
            
            # Extract version and name from filename
            filename = file_path.stem
            if '_' in filename:
                version, name = filename.split('_', 1)
            else:
                version = filename
                name = "Migration"
            
            migration = Migration(
                version=version,
                name=name.replace('_', ' ').title(),
                up_sql='\n'.join(up_sql),
                down_sql='\n'.join(down_sql) if down_sql else None
            )
            
            self.migrations.append(migration)
            logger.debug(f"Loaded migration from file: {migration}")
            
        except Exception as e:
            logger.error(f"Failed to load migration file {file_path}: {e}")
    
    async def _load_builtin_migrations(self):
        """Load built-in migrations for core functionality."""
        # Initial schema migration
        initial_migration = Migration(
            version="001",
            name="Initial Schema",
            up_sql="""
            -- Create users table
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                email VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Create channels table
            CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                is_private BOOLEAN DEFAULT FALSE,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id)
            );
            
            -- Create messages table
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                content TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                channel_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (channel_id) REFERENCES channels(id)
            );
            
            -- Create files table
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                original_filename VARCHAR(255) NOT NULL,
                content_type VARCHAR(255),
                size_bytes INTEGER,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """,
            down_sql="""
            DROP TABLE IF EXISTS files;
            DROP TABLE IF EXISTS messages;
            DROP TABLE IF EXISTS channels;
            DROP TABLE IF EXISTS users;
            """
        )
        
        # Backup system migration
        backup_migration = Migration(
            version="002",
            name="Backup System",
            up_sql="""
            -- Create backups table
            CREATE TABLE IF NOT EXISTS backups (
                id INTEGER PRIMARY KEY,
                backup_id VARCHAR(255) NOT NULL UNIQUE,
                status VARCHAR(50) DEFAULT 'created',
                size_bytes INTEGER,
                checksum VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            );
            
            -- Create backup shards table
            CREATE TABLE IF NOT EXISTS backup_shards (
                id INTEGER PRIMARY KEY,
                shard_id VARCHAR(255) NOT NULL UNIQUE,
                backup_id VARCHAR(255) NOT NULL,
                user_id INTEGER NOT NULL,
                size_bytes INTEGER,
                checksum VARCHAR(255),
                encrypted_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (backup_id) REFERENCES backups(backup_id)
            );
            """,
            down_sql="""
            DROP TABLE IF EXISTS backup_shards;
            DROP TABLE IF EXISTS backups;
            """
        )
        
        # Analytics migration
        analytics_migration = Migration(
            version="003",
            name="Analytics System",
            up_sql="""
            -- Create analytics events table
            CREATE TABLE IF NOT EXISTS analytics_events (
                id INTEGER PRIMARY KEY,
                event_type VARCHAR(100) NOT NULL,
                user_id INTEGER,
                session_id VARCHAR(255),
                data TEXT,
                ip_address VARCHAR(45),
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            
            -- Create system metrics table
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY,
                metric_name VARCHAR(100) NOT NULL,
                metric_value DECIMAL(10,2),
                metric_unit VARCHAR(20),
                recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Create indexes for performance
            CREATE INDEX IF NOT EXISTS idx_analytics_events_type ON analytics_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_analytics_events_user ON analytics_events(user_id);
            CREATE INDEX IF NOT EXISTS idx_analytics_events_created ON analytics_events(created_at);
            CREATE INDEX IF NOT EXISTS idx_system_metrics_name ON system_metrics(metric_name);
            CREATE INDEX IF NOT EXISTS idx_system_metrics_recorded ON system_metrics(recorded_at);
            """,
            down_sql="""
            DROP INDEX IF EXISTS idx_system_metrics_recorded;
            DROP INDEX IF EXISTS idx_system_metrics_name;
            DROP INDEX IF EXISTS idx_analytics_events_created;
            DROP INDEX IF EXISTS idx_analytics_events_user;
            DROP INDEX IF EXISTS idx_analytics_events_type;
            DROP TABLE IF EXISTS system_metrics;
            DROP TABLE IF EXISTS analytics_events;
            """
        )
        
        self.migrations.extend([initial_migration, backup_migration, analytics_migration])
    
    async def get_applied_migrations(self) -> List[str]:
        """Get list of applied migration versions."""
        try:
            async with db_manager.async_engine.begin() as conn:
                result = await conn.execute(text("SELECT version FROM schema_migrations ORDER BY version"))
                return [row[0] for row in result.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get applied migrations: {e}")
            return []
    
    async def get_pending_migrations(self) -> List[Migration]:
        """Get list of pending migrations."""
        applied = await self.get_applied_migrations()
        return [m for m in self.migrations if m.version not in applied]
    
    async def apply_migration(self, migration: Migration) -> bool:
        """Apply a single migration."""
        try:
            logger.info(f"Applying migration: {migration}")
            
            async with db_manager.async_engine.begin() as conn:
                # Execute migration SQL
                if migration.up_sql:
                    # Split SQL into individual statements
                    statements = [s.strip() for s in migration.up_sql.split(';') if s.strip()]
                    
                    for statement in statements:
                        # Adjust SQL for different backends
                        adjusted_statement = self._adjust_sql_for_backend(statement)
                        await conn.execute(text(adjusted_statement))
                
                # Record migration as applied
                await conn.execute(text("""
                    INSERT INTO schema_migrations (version, name, applied_at)
                    VALUES (:version, :name, :applied_at)
                """), {
                    "version": migration.version,
                    "name": migration.name,
                    "applied_at": datetime.now(timezone.utc)
                })
            
            logger.info(f"Successfully applied migration: {migration}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply migration {migration}: {e}")
            return False
    
    async def rollback_migration(self, migration: Migration) -> bool:
        """Rollback a single migration."""
        if not migration.down_sql:
            logger.error(f"No rollback SQL for migration: {migration}")
            return False
        
        try:
            logger.info(f"Rolling back migration: {migration}")
            
            async with db_manager.async_engine.begin() as conn:
                # Execute rollback SQL
                statements = [s.strip() for s in migration.down_sql.split(';') if s.strip()]
                
                for statement in statements:
                    adjusted_statement = self._adjust_sql_for_backend(statement)
                    await conn.execute(text(adjusted_statement))
                
                # Remove migration record
                await conn.execute(text("""
                    DELETE FROM schema_migrations WHERE version = :version
                """), {"version": migration.version})
            
            logger.info(f"Successfully rolled back migration: {migration}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rollback migration {migration}: {e}")
            return False
    
    def _adjust_sql_for_backend(self, sql: str) -> str:
        """Adjust SQL for different database backends."""
        backend_url = str(db_manager.backend.url)
        
        if 'postgresql' in backend_url:
            # PostgreSQL adjustments
            sql = sql.replace('INTEGER PRIMARY KEY', 'SERIAL PRIMARY KEY')
            sql = sql.replace('BOOLEAN', 'BOOLEAN')
            
        elif 'mysql' in backend_url:
            # MySQL adjustments
            sql = sql.replace('INTEGER PRIMARY KEY', 'INT AUTO_INCREMENT PRIMARY KEY')
            sql = sql.replace('BOOLEAN', 'TINYINT(1)')
            sql = sql.replace('TEXT', 'LONGTEXT')
            
        return sql
    
    async def migrate_up(self, target_version: Optional[str] = None) -> bool:
        """Apply all pending migrations up to target version."""
        pending = await self.get_pending_migrations()
        
        if target_version:
            pending = [m for m in pending if m.version <= target_version]
        
        if not pending:
            logger.info("No pending migrations")
            return True
        
        logger.info(f"Applying {len(pending)} migrations")
        
        for migration in pending:
            success = await self.apply_migration(migration)
            if not success:
                logger.error(f"Migration failed, stopping at: {migration}")
                return False
        
        logger.info("All migrations applied successfully")
        return True
    
    async def migrate_down(self, target_version: str) -> bool:
        """Rollback migrations down to target version."""
        applied = await self.get_applied_migrations()
        
        # Find migrations to rollback (in reverse order)
        to_rollback = []
        for version in reversed(applied):
            if version > target_version:
                migration = next((m for m in self.migrations if m.version == version), None)
                if migration:
                    to_rollback.append(migration)
        
        if not to_rollback:
            logger.info("No migrations to rollback")
            return True
        
        logger.info(f"Rolling back {len(to_rollback)} migrations")
        
        for migration in to_rollback:
            success = await self.rollback_migration(migration)
            if not success:
                logger.error(f"Rollback failed, stopping at: {migration}")
                return False
        
        logger.info("All rollbacks completed successfully")
        return True
    
    async def get_migration_status(self) -> Dict[str, Any]:
        """Get current migration status."""
        applied = await self.get_applied_migrations()
        pending = await self.get_pending_migrations()
        
        return {
            "total_migrations": len(self.migrations),
            "applied_count": len(applied),
            "pending_count": len(pending),
            "applied_versions": applied,
            "pending_versions": [m.version for m in pending],
            "current_version": applied[-1] if applied else None
        }

# Global migration manager instance
migration_manager = MigrationManager()
