"""
PlexiChat Database Migrations

Database schema migration system for version management and upgrades.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import json
import hashlib

try:
    from plexichat.infrastructure.database.db_engines import engine_manager
    from plexichat.app.logger_config import get_logger
    from plexichat.core.config import settings
except ImportError:
    engine_manager = None
    get_logger = lambda name: logging.getLogger(name)
    settings = {}

logger = get_logger(__name__)

@dataclass
class Migration:
    """Database migration definition."""
    version: str
    name: str
    description: str
    up_sql: str
    down_sql: str
    checksum: str
    created_at: datetime
    dependencies: List[str] = None

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        
        # Calculate checksum if not provided
        if not self.checksum:
            content = f"{self.up_sql}{self.down_sql}"
            self.checksum = hashlib.sha256(content.encode()).hexdigest()

class MigrationManager:
    """Database migration manager."""
    
    def __init__(self, engine_name: str = 'primary'):
        self.engine_name = engine_name
        self.migrations: Dict[str, Migration] = {}
        self.migrations_table = 'schema_migrations'
    
    async def initialize(self) -> bool:
        """Initialize migration system."""
        try:
            # Create migrations table if it doesn't exist
            await self._create_migrations_table()
            
            # Load migrations from files
            await self._load_migrations()
            
            logger.info("Migration system initialized")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize migration system: {e}")
            return False
    
    async def _create_migrations_table(self) -> None:
        """Create the migrations tracking table."""
        if not engine_manager:
            raise RuntimeError("Database engine manager not available")
        
        engine = engine_manager.get_engine(self.engine_name)
        if not engine:
            raise RuntimeError(f"Database engine '{self.engine_name}' not found")
        
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {self.migrations_table} (
            version VARCHAR(255) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            checksum VARCHAR(64) NOT NULL,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            execution_time INTEGER DEFAULT 0
        )
        """
        
        await engine.execute(create_table_sql)
        logger.info(f"Created migrations table: {self.migrations_table}")
    
    async def _load_migrations(self) -> None:
        """Load migration files from disk."""
        migrations_dir = Path("migrations")
        
        if not migrations_dir.exists():
            migrations_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created migrations directory: {migrations_dir}")
            return
        
        for migration_file in sorted(migrations_dir.glob("*.json")):
            try:
                with open(migration_file, 'r') as f:
                    migration_data = json.load(f)
                
                migration = Migration(
                    version=migration_data['version'],
                    name=migration_data['name'],
                    description=migration_data['description'],
                    up_sql=migration_data['up_sql'],
                    down_sql=migration_data['down_sql'],
                    checksum=migration_data.get('checksum', ''),
                    created_at=datetime.fromisoformat(migration_data['created_at']),
                    dependencies=migration_data.get('dependencies', [])
                )
                
                self.migrations[migration.version] = migration
                logger.debug(f"Loaded migration: {migration.version} - {migration.name}")
                
            except Exception as e:
                logger.error(f"Failed to load migration {migration_file}: {e}")
        
        logger.info(f"Loaded {len(self.migrations)} migrations")
    
    async def get_applied_migrations(self) -> List[str]:
        """Get list of applied migration versions."""
        if not engine_manager:
            return []
        
        engine = engine_manager.get_engine(self.engine_name)
        if not engine:
            return []
        
        try:
            query = f"SELECT version FROM {self.migrations_table} ORDER BY applied_at"
            rows = await engine.fetch_all(query)
            return [row['version'] for row in rows]
            
        except Exception as e:
            logger.error(f"Failed to get applied migrations: {e}")
            return []
    
    async def get_pending_migrations(self) -> List[Migration]:
        """Get list of pending migrations."""
        applied = await self.get_applied_migrations()
        pending = []
        
        for version in sorted(self.migrations.keys()):
            if version not in applied:
                migration = self.migrations[version]
                
                # Check dependencies
                if all(dep in applied for dep in migration.dependencies):
                    pending.append(migration)
                else:
                    logger.warning(f"Migration {version} has unmet dependencies")
        
        return pending
    
    async def apply_migration(self, migration: Migration) -> bool:
        """Apply a single migration."""
        if not engine_manager:
            return False
        
        engine = engine_manager.get_engine(self.engine_name)
        if not engine:
            return False
        
        try:
            start_time = datetime.now()
            
            # Execute migration SQL
            await engine.execute(migration.up_sql)
            
            # Record migration as applied
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            
            insert_sql = f"""
            INSERT INTO {self.migrations_table} 
            (version, name, description, checksum, execution_time)
            VALUES (?, ?, ?, ?, ?)
            """
            
            await engine.execute(insert_sql, {
                'version': migration.version,
                'name': migration.name,
                'description': migration.description,
                'checksum': migration.checksum,
                'execution_time': execution_time
            })
            
            logger.info(f"Applied migration: {migration.version} - {migration.name} ({execution_time}ms)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply migration {migration.version}: {e}")
            return False
    
    async def rollback_migration(self, migration: Migration) -> bool:
        """Rollback a single migration."""
        if not engine_manager:
            return False
        
        engine = engine_manager.get_engine(self.engine_name)
        if not engine:
            return False
        
        try:
            # Execute rollback SQL
            await engine.execute(migration.down_sql)
            
            # Remove migration record
            delete_sql = f"DELETE FROM {self.migrations_table} WHERE version = ?"
            await engine.execute(delete_sql, {'version': migration.version})
            
            logger.info(f"Rolled back migration: {migration.version} - {migration.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rollback migration {migration.version}: {e}")
            return False
    
    async def migrate_up(self, target_version: Optional[str] = None) -> bool:
        """Apply pending migrations up to target version."""
        try:
            pending = await self.get_pending_migrations()
            
            if target_version:
                # Filter to only migrations up to target
                pending = [m for m in pending if m.version <= target_version]
            
            if not pending:
                logger.info("No pending migrations to apply")
                return True
            
            logger.info(f"Applying {len(pending)} migrations...")
            
            for migration in pending:
                success = await self.apply_migration(migration)
                if not success:
                    logger.error(f"Migration failed at version {migration.version}")
                    return False
            
            logger.info("All migrations applied successfully")
            return True
            
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            return False
    
    async def migrate_down(self, target_version: str) -> bool:
        """Rollback migrations down to target version."""
        try:
            applied = await self.get_applied_migrations()
            
            # Find migrations to rollback (in reverse order)
            to_rollback = []
            for version in reversed(applied):
                if version > target_version:
                    if version in self.migrations:
                        to_rollback.append(self.migrations[version])
                else:
                    break
            
            if not to_rollback:
                logger.info("No migrations to rollback")
                return True
            
            logger.info(f"Rolling back {len(to_rollback)} migrations...")
            
            for migration in to_rollback:
                success = await self.rollback_migration(migration)
                if not success:
                    logger.error(f"Rollback failed at version {migration.version}")
                    return False
            
            logger.info("All rollbacks completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False
    
    async def get_migration_status(self) -> Dict[str, Any]:
        """Get current migration status."""
        try:
            applied = await self.get_applied_migrations()
            pending = await self.get_pending_migrations()
            
            return {
                "total_migrations": len(self.migrations),
                "applied_count": len(applied),
                "pending_count": len(pending),
                "current_version": applied[-1] if applied else None,
                "latest_version": max(self.migrations.keys()) if self.migrations else None,
                "applied_migrations": applied,
                "pending_migrations": [m.version for m in pending]
            }
            
        except Exception as e:
            logger.error(f"Failed to get migration status: {e}")
            return {"error": str(e)}
    
    def create_migration(self, name: str, description: str, up_sql: str, down_sql: str) -> str:
        """Create a new migration file."""
        try:
            # Generate version (timestamp-based)
            version = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            migration_data = {
                "version": version,
                "name": name,
                "description": description,
                "up_sql": up_sql,
                "down_sql": down_sql,
                "created_at": datetime.now().isoformat(),
                "dependencies": []
            }
            
            # Calculate checksum
            content = f"{up_sql}{down_sql}"
            migration_data["checksum"] = hashlib.sha256(content.encode()).hexdigest()
            
            # Save to file
            migrations_dir = Path("migrations")
            migrations_dir.mkdir(parents=True, exist_ok=True)
            
            filename = f"{version}_{name.lower().replace(' ', '_')}.json"
            filepath = migrations_dir / filename
            
            with open(filepath, 'w') as f:
                json.dump(migration_data, f, indent=2)
            
            logger.info(f"Created migration: {filepath}")
            return version
            
        except Exception as e:
            logger.error(f"Failed to create migration: {e}")
            raise

# Global migration manager
migration_manager = MigrationManager()

# Built-in migrations
INITIAL_MIGRATIONS = [
    {
        "version": "20240101_000001",
        "name": "create_users_table",
        "description": "Create users table with basic authentication fields",
        "up_sql": """
        CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE INDEX idx_users_username ON users(username);
        CREATE INDEX idx_users_email ON users(email);
        """,
        "down_sql": """
        DROP INDEX IF EXISTS idx_users_email;
        DROP INDEX IF EXISTS idx_users_username;
        DROP TABLE IF EXISTS users;
        """
    },
    {
        "version": "20240101_000002",
        "name": "create_messages_table",
        "description": "Create messages table for chat functionality",
        "up_sql": """
        CREATE TABLE messages (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            channel_id VARCHAR(255) NOT NULL,
            content TEXT NOT NULL,
            message_type VARCHAR(50) DEFAULT 'text',
            metadata JSONB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE INDEX idx_messages_user_id ON messages(user_id);
        CREATE INDEX idx_messages_channel_id ON messages(channel_id);
        CREATE INDEX idx_messages_created_at ON messages(created_at);
        """,
        "down_sql": """
        DROP INDEX IF EXISTS idx_messages_created_at;
        DROP INDEX IF EXISTS idx_messages_channel_id;
        DROP INDEX IF EXISTS idx_messages_user_id;
        DROP TABLE IF EXISTS messages;
        """
    }
]

async def create_initial_migrations():
    """Create initial migration files if they don't exist."""
    migrations_dir = Path("migrations")
    
    for migration_data in INITIAL_MIGRATIONS:
        filename = f"{migration_data['version']}_{migration_data['name']}.json"
        filepath = migrations_dir / filename
        
        if not filepath.exists():
            migration_data["created_at"] = datetime.now().isoformat()
            migration_data["dependencies"] = []
            
            # Calculate checksum
            content = f"{migration_data['up_sql']}{migration_data['down_sql']}"
            migration_data["checksum"] = hashlib.sha256(content.encode()).hexdigest()
            
            migrations_dir.mkdir(parents=True, exist_ok=True)
            
            with open(filepath, 'w') as f:
                json.dump(migration_data, f, indent=2)
            
            logger.info(f"Created initial migration: {filename}")

__all__ = [
    'Migration', 'MigrationManager', 'migration_manager',
    'create_initial_migrations'
]
