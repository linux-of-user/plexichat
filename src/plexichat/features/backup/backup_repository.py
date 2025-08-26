"""
Enhanced Backup Repository - Advanced metadata management with indexing and analytics
"""

import asyncio
import hashlib
import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import asdict
from contextlib import asynccontextmanager

# Import backup types
try:
    from plexichat.features.backup.backup_engine import BackupMetadata, BackupStatus, BackupType, SecurityLevel
except ImportError:
    # Fallback for circular import issues
    BackupMetadata = Any
    BackupStatus = str
    BackupType = str
    SecurityLevel = str

logger = logging.getLogger(__name__)


class BackupRepository:
    """
    Advanced repository for backup metadata with enterprise features,
    integrated with the unified database and caching systems.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logger

        try:
            from plexichat.core.database.manager import database_manager
            self.db_manager = database_manager
        except ImportError:
            self.db_manager = None
            self.logger.error("Failed to import database_manager. Backup repository will be non-functional.")

        # Caching - using unified cache now
        try:
            from plexichat.core.caching.unified_cache_integration import cache_get, cache_set, cache_delete
            self.cache_get = cache_get
            self.cache_set = cache_set
            self.cache_delete = cache_delete
        except ImportError:
            self.cache_get = None
            self.cache_set = None
            self.cache_delete = None
            self.logger.warning("Unified cache not available for backup repository.")

        self.cache_ttl = self.config.get("cache_ttl_seconds", 300)

        # Statistics
        self.repository_stats = {
            "total_backups": 0,
            "total_queries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "failed_operations": 0
        }
        self._db_initialized = False

    async def _initialize_database(self):
        """Initialize the database tables using the unified database manager."""
        if self._db_initialized or not self.db_manager:
            return

        try:
            await self._create_tables()
            self._db_initialized = True
            self.logger.info("Backup repository database tables initialized successfully.")
        except Exception as e:
            self.logger.error(f"Failed to initialize backup repository tables: {e}")
            self._db_initialized = False
            raise

    async def _create_tables(self):
        """Create database tables using the database manager."""
        # Backup metadata table
        schema_metadata = {
            "backup_id": "TEXT PRIMARY KEY",
            "backup_type": "TEXT NOT NULL",
            "security_level": "TEXT NOT NULL",
            "status": "TEXT NOT NULL",
            "user_id": "TEXT",
            "original_size": "INTEGER DEFAULT 0",
            "compressed_size": "INTEGER DEFAULT 0",
            "encrypted_size": "INTEGER DEFAULT 0",
            "compression_ratio": "REAL DEFAULT 0.0",
            "shard_count": "INTEGER DEFAULT 0",
            "checksum": "TEXT",
            "created_at": "TEXT NOT NULL",
            "completed_at": "TEXT",
            "expires_at": "TEXT",
            "tags": "TEXT",
            "metadata": "TEXT",
            "storage_locations": "TEXT",
            "recovery_info": "TEXT",
            "version": "INTEGER DEFAULT 1",
            "last_modified": "TEXT NOT NULL"
        }
        await self.db_manager.ensure_table_exists("backup_metadata", schema_metadata)

        # Backup shards table
        schema_shards = {
            "shard_id": "TEXT PRIMARY KEY",
            "backup_id": "TEXT NOT NULL",
            "shard_index": "INTEGER NOT NULL",
            "total_shards": "INTEGER NOT NULL",
            "size_bytes": "INTEGER NOT NULL",
            "checksum": "TEXT NOT NULL",
            "storage_location": "TEXT NOT NULL",
            "storage_path": "TEXT NOT NULL",
            "created_at": "TEXT NOT NULL",
            "verified_at": "TEXT"
            # FOREIGN KEY would need to be handled by the application logic if not supported by ensure_table_exists
        }
        await self.db_manager.ensure_table_exists("backup_shards", schema_shards)

        # Backup operations log
        schema_operations = {
            "operation_id": "TEXT PRIMARY KEY",
            "backup_id": "TEXT",
            "operation_type": "TEXT NOT NULL",
            "status": "TEXT NOT NULL",
            "started_at": "TEXT NOT NULL",
            "completed_at": "TEXT",
            "duration_seconds": "REAL",
            "user_id": "TEXT",
            "details": "TEXT",
            "error_message": "TEXT"
        }
        await self.db_manager.ensure_table_exists("backup_operations", schema_operations)

        # User quotas table
        schema_quotas = {
            "user_id": "TEXT PRIMARY KEY",
            "quota_bytes": "INTEGER NOT NULL",
            "used_bytes": "INTEGER DEFAULT 0",
            "backup_count": "INTEGER DEFAULT 0",
            "last_backup": "TEXT",
            "created_at": "TEXT NOT NULL",
            "updated_at": "TEXT NOT NULL"
        }
        await self.db_manager.ensure_table_exists("user_quotas", schema_quotas)

        # Backup analytics table
        schema_analytics = {
            "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
            "date": "TEXT NOT NULL",
            "metric_name": "TEXT NOT NULL",
            "metric_value": "REAL NOT NULL",
            "metadata": "TEXT",
            "created_at": "TEXT NOT NULL"
        }
        await self.db_manager.ensure_table_exists("backup_analytics", schema_analytics)

    async def store_backup_metadata_async(self, metadata: Any) -> bool:
        """Store backup metadata using the unified database manager."""
        try:
            await self._initialize_database()  # Ensure tables exist

            if hasattr(metadata, '__dict__'):
                metadata_dict = asdict(metadata) if hasattr(metadata, '__dataclass_fields__') else metadata.__dict__
            else:
                metadata_dict = metadata

            backup_data = {
                'backup_id': metadata_dict.get('backup_id'),
                'backup_type': str(metadata_dict.get('backup_type', '')),
                'security_level': str(metadata_dict.get('security_level', '')),
                'status': str(metadata_dict.get('status', '')),
                'user_id': metadata_dict.get('user_id'),
                'original_size': metadata_dict.get('original_size', 0),
                'compressed_size': metadata_dict.get('compressed_size', 0),
                'encrypted_size': metadata_dict.get('encrypted_size', 0),
                'compression_ratio': metadata_dict.get('compression_ratio', 0.0),
                'shard_count': metadata_dict.get('shard_count', 0),
                'checksum': metadata_dict.get('checksum', ''),
                'created_at': self._safe_datetime_to_string(metadata_dict.get('created_at')),
                'completed_at': self._safe_datetime_to_string(metadata_dict.get('completed_at')),
                'expires_at': self._safe_datetime_to_string(metadata_dict.get('expires_at')),
                'tags': json.dumps(metadata_dict.get('tags', [])),
                'metadata': json.dumps(metadata_dict.get('metadata', {})),
                'storage_locations': json.dumps(metadata_dict.get('storage_locations', [])),
                'recovery_info': json.dumps(metadata_dict.get('recovery_info', {})),
                'version': metadata_dict.get('version', 1),
                'last_modified': datetime.now(timezone.utc).isoformat()
            }

            async with self.db_manager.get_session() as session:
                await session.execute(
                    """
                    INSERT OR REPLACE INTO backup_metadata (
                        backup_id, backup_type, security_level, status, user_id, original_size,
                        compressed_size, encrypted_size, compression_ratio, shard_count, checksum,
                        created_at, completed_at, expires_at, tags, metadata, storage_locations,
                        recovery_info, version, last_modified)
                    VALUES (:backup_id, :backup_type, :security_level, :status, :user_id, :original_size,
                        :compressed_size, :encrypted_size, :compression_ratio, :shard_count, :checksum,
                        :created_at, :completed_at, :expires_at, :tags, :metadata, :storage_locations,
                        :recovery_info, :version, :last_modified)
                    """,
                    backup_data
                )
                await session.commit()

            if self.cache_set:
                await self.cache_set(f"backup_meta_{backup_data['backup_id']}", backup_data, ttl=self.cache_ttl)

            self.repository_stats["total_backups"] += 1
            return True

        except Exception as e:
            self.logger.error(f"Failed to store backup metadata: {str(e)}", exc_info=True)
            self.repository_stats["failed_operations"] += 1
            return False

    async def get_backup_metadata_async(self, backup_id: str) -> Optional[Dict[str, Any]]:
        """Get backup metadata with unified caching and DB manager."""
        try:
            self.repository_stats["total_queries"] += 1

            if self.cache_get:
                cached_data = await self.cache_get(f"backup_meta_{backup_id}")
                if cached_data:
                    self.repository_stats["cache_hits"] += 1
                    return cached_data

            self.repository_stats["cache_misses"] += 1
            await self._initialize_database()

            async with self.db_manager.get_session() as session:
                row = await session.fetchone(
                    "SELECT * FROM backup_metadata WHERE backup_id = :backup_id",
                    {"backup_id": backup_id}
                )

                if row:
                    metadata = dict(row)
                    metadata['tags'] = json.loads(metadata.get('tags', '[]'))
                    metadata['metadata'] = json.loads(metadata.get('metadata', '{}'))
                    metadata['storage_locations'] = json.loads(metadata.get('storage_locations', '[]'))
                    metadata['recovery_info'] = json.loads(metadata.get('recovery_info', '{}'))

                    if self.cache_set:
                        await self.cache_set(f"backup_meta_{backup_id}", metadata, ttl=self.cache_ttl)
                    return metadata

                return None
        except Exception as e:
            self.logger.error(f"Failed to get backup metadata for {backup_id}: {str(e)}", exc_info=True)
            self.repository_stats["failed_operations"] += 1
            return None

    async def list_backups_async(self, filters: Optional[Dict[str, Any]] = None,
                               limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List backups with advanced filtering using the unified DB manager."""
        try:
            await self._initialize_database()
            self.repository_stats["total_queries"] += 1

            params = {}
            where_clauses = []
            if filters:
                for key, value in filters.items():
                    if key in ['user_id', 'status', 'backup_type']:
                        where_clauses.append(f"{key} = :{key}")
                        params[key] = value
                    elif key == 'created_after':
                        where_clauses.append("created_at > :created_after")
                        params['created_after'] = value
                    elif key == 'created_before':
                        where_clauses.append("created_at < :created_before")
                        params['created_before'] = value

            where_clause = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
            query = f"SELECT * FROM backup_metadata {where_clause} ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
            params['limit'] = limit
            params['offset'] = offset

            async with self.db_manager.get_session() as session:
                rows = await session.fetchall(query, params)

                backups = []
                for row in rows:
                    metadata = dict(row)
                    metadata['tags'] = json.loads(metadata.get('tags', '[]'))
                    metadata['metadata'] = json.loads(metadata.get('metadata', '{}'))
                    metadata['storage_locations'] = json.loads(metadata.get('storage_locations', '[]'))
                    metadata['recovery_info'] = json.loads(metadata.get('recovery_info', '{}'))
                    backups.append(metadata)
                return backups

        except Exception as e:
            self.logger.error(f"Failed to list backups: {str(e)}", exc_info=True)
            self.repository_stats["failed_operations"] += 1
            return []

    async def delete_backup_metadata_async(self, backup_id: str) -> bool:
        """Delete backup metadata from the unified database."""
        try:
            await self._initialize_database()
            async with self.db_manager.get_session() as session:
                await session.delete("backup_shards", where={"backup_id": backup_id})
                await session.delete("backup_operations", where={"backup_id": backup_id})
                await session.delete("backup_metadata", where={"backup_id": backup_id})
                await session.commit()

            if self.cache_delete:
                await self.cache_delete(f"backup_meta_{backup_id}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to delete backup metadata for {backup_id}: {str(e)}", exc_info=True)
            self.repository_stats["failed_operations"] += 1
            return False

    async def find_backup_by_hash_async(self, content_hash: str) -> Optional[Dict[str, Any]]:
        """Find backup by content hash using the unified DB manager."""
        try:
            await self._initialize_database()
            query = "SELECT * FROM backup_metadata WHERE checksum = :checksum ORDER BY created_at DESC LIMIT 1"
            params = {"checksum": content_hash}

            async with self.db_manager.get_session() as session:
                row = await session.fetchone(query, params)

                if row:
                    metadata = dict(row)
                    metadata['tags'] = json.loads(metadata.get('tags', '[]'))
                    metadata['metadata'] = json.loads(metadata.get('metadata', '{}'))
                    metadata['storage_locations'] = json.loads(metadata.get('storage_locations', '[]'))
                    metadata['recovery_info'] = json.loads(metadata.get('recovery_info', '{}'))
                    return metadata

                return None
        except Exception as e:
            self.logger.error(f"Failed to find backup by hash: {str(e)}", exc_info=True)
            return None

    async def verify_metadata_async(self, backup_id: str) -> bool:
        """Verify metadata integrity."""
        try:
            metadata = await self.get_backup_metadata_async(backup_id)
            if not metadata:
                return False

            # Basic integrity checks
            required_fields = ['backup_id', 'backup_type', 'status', 'created_at']
            for field in required_fields:
                if not metadata.get(field):
                    return False

            # Check if backup_id matches
            if metadata['backup_id'] != backup_id:
                return False

            return True

        except Exception as e:
            self.logger.error(f"Failed to verify metadata for {backup_id}: {str(e)}")
            return False

    def _safe_datetime_to_string(self, dt: Any) -> Optional[str]:
        """Safely convert datetime to string."""
        if dt is None:
            return None
        if isinstance(dt, datetime):
            return dt.isoformat()
        return str(dt) if dt else None









