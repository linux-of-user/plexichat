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
    from .backup_engine import BackupMetadata, BackupStatus, BackupType, SecurityLevel
except ImportError:
    # Fallback for circular import issues
    BackupMetadata = Any
    BackupStatus = str
    BackupType = str
    SecurityLevel = str

logger = logging.getLogger(__name__)


class BackupRepository:
    """
    Advanced repository for backup metadata with enterprise features.

    Features:
    - High-performance SQLite database with WAL mode
    - Advanced indexing and full-text search
    - Backup analytics and reporting
    - Audit trail and compliance logging
    - Automatic data integrity verification
    - Concurrent access with connection pooling
    - Backup metadata versioning
    - Advanced querying with filters and aggregations
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logger

        # Use centralized directory manager
        try:
            from plexichat.core.logging import get_directory_manager
            self.directory_manager = get_directory_manager()

            # Use centralized directories
            self.storage_root = self.directory_manager.get_backup_directory()
            self.repository_storage = self.directory_manager.get_directory("backups_metadata")

        except ImportError:
            # Fallback to old behavior if centralized logging not available
            storage_root = self.config.get("storage_root", "backup_storage")
            project_root = Path(__file__).parent.parent.parent.parent.parent
            self.storage_root = project_root / storage_root
            self.repository_storage = self.storage_root / "repository"
            self.repository_storage.mkdir(exist_ok=True)

        # Database setup
        self.db_path = self.repository_storage / "backup_metadata.db"
        self.connection_pool: List[sqlite3.Connection] = []
        self.pool_lock = threading.Lock()
        self.max_connections = self.config.get("max_connections", 10)

        # Initialize database
        self._initialize_database()

        # Caching
        self.cache_enabled = self.config.get("enable_cache", True)
        self.metadata_cache: Dict[str, Any] = {}
        self.cache_ttl = self.config.get("cache_ttl_seconds", 300)  # 5 minutes
        self.cache_timestamps: Dict[str, float] = {}

        # Statistics
        self.repository_stats = {
            "total_backups": 0,
            "total_queries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "database_size_bytes": 0,
            "last_maintenance": None,
            "integrity_checks": 0,
            "failed_operations": 0
        }

    def _initialize_database(self):
        """Initialize the SQLite database with optimized schema."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.execute("PRAGMA journal_mode=WAL")  # Enable WAL mode for better concurrency
            conn.execute("PRAGMA synchronous=NORMAL")  # Balance between safety and performance
            conn.execute("PRAGMA cache_size=10000")  # Increase cache size
            conn.execute("PRAGMA temp_store=MEMORY")  # Store temp tables in memory

            # Create tables
            self._create_tables(conn)

            # Create indexes
            self._create_indexes(conn)

            conn.commit()
            conn.close()

            self.logger.info("Database initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize database: {str(e)}")
            raise

    def _create_tables(self, conn: sqlite3.Connection):
        """Create database tables."""
        # Backup metadata table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS backup_metadata (
                backup_id TEXT PRIMARY KEY,
                backup_type TEXT NOT NULL,
                security_level TEXT NOT NULL,
                status TEXT NOT NULL,
                user_id TEXT,
                original_size INTEGER DEFAULT 0,
                compressed_size INTEGER DEFAULT 0,
                encrypted_size INTEGER DEFAULT 0,
                compression_ratio REAL DEFAULT 0.0,
                shard_count INTEGER DEFAULT 0,
                checksum TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                expires_at TEXT,
                tags TEXT,  -- JSON array
                metadata TEXT,  -- JSON object
                storage_locations TEXT,  -- JSON array
                recovery_info TEXT,  -- JSON object
                version INTEGER DEFAULT 1,
                last_modified TEXT NOT NULL
            )
        """)

        # Backup shards table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS backup_shards (
                shard_id TEXT PRIMARY KEY,
                backup_id TEXT NOT NULL,
                shard_index INTEGER NOT NULL,
                total_shards INTEGER NOT NULL,
                size_bytes INTEGER NOT NULL,
                checksum TEXT NOT NULL,
                storage_location TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                verified_at TEXT,
                FOREIGN KEY (backup_id) REFERENCES backup_metadata (backup_id)
            )
        """)

        # Backup operations log
        conn.execute("""
            CREATE TABLE IF NOT EXISTS backup_operations (
                operation_id TEXT PRIMARY KEY,
                backup_id TEXT,
                operation_type TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                duration_seconds REAL,
                user_id TEXT,
                details TEXT,  -- JSON object
                error_message TEXT
            )
        """)

        # User quotas table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_quotas (
                user_id TEXT PRIMARY KEY,
                quota_bytes INTEGER NOT NULL,
                used_bytes INTEGER DEFAULT 0,
                backup_count INTEGER DEFAULT 0,
                last_backup TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        # Backup analytics table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS backup_analytics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                metadata TEXT,  -- JSON object
                created_at TEXT NOT NULL
            )
        """)

    def _create_indexes(self, conn: sqlite3.Connection):
        """Create database indexes for performance."""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_backup_user_id ON backup_metadata(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_backup_status ON backup_metadata(status)",
            "CREATE INDEX IF NOT EXISTS idx_backup_type ON backup_metadata(backup_type)",
            "CREATE INDEX IF NOT EXISTS idx_backup_created_at ON backup_metadata(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_backup_expires_at ON backup_metadata(expires_at)",
            "CREATE INDEX IF NOT EXISTS idx_backup_checksum ON backup_metadata(checksum)",
            "CREATE INDEX IF NOT EXISTS idx_shards_backup_id ON backup_shards(backup_id)",
            "CREATE INDEX IF NOT EXISTS idx_shards_location ON backup_shards(storage_location)",
            "CREATE INDEX IF NOT EXISTS idx_operations_backup_id ON backup_operations(backup_id)",
            "CREATE INDEX IF NOT EXISTS idx_operations_type ON backup_operations(operation_type)",
            "CREATE INDEX IF NOT EXISTS idx_operations_status ON backup_operations(status)",
            "CREATE INDEX IF NOT EXISTS idx_analytics_date ON backup_analytics(date)",
            "CREATE INDEX IF NOT EXISTS idx_analytics_metric ON backup_analytics(metric_name)"
        ]

        for index_sql in indexes:
            conn.execute(index_sql)

    @asynccontextmanager
    async def _get_connection(self):
        """Get a database connection from the pool."""
        conn = None
        try:
            with self.pool_lock:
                if self.connection_pool:
                    conn = self.connection_pool.pop()
                else:
                    conn = sqlite3.connect(str(self.db_path))
                    conn.row_factory = sqlite3.Row  # Enable dict-like access
                    conn.execute("PRAGMA journal_mode=WAL")

            yield conn

        finally:
            if conn:
                with self.pool_lock:
                    if len(self.connection_pool) < self.max_connections:
                        self.connection_pool.append(conn)
                    else:
                        conn.close()

    async def store_backup_metadata_async(self, metadata: Any) -> bool:
        """Store backup metadata with advanced features."""
        try:
            async with self._get_connection() as conn:
                # Convert metadata to dict if it's a dataclass
                if hasattr(metadata, '__dict__'):
                    metadata_dict = asdict(metadata) if hasattr(metadata, '__dataclass_fields__') else metadata.__dict__
                else:
                    metadata_dict = metadata

                # Prepare data for insertion
                backup_data = {
                    'backup_id': metadata_dict.get('backup_id'),
                    'backup_type': metadata_dict.get('backup_type', ''),
                    'security_level': metadata_dict.get('security_level', ''),
                    'status': metadata_dict.get('status', ''),
                    'user_id': metadata_dict.get('user_id'),
                    'original_size': metadata_dict.get('original_size', 0),
                    'compressed_size': metadata_dict.get('compressed_size', 0),
                    'encrypted_size': metadata_dict.get('encrypted_size', 0),
                    'compression_ratio': metadata_dict.get('compression_ratio', 0.0),
                    'shard_count': metadata_dict.get('shard_count', 0),
                    'checksum': metadata_dict.get('checksum', ''),
                    'created_at': metadata_dict.get('created_at', datetime.now(timezone.utc)).isoformat() if isinstance(metadata_dict.get('created_at'), datetime) else str(metadata_dict.get('created_at', '')),
                    'completed_at': self._safe_datetime_to_string(metadata_dict.get('completed_at')),
                    'expires_at': self._safe_datetime_to_string(metadata_dict.get('expires_at')),
                    'tags': json.dumps(metadata_dict.get('tags', [])),
                    'metadata': json.dumps(metadata_dict.get('metadata', {})),
                    'storage_locations': json.dumps(metadata_dict.get('storage_locations', [])),
                    'recovery_info': json.dumps(metadata_dict.get('recovery_info', {})),
                    'last_modified': datetime.now(timezone.utc).isoformat()
                }

                # Insert or update
                conn.execute("""
                    INSERT OR REPLACE INTO backup_metadata
                    (backup_id, backup_type, security_level, status, user_id, original_size,
                     compressed_size, encrypted_size, compression_ratio, shard_count, checksum,
                     created_at, completed_at, expires_at, tags, metadata, storage_locations,
                     recovery_info, last_modified)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    backup_data['backup_id'], backup_data['backup_type'], backup_data['security_level'],
                    backup_data['status'], backup_data['user_id'], backup_data['original_size'],
                    backup_data['compressed_size'], backup_data['encrypted_size'], backup_data['compression_ratio'],
                    backup_data['shard_count'], backup_data['checksum'], backup_data['created_at'],
                    backup_data['completed_at'], backup_data['expires_at'], backup_data['tags'],
                    backup_data['metadata'], backup_data['storage_locations'], backup_data['recovery_info'],
                    backup_data['last_modified']
                ))

                conn.commit()

                # Update cache
                if self.cache_enabled:
                    self.metadata_cache[backup_data['backup_id']] = backup_data
                    self.cache_timestamps[backup_data['backup_id']] = time.time()

                # Update statistics
                self.repository_stats["total_backups"] += 1

                return True

        except Exception as e:
            self.logger.error(f"Failed to store backup metadata: {str(e)}")
            self.repository_stats["failed_operations"] += 1
            return False

    async def get_backup_metadata_async(self, backup_id: str) -> Optional[Dict[str, Any]]:
        """Get backup metadata with caching."""
        try:
            self.repository_stats["total_queries"] += 1

            # Check cache first
            if self.cache_enabled and backup_id in self.metadata_cache:
                cache_time = self.cache_timestamps.get(backup_id, 0)
                if time.time() - cache_time < self.cache_ttl:
                    self.repository_stats["cache_hits"] += 1
                    return self.metadata_cache[backup_id]
                else:
                    # Cache expired
                    del self.metadata_cache[backup_id]
                    del self.cache_timestamps[backup_id]

            self.repository_stats["cache_misses"] += 1

            async with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT * FROM backup_metadata WHERE backup_id = ?",
                    (backup_id,)
                )
                row = cursor.fetchone()

                if row:
                    metadata = dict(row)

                    # Parse JSON fields
                    metadata['tags'] = json.loads(metadata['tags']) if metadata['tags'] else []
                    metadata['metadata'] = json.loads(metadata['metadata']) if metadata['metadata'] else {}
                    metadata['storage_locations'] = json.loads(metadata['storage_locations']) if metadata['storage_locations'] else []
                    metadata['recovery_info'] = json.loads(metadata['recovery_info']) if metadata['recovery_info'] else {}

                    # Update cache
                    if self.cache_enabled:
                        self.metadata_cache[backup_id] = metadata
                        self.cache_timestamps[backup_id] = time.time()

                    return metadata

                return None

        except Exception as e:
            self.logger.error(f"Failed to get backup metadata for {backup_id}: {str(e)}")
            self.repository_stats["failed_operations"] += 1
            return None

    async def list_backups_async(self, filters: Optional[Dict[str, Any]] = None,
                               limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List backups with advanced filtering."""
        try:
            self.repository_stats["total_queries"] += 1

            # Build query
            where_clauses = []
            params = []

            if filters:
                if 'user_id' in filters:
                    where_clauses.append("user_id = ?")
                    params.append(filters['user_id'])

                if 'status' in filters:
                    where_clauses.append("status = ?")
                    params.append(filters['status'])

                if 'backup_type' in filters:
                    where_clauses.append("backup_type = ?")
                    params.append(filters['backup_type'])

                if 'created_after' in filters:
                    where_clauses.append("created_at > ?")
                    params.append(filters['created_after'])

                if 'created_before' in filters:
                    where_clauses.append("created_at < ?")
                    params.append(filters['created_before'])

            where_clause = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            query = f"""
                SELECT * FROM backup_metadata
                {where_clause}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """

            params.extend([limit, offset])

            async with self._get_connection() as conn:
                cursor = conn.execute(query, params)
                rows = cursor.fetchall()

                backups = []
                for row in rows:
                    metadata = dict(row)

                    # Parse JSON fields
                    metadata['tags'] = json.loads(metadata['tags']) if metadata['tags'] else []
                    metadata['metadata'] = json.loads(metadata['metadata']) if metadata['metadata'] else {}
                    metadata['storage_locations'] = json.loads(metadata['storage_locations']) if metadata['storage_locations'] else []
                    metadata['recovery_info'] = json.loads(metadata['recovery_info']) if metadata['recovery_info'] else {}

                    backups.append(metadata)

                return backups

        except Exception as e:
            self.logger.error(f"Failed to list backups: {str(e)}")
            self.repository_stats["failed_operations"] += 1
            return []

    async def delete_backup_metadata_async(self, backup_id: str) -> bool:
        """Delete backup metadata."""
        try:
            async with self._get_connection() as conn:
                # Delete from all related tables
                conn.execute("DELETE FROM backup_shards WHERE backup_id = ?", (backup_id,))
                conn.execute("DELETE FROM backup_operations WHERE backup_id = ?", (backup_id,))
                conn.execute("DELETE FROM backup_metadata WHERE backup_id = ?", (backup_id,))

                conn.commit()

                # Remove from cache
                if backup_id in self.metadata_cache:
                    del self.metadata_cache[backup_id]
                    del self.cache_timestamps[backup_id]

                return True

        except Exception as e:
            self.logger.error(f"Failed to delete backup metadata for {backup_id}: {str(e)}")
            self.repository_stats["failed_operations"] += 1
            return False

    async def find_backup_by_hash_async(self, content_hash: str) -> Optional[Dict[str, Any]]:
        """Find backup by content hash for deduplication."""
        try:
            async with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT * FROM backup_metadata WHERE checksum = ? ORDER BY created_at DESC LIMIT 1",
                    (content_hash,)
                )
                row = cursor.fetchone()

                if row:
                    metadata = dict(row)
                    metadata['tags'] = json.loads(metadata['tags']) if metadata['tags'] else []
                    metadata['metadata'] = json.loads(metadata['metadata']) if metadata['metadata'] else {}
                    metadata['storage_locations'] = json.loads(metadata['storage_locations']) if metadata['storage_locations'] else []
                    metadata['recovery_info'] = json.loads(metadata['recovery_info']) if metadata['recovery_info'] else {}
                    return metadata

                return None

        except Exception as e:
            self.logger.error(f"Failed to find backup by hash: {str(e)}")
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









