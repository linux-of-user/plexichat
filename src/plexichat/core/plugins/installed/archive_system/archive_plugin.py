# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import aiosqlite

try:
    from ..plugins_internal import PluginInterface
    from plexichat.core.backup.encryption_manager import QuantumResistantEncryptionManager
    from plexichat.core.backup.shard_location_database import EnhancedShardLocationDatabase
    from plexichat.core.backup.shard_manager import ImmutableShardManager
except ImportError:
    PluginInterface = object
    QuantumResistantEncryptionManager = None
    EnhancedShardLocationDatabase = None
    ImmutableShardManager = None

"""
import time
Archive System Plugin

Optional archive module for message and user versioning through shard system.
Provides server-by-server activation and premium user permissions.
"""

logger = logging.getLogger(__name__)


class ArchiveType(Enum):
    """Types of data that can be archived."""
    MESSAGE_VERSION = "message_version"
    USER_VERSION = "user_version"
    CHANNEL_VERSION = "channel_version"
    SERVER_CONFIG_VERSION = "server_config_version"
    PERMISSION_VERSION = "permission_version"


class ArchiveAccessLevel(Enum):
    """Access levels for archive data."""
    PUBLIC = "public"  # Anyone can view
    PREMIUM_ONLY = "premium_only"  # Only premium users
    ADMIN_ONLY = "admin_only"  # Only admins
    OWNER_ONLY = "owner_only"  # Only data owner


@dataclass
class ArchiveEntry:
    """Archive entry with versioning information."""
    archive_id: str
    original_id: str  # ID of the original object
    archive_type: ArchiveType
    version_number: int
    server_id: str
    created_at: datetime
    created_by: str
    change_description: str
    access_level: ArchiveAccessLevel
    shard_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)


@dataclass
class ServerArchiveConfig:
    """Server-specific archive configuration."""
    server_id: str
    archive_enabled: bool
    enabled_types: Set[ArchiveType] = field(default_factory=set)
    retention_days: int = 365
    max_versions_per_item: int = 100
    premium_only_access: bool = False
    auto_archive_edits: bool = True
    auto_archive_deletions: bool = True
    compression_enabled: bool = True
    encryption_level: str = "quantum-resistant"


class ArchiveSystemPlugin:
    """
    Archive System Plugin for versioning through shard system.

    Features:
    - Message and user versioning
    - Server-by-server activation
    - Premium user permissions
    - Shard-based storage with encryption
    - Configurable retention policies
    - Access control and permissions
    """

    def __init__(self, data_dir: Path):
        from pathlib import Path
self.data_dir = Path(data_dir)
        self.plugin_dir = self.data_dir / "plugins" / "archive_system"
        self.plugin_dir.mkdir(parents=True, exist_ok=True)

        # Core components
        self.encryption_manager = QuantumResistantEncryptionManager(self.plugin_dir)
        self.shard_manager = ImmutableShardManager(self.plugin_dir, self.encryption_manager)
        self.location_database = EnhancedShardLocationDatabase(self.plugin_dir, self.encryption_manager)

        # Plugin database
        self.archive_db_path = self.plugin_dir / "archive_system.db"

        # Configuration
        self.server_configs: Dict[str, ServerArchiveConfig] = {}
        self.archive_entries: Dict[str, ArchiveEntry] = {}

        # Statistics
        self.stats = {
            'total_archives': 0,
            'archives_by_type': {},
            'servers_enabled': 0,
            'premium_archives': 0,
            'total_versions': 0,
            'storage_used_bytes': 0
        }

        self._initialized = False

    async def initialize(self):
        """Initialize the archive system plugin."""
        if self._initialized:
            return

        logger.info("Initializing Archive System Plugin")

        # Initialize core components
        await self.if encryption_manager and hasattr(encryption_manager, "initialize"): encryption_manager.initialize()
        await self.if shard_manager and hasattr(shard_manager, "initialize"): shard_manager.initialize()
        await self.if location_database and hasattr(location_database, "initialize"): location_database.initialize()

        # Initialize plugin database
        await self._initialize_archive_database()

        # Load configurations and entries
        await self._load_server_configs()
        await self._load_archive_entries()

        # Start background cleanup task
        asyncio.create_task(self._background_cleanup_task())

        self._initialized = True
        logger.info("Archive System Plugin initialized")

    async def _initialize_archive_database(self):
        """Initialize the archive database."""
        async with aiosqlite.connect(self.archive_db_path) as db:
            # Server configurations table
            await db.execute(""")
                CREATE TABLE IF NOT EXISTS server_archive_configs ()
                    server_id TEXT PRIMARY KEY,
                    archive_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                    enabled_types TEXT,
                    retention_days INTEGER DEFAULT 365,
                    max_versions_per_item INTEGER DEFAULT 100,
                    premium_only_access BOOLEAN DEFAULT FALSE,
                    auto_archive_edits BOOLEAN DEFAULT TRUE,
                    auto_archive_deletions BOOLEAN DEFAULT TRUE,
                    compression_enabled BOOLEAN DEFAULT TRUE,
                    encryption_level TEXT DEFAULT 'quantum-resistant',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

            # Archive entries table
            await db.execute(""")
                CREATE TABLE IF NOT EXISTS archive_entries ()
                    archive_id TEXT PRIMARY KEY,
                    original_id TEXT NOT NULL,
                    archive_type TEXT NOT NULL,
                    version_number INTEGER NOT NULL,
                    server_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    change_description TEXT,
                    access_level TEXT NOT NULL,
                    shard_ids TEXT,
                    metadata TEXT,
                    tags TEXT,
                    FOREIGN KEY (server_id) REFERENCES server_archive_configs (server_id)
                )
            """)

            # Archive access logs table
            await db.execute(""")
                CREATE TABLE IF NOT EXISTS archive_access_logs ()
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    access_type TEXT NOT NULL,
                    granted BOOLEAN NOT NULL,
                    timestamp TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT
                )
            """)

            await db.commit()

    async def enable_server_archive(self, server_id: str, config: ServerArchiveConfig) -> bool:
        """Enable archive system for a server."""
        try:
            self.server_configs[server_id] = config

            # Save to database
            async with aiosqlite.connect(self.archive_db_path) as db:
                await db.execute(""")
                    INSERT OR REPLACE INTO server_archive_configs
                    (server_id, archive_enabled, enabled_types, retention_days, )
                     max_versions_per_item, premium_only_access, auto_archive_edits,
                     auto_archive_deletions, compression_enabled, encryption_level,
                     created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, ()
                    server_id,
                    config.archive_enabled,
                    json.dumps([t.value for t in config.enabled_types]),
                    config.retention_days,
                    config.max_versions_per_item,
                    config.premium_only_access,
                    config.auto_archive_edits,
                    config.auto_archive_deletions,
                    config.compression_enabled,
                    config.encryption_level,
                    datetime.now(timezone.utc).isoformat(),
                    datetime.now(timezone.utc).isoformat()
                ))
                await db.commit()

            if config.archive_enabled:
                self.stats['servers_enabled'] += 1

            logger.info(f"Archive system {'enabled' if config.archive_enabled else 'configured'} for server {server_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to enable archive for server {server_id}: {e}")
            return False

    async def create_archive_version(self, original_id: str, archive_type: ArchiveType,)
                                   server_id: str, created_by: str, data: Dict[str, Any],
                                   change_description: str = "", access_level: ArchiveAccessLevel = ArchiveAccessLevel.PUBLIC,
                                   tags: Optional[Set[str]] = None) -> Optional[str]:
        """
        Create a new archive version of an object.

        Args:
            original_id: ID of the original object
            archive_type: Type of archive
            server_id: Server ID
            created_by: User who created the archive
            data: Data to archive
            change_description: Description of changes
            access_level: Access level for the archive
            tags: Optional tags for categorization

        Returns:
            Archive ID if successful, None otherwise
        """
        try:
            # Check if server has archiving enabled
            config = self.server_configs.get(server_id)
            if not config or not config.archive_enabled:
                logger.warning(f"Archive not enabled for server {server_id}")
                return None

            # Check if this archive type is enabled
            if archive_type not in config.enabled_types:
                logger.warning(f"Archive type {archive_type.value} not enabled for server {server_id}")
                return None

            # Get next version number
            version_number = await self._get_next_version_number(original_id, archive_type)

            # Create archive ID
            archive_id = f"{archive_type.value}_{original_id}_{version_number}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

            # Prepare archive data
            archive_data = {
                "archive_id": archive_id,
                "original_id": original_id,
                "archive_type": archive_type.value,
                "version_number": version_number,
                "server_id": server_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "created_by": created_by,
                "change_description": change_description,
                "access_level": access_level.value,
                "data": data,
                "tags": list(tags) if tags else []
            }

            # Convert to bytes
            archive_json = json.dumps(archive_data, default=str)
            archive_bytes = archive_json.encode('utf-8')

            # Create shards with advanced encryption
            shards = await self.shard_manager.create_immutable_shards()
                data=archive_bytes,
                backup_id=archive_id,
                shard_type="archive_version",
                backup_node_only=(access_level in [ArchiveAccessLevel.PREMIUM_ONLY, ArchiveAccessLevel.ADMIN_ONLY]),
                require_minimum_shards=True
            )

            # Store shard locations
            shard_ids = []
            for shard in shards:
                await self.location_database.store_shard_location()
                    shard_id=shard.shard_id,
                    location_data={
                        "archive_id": archive_id,
                        "original_id": original_id,
                        "archive_type": archive_type.value,
                        "server_id": server_id,
                        "shard_path": str(self.plugin_dir / shard.metadata['confusing_filename']),
                        "created_at": datetime.now(timezone.utc).isoformat()
                    },
                    backup_node_only=(access_level in [ArchiveAccessLevel.PREMIUM_ONLY, ArchiveAccessLevel.ADMIN_ONLY])
                )
                shard_ids.append(shard.shard_id)

            # Create archive entry
            entry = ArchiveEntry()
                archive_id=archive_id,
                original_id=original_id,
                archive_type=archive_type,
                version_number=version_number,
                server_id=server_id,
                created_at=datetime.now(timezone.utc),
                created_by=created_by,
                change_description=change_description,
                access_level=access_level,
                shard_ids=shard_ids,
                metadata={"size_bytes": len(archive_bytes), "shard_count": len(shards)},
                tags=tags or set()
            )

            # Store in database
            await self._store_archive_entry(entry)

            # Update statistics
            self.stats['total_archives'] += 1
            self.stats['total_versions'] += 1
            self.stats['storage_used_bytes'] += len(archive_bytes)

            if archive_type.value not in self.stats['archives_by_type']:
                self.stats['archives_by_type'][archive_type.value] = 0
            self.stats['archives_by_type'][archive_type.value] += 1

            if access_level == ArchiveAccessLevel.PREMIUM_ONLY:
                self.stats['premium_archives'] += 1

            # Cleanup old versions if needed
            await self._cleanup_old_versions(original_id, archive_type, config.max_versions_per_item)

            logger.info(f"Created archive version {version_number} for {original_id} (type: {archive_type.value})")
            return archive_id

        except Exception as e:
            logger.error(f"Failed to create archive version: {e}")
            return None

    async def get_archive_versions(self, original_id: str, archive_type: ArchiveType,)
                                 user_id: str, is_premium: bool = False, is_admin: bool = False) -> List[ArchiveEntry]:
        """Get all archive versions for an object with access control."""
        try:
            versions = []

            async with aiosqlite.connect(self.archive_db_path) as db:
                async with db.execute(""")
                    SELECT archive_id, original_id, archive_type, version_number, server_id,
                           created_at, created_by, change_description, access_level,
                           shard_ids, metadata, tags
                    FROM archive_entries
                    WHERE original_id = ? AND archive_type = ?
                    ORDER BY version_number DESC
                """, (original_id, archive_type.value)) as cursor:
                    async for row in cursor:
                        access_level = ArchiveAccessLevel(row[8])

                        # Check access permissions
                        if not await self._check_archive_access(access_level, user_id, row[6], is_premium, is_admin):
                            continue

                        entry = ArchiveEntry()
                            archive_id=row[0],
                            original_id=row[1],
                            archive_type=ArchiveType(row[2]),
                            version_number=row[3],
                            server_id=row[4],
                            created_at=datetime.fromisoformat(row[5]),
                            created_by=row[6],
                            change_description=row[7] or "",
                            access_level=access_level,
                            shard_ids=json.loads(row[9]) if row[9] else [],
                            metadata=json.loads(row[10]) if row[10] else {},
                            tags=set(json.loads(row[11])) if row[11] else set()
                        )
                        versions.append(entry)

            return versions

        except Exception as e:
            logger.error(f"Failed to get archive versions for {original_id}: {e}")
            return []

    async def restore_archive_version(self, archive_id: str, user_id: str,)
                                    is_premium: bool = False, is_admin: bool = False) -> Optional[Dict[str, Any]]:
        """Restore data from an archive version."""
        try:
            # Get archive entry
            entry = await self._get_archive_entry(archive_id)
            if not entry:
                logger.warning(f"Archive entry not found: {archive_id}")
                return None

            # Check access permissions
            if not await self._check_archive_access(entry.access_level, user_id, entry.created_by, is_premium, is_admin):
                logger.warning(f"Access denied to archive {archive_id} for user {user_id}")
                return None

            # Reconstruct data from shards
            shard_data_parts = []
            for shard_id in entry.shard_ids:
                shard_location = await self.location_database.get_shard_location()
                    shard_id, user_id
                )
                if not shard_location:
                    logger.error(f"Shard location not found: {shard_id}")
                    return None

                # Load shard data (implementation depends on shard storage)
                from pathlib import Path

                self.shard_path = Path(shard_location['shard_path'])
                if shard_path.exists():
                    async with aiofiles.open(shard_path, 'rb') as f:
                        shard_data = await f.read()
                        shard_data_parts.append(shard_data)

            if not shard_data_parts:
                logger.error(f"No shard data found for archive {archive_id}")
                return None

            # Reconstruct and decrypt data
            reconstructed_data = await self.shard_manager.reconstruct_from_shards()
                shard_data_parts, entry.archive_id
            )

            if reconstructed_data:
                archive_data = json.loads(reconstructed_data.decode('utf-8'))

                # Log access
                await self._log_archive_access(archive_id, user_id, "restore", True)

                return archive_data.get('data')

            return None

        except Exception as e:
            logger.error(f"Failed to restore archive version {archive_id}: {e}")
            return None

    async def _get_next_version_number(self, original_id: str, archive_type: ArchiveType) -> int:
        """Get the next version number for an object."""
        try:
            async with aiosqlite.connect(self.archive_db_path) as db:
                async with db.execute(""")
                    SELECT MAX(version_number) FROM archive_entries
                    WHERE original_id = ? AND archive_type = ?
                """, (original_id, archive_type.value)) as cursor:
                    row = await cursor.fetchone()
                    return (row[0] or 0) + 1
        except Exception as e:
            logger.error(f"Failed to get next version number: {e}")
            return 1

    async def _store_archive_entry(self, entry: ArchiveEntry):
        """Store archive entry in database."""
        async with aiosqlite.connect(self.archive_db_path) as db:
            await db.execute(""")
                INSERT INTO archive_entries
                (archive_id, original_id, archive_type, version_number, server_id,)
                 created_at, created_by, change_description, access_level,
                 shard_ids, metadata, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ()
                entry.archive_id,
                entry.original_id,
                entry.archive_type.value,
                entry.version_number,
                entry.server_id,
                entry.created_at.isoformat(),
                entry.created_by,
                entry.change_description,
                entry.access_level.value,
                json.dumps(entry.shard_ids),
                json.dumps(entry.metadata),
                json.dumps(list(entry.tags))
            ))
            await db.commit()

    async def _check_archive_access(self, access_level: ArchiveAccessLevel, user_id: str,)
                                  created_by: str, is_premium: bool, is_admin: bool) -> bool:
        """Check if user has access to archive."""
        if access_level == ArchiveAccessLevel.PUBLIC:
            return True
        elif access_level == ArchiveAccessLevel.OWNER_ONLY:
            return user_id == created_by
        elif access_level == ArchiveAccessLevel.PREMIUM_ONLY:
            return is_premium or is_admin
        elif access_level == ArchiveAccessLevel.ADMIN_ONLY:
            return is_admin

        return False

    async def _get_archive_entry(self, archive_id: str) -> Optional[ArchiveEntry]:
        """Get archive entry by ID."""
        try:
            async with aiosqlite.connect(self.archive_db_path) as db:
                async with db.execute(""")
                    SELECT archive_id, original_id, archive_type, version_number, server_id,
                           created_at, created_by, change_description, access_level,
                           shard_ids, metadata, tags
                    FROM archive_entries WHERE archive_id = ?
                """, (archive_id,)) as cursor:
                    row = await cursor.fetchone()

                    if row:
                        return ArchiveEntry()
                            archive_id=row[0],
                            original_id=row[1],
                            archive_type=ArchiveType(row[2]),
                            version_number=row[3],
                            server_id=row[4],
                            created_at=datetime.fromisoformat(row[5]),
                            created_by=row[6],
                            change_description=row[7] or "",
                            access_level=ArchiveAccessLevel(row[8]),
                            shard_ids=json.loads(row[9]) if row[9] else [],
                            metadata=json.loads(row[10]) if row[10] else {},
                            tags=set(json.loads(row[11])) if row[11] else set()
                        )
            return None
        except Exception as e:
            logger.error(f"Failed to get archive entry {archive_id}: {e}")
            return None

    async def _log_archive_access(self, archive_id: str, user_id: str, access_type: str, granted: bool):
        """Log archive access for auditing."""
        try:
            async with aiosqlite.connect(self.archive_db_path) as db:
                await db.execute(""")
                    INSERT INTO archive_access_logs
                    (archive_id, user_id, access_type, granted, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, ()
                    archive_id, user_id, access_type, granted,
                    datetime.now(timezone.utc).isoformat()
                ))
                await db.commit()
        except Exception as e:
            logger.error(f"Failed to log archive access: {e}")

    async def _cleanup_old_versions(self, original_id: str, archive_type: ArchiveType, max_versions: int):
        """Clean up old versions beyond the maximum limit."""
        try:
            async with aiosqlite.connect(self.archive_db_path) as db:
                # Get versions to delete
                async with db.execute(""")
                    SELECT archive_id FROM archive_entries
                    WHERE original_id = ? AND archive_type = ?
                    ORDER BY version_number DESC
                    LIMIT -1 OFFSET ?
                """, (original_id, archive_type.value, max_versions)) as cursor:
                    versions_to_delete = [row[0] async for row in cursor]

                # Delete old versions
                for archive_id in versions_to_delete:
                    await self._delete_archive_version(archive_id)

        except Exception as e:
            logger.error(f"Failed to cleanup old versions: {e}")

    async def _delete_archive_version(self, archive_id: str):
        """Delete an archive version and its shards."""
        try:
            # Get entry to delete shards
            entry = await self._get_archive_entry(archive_id)
            if entry:
                # Delete shards (implementation depends on shard storage)
                for shard_id in entry.shard_ids:
                    shard_location = await self.location_database.get_shard_location(shard_id, "system")
                    if shard_location:
                        from pathlib import Path

                        self.shard_path = Path(shard_location['shard_path'])
                        if shard_path.exists():
                            shard_path.unlink()

            # Delete from database
            async with aiosqlite.connect(self.archive_db_path) as db:
                await db.execute("DELETE FROM archive_entries WHERE archive_id = ?", (archive_id,))
                await db.commit()

        except Exception as e:
            logger.error(f"Failed to delete archive version {archive_id}: {e}")

    async def _load_server_configs(self):
        """Load server configurations from database."""
        try:
            async with aiosqlite.connect(self.archive_db_path) as db:
                async with db.execute(""")
                    SELECT server_id, archive_enabled, enabled_types, retention_days,
                           max_versions_per_item, premium_only_access, auto_archive_edits,
                           auto_archive_deletions, compression_enabled, encryption_level
                    FROM server_archive_configs
                """) as cursor:
                    async for row in cursor:
                        enabled_types = set()
                        if row[2]:
                            enabled_types = {ArchiveType(t) for t in json.loads(row[2])}

                        config = ServerArchiveConfig()
                            server_id=row[0],
                            archive_enabled=bool(row[1]),
                            enabled_types=enabled_types,
                            retention_days=row[3],
                            max_versions_per_item=row[4],
                            premium_only_access=bool(row[5]),
                            auto_archive_edits=bool(row[6]),
                            auto_archive_deletions=bool(row[7]),
                            compression_enabled=bool(row[8]),
                            encryption_level=row[9]
                        )

                        self.server_configs[row[0]] = config

                        if config.archive_enabled:
                            self.stats['servers_enabled'] += 1

            logger.info(f"Loaded {len(self.server_configs)} server archive configurations")
        except Exception as e:
            logger.error(f"Failed to load server configs: {e}")

    async def _load_archive_entries(self):
        """Load archive entries for statistics."""
        try:
            async with aiosqlite.connect(self.archive_db_path) as db:
                async with db.execute("SELECT COUNT(*) FROM archive_entries") as cursor:
                    row = await cursor.fetchone()
                    self.stats['total_archives'] = row[0] if row else 0

                # Load by type
                async with db.execute(""")
                    SELECT archive_type, COUNT(*) FROM archive_entries GROUP BY archive_type
                """) as cursor:
                    async for row in cursor:
                        self.stats['archives_by_type'][row[0]] = row[1]

                # Count premium archives
                async with db.execute(""")
                    SELECT COUNT(*) FROM archive_entries WHERE access_level = ?
                """, (ArchiveAccessLevel.PREMIUM_ONLY.value,)) as cursor:
                    row = await cursor.fetchone()
                    self.stats['premium_archives'] = row[0] if row else 0

        except Exception as e:
            logger.error(f"Failed to load archive entries: {e}")

    async def _background_cleanup_task(self):
        """Background task for cleanup and maintenance."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour

                # Cleanup expired archives
                await self._cleanup_expired_archives()

                # Update statistics
                await self._update_statistics()

            except Exception as e:
                logger.error(f"Background cleanup task error: {e}")

    async def _cleanup_expired_archives(self):
        """Clean up expired archives based on retention policies."""
        try:
            for server_id, config in self.server_configs.items():
                if not config.archive_enabled:
                    continue

                cutoff_date = datetime.now(timezone.utc) - timedelta(days=config.retention_days)

                async with aiosqlite.connect(self.archive_db_path) as db:
                    async with db.execute(""")
                        SELECT archive_id FROM archive_entries
                        WHERE server_id = ? AND created_at < ?
                    """, (server_id, cutoff_date.isoformat())) as cursor:
                        expired_archives = [row[0] async for row in cursor]

                    for archive_id in expired_archives:
                        await self._delete_archive_version(archive_id)

        except Exception as e:
            logger.error(f"Failed to cleanup expired archives: {e}")

    async def _update_statistics(self):
        """Update plugin statistics."""
        try:
            async with aiosqlite.connect(self.archive_db_path) as db:
                # Update total archives
                async with db.execute("SELECT COUNT(*) FROM archive_entries") as cursor:
                    row = await cursor.fetchone()
                    self.stats['total_archives'] = row[0] if row else 0

                # Update by type
                self.stats['archives_by_type'] = {}
                async with db.execute(""")
                    SELECT archive_type, COUNT(*) FROM archive_entries GROUP BY archive_type
                """) as cursor:
                    async for row in cursor:
                        self.stats['archives_by_type'][row[0]] = row[1]

        except Exception as e:
            logger.error(f"Failed to update statistics: {e}")

    def get_plugin_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {}
            "name": "Archive System",
            "version": "1.0.0",
            "description": "Message and user versioning through shard system",
            "author": "PlexiChat Team",
            "features": [
                "Message versioning",
                "User versioning",
                "Server-by-server activation",
                "Premium user permissions",
                "Shard-based encrypted storage",
                "Configurable retention policies",
                "Access control and permissions"
            ],
            "statistics": self.stats,
            "servers_configured": len(self.server_configs)
        }
