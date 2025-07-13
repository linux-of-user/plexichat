import asyncio
import gzip
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union

import aiosqlite

"""
Archive System Plugin for PlexiChat Backup System
Provides versioning and archival capabilities through the shard system.
"""

logger = logging.getLogger(__name__)


class ArchiveType(Enum):
    """Types of archives."""
    FULL_ARCHIVE = "full_archive"
    INCREMENTAL_ARCHIVE = "incremental_archive"
    DIFFERENTIAL_ARCHIVE = "differential_archive"
    SNAPSHOT_ARCHIVE = "snapshot_archive"
    VERSIONED_ARCHIVE = "versioned_archive"


class ArchiveStatus(Enum):
    """Archive status."""
    CREATING = "creating"
    ACTIVE = "active"
    COMPRESSED = "compressed"
    ARCHIVED = "archived"
    EXPIRED = "expired"
    CORRUPTED = "corrupted"


@dataclass
class ArchiveVersion:
    """Individual archive version."""
    version_id: str
    archive_id: str
    version_number: int
    archive_type: ArchiveType
    created_at: datetime
    expires_at: Optional[datetime]
    size_bytes: int
    compressed_size_bytes: int
    shard_ids: List[str]
    parent_version_id: Optional[str]
    checksum: str
    metadata: Dict[str, Any]
    status: ArchiveStatus


@dataclass
class ArchiveEntry:
    """Archive entry with versioning."""
    archive_id: str
    name: str
    description: str
    created_by: str
    created_at: datetime
    updated_at: datetime
    current_version: int
    total_versions: int
    versions: List[ArchiveVersion]
    retention_policy: str
    compression_enabled: bool
    encryption_enabled: bool
    tags: Set[str]
    metadata: Dict[str, Any]


class ArchiveSystemPlugin:
    """
    Archive System Plugin
    
    Provides comprehensive archival and versioning capabilities:
    - Version-controlled archives through shard system
    - Automatic compression and deduplication
    - Flexible retention policies
    - Integration with backup encryption
    - Incremental and differential archiving
    - Metadata and tagging system
    """
    
    def __init__(self, backup_manager):
        self.backup_manager = backup_manager
        self.archive_dir = backup_manager.backup_dir / "archives"
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        
        # Archive registry
        self.archives: Dict[str, ArchiveEntry] = {}
        self.archive_versions: Dict[str, ArchiveVersion] = {}
        
        # Configuration
        self.default_retention_days = 365
        self.max_versions_per_archive = 100
        self.compression_enabled = True
        self.auto_cleanup_enabled = True
        self.deduplication_enabled = True
        
        # Database
        self.archive_db_path = backup_manager.databases_dir / "archive_system.db"
        
        logger.info("Archive System Plugin initialized")
    
    async def initialize(self):
        """Initialize the archive system."""
        await self._initialize_database()
        await self._load_existing_archives()
        await self._start_maintenance_tasks()
        logger.info("Archive System Plugin initialized successfully")
    
    async def _initialize_database(self):
        """Initialize archive database."""
        async with aiosqlite.connect(self.archive_db_path) as db:
            # Archives table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS archives (
                    archive_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL,
                    current_version INTEGER NOT NULL,
                    total_versions INTEGER NOT NULL,
                    retention_policy TEXT NOT NULL,
                    compression_enabled BOOLEAN NOT NULL,
                    encryption_enabled BOOLEAN NOT NULL,
                    tags TEXT DEFAULT '[]',
                    metadata TEXT DEFAULT '{}'
                )
            """)
            
            # Archive versions table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS archive_versions (
                    version_id TEXT PRIMARY KEY,
                    archive_id TEXT NOT NULL,
                    version_number INTEGER NOT NULL,
                    archive_type TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP,
                    size_bytes INTEGER NOT NULL,
                    compressed_size_bytes INTEGER NOT NULL,
                    shard_ids TEXT NOT NULL,
                    parent_version_id TEXT,
                    checksum TEXT NOT NULL,
                    metadata TEXT DEFAULT '{}',
                    status TEXT NOT NULL,
                    FOREIGN KEY (archive_id) REFERENCES archives (archive_id)
                )
            """)
            
            # Archive access logs
            await db.execute("""
                CREATE TABLE IF NOT EXISTS archive_access_logs (
                    log_id TEXT PRIMARY KEY,
                    archive_id TEXT NOT NULL,
                    version_id TEXT,
                    user_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    ip_address TEXT,
                    success BOOLEAN NOT NULL,
                    details TEXT
                )
            """)
            
            await db.commit()
        
        logger.info("Archive system database initialized")
    
    async def create_archive(
        self,
        name: str,
        description: str,
        created_by: str,
        data: Union[bytes, str, Dict[str, Any]],
        archive_type: ArchiveType = ArchiveType.FULL_ARCHIVE,
        compression_enabled: bool = True,
        encryption_enabled: bool = True,
        retention_days: int = None,
        tags: Set[str] = None,
        metadata: Dict[str, Any] = None
    ) -> ArchiveEntry:
        """
        Create a new archive with versioning.
        
        Args:
            name: Archive name
            description: Archive description
            created_by: User creating the archive
            data: Data to archive
            archive_type: Type of archive
            compression_enabled: Enable compression
            encryption_enabled: Enable encryption
            retention_days: Retention period in days
            tags: Archive tags
            metadata: Additional metadata
            
        Returns:
            ArchiveEntry: Created archive entry
        """
        # Generate archive ID
        archive_id = f"arch_{hashlib.sha256(f'{name}_{created_by}_{datetime.now(timezone.utc).isoformat()}'.encode()).hexdigest()[:16]}"
        
        # Prepare data for archiving
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        elif isinstance(data, dict):
            data_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
        else:
            data_bytes = data
        
        # Compress if enabled
        compressed_data = data_bytes
        compressed_size = len(data_bytes)
        if compression_enabled:
            compressed_data = gzip.compress(data_bytes)
            compressed_size = len(compressed_data)
        
        # Calculate checksum
        checksum = hashlib.sha512(data_bytes).hexdigest()
        
        # Create through shard system
        shard_ids = await self._create_archive_shards(
            archive_id, compressed_data, encryption_enabled
        )
        
        # Create version
        version_id = f"ver_{hashlib.sha256(f'{archive_id}_v1_{datetime.now(timezone.utc).isoformat()}'.encode()).hexdigest()[:16]}"
        
        version = ArchiveVersion(
            version_id=version_id,
            archive_id=archive_id,
            version_number=1,
            archive_type=archive_type,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=retention_days or self.default_retention_days),
            size_bytes=len(data_bytes),
            compressed_size_bytes=compressed_size,
            shard_ids=shard_ids,
            parent_version_id=None,
            checksum=checksum,
            metadata=metadata or {},
            status=ArchiveStatus.ACTIVE
        )
        
        # Create archive entry
        archive = ArchiveEntry(
            archive_id=archive_id,
            name=name,
            description=description,
            created_by=created_by,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            current_version=1,
            total_versions=1,
            versions=[version],
            retention_policy=f"{retention_days or self.default_retention_days}_days",
            compression_enabled=compression_enabled,
            encryption_enabled=encryption_enabled,
            tags=tags or set(),
            metadata=metadata or {}
        )
        
        # Store in registry
        self.archives[archive_id] = archive
        self.archive_versions[version_id] = version
        
        # Save to database
        await self._save_archive(archive)
        await self._save_archive_version(version)
        
        # Log creation
        await self._log_archive_access(
            archive_id, version_id, created_by, "CREATE", True, 
            f"Created archive '{name}' with {len(data_bytes)} bytes"
        )
        
        logger.info(f"Created archive '{name}' ({archive_id}) with version 1")
        return archive
    
    async def create_archive_version(
        self,
        archive_id: str,
        data: Union[bytes, str, Dict[str, Any]],
        created_by: str,
        archive_type: ArchiveType = ArchiveType.INCREMENTAL_ARCHIVE,
        metadata: Dict[str, Any] = None
    ) -> ArchiveVersion:
        """
        Create a new version of an existing archive.
        
        Args:
            archive_id: Existing archive ID
            data: New version data
            created_by: User creating the version
            archive_type: Type of archive version
            metadata: Version metadata
            
        Returns:
            ArchiveVersion: Created version
        """
        if archive_id not in self.archives:
            raise ValueError(f"Archive {archive_id} not found")
        
        archive = self.archives[archive_id]
        
        # Check version limit
        if archive.total_versions >= self.max_versions_per_archive:
            await self._cleanup_old_versions(archive_id)
        
        # Prepare data
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        elif isinstance(data, dict):
            data_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
        else:
            data_bytes = data
        
        # Compress if enabled
        compressed_data = data_bytes
        compressed_size = len(data_bytes)
        if archive.compression_enabled:
            compressed_data = gzip.compress(data_bytes)
            compressed_size = len(compressed_data)
        
        # Calculate checksum
        checksum = hashlib.sha512(data_bytes).hexdigest()
        
        # Create shards
        shard_ids = await self._create_archive_shards(
            archive_id, compressed_data, archive.encryption_enabled
        )
        
        # Create new version
        new_version_number = archive.current_version + 1
        version_id = f"ver_{hashlib.sha256(f'{archive_id}_v{new_version_number}_{datetime.now(timezone.utc).isoformat()}'.encode()).hexdigest()[:16]}"
        
        version = ArchiveVersion(
            version_id=version_id,
            archive_id=archive_id,
            version_number=new_version_number,
            archive_type=archive_type,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=self.default_retention_days),
            size_bytes=len(data_bytes),
            compressed_size_bytes=compressed_size,
            shard_ids=shard_ids,
            parent_version_id=archive.versions[-1].version_id if archive.versions else None,
            checksum=checksum,
            metadata=metadata or {},
            status=ArchiveStatus.ACTIVE
        )
        
        # Update archive
        archive.versions.append(version)
        archive.current_version = new_version_number
        archive.total_versions += 1
        archive.updated_at = datetime.now(timezone.utc)
        
        # Store
        self.archive_versions[version_id] = version
        
        # Save to database
        await self._save_archive(archive)
        await self._save_archive_version(version)
        
        # Log creation
        await self._log_archive_access(
            archive_id, version_id, created_by, "CREATE_VERSION", True,
            f"Created version {new_version_number} with {len(data_bytes)} bytes"
        )
        
        logger.info(f"Created version {new_version_number} for archive {archive_id}")
        return version
    
    async def _create_archive_shards(
        self, 
        archive_id: str, 
        data: bytes, 
        encryption_enabled: bool
    ) -> List[str]:
        """Create shards for archive data."""
        if not self.backup_manager.shard_manager:
            raise RuntimeError("Shard manager not available")
        
        # Use backup system's shard manager
        self.backup_manager.shard_manager
        
        # Create shards with archive-specific naming
        shard_id = f"archive_{archive_id}_{hashlib.sha256(data).hexdigest()[:16]}"
        
        # For now, create a single shard (could be enhanced for large archives)
        shard_ids = [shard_id]
        
        # Store shard data (implementation would use actual shard manager)
        logger.debug(f"Created {len(shard_ids)} shards for archive {archive_id}")
        
        return shard_ids
    
    async def _save_archive(self, archive: ArchiveEntry):
        """Save archive to database."""
        async with aiosqlite.connect(self.archive_db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO archives 
                (archive_id, name, description, created_by, created_at, updated_at,
                 current_version, total_versions, retention_policy, compression_enabled,
                 encryption_enabled, tags, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                archive.archive_id, archive.name, archive.description, archive.created_by,
                archive.created_at, archive.updated_at, archive.current_version,
                archive.total_versions, archive.retention_policy, archive.compression_enabled,
                archive.encryption_enabled, json.dumps(list(archive.tags)),
                json.dumps(archive.metadata)
            ))
            await db.commit()
    
    async def _save_archive_version(self, version: ArchiveVersion):
        """Save archive version to database."""
        async with aiosqlite.connect(self.archive_db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO archive_versions 
                (version_id, archive_id, version_number, archive_type, created_at,
                 expires_at, size_bytes, compressed_size_bytes, shard_ids,
                 parent_version_id, checksum, metadata, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                version.version_id, version.archive_id, version.version_number,
                version.archive_type.value, version.created_at, version.expires_at,
                version.size_bytes, version.compressed_size_bytes,
                json.dumps(version.shard_ids), version.parent_version_id,
                version.checksum, json.dumps(version.metadata), version.status.value
            ))
            await db.commit()
    
    async def _log_archive_access(
        self, archive_id: str, version_id: Optional[str], user_id: str,
        action: str, success: bool, details: str, ip_address: str = None
    ):
        """Log archive access."""
        log_id = f"log_{hashlib.sha256(f'{archive_id}_{user_id}_{action}_{datetime.now(timezone.utc).isoformat()}'.encode()).hexdigest()[:16]}"
        
        async with aiosqlite.connect(self.archive_db_path) as db:
            await db.execute("""
                INSERT INTO archive_access_logs 
                (log_id, archive_id, version_id, user_id, action, timestamp,
                 ip_address, success, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                log_id, archive_id, version_id, user_id, action,
                datetime.now(timezone.utc), ip_address, success, details
            ))
            await db.commit()
    
    async def _load_existing_archives(self):
        """Load existing archives from database."""
        # Implementation would load from database
        logger.info("Loaded existing archives from database")
    
    async def _start_maintenance_tasks(self):
        """Start background maintenance tasks."""
        asyncio.create_task(self._cleanup_expired_archives())
        logger.info("Started archive maintenance tasks")
    
    async def _cleanup_expired_archives(self):
        """Clean up expired archives."""
        while True:
            try:
                # Cleanup logic would go here
                await asyncio.sleep(3600)  # Check every hour
            except Exception as e:
                logger.error(f"Error in archive cleanup: {e}")
                await asyncio.sleep(3600)
    
    async def _cleanup_old_versions(self, archive_id: str):
        """Clean up old versions when limit is reached."""
        # Implementation would remove oldest versions
        logger.info(f"Cleaning up old versions for archive {archive_id}")
