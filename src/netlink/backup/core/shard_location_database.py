"""
Enhanced Shard Location Database

Encrypted and redundant database for storing shard locations with access control.
Prevents non-backup nodes from accessing all shard locations for security.
"""

import asyncio
import logging
import secrets
import hashlib
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import aiosqlite
import aiofiles

from .encryption_manager import QuantumResistantEncryptionManager, EncryptionAlgorithm

logger = logging.getLogger(__name__)


class AccessLevel(Enum):
    """Access levels for shard location database."""
    BACKUP_NODE = "backup_node"  # Full access to all shard locations
    REGULAR_NODE = "regular_node"  # Limited access
    USER_NODE = "user_node"  # Only own shard locations


@dataclass
class ShardLocationEntry:
    """Encrypted shard location entry."""
    shard_id: str
    encrypted_location_data: bytes
    access_level_required: AccessLevel
    backup_node_only: bool
    created_at: datetime
    last_accessed: Optional[datetime] = None
    access_count: int = 0
    redundancy_locations: List[str] = field(default_factory=list)
    verification_hash: str = ""


class EnhancedShardLocationDatabase:
    """
    Enhanced encrypted and redundant shard location database.
    
    Features:
    - Encrypted storage of shard locations
    - Access control based on node type
    - Redundant storage across multiple databases
    - Backup node API key verification
    - Prevention of complete shard enumeration
    """
    
    def __init__(self, data_dir: Path, encryption_manager: QuantumResistantEncryptionManager):
        self.data_dir = Path(data_dir)
        self.encryption_manager = encryption_manager
        
        # Database paths for redundancy
        self.primary_db_path = self.data_dir / "shard_locations_primary.db"
        self.secondary_db_path = self.data_dir / "shard_locations_secondary.db"
        self.tertiary_db_path = self.data_dir / "shard_locations_tertiary.db"
        
        # In-memory cache for performance
        self.location_cache: Dict[str, ShardLocationEntry] = {}
        self.backup_node_keys: Set[str] = set()
        
        # Access control
        self.access_logs: List[Dict[str, Any]] = []
        self.failed_access_attempts: Dict[str, int] = {}
        
        # Statistics
        self.stats = {
            'total_locations': 0,
            'backup_node_locations': 0,
            'regular_locations': 0,
            'access_attempts': 0,
            'denied_access_attempts': 0,
            'database_syncs': 0
        }
        
        self._initialized = False

    async def initialize(self):
        """Initialize the shard location database."""
        if self._initialized:
            return
        
        logger.info("Initializing Enhanced Shard Location Database")
        
        # Create data directory
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize all database replicas
        await self._initialize_database(self.primary_db_path)
        await self._initialize_database(self.secondary_db_path)
        await self._initialize_database(self.tertiary_db_path)
        
        # Load backup node keys
        await self._load_backup_node_keys()
        
        # Load existing locations into cache
        await self._load_locations_cache()
        
        # Start background sync task
        asyncio.create_task(self._background_sync_task())
        
        self._initialized = True
        logger.info("Enhanced Shard Location Database initialized")

    async def _initialize_database(self, db_path: Path):
        """Initialize a single database replica."""
        async with aiosqlite.connect(db_path) as db:
            # Shard locations table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS shard_locations (
                    shard_id TEXT PRIMARY KEY,
                    encrypted_location_data BLOB NOT NULL,
                    access_level_required TEXT NOT NULL,
                    backup_node_only BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TEXT NOT NULL,
                    last_accessed TEXT,
                    access_count INTEGER DEFAULT 0,
                    redundancy_locations TEXT,
                    verification_hash TEXT NOT NULL
                )
            """)
            
            # Backup node keys table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS backup_node_keys (
                    key_id TEXT PRIMARY KEY,
                    key_hash TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    permissions TEXT NOT NULL,
                    active BOOLEAN DEFAULT TRUE
                )
            """)
            
            # Access logs table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS access_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    shard_id TEXT NOT NULL,
                    requester_id TEXT NOT NULL,
                    access_level TEXT NOT NULL,
                    granted BOOLEAN NOT NULL,
                    timestamp TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT
                )
            """)
            
            await db.commit()

    async def store_shard_location(self, shard_id: str, location_data: Dict[str, Any],
                                 backup_node_only: bool = False,
                                 api_key: Optional[str] = None) -> bool:
        """
        Store encrypted shard location with access control.
        
        Args:
            shard_id: Unique shard identifier
            location_data: Location information to encrypt and store
            backup_node_only: If True, only backup nodes can access
            api_key: API key for verification (required for backup_node_only)
            
        Returns:
            True if stored successfully
        """
        try:
            # Verify API key for backup node only shards
            if backup_node_only and not await self._verify_backup_node_key(api_key):
                logger.warning(f"Invalid backup node API key for shard {shard_id}")
                return False
            
            # Encrypt location data
            location_json = json.dumps(location_data)
            encrypted_data, metadata = await self.encryption_manager.encrypt_data(
                location_json.encode(),
                EncryptionAlgorithm.MULTI_LAYER_QUANTUM
            )
            
            # Determine access level
            access_level = AccessLevel.BACKUP_NODE if backup_node_only else AccessLevel.REGULAR_NODE
            
            # Create verification hash
            verification_hash = hashlib.sha512(
                f"{shard_id}_{location_json}_{datetime.now(timezone.utc).isoformat()}".encode()
            ).hexdigest()
            
            # Create location entry
            entry = ShardLocationEntry(
                shard_id=shard_id,
                encrypted_location_data=encrypted_data,
                access_level_required=access_level,
                backup_node_only=backup_node_only,
                created_at=datetime.now(timezone.utc),
                verification_hash=verification_hash
            )
            
            # Store in all database replicas
            await self._store_in_all_databases(entry)
            
            # Update cache
            self.location_cache[shard_id] = entry
            
            # Update statistics
            self.stats['total_locations'] += 1
            if backup_node_only:
                self.stats['backup_node_locations'] += 1
            else:
                self.stats['regular_locations'] += 1
            
            logger.debug(f"Stored shard location for {shard_id} (backup_only: {backup_node_only})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store shard location for {shard_id}: {e}")
            return False

    async def get_shard_location(self, shard_id: str, requester_id: str,
                               api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieve shard location with access control.
        
        Args:
            shard_id: Shard to locate
            requester_id: ID of the requesting entity
            api_key: API key for backup node access
            
        Returns:
            Decrypted location data if access granted, None otherwise
        """
        try:
            self.stats['access_attempts'] += 1
            
            # Check if shard exists
            if shard_id not in self.location_cache:
                await self._load_shard_from_database(shard_id)
            
            entry = self.location_cache.get(shard_id)
            if not entry:
                logger.warning(f"Shard location not found: {shard_id}")
                return None
            
            # Check access permissions
            access_granted = await self._check_access_permission(
                entry, requester_id, api_key
            )
            
            # Log access attempt
            await self._log_access_attempt(shard_id, requester_id, entry.access_level_required, access_granted)
            
            if not access_granted:
                self.stats['denied_access_attempts'] += 1
                logger.warning(f"Access denied for shard {shard_id} to requester {requester_id}")
                return None
            
            # Decrypt location data
            decrypted_data = await self.encryption_manager.decrypt_data(
                entry.encrypted_location_data,
                EncryptionAlgorithm.MULTI_LAYER_QUANTUM
            )
            
            # Update access tracking
            entry.last_accessed = datetime.now(timezone.utc)
            entry.access_count += 1
            
            # Update database
            await self._update_access_tracking(shard_id, entry)
            
            return json.loads(decrypted_data.decode())

        except Exception as e:
            logger.error(f"Failed to get shard location for {shard_id}: {e}")
            return None

    async def _verify_backup_node_key(self, api_key: Optional[str]) -> bool:
        """Verify backup node API key."""
        if not api_key:
            return False

        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        return key_hash in self.backup_node_keys

    async def _check_access_permission(self, entry: ShardLocationEntry,
                                     requester_id: str, api_key: Optional[str]) -> bool:
        """Check if requester has permission to access shard location."""
        # Backup node only shards require valid API key
        if entry.backup_node_only:
            return await self._verify_backup_node_key(api_key)

        # Regular access based on access level
        if entry.access_level_required == AccessLevel.BACKUP_NODE:
            return await self._verify_backup_node_key(api_key)

        # Regular nodes can access non-restricted shards
        return True

    async def _store_in_all_databases(self, entry: ShardLocationEntry):
        """Store entry in all database replicas for redundancy."""
        databases = [self.primary_db_path, self.secondary_db_path, self.tertiary_db_path]

        for db_path in databases:
            try:
                async with aiosqlite.connect(db_path) as db:
                    await db.execute("""
                        INSERT OR REPLACE INTO shard_locations
                        (shard_id, encrypted_location_data, access_level_required,
                         backup_node_only, created_at, redundancy_locations, verification_hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        entry.shard_id,
                        entry.encrypted_location_data,
                        entry.access_level_required.value,
                        entry.backup_node_only,
                        entry.created_at.isoformat(),
                        json.dumps(entry.redundancy_locations),
                        entry.verification_hash
                    ))
                    await db.commit()
            except Exception as e:
                logger.error(f"Failed to store in database {db_path}: {e}")

    async def _load_backup_node_keys(self):
        """Load backup node API keys from database."""
        try:
            async with aiosqlite.connect(self.primary_db_path) as db:
                async with db.execute("""
                    SELECT key_hash FROM backup_node_keys
                    WHERE active = TRUE AND (expires_at IS NULL OR expires_at > ?)
                """, (datetime.now(timezone.utc).isoformat(),)) as cursor:
                    async for row in cursor:
                        self.backup_node_keys.add(row[0])

            logger.info(f"Loaded {len(self.backup_node_keys)} backup node keys")
        except Exception as e:
            logger.error(f"Failed to load backup node keys: {e}")

    async def _load_locations_cache(self):
        """Load shard locations into memory cache."""
        try:
            async with aiosqlite.connect(self.primary_db_path) as db:
                async with db.execute("""
                    SELECT shard_id, encrypted_location_data, access_level_required,
                           backup_node_only, created_at, last_accessed, access_count,
                           redundancy_locations, verification_hash
                    FROM shard_locations
                """) as cursor:
                    async for row in cursor:
                        entry = ShardLocationEntry(
                            shard_id=row[0],
                            encrypted_location_data=row[1],
                            access_level_required=AccessLevel(row[2]),
                            backup_node_only=bool(row[3]),
                            created_at=datetime.fromisoformat(row[4]),
                            last_accessed=datetime.fromisoformat(row[5]) if row[5] else None,
                            access_count=row[6],
                            redundancy_locations=json.loads(row[7]) if row[7] else [],
                            verification_hash=row[8]
                        )
                        self.location_cache[row[0]] = entry

            logger.info(f"Loaded {len(self.location_cache)} shard locations into cache")
        except Exception as e:
            logger.error(f"Failed to load locations cache: {e}")

    async def _log_access_attempt(self, shard_id: str, requester_id: str,
                                access_level: AccessLevel, granted: bool):
        """Log access attempt for security auditing."""
        log_entry = {
            'shard_id': shard_id,
            'requester_id': requester_id,
            'access_level': access_level.value,
            'granted': granted,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        self.access_logs.append(log_entry)

        # Store in database
        try:
            async with aiosqlite.connect(self.primary_db_path) as db:
                await db.execute("""
                    INSERT INTO access_logs
                    (shard_id, requester_id, access_level, granted, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (shard_id, requester_id, access_level.value, granted, log_entry['timestamp']))
                await db.commit()
        except Exception as e:
            logger.error(f"Failed to log access attempt: {e}")

    async def _background_sync_task(self):
        """Background task to sync databases and cleanup."""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes

                # Sync databases
                await self._sync_databases()

                # Cleanup old access logs
                await self._cleanup_old_logs()

                self.stats['database_syncs'] += 1

            except Exception as e:
                logger.error(f"Background sync task error: {e}")

    async def _sync_databases(self):
        """Synchronize all database replicas."""
        # Implementation for database synchronization
        pass

    async def _cleanup_old_logs(self):
        """Clean up old access logs."""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=30)

        for db_path in [self.primary_db_path, self.secondary_db_path, self.tertiary_db_path]:
            try:
                async with aiosqlite.connect(db_path) as db:
                    await db.execute("""
                        DELETE FROM access_logs WHERE timestamp < ?
                    """, (cutoff_date.isoformat(),))
                    await db.commit()
            except Exception as e:
                logger.error(f"Failed to cleanup logs in {db_path}: {e}")

    async def add_backup_node_key(self, node_id: str, api_key: str,
                                permissions: List[str], expires_at: Optional[datetime] = None) -> bool:
        """Add a new backup node API key."""
        try:
            key_id = secrets.token_hex(16)
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()

            # Store in all databases
            for db_path in [self.primary_db_path, self.secondary_db_path, self.tertiary_db_path]:
                async with aiosqlite.connect(db_path) as db:
                    await db.execute("""
                        INSERT INTO backup_node_keys
                        (key_id, key_hash, node_id, created_at, expires_at, permissions, active)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        key_id, key_hash, node_id,
                        datetime.now(timezone.utc).isoformat(),
                        expires_at.isoformat() if expires_at else None,
                        json.dumps(permissions),
                        True
                    ))
                    await db.commit()

            # Add to memory cache
            self.backup_node_keys.add(key_hash)

            logger.info(f"Added backup node key for {node_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to add backup node key: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics."""
        return {
            **self.stats,
            'cache_size': len(self.location_cache),
            'backup_node_keys_count': len(self.backup_node_keys),
            'recent_access_logs': len(self.access_logs[-100:])  # Last 100 logs
        }
