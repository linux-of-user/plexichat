"""
Immutable Shard Manager

Manages the creation, verification, and lifecycle of immutable backup shards.
Once created, shards are never modified or deleted unless explicitly requested by super admin.
Implements government-level hashing and integrity verification.
"""

import asyncio
import hashlib
import secrets
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import aiosqlite
import aiofiles

logger = logging.getLogger(__name__)


class ShardType(Enum):
    """Types of backup shards."""
    IMMUTABLE = "immutable"          # Original data shard (never modified)
    DIFFERENCE = "difference"        # Edit/delete operations
    METADATA = "metadata"           # Shard metadata and checksums
    RECOVERY = "recovery"           # Recovery assistance data


class ShardStatus(Enum):
    """Shard status."""
    CREATED = "created"
    DISTRIBUTED = "distributed"
    VERIFIED = "verified"
    CORRUPTED = "corrupted"
    MISSING = "missing"
    ARCHIVED = "archived"


@dataclass
class ImmutableShard:
    """Represents an immutable backup shard."""
    shard_id: str
    backup_id: str
    shard_type: ShardType
    shard_index: int
    total_shards: int
    data_hash_sha256: str
    data_hash_sha512: str
    data_hash_blake2b: str
    size_bytes: int
    created_at: datetime
    status: ShardStatus
    redundancy_factor: int = 5
    distribution_nodes: List[str] = field(default_factory=list)
    verification_count: int = 0
    last_verified: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DifferenceShard:
    """Represents a difference shard for edits/deletes."""
    diff_id: str
    original_shard_id: str
    operation_type: str  # 'edit', 'delete', 'restore'
    operation_data: bytes
    operation_hash: str
    created_at: datetime
    user_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ImmutableShardManager:
    """
    Immutable Shard Manager
    
    Manages the creation and lifecycle of immutable backup shards with:
    - Government-level hashing algorithms (SHA-256, SHA-512, BLAKE2b)
    - Immutable guarantee (shards never modified after creation)
    - Difference file system for edits/deletes
    - Advanced integrity verification
    - Intelligent shard distribution tracking
    """
    
    def __init__(self, backup_manager):
        """Initialize the immutable shard manager."""
        self.backup_manager = backup_manager
        self.shards_dir = backup_manager.shards_dir
        self.immutable_dir = self.shards_dir / "immutable"
        self.differences_dir = self.shards_dir / "differences"
        self.metadata_dir = self.shards_dir / "metadata"
        self.temporary_dir = self.shards_dir / "temporary"
        
        # Ensure directories exist
        for directory in [self.immutable_dir, self.differences_dir, self.metadata_dir, self.temporary_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Shard registry
        self.immutable_shards: Dict[str, ImmutableShard] = {}
        self.difference_shards: Dict[str, DifferenceShard] = {}
        
        # Configuration
        self.max_shard_size = 50 * 1024 * 1024  # 50MB
        self.min_shard_size = 1024 * 1024       # 1MB
        self.hash_algorithms = ['sha512', 'sha256', 'blake2b']  # SHA-512 first for government-level security
        self.primary_hash_algorithm = 'sha512'  # Primary algorithm for all operations
        self.minimum_shards_for_recovery = 2  # Minimum 2 shards required for data recovery
        
        # Database
        self.shard_db_path = backup_manager.databases_dir / "shard_registry.db"
        self.encrypted_location_db_path = backup_manager.databases_dir / "encrypted_shard_locations.db"
        self.redundant_location_db_path = backup_manager.databases_dir / "redundant_shard_locations.db"

        # Shard location encryption
        self.location_encryption_key = None
        self.confusing_filename_enabled = True

        logger.info("Immutable Shard Manager initialized with encrypted location database")
    
    async def initialize(self):
        """Initialize the shard manager."""
        await self._initialize_database()
        await self._initialize_encrypted_location_database()
        await self._initialize_location_encryption()
        await self._load_existing_shards()
        logger.info("Shard Manager initialized successfully with government-level security")

    def _generate_confusing_filename(self, shard_id: str) -> str:
        """Generate confusing filename for shard to enhance security."""
        if not self.confusing_filename_enabled:
            return f"{shard_id}.shard"

        # Create confusing filename using hash and random elements
        import secrets
        import string

        # Generate base hash from shard_id
        base_hash = hashlib.sha512(shard_id.encode()).hexdigest()[:16]

        # Add random elements
        random_prefix = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
        random_suffix = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))

        # Create confusing extensions
        fake_extensions = ['.tmp', '.log', '.cache', '.bak', '.old', '.data', '.bin', '.sys']
        fake_ext = secrets.choice(fake_extensions)

        return f"{random_prefix}_{base_hash}_{random_suffix}{fake_ext}"

    async def _initialize_database(self):
        """Initialize the shard registry database."""
        async with aiosqlite.connect(self.shard_db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS immutable_shards (
                    shard_id TEXT PRIMARY KEY,
                    backup_id TEXT NOT NULL,
                    shard_type TEXT NOT NULL,
                    shard_index INTEGER NOT NULL,
                    total_shards INTEGER NOT NULL,
                    data_hash_sha256 TEXT NOT NULL,
                    data_hash_sha512 TEXT NOT NULL,
                    data_hash_blake2b TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    redundancy_factor INTEGER DEFAULT 5,
                    distribution_nodes TEXT,
                    verification_count INTEGER DEFAULT 0,
                    last_verified TEXT,
                    metadata TEXT
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS difference_shards (
                    diff_id TEXT PRIMARY KEY,
                    original_shard_id TEXT NOT NULL,
                    operation_type TEXT NOT NULL,
                    operation_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    user_id TEXT,
                    metadata TEXT
                )
            """)
            
            await db.commit()

    async def _initialize_encrypted_location_database(self):
        """Initialize encrypted shard location database."""
        async with aiosqlite.connect(self.encrypted_location_db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS shard_locations (
                    shard_id TEXT PRIMARY KEY,
                    encrypted_filename TEXT NOT NULL,
                    encrypted_path TEXT NOT NULL,
                    node_id TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            await db.commit()

    async def _initialize_location_encryption(self):
        """Initialize location encryption key."""
        from cryptography.fernet import Fernet
        
        key_file = self.backup_manager.databases_dir / "location_encryption.key"
        
        if key_file.exists():
            async with aiofiles.open(key_file, 'rb') as f:
                self.location_encryption_key = await f.read()
        else:
            self.location_encryption_key = Fernet.generate_key()
            async with aiofiles.open(key_file, 'wb') as f:
                await f.write(self.location_encryption_key)
        
        logger.info("Location encryption initialized")

    async def _load_existing_shards(self):
        """Load existing shards from database."""
        async with aiosqlite.connect(self.shard_db_path) as db:
            # Load immutable shards
            async with db.execute("SELECT * FROM immutable_shards") as cursor:
                async for row in cursor:
                    shard = ImmutableShard(
                        shard_id=row[0],
                        backup_id=row[1],
                        shard_type=ShardType(row[2]),
                        shard_index=row[3],
                        total_shards=row[4],
                        data_hash_sha256=row[5],
                        data_hash_sha512=row[6],
                        data_hash_blake2b=row[7],
                        size_bytes=row[8],
                        created_at=datetime.fromisoformat(row[9]),
                        status=ShardStatus(row[10]),
                        redundancy_factor=row[11],
                        distribution_nodes=row[12].split(',') if row[12] else [],
                        verification_count=row[13],
                        last_verified=datetime.fromisoformat(row[14]) if row[14] else None,
                        metadata=eval(row[15]) if row[15] else {}
                    )
                    self.immutable_shards[shard.shard_id] = shard

    def _calculate_multiple_hashes(self, data: bytes) -> Tuple[str, str, str]:
        """Calculate SHA-256, SHA-512, and BLAKE2b hashes for government-level security."""
        sha256_hash = hashlib.sha256(data).hexdigest()
        sha512_hash = hashlib.sha512(data).hexdigest()
        blake2b_hash = hashlib.blake2b(data).hexdigest()
        
        return sha256_hash, sha512_hash, blake2b_hash

    async def create_immutable_shard(
        self,
        backup_id: str,
        shard_data: bytes,
        shard_index: int,
        total_shards: int,
        redundancy_factor: int = 5
    ) -> ImmutableShard:
        """Create a new immutable shard."""
        shard_id = f"{backup_id}_shard_{shard_index:04d}_{secrets.token_hex(8)}"
        
        # Calculate multiple hashes for government-level security
        sha256_hash, sha512_hash, blake2b_hash = self._calculate_multiple_hashes(shard_data)
        
        # Create shard object
        shard = ImmutableShard(
            shard_id=shard_id,
            backup_id=backup_id,
            shard_type=ShardType.IMMUTABLE,
            shard_index=shard_index,
            total_shards=total_shards,
            data_hash_sha256=sha256_hash,
            data_hash_sha512=sha512_hash,
            data_hash_blake2b=blake2b_hash,
            size_bytes=len(shard_data),
            created_at=datetime.now(timezone.utc),
            status=ShardStatus.CREATED,
            redundancy_factor=redundancy_factor
        )
        
        # Generate confusing filename for security
        filename = self._generate_confusing_filename(shard_id)
        shard_path = self.immutable_dir / filename
        
        # Write shard data to file
        async with aiofiles.open(shard_path, 'wb') as f:
            await f.write(shard_data)
        
        # Store in registry
        self.immutable_shards[shard_id] = shard
        
        # Save to database
        await self._save_shard_to_database(shard)
        await self._save_encrypted_location(shard_id, filename, str(shard_path))
        
        logger.info(f"Created immutable shard {shard_id} with {len(shard_data)} bytes")
        return shard

# Global instance will be created by backup manager
immutable_shard_manager = None
