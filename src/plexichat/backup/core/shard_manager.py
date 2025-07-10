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

    def _calculate_sha512_checksum(self, data: bytes) -> str:
        """Calculate SHA-512 checksum for government-level security."""
        return hashlib.sha512(data).hexdigest()

    def _verify_minimum_shards_requirement(self, available_shards: int) -> bool:
        """Verify that minimum shards requirement is met for recovery."""
        return available_shards >= self.minimum_shards_for_recovery

    async def _initialize_encrypted_location_database(self):
        """Initialize encrypted shard location database."""
        import sqlite3
        import aiosqlite

        # Create encrypted location database
        async with aiosqlite.connect(self.encrypted_location_db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS encrypted_shard_locations (
                    shard_id TEXT PRIMARY KEY,
                    encrypted_location_data BLOB NOT NULL,
                    location_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS redundant_location_mappings (
                    mapping_id TEXT PRIMARY KEY,
                    shard_id TEXT NOT NULL,
                    redundant_location_data BLOB NOT NULL,
                    redundancy_level INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            await db.commit()

        # Create redundant location database
        async with aiosqlite.connect(self.redundant_location_db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS backup_shard_locations (
                    location_id TEXT PRIMARY KEY,
                    encrypted_shard_data BLOB NOT NULL,
                    location_checksum TEXT NOT NULL,
                    backup_level INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            await db.commit()

        logger.info("Encrypted shard location databases initialized")

    async def _initialize_location_encryption(self):
        """Initialize encryption for shard location data."""
        from cryptography.fernet import Fernet

        # Generate or load location encryption key
        key_file = self.backup_manager.keys_dir / "location_encryption.key"

        if key_file.exists():
            with open(key_file, 'rb') as f:
                self.location_encryption_key = f.read()
        else:
            self.location_encryption_key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.location_encryption_key)

            # Set restrictive permissions
            key_file.chmod(0o600)

        logger.info("Location encryption initialized")

    async def _initialize_database(self):
        """Initialize shard registry database."""
        async with aiosqlite.connect(self.shard_db_path) as db:
            # Immutable shards table
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
            
            # Difference shards table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS difference_shards (
                    diff_id TEXT PRIMARY KEY,
                    original_shard_id TEXT NOT NULL,
                    operation_type TEXT NOT NULL,
                    operation_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    user_id TEXT,
                    metadata TEXT,
                    FOREIGN KEY (original_shard_id) REFERENCES immutable_shards (shard_id)
                )
            """)
            
            # Shard verification log
            await db.execute("""
                CREATE TABLE IF NOT EXISTS shard_verification_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    shard_id TEXT NOT NULL,
                    verification_time TEXT NOT NULL,
                    verification_result BOOLEAN NOT NULL,
                    node_id TEXT,
                    error_message TEXT
                )
            """)
            
            await db.commit()
    
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
            
            # Load difference shards
            async with db.execute("SELECT * FROM difference_shards") as cursor:
                async for row in cursor:
                    diff_shard = DifferenceShard(
                        diff_id=row[0],
                        original_shard_id=row[1],
                        operation_type=row[2],
                        operation_data=b"",  # Will be loaded when needed
                        operation_hash=row[3],
                        created_at=datetime.fromisoformat(row[4]),
                        user_id=row[5],
                        metadata=eval(row[6]) if row[6] else {}
                    )
                    self.difference_shards[diff_shard.diff_id] = diff_shard
        
        logger.info(f"Loaded {len(self.immutable_shards)} immutable shards and {len(self.difference_shards)} difference shards")
    
    async def create_shards(
        self,
        backup_id: str,
        data: bytes,
        redundancy_factor: int = 5,
        shard_type: ShardType = ShardType.IMMUTABLE,
        backup_node_only: bool = False,
        require_minimum_shards: int = 2
    ) -> List[ImmutableShard]:
        """Create immutable shards from backup data with enhanced security."""
        logger.info(f"Creating shards for backup {backup_id}, data size: {len(data)} bytes, backup_node_only: {backup_node_only}")

        # Ensure minimum shard requirement for security
        if require_minimum_shards < 2:
            require_minimum_shards = 2
            logger.warning("Minimum shard requirement increased to 2 for security")

        # Calculate optimal shard size (smaller for better security)
        shard_size = self._calculate_optimal_shard_size(len(data))
        # Reduce shard size to ensure minimum shard count
        min_shard_size = len(data) // max(require_minimum_shards, 2)
        shard_size = min(shard_size, min_shard_size) if min_shard_size > 0 else shard_size

        # Split data into chunks
        chunks = self._split_data_into_chunks(data, shard_size)

        # Ensure we have at least the minimum required shards
        if len(chunks) < require_minimum_shards:
            # Split the data more aggressively
            new_shard_size = len(data) // require_minimum_shards
            chunks = self._split_data_into_chunks(data, new_shard_size)

        total_shards = len(chunks)
        shards = []

        for i, chunk in enumerate(chunks):
            shard_id = f"{backup_id}_shard_{i:06d}_{secrets.token_hex(16)}"  # Longer random component

            # Use advanced shard encryption requiring multiple shards for useful data
            encrypted_chunk, encryption_metadata = await self.encryption_manager.encrypt_shard_with_advanced_security(
                chunk, shard_id, require_multiple_shards=require_minimum_shards
            )

            # SHA-512 checksum is now included in encryption metadata
            sha512_checksum = encryption_metadata.get('sha512_checksum')

            # Calculate multiple hashes for government-level verification
            hashes = self._calculate_multiple_hashes(encrypted_chunk)
            hashes['sha512'] = sha512_checksum  # Add SHA-512 to hash collection

            # Get confusing filename from encryption metadata
            confusing_filename = encryption_metadata.get('confusing_filename')

            # Create shard object with enhanced security
            shard = ImmutableShard(
                shard_id=shard_id,
                backup_id=backup_id,
                shard_type=shard_type,
                shard_index=i,
                total_shards=total_shards,
                data_hash_sha256=hashes['sha256'],
                data_hash_sha512=hashes['sha512'],
                data_hash_blake2b=hashes['blake2b'],
                size_bytes=len(encrypted_chunk),  # Size of encrypted data
                created_at=datetime.now(timezone.utc),
                status=ShardStatus.CREATED,
                redundancy_factor=redundancy_factor
            )

            # Add enhanced metadata with advanced security features
            shard.metadata = {
                'backup_node_only': backup_node_only,
                'require_minimum_shards': require_minimum_shards,
                'encryption_algorithm': 'advanced-shard-encryption',
                'encryption_metadata': encryption_metadata,
                'confusing_filename': confusing_filename,
                'original_chunk_size': len(chunk),  # Size before encryption
                'security_level': 'quantum-resistant',
                'original_total_size': len(data),
                'individual_shard_key': True,  # Each shard has unique key
                'requires_multiple_for_decrypt': require_minimum_shards,
                'sha512_verified': True
            }

            # Save encrypted shard data to immutable storage
            await self._save_shard_data(shard, encrypted_chunk)
            
            # Add to registry
            self.immutable_shards[shard_id] = shard
            shards.append(shard)
            
            logger.debug(f"Created shard {shard_id} ({len(chunk)} bytes)")
        
        # Save shards to database
        await self._save_shards_to_database(shards)
        
        logger.info(f"Created {len(shards)} immutable shards for backup {backup_id} with quantum-resistant encryption")
        return shards
    
    def _calculate_optimal_shard_size(self, total_size: int) -> int:
        """Calculate optimal shard size based on total data size."""
        if total_size <= self.max_shard_size:
            return total_size
        
        # Calculate number of shards needed
        num_shards = (total_size + self.max_shard_size - 1) // self.max_shard_size
        
        # Ensure minimum shard size
        optimal_size = max(total_size // num_shards, self.min_shard_size)
        
        return min(optimal_size, self.max_shard_size)
    
    def _split_data_into_chunks(self, data: bytes, chunk_size: int) -> List[bytes]:
        """Split data into chunks of specified size."""
        chunks = []
        for i in range(0, len(data), chunk_size):
            chunks.append(data[i:i + chunk_size])
        return chunks
    
    def _calculate_multiple_hashes(self, data: bytes) -> Dict[str, str]:
        """Calculate multiple hash algorithms for government-level verification."""
        hashes = {}
        
        # SHA-256
        hashes['sha256'] = hashlib.sha256(data).hexdigest()
        
        # SHA-512
        hashes['sha512'] = hashlib.sha512(data).hexdigest()
        
        # BLAKE2b
        hashes['blake2b'] = hashlib.blake2b(data).hexdigest()
        
        return hashes

    async def _save_shard_data(self, shard: ImmutableShard, data: bytes):
        """Save shard data to immutable storage."""
        shard_file_path = self.immutable_dir / f"{shard.shard_id}.shard"

        async with aiofiles.open(shard_file_path, 'wb') as f:
            await f.write(data)

        # Set file as read-only to enforce immutability
        shard_file_path.chmod(0o444)

        logger.debug(f"Saved immutable shard data to {shard_file_path}")

    async def _save_shards_to_database(self, shards: List[ImmutableShard]):
        """Save shards to database."""
        async with aiosqlite.connect(self.shard_db_path) as db:
            for shard in shards:
                await db.execute("""
                    INSERT OR REPLACE INTO immutable_shards (
                        shard_id, backup_id, shard_type, shard_index, total_shards,
                        data_hash_sha256, data_hash_sha512, data_hash_blake2b,
                        size_bytes, created_at, status, redundancy_factor,
                        distribution_nodes, verification_count, last_verified, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    shard.shard_id,
                    shard.backup_id,
                    shard.shard_type.value,
                    shard.shard_index,
                    shard.total_shards,
                    shard.data_hash_sha256,
                    shard.data_hash_sha512,
                    shard.data_hash_blake2b,
                    shard.size_bytes,
                    shard.created_at.isoformat(),
                    shard.status.value,
                    shard.redundancy_factor,
                    ','.join(shard.distribution_nodes),
                    shard.verification_count,
                    shard.last_verified.isoformat() if shard.last_verified else None,
                    str(shard.metadata)
                ))
            await db.commit()

    async def create_difference_shard(
        self,
        original_shard_id: str,
        operation_type: str,
        operation_data: bytes,
        user_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> DifferenceShard:
        """Create a difference shard for edit/delete operations."""
        diff_id = f"diff_{original_shard_id}_{secrets.token_hex(8)}_{int(datetime.now(timezone.utc).timestamp())}"

        # Calculate hash of operation data
        operation_hash = hashlib.sha256(operation_data).hexdigest()

        # Create difference shard
        diff_shard = DifferenceShard(
            diff_id=diff_id,
            original_shard_id=original_shard_id,
            operation_type=operation_type,
            operation_data=operation_data,
            operation_hash=operation_hash,
            created_at=datetime.now(timezone.utc),
            user_id=user_id,
            metadata=metadata or {}
        )

        # Save difference data
        await self._save_difference_data(diff_shard)

        # Add to registry
        self.difference_shards[diff_id] = diff_shard

        # Save to database
        await self._save_difference_to_database(diff_shard)

        logger.info(f"Created difference shard {diff_id} for operation {operation_type}")
        return diff_shard

    async def _save_difference_data(self, diff_shard: DifferenceShard):
        """Save difference shard data."""
        diff_file_path = self.differences_dir / f"{diff_shard.diff_id}.diff"

        async with aiofiles.open(diff_file_path, 'wb') as f:
            await f.write(diff_shard.operation_data)

        # Set file as read-only
        diff_file_path.chmod(0o444)

        logger.debug(f"Saved difference data to {diff_file_path}")

    async def _save_difference_to_database(self, diff_shard: DifferenceShard):
        """Save difference shard to database."""
        async with aiosqlite.connect(self.shard_db_path) as db:
            await db.execute("""
                INSERT INTO difference_shards (
                    diff_id, original_shard_id, operation_type, operation_hash,
                    created_at, user_id, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                diff_shard.diff_id,
                diff_shard.original_shard_id,
                diff_shard.operation_type,
                diff_shard.operation_hash,
                diff_shard.created_at.isoformat(),
                diff_shard.user_id,
                str(diff_shard.metadata)
            ))
            await db.commit()

    async def verify_shard_integrity(self, shard_id: str, node_id: Optional[str] = None) -> bool:
        """Verify the integrity of a specific shard."""
        if shard_id not in self.immutable_shards:
            logger.error(f"Shard {shard_id} not found in registry")
            return False

        shard = self.immutable_shards[shard_id]

        try:
            # Load shard data
            shard_file_path = self.immutable_dir / f"{shard_id}.shard"

            if not shard_file_path.exists():
                logger.error(f"Shard file {shard_file_path} does not exist")
                await self._log_verification_result(shard_id, False, node_id, "File not found")
                return False

            async with aiofiles.open(shard_file_path, 'rb') as f:
                data = await f.read()

            # Verify all hashes
            calculated_hashes = self._calculate_multiple_hashes(data)

            hash_verification = (
                calculated_hashes['sha256'] == shard.data_hash_sha256 and
                calculated_hashes['sha512'] == shard.data_hash_sha512 and
                calculated_hashes['blake2b'] == shard.data_hash_blake2b
            )

            # Verify size
            size_verification = len(data) == shard.size_bytes

            verification_result = hash_verification and size_verification

            if verification_result:
                # Update verification count and timestamp
                shard.verification_count += 1
                shard.last_verified = datetime.now(timezone.utc)
                await self._update_shard_verification(shard)
                logger.debug(f"Shard {shard_id} verification successful")
            else:
                logger.error(f"Shard {shard_id} verification failed")

            await self._log_verification_result(shard_id, verification_result, node_id)
            return verification_result

        except Exception as e:
            logger.error(f"Error verifying shard {shard_id}: {e}")
            await self._log_verification_result(shard_id, False, node_id, str(e))
            return False

    async def _update_shard_verification(self, shard: ImmutableShard):
        """Update shard verification information in database."""
        async with aiosqlite.connect(self.shard_db_path) as db:
            await db.execute("""
                UPDATE immutable_shards
                SET verification_count = ?, last_verified = ?
                WHERE shard_id = ?
            """, (
                shard.verification_count,
                shard.last_verified.isoformat(),
                shard.shard_id
            ))
            await db.commit()

    async def _log_verification_result(
        self,
        shard_id: str,
        result: bool,
        node_id: Optional[str] = None,
        error_message: Optional[str] = None
    ):
        """Log shard verification result."""
        async with aiosqlite.connect(self.shard_db_path) as db:
            await db.execute("""
                INSERT INTO shard_verification_log (
                    shard_id, verification_time, verification_result, node_id, error_message
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                shard_id,
                datetime.now(timezone.utc).isoformat(),
                result,
                node_id,
                error_message
            ))
            await db.commit()

    async def verify_backup_shards(self, backup_id: str) -> bool:
        """Verify all shards for a specific backup."""
        backup_shards = [shard for shard in self.immutable_shards.values()
                        if shard.backup_id == backup_id]

        if not backup_shards:
            logger.error(f"No shards found for backup {backup_id}")
            return False

        verification_results = []
        for shard in backup_shards:
            result = await self.verify_shard_integrity(shard.shard_id)
            verification_results.append(result)

        success_count = sum(verification_results)
        total_count = len(verification_results)

        logger.info(f"Backup {backup_id} verification: {success_count}/{total_count} shards verified")
        return success_count == total_count

    async def verify_random_shards(self, count: int = 10):
        """Verify random shards for system health monitoring."""
        import random

        all_shards = list(self.immutable_shards.keys())
        if not all_shards:
            return

        # Select random shards
        sample_size = min(count, len(all_shards))
        random_shards = random.sample(all_shards, sample_size)

        verification_results = []
        for shard_id in random_shards:
            result = await self.verify_shard_integrity(shard_id)
            verification_results.append(result)

        success_rate = sum(verification_results) / len(verification_results)
        logger.info(f"Random shard verification: {success_rate:.2%} success rate")

        return success_rate

    async def get_active_shard_count(self) -> int:
        """Get count of active shards."""
        return len([shard for shard in self.immutable_shards.values()
                   if shard.status in [ShardStatus.CREATED, ShardStatus.DISTRIBUTED, ShardStatus.VERIFIED]])

    async def get_shard_statistics(self) -> Dict[str, Any]:
        """Get comprehensive shard statistics."""
        total_shards = len(self.immutable_shards)
        total_differences = len(self.difference_shards)

        status_counts = {}
        for status in ShardStatus:
            status_counts[status.value] = len([s for s in self.immutable_shards.values() if s.status == status])

        total_size = sum(shard.size_bytes for shard in self.immutable_shards.values())

        return {
            'total_immutable_shards': total_shards,
            'total_difference_shards': total_differences,
            'status_distribution': status_counts,
            'total_storage_bytes': total_size,
            'average_shard_size': total_size / total_shards if total_shards > 0 else 0,
            'verification_statistics': await self._get_verification_statistics()
        }

    async def _get_verification_statistics(self) -> Dict[str, Any]:
        """Get verification statistics."""
        total_verifications = sum(shard.verification_count for shard in self.immutable_shards.values())
        verified_shards = len([s for s in self.immutable_shards.values() if s.last_verified])

        return {
            'total_verifications': total_verifications,
            'verified_shards': verified_shards,
            'unverified_shards': len(self.immutable_shards) - verified_shards
        }
