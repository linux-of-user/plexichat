# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import aiosqlite

from ...core.logging import get_logger
from ...security import quantum_encryption
from .unified_backup_manager import UnifiedShard


"""
import time
Unified Shard Manager

Consolidates all shard management functionality from:
- ImmutableShardManager
- DistributedShardSystem
- Various shard managers

Features:
- Immutable shard creation with cryptographic integrity
- Intelligent shard distribution algorithms
- Reed-Solomon error correction
- Blockchain-inspired audit trails
- Automatic shard verification and repair
- Performance optimization with caching
"""

logger = get_logger(__name__)


class ShardState(Enum):
    """Shard states."""

    CREATING = "creating"
    ACTIVE = "active"
    VERIFYING = "verifying"
    CORRUPTED = "corrupted"
    MISSING = "missing"
    REPAIRING = "repairing"


class ShardType(Enum):
    """Types of shards."""

    DATA = "data"
    PARITY = "parity"
    METADATA = "metadata"
    VERIFICATION = "verification"


@dataclass
class ShardMetadata:
    """Comprehensive shard metadata."""

    shard_id: str
    backup_id: str
    shard_type: ShardType
    shard_index: int
    total_shards: int

    # Data integrity
    data_hash: str
    size: int
    checksum: str

    # Reed-Solomon information
    data_shards: int
    parity_shards: int

    # Encryption
    encryption_key_id: str
    encryption_algorithm: str

    # Distribution
    node_assignments: List[str] = field(default_factory=list)
    replication_factor: int = 3

    # State tracking
    state: ShardState = ShardState.CREATING
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_verified: Optional[datetime] = None
    verification_failures: int = 0

    # Audit trail
    creation_signature: Optional[str] = None
    modification_history: List[Dict[str, Any]] = field(default_factory=list)

    # Performance
    access_count: int = 0
    last_accessed: Optional[datetime] = None

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


class UnifiedShardManager:
    """
    Unified Shard Manager

    Manages all aspects of shard lifecycle including creation, distribution,
    verification, repair, and cleanup with enterprise-grade reliability.
    """

    def __init__(self, backup_manager):
        self.backup_manager = backup_manager
        self.initialized = False

        # Configuration
        self.config = backup_manager.config.get("shards", {})
        self.shard_size = self.config.get("shard_size", 64 * 1024 * 1024)  # 64MB
        self.min_shards = self.config.get("min_shards", 3)
        self.max_shards = self.config.get("max_shards", 100)
        self.parity_ratio = self.config.get("parity_ratio", 0.3)  # 30% parity shards

        # Directories
        self.shard_dir = backup_manager.shard_dir
        self.metadata_dir = backup_manager.metadata_dir

        # Database
        self.db_path = backup_manager.backup_dir / "shard_metadata.db"

        # In-memory caches
        self.shard_cache: Dict[str, ShardMetadata] = {}
        self.verification_queue: asyncio.Queue = asyncio.Queue()

        # Performance tracking
        self.stats = {
            "shards_created": 0,
            "shards_verified": 0,
            "shards_repaired": 0,
            "verification_failures": 0,
        }

        logger.info("Unified Shard Manager initialized")

    async def initialize(self) -> None:
        """Initialize the shard manager."""
        if self.initialized:
            return

        # Create directories
        self.shard_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)

        # Initialize database
        await self._initialize_database()

        # Load existing shards
        await self._load_existing_shards()

        # Start background tasks
        asyncio.create_task(self._verification_worker())
        asyncio.create_task(self._repair_worker())

        self.initialized = True
        logger.info("Unified Shard Manager initialized successfully")

    async def _initialize_database(self) -> None:
        """Initialize shard metadata database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute()
                """
                CREATE TABLE IF NOT EXISTS shard_metadata ()
                    shard_id TEXT PRIMARY KEY,
                    backup_id TEXT NOT NULL,
                    shard_type TEXT NOT NULL,
                    shard_index INTEGER NOT NULL,
                    total_shards INTEGER NOT NULL,
                    data_hash TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    checksum TEXT NOT NULL,
                    data_shards INTEGER NOT NULL,
                    parity_shards INTEGER NOT NULL,
                    encryption_key_id TEXT NOT NULL,
                    encryption_algorithm TEXT NOT NULL,
                    node_assignments TEXT,
                    replication_factor INTEGER DEFAULT 3,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_verified TEXT,
                    verification_failures INTEGER DEFAULT 0,
                    creation_signature TEXT,
                    modification_history TEXT,
                    access_count INTEGER DEFAULT 0,
                    last_accessed TEXT,
                    metadata TEXT
                )
            """
            )

            # Create indexes
            await db.execute()
                "CREATE INDEX IF NOT EXISTS idx_shard_backup_id ON shard_metadata(backup_id)"
            )
            await db.execute()
                "CREATE INDEX IF NOT EXISTS idx_shard_state ON shard_metadata(state)"
            )
            await db.execute()
                "CREATE INDEX IF NOT EXISTS idx_shard_created_at ON shard_metadata(created_at)"
            )

            await db.commit()

    async def create_shards(self, data: bytes, operation) -> List["UnifiedShard"]:
        """Create shards from data using Reed-Solomon encoding."""
        if not self.initialized:
            await if self and hasattr(self, "initialize"): self.initialize()

        logger.info()
            f"Creating shards for backup {operation.backup_id}, data size: {len(data)} bytes"
        )

        # Calculate optimal shard configuration
        shard_config = self._calculate_shard_configuration()
            len(data), operation.redundancy_factor
        )

        # Split data into chunks
        data_chunks = self._split_data_into_chunks(data, shard_config["data_shards"])

        # Create Reed-Solomon encoder
        rs_encoder = self._create_reed_solomon_encoder()
            shard_config["data_shards"], shard_config["parity_shards"]
        )

        # Generate parity chunks
        parity_chunks = rs_encoder.encode(data_chunks)

        # Create shard objects
        shards = []
        all_chunks = data_chunks + parity_chunks

        for i, chunk in enumerate(all_chunks):
            shard_type = ShardType.DATA if i < len(data_chunks) else ShardType.PARITY

            # Encrypt chunk
            encrypted_chunk, encryption_metadata = await self._encrypt_shard_data()
                chunk, operation
            )

            # Create shard
            shard = await self._create_shard_object()
                chunk_data=encrypted_chunk,
                shard_index=i,
                total_shards=len(all_chunks),
                shard_type=shard_type,
                operation=operation,
                encryption_metadata=encryption_metadata,
                shard_config=shard_config,
            )

            shards.append(shard)

        # Save all shards
        await self._save_shards_batch(shards)

        self.stats["shards_created"] += len(shards)
        logger.info(f"Created {len(shards)} shards for backup {operation.backup_id}")

        return shards

    async def verify_shard(self, shard_id: str) -> bool:
        """Verify a single shard's integrity."""
        if shard_id not in self.shard_cache:
            await self._load_shard_metadata(shard_id)

        if shard_id not in self.shard_cache:
            logger.error(f"Shard {shard_id} not found")
            return False

        metadata = self.shard_cache[shard_id]

        try:
            # Read shard data
            shard_path = self.shard_dir / f"{shard_id}.shard"
            if not shard_path.exists():
                logger.error(f"Shard file {shard_path} not found")
                metadata.state = ShardState.MISSING
                await self._save_shard_metadata(metadata)
                return False

            # Verify checksum
            with open(shard_path, "rb") as f:
                data = f.read()

            calculated_checksum = hashlib.sha256(data).hexdigest()
            if calculated_checksum != metadata.checksum:
                logger.error(f"Shard {shard_id} checksum mismatch")
                metadata.state = ShardState.CORRUPTED
                metadata.verification_failures += 1
                await self._save_shard_metadata(metadata)
                return False

            # Update verification status
            metadata.last_verified = datetime.now(timezone.utc)
            metadata.state = ShardState.ACTIVE
            await self._save_shard_metadata(metadata)

            self.stats["shards_verified"] += 1
            return True

        except Exception as e:
            logger.error(f"Error verifying shard {shard_id}: {e}")
            metadata.verification_failures += 1
            await self._save_shard_metadata(metadata)
            return False

    async def verify_random_shards(self, count: int = 10) -> Dict[str, bool]:
        """Verify random shards for system health monitoring."""
        # Get random shard IDs
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute()
                """
                SELECT shard_id FROM shard_metadata
                WHERE state = 'active'
                ORDER BY RANDOM()
                LIMIT ?
            """,
                (count,),
            ) as cursor:
                shard_ids = [row[0] async for row in cursor]

        # Verify each shard
        results = {}
        for shard_id in shard_ids:
            results[shard_id] = await self.verify_shard(shard_id)

        return results

    async def get_shard_statistics(self) -> Dict[str, int]:
        """Get comprehensive shard statistics."""
        async with aiosqlite.connect(self.db_path) as db:
            stats = {"total": 0, "healthy": 0, "corrupted": 0, "missing": 0}

            async with db.execute()
                """
                SELECT state, COUNT(*) FROM shard_metadata GROUP BY state
            """
            ) as cursor:
                async for row in cursor:
                    state, count = row
                    stats["total"] += count
                    if state == "active":
                        stats["healthy"] = count
                    elif state == "corrupted":
                        stats["corrupted"] = count
                    elif state == "missing":
                        stats["missing"] = count

        return stats

    # Utility Methods

    def _calculate_shard_configuration():
        self, data_size: int, redundancy_factor: int
    ) -> Dict[str, int]:
        """Calculate optimal shard configuration."""
        # Calculate number of data shards based on size
        data_shards = min()
            max(self.min_shards, (data_size + self.shard_size - 1) // self.shard_size),
            self.max_shards,
        )

        # Calculate parity shards based on redundancy factor
        parity_shards = max(1, int(data_shards * self.parity_ratio * redundancy_factor))

        return {
            "data_shards": data_shards,
            "parity_shards": parity_shards,
            "total_shards": data_shards + parity_shards,
        }

    def _split_data_into_chunks(self, data: bytes, num_chunks: int) -> List[bytes]:
        """Split data into equal-sized chunks."""
        chunk_size = (len(data) + num_chunks - 1) // num_chunks
        chunks = []

        for i in range(num_chunks):
            start = i * chunk_size
            end = min(start + chunk_size, len(data))
            chunk = data[start:end]

            # Pad last chunk if necessary
            if len(chunk) < chunk_size and i == num_chunks - 1:
                chunk += b"\x00" * (chunk_size - len(chunk))

            chunks.append(chunk)

        return chunks

    def _create_reed_solomon_encoder(self, data_shards: int, parity_shards: int):
        """Create Reed-Solomon encoder (simplified implementation)."""

        # In production, use a proper Reed-Solomon library like pyfinite
        class SimpleRSEncoder:
            def __init__(self, data_shards, parity_shards):
                self.data_shards = data_shards
                self.parity_shards = parity_shards

            def encode(self, data_chunks):
                # Simplified parity generation using XOR
                parity_chunks = []
                for i in range(self.parity_shards):
                    parity = bytearray(len(data_chunks[0]))
                    for chunk in data_chunks:
                        for j, byte in enumerate(chunk):
                            parity[j] ^= byte
                    parity_chunks.append(bytes(parity))
                return parity_chunks

        return SimpleRSEncoder(data_shards, parity_shards)

    async def _encrypt_shard_data()
        self, data: bytes, operation
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Encrypt shard data using quantum-resistant encryption."""
        # Generate unique key for this shard
        shard_key_id = f"shard_{operation.backup_id}_{secrets.token_hex(8)}"

        # Encrypt using quantum encryption
        encrypted_data = await quantum_encryption.encrypt_data()
            data,
            key_domain=f"backup.{operation.backup_id}",
            classification=operation.security_level.name,
        )

        encryption_metadata = {
            "key_id": shard_key_id,
            "algorithm": "quantum_resistant",
            "key_domain": f"backup.{operation.backup_id}",
            "classification": operation.security_level.name,
        }

        return encrypted_data, encryption_metadata

    async def _create_shard_object()
        self,
        chunk_data: bytes,
        shard_index: int,
        total_shards: int,
        shard_type: ShardType,
        operation,
        encryption_metadata: Dict[str, Any],
        shard_config: Dict[str, int],
    ) -> "UnifiedShard":
        """Create a unified shard object."""
        # Generate shard ID
        shard_id = ()
            f"shard_{operation.backup_id}_{shard_index:04d}_{secrets.token_hex(8)}"
        )

        # Calculate hashes
        data_hash = hashlib.sha256(chunk_data).hexdigest()
        checksum = hashlib.sha256(chunk_data).hexdigest()

        # Create shard metadata
        metadata = ShardMetadata()
            shard_id=shard_id,
            backup_id=operation.backup_id,
            shard_type=shard_type,
            shard_index=shard_index,
            total_shards=total_shards,
            data_hash=data_hash,
            size=len(chunk_data),
            checksum=checksum,
            data_shards=shard_config["data_shards"],
            parity_shards=shard_config["parity_shards"],
            encryption_key_id=encryption_metadata["key_id"],
            encryption_algorithm=encryption_metadata["algorithm"],
            replication_factor=operation.redundancy_factor,
        )

        # Create digital signature for audit trail
        metadata.creation_signature = await self._create_shard_signature(metadata)

        # Store in cache
        self.shard_cache[shard_id] = metadata

        # Create unified shard object
        shard = UnifiedShard()
            shard_id=shard_id,
            backup_id=operation.backup_id,
            shard_index=shard_index,
            total_shards=total_shards,
            data_hash=data_hash,
            encrypted_data=chunk_data,
            size=len(chunk_data),
            encryption_metadata=encryption_metadata,
            verification_hash=checksum,
        )

        return shard

    async def _create_shard_signature(self, metadata: ShardMetadata) -> str:
        """Create digital signature for shard audit trail."""
        # Create signature data
        signature_data = f"{metadata.shard_id}:{metadata.data_hash}:{metadata.created_at.isoformat()}"

        # Sign with system key
        signature = hashlib.sha256(signature_data.encode()).hexdigest()

        return signature

    async def _save_shards_batch(self, shards: List["UnifiedShard"]) -> None:
        """Save multiple shards efficiently."""
        # Save shard files
        for shard in shards:
            shard_path = self.shard_dir / f"{shard.shard_id}.shard"
            with open(shard_path, "wb") as f:
                f.write(shard.encrypted_data)

        # Save metadata to database
        async with aiosqlite.connect(self.db_path) as db:
            for shard in shards:
                metadata = self.shard_cache[shard.shard_id]
                await self._insert_shard_metadata(db, metadata)
            await db.commit()

    async def _insert_shard_metadata(self, db, metadata: ShardMetadata) -> None:
        """Insert shard metadata into database."""
        await db.execute()
            """
            INSERT INTO shard_metadata ()
                shard_id, backup_id, shard_type, shard_index, total_shards,
                data_hash, size, checksum, data_shards, parity_shards,
                encryption_key_id, encryption_algorithm, node_assignments,
                replication_factor, state, created_at, last_verified,
                verification_failures, creation_signature, modification_history,
                access_count, last_accessed, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            ()
                metadata.shard_id,
                metadata.backup_id,
                metadata.shard_type.value,
                metadata.shard_index,
                metadata.total_shards,
                metadata.data_hash,
                metadata.size,
                metadata.checksum,
                metadata.data_shards,
                metadata.parity_shards,
                metadata.encryption_key_id,
                metadata.encryption_algorithm,
                ",".join(metadata.node_assignments),
                metadata.replication_factor,
                metadata.state.value,
                metadata.created_at.isoformat(),
                metadata.last_verified.isoformat() if metadata.last_verified else None,
                metadata.verification_failures,
                metadata.creation_signature,
                str(metadata.modification_history),
                metadata.access_count,
                metadata.last_accessed.isoformat() if metadata.last_accessed else None,
                str(metadata.metadata),
            ),
        )

    async def _save_shard_metadata(self, metadata: ShardMetadata) -> None:
        """Save single shard metadata to database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute()
                """
                UPDATE shard_metadata SET
                    state = ?, last_verified = ?, verification_failures = ?,
                    access_count = ?, last_accessed = ?
                WHERE shard_id = ?
            """,
                ()
                    metadata.state.value,
                    ()
                        metadata.last_verified.isoformat()
                        if metadata.last_verified
                        else None
                    ),
                    metadata.verification_failures,
                    metadata.access_count,
                    ()
                        metadata.last_accessed.isoformat()
                        if metadata.last_accessed
                        else None
                    ),
                    metadata.shard_id,
                ),
            )
            await db.commit()

    async def _load_existing_shards(self) -> None:
        """Load existing shard metadata into cache."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT * FROM shard_metadata") as cursor:
                async for row in cursor:
                    metadata = self._row_to_shard_metadata(row)
                    self.shard_cache[metadata.shard_id] = metadata

        logger.info(f"Loaded {len(self.shard_cache)} shards into cache")

    async def _load_shard_metadata(self, shard_id: str) -> None:
        """Load specific shard metadata from database."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute()
                "SELECT * FROM shard_metadata WHERE shard_id = ?", (shard_id,)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    metadata = self._row_to_shard_metadata(row)
                    self.shard_cache[shard_id] = metadata

    def _row_to_shard_metadata(self, row) -> ShardMetadata:
        """Convert database row to ShardMetadata object."""
        return ShardMetadata()
            shard_id=row[0],
            backup_id=row[1],
            shard_type=ShardType(row[2]),
            shard_index=row[3],
            total_shards=row[4],
            data_hash=row[5],
            size=row[6],
            checksum=row[7],
            data_shards=row[8],
            parity_shards=row[9],
            encryption_key_id=row[10],
            encryption_algorithm=row[11],
            node_assignments=row[12].split(",") if row[12] else [],
            replication_factor=row[13],
            state=ShardState(row[14]),
            created_at=datetime.fromisoformat(row[15]),
            last_verified=datetime.fromisoformat(row[16]) if row[16] else None,
            verification_failures=row[17],
            creation_signature=row[18],
            modification_history=eval(row[19]) if row[19] else [],
            access_count=row[20],
            last_accessed=datetime.fromisoformat(row[21]) if row[21] else None,
            metadata=eval(row[22]) if row[22] else {},
        )

    # Background Workers

    async def _verification_worker(self) -> None:
        """Background worker for shard verification."""
        while True:
            try:
                # Wait for verification requests
                shard_id = await self.verification_queue.get()

                # Verify the shard
                await self.verify_shard(shard_id)

                # Mark task as done
                self.verification_queue.task_done()

            except Exception as e:
                logger.error(f"Verification worker error: {e}")
                await asyncio.sleep(1)

    async def _repair_worker(self) -> None:
        """Background worker for shard repair."""
        while True:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes

                # Find corrupted or missing shards
                corrupted_shards = await self._find_corrupted_shards()

                for shard_id in corrupted_shards:
                    await self._attempt_shard_repair(shard_id)

            except Exception as e:
                logger.error(f"Repair worker error: {e}")

    async def _find_corrupted_shards(self) -> List[str]:
        """Find shards that need repair."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """
                SELECT shard_id FROM shard_metadata
                WHERE state IN ('corrupted', 'missing')
                ORDER BY verification_failures ASC
                LIMIT 10
                """
            ) as cursor:
                return [row[0] async for row in cursor]

    async def _attempt_shard_repair(self, shard_id: str) -> bool:
        """Attempt to repair a corrupted or missing shard."""
        try:
            if shard_id not in self.shard_cache:
                await self._load_shard_metadata(shard_id)

            metadata = self.shard_cache[shard_id]

            # Try to reconstruct from other shards using Reed-Solomon
            reconstructed_data = await self._reconstruct_shard_data(metadata)

            if reconstructed_data:
                # Save reconstructed shard
                shard_path = self.shard_dir / f"{shard_id}.shard"
                with open(shard_path, "wb") as f:
                    f.write(reconstructed_data)

                # Verify reconstruction
                if await self.verify_shard(shard_id):
                    metadata.state = ShardState.ACTIVE
                    await self._save_shard_metadata(metadata)
                    self.stats["shards_repaired"] += 1
                    logger.info(f"Successfully repaired shard {shard_id}")
                    return True

            logger.warning(f"Failed to repair shard {shard_id}")
            return False

        except Exception as e:
            logger.error(f"Error repairing shard {shard_id}: {e}")
            return False

    async def _reconstruct_shard_data(self, metadata: ShardMetadata) -> Optional[bytes]:
        """Reconstruct shard data from other shards using Reed-Solomon."""
        try:
            # Get all shards for the same backup
            backup_shards = []
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute()
                    """
                    SELECT shard_id, shard_index, state FROM shard_metadata
                    WHERE backup_id = ? AND shard_id != ?
                    ORDER BY shard_index
                """,
                    (metadata.backup_id, metadata.shard_id),
                ) as cursor:
                    async for row in cursor:
                        if row[2] == "active":  # Only use healthy shards
                            backup_shards.append((row[0], row[1]))

            # Check if we have enough shards for reconstruction
            if len(backup_shards) < metadata.data_shards:
                logger.warning()
                    f"Not enough healthy shards for reconstruction: {len(backup_shards)}/{metadata.data_shards}"
                )
                return None

            # Load shard data
            shard_data = {}
            for shard_id, shard_index in backup_shards:
                shard_path = self.shard_dir / f"{shard_id}.shard"
                if shard_path.exists():
                    with open(shard_path, "rb") as f:
                        shard_data[shard_index] = f.read()

            # Reconstruct using Reed-Solomon (simplified)
            # In production, use proper Reed-Solomon reconstruction
            if metadata.shard_index < metadata.data_shards:
                # Reconstruct data shard from parity
                reconstructed = bytearray(len(list(shard_data.values())[0]))
                for data in shard_data.values():
                    for i, byte in enumerate(data):
                        reconstructed[i] ^= byte
                return bytes(reconstructed)

            return None

        except Exception as e:
            logger.error(f"Error reconstructing shard data: {e}")
            return None
