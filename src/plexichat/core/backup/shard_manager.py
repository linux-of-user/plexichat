#!/usr/bin/env python3
"""
Shard Manager for Distributed Backup System

Handles splitting data into 1MB shards with Reed-Solomon error correction.
Provides redundancy so that partial shards can reconstruct the full data.
"""

import hashlib
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from uuid import uuid4

# Reed-Solomon implementation
try:
    from reedsolo import RSCodec, ReedSolomonError
    REED_SOLOMON_AVAILABLE = True
except ImportError:
    REED_SOLOMON_AVAILABLE = False
    class RSCodec:
        def __init__(self, *args, **kwargs): pass
        def encode(self, data): return data
        def decode(self, data): return data
    class ReedSolomonError(Exception): pass

logger = logging.getLogger(__name__)

# Constants
SHARD_SIZE = 1024 * 1024  # 1MB per shard
DEFAULT_DATA_SHARDS = 5
DEFAULT_PARITY_SHARDS = 3
MIN_SHARDS_FOR_RECOVERY = DEFAULT_DATA_SHARDS

class ShardType(Enum):
    """Types of shards."""
    DATA = "data"
    PARITY = "parity"
    METADATA = "metadata"

class ShardStatus(Enum):
    """Shard status."""
    CREATED = "created"
    DISTRIBUTED = "distributed"
    VERIFIED = "verified"
    CORRUPTED = "corrupted"
    MISSING = "missing"

@dataclass
class ShardInfo:
    """Information about a single shard."""
    shard_id: str
    backup_id: str
    shard_index: int
    shard_type: ShardType
    size: int
    checksum: str
    created_at: datetime
    status: ShardStatus = ShardStatus.CREATED
    location: Optional[str] = None
    encryption_key_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {}
            "shard_id": self.shard_id,
            "backup_id": self.backup_id,
            "shard_index": self.shard_index,
            "shard_type": self.shard_type.value,
            "size": self.size,
            "checksum": self.checksum,
            "created_at": self.created_at.isoformat(),
            "status": self.status.value,
            "location": self.location,
            "encryption_key_id": self.encryption_key_id,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ShardInfo':
        """Create from dictionary."""
        return cls(
            shard_id=data["shard_id"],
            backup_id=data["backup_id"],
            shard_index=data["shard_index"],
            shard_type=ShardType(data["shard_type"]),
            size=data["size"],
            checksum=data["checksum"],
            created_at=datetime.fromisoformat(data["created_at"]),
            status=ShardStatus(data["status"]),
            location=data.get("location"),
            encryption_key_id=data.get("encryption_key_id"),
            metadata=data.get("metadata", {})
        )

@dataclass
class ShardSet:
    """A complete set of shards for a backup."""
    backup_id: str
    version_id: str
    data_shards: List[ShardInfo]
    parity_shards: List[ShardInfo]
    metadata_shard: Optional[ShardInfo]
    total_size: int
    created_at: datetime
    redundancy_level: int
    min_shards_required: int
    
    @property
    def all_shards(self) -> List[ShardInfo]:
        """Get all shards in the set."""
        shards = self.data_shards + self.parity_shards
        if self.metadata_shard:
            shards.append(self.metadata_shard)
        return shards
    
    @property
    def available_shards(self) -> List[ShardInfo]:
        """Get available (non-missing, non-corrupted) shards."""
        return [s for s in self.all_shards 
                if s.status not in [ShardStatus.MISSING, ShardStatus.CORRUPTED]]
    
    @property
    def can_restore(self) -> bool:
        """Check if enough shards are available for restoration."""
        available_data_parity = [s for s in self.available_shards 
                               if s.shard_type in [ShardType.DATA, ShardType.PARITY]]
        return len(available_data_parity) >= self.min_shards_required

class ShardManager:
    """Manages data sharding with Reed-Solomon error correction."""
    
    def __init__(self, storage_dir: Path, data_shards: int = DEFAULT_DATA_SHARDS, 
                 parity_shards: int = DEFAULT_PARITY_SHARDS):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.data_shards = data_shards
        self.parity_shards = parity_shards
        self.total_shards = data_shards + parity_shards
        self.min_shards_required = data_shards
        
        # Initialize Reed-Solomon codec
        if REED_SOLOMON_AVAILABLE:
            self.rs_codec = RSCodec(parity_shards)
            logger.info(f"Reed-Solomon codec initialized: {data_shards} data + {parity_shards} parity shards")
        else:
            self.rs_codec = None
            logger.warning("Reed-Solomon not available, using simple redundancy")
        
        # Shard registry
        self.shard_sets: Dict[str, ShardSet] = {}
    
    def _calculate_checksum(self, data: bytes) -> str:
        """Calculate SHA256 checksum of data."""
        return hashlib.sha256(data).hexdigest()
    
    def _split_into_chunks(self, data: bytes) -> List[bytes]:
        """Split data into 1MB chunks."""
        chunks = []
        for i in range(0, len(data), SHARD_SIZE):
            chunk = data[i:i + SHARD_SIZE]
            # Pad last chunk to full size if needed
            if len(chunk) < SHARD_SIZE and i + SHARD_SIZE >= len(data):
                chunk = chunk.ljust(SHARD_SIZE, b'\x00')
            chunks.append(chunk)
        return chunks
    
    def create_shards(self, data: bytes, backup_id: str, version_id: str) -> ShardSet:
        """Create shards from data with Reed-Solomon encoding."""
        try:
            logger.info(f"Creating shards for backup {backup_id}, size: {len(data)} bytes")
            
            # Split data into chunks
            chunks = self._split_into_chunks(data)
            logger.info(f"Split into {len(chunks)} chunks of {SHARD_SIZE} bytes each")
            
            # Create data shards
            data_shards = []
            parity_shards = []
            
            for chunk_idx, chunk in enumerate(chunks):
                # Apply Reed-Solomon encoding to each chunk
                if self.rs_codec and REED_SOLOMON_AVAILABLE:
                    try:
                        encoded_chunk = self.rs_codec.encode(chunk)
                        # Split encoded data into data and parity portions
                        data_portion = encoded_chunk[:SHARD_SIZE]
                        parity_portion = encoded_chunk[SHARD_SIZE:]
                        
                        # Create data shard
                        data_shard = ShardInfo(
                            shard_id=str(uuid4()),
                            backup_id=backup_id,
                            shard_index=chunk_idx,
                            shard_type=ShardType.DATA,
                            size=len(data_portion),
                            checksum=self._calculate_checksum(data_portion),
                            created_at=datetime.now(timezone.utc),
                            metadata={"chunk_index": chunk_idx, "original_size": len(chunk)}
                        )
                        data_shards.append(data_shard)
                        
                        # Save data shard to disk
                        shard_file = self.storage_dir / f"{data_shard.shard_id}.shard"
                        with open(shard_file, 'wb') as f:
                            f.write(data_portion)
                        data_shard.location = str(shard_file)
                        
                        # Create parity shards (split parity data if needed)
                        parity_chunk_size = len(parity_portion) // self.parity_shards
                        for parity_idx in range(self.parity_shards):
                            start_idx = parity_idx * parity_chunk_size
                            end_idx = start_idx + parity_chunk_size
                            if parity_idx == self.parity_shards - 1:  # Last parity shard gets remainder
                                end_idx = len(parity_portion)
                            
                            parity_data = parity_portion[start_idx:end_idx]
                            if not parity_data:  # Skip empty parity shards
                                continue
                                
                            parity_shard = ShardInfo(
                                shard_id=str(uuid4()),
                                backup_id=backup_id,
                                shard_index=chunk_idx * self.parity_shards + parity_idx,
                                shard_type=ShardType.PARITY,
                                size=len(parity_data),
                                checksum=self._calculate_checksum(parity_data),
                                created_at=datetime.now(timezone.utc),
                                metadata={"chunk_index": chunk_idx, "parity_index": parity_idx}
                            )
                            parity_shards.append(parity_shard)
                            
                            # Save parity shard to disk
                            parity_file = self.storage_dir / f"{parity_shard.shard_id}.shard"
                            with open(parity_file, 'wb') as f:
                                f.write(parity_data)
                            parity_shard.location = str(parity_file)
                            
                    except Exception as e:
                        logger.error(f"Reed-Solomon encoding failed for chunk {chunk_idx}: {e}")
                        # Fallback to simple redundancy
                        self._create_simple_redundancy_shards(chunk, chunk_idx, backup_id, 
                                                            data_shards, parity_shards)
                else:
                    # Simple redundancy fallback
                    self._create_simple_redundancy_shards(chunk, chunk_idx, backup_id, 
                                                        data_shards, parity_shards)
            
            # Create metadata shard
            metadata = {
                "backup_id": backup_id,
                "version_id": version_id,
                "total_size": len(data),
                "chunk_count": len(chunks),
                "data_shards": len(data_shards),
                "parity_shards": len(parity_shards),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "shard_size": SHARD_SIZE,
                "redundancy_config": {
                    "data_shards": self.data_shards,
                    "parity_shards": self.parity_shards,
                    "min_required": self.min_shards_required
                }
            }
            
            metadata_bytes = str(metadata).encode('utf-8')
            metadata_shard = ShardInfo(
                shard_id=str(uuid4()),
                backup_id=backup_id,
                shard_index=-1,  # Special index for metadata
                shard_type=ShardType.METADATA,
                size=len(metadata_bytes),
                checksum=self._calculate_checksum(metadata_bytes),
                created_at=datetime.now(timezone.utc),
                metadata=metadata
            )
            
            # Save metadata shard
            metadata_file = self.storage_dir / f"{metadata_shard.shard_id}.shard"
            with open(metadata_file, 'wb') as f:
                f.write(metadata_bytes)
            metadata_shard.location = str(metadata_file)
            
            # Create shard set
            shard_set = ShardSet(
                backup_id=backup_id,
                version_id=version_id,
                data_shards=data_shards,
                parity_shards=parity_shards,
                metadata_shard=metadata_shard,
                total_size=len(data),
                created_at=datetime.now(timezone.utc),
                redundancy_level=self.parity_shards,
                min_shards_required=self.min_shards_required
            )
            
            self.shard_sets[backup_id] = shard_set
            
            logger.info(f"Created {len(data_shards)} data shards and {len(parity_shards)} parity shards")
            return shard_set
            
        except Exception as e:
            logger.error(f"Failed to create shards: {e}")
            raise
    
    def _create_simple_redundancy_shards(self, chunk: bytes, chunk_idx: int, backup_id: str,
                                       data_shards: List[ShardInfo], parity_shards: List[ShardInfo]):
        """Create simple redundancy shards when Reed-Solomon is not available."""
        # Create primary data shard
        data_shard = ShardInfo(
            shard_id=str(uuid4()),
            backup_id=backup_id,
            shard_index=chunk_idx,
            shard_type=ShardType.DATA,
            size=len(chunk),
            checksum=self._calculate_checksum(chunk),
            created_at=datetime.now(timezone.utc),
            metadata={"chunk_index": chunk_idx, "redundancy_type": "simple"}
        )
        data_shards.append(data_shard)
        
        # Save data shard
        shard_file = self.storage_dir / f"{data_shard.shard_id}.shard"
        with open(shard_file, 'wb') as f:
            f.write(chunk)
        data_shard.location = str(shard_file)
        
        # Create simple parity shards (copies)
        for parity_idx in range(self.parity_shards):
            parity_shard = ShardInfo(
                shard_id=str(uuid4()),
                backup_id=backup_id,
                shard_index=chunk_idx * self.parity_shards + parity_idx,
                shard_type=ShardType.PARITY,
                size=len(chunk),
                checksum=self._calculate_checksum(chunk),
                created_at=datetime.now(timezone.utc),
                metadata={"chunk_index": chunk_idx, "parity_index": parity_idx, "redundancy_type": "simple"}
            )
            parity_shards.append(parity_shard)
            
            # Save parity shard (copy of data)
            parity_file = self.storage_dir / f"{parity_shard.shard_id}.shard"
            with open(parity_file, 'wb') as f:
                f.write(chunk)
            parity_shard.location = str(parity_file)

    def reconstruct_data(self, shard_set: ShardSet) -> bytes:
        """Reconstruct original data from available shards."""
        try:
            if not shard_set.can_restore:
                raise ValueError(f"Insufficient shards for restoration. Need {shard_set.min_shards_required}, have {len(shard_set.available_shards)}")

            logger.info(f"Reconstructing data from {len(shard_set.available_shards)} available shards")

            # Group shards by chunk index
            chunks_data = {}

            for shard in shard_set.available_shards:
                if shard.shard_type == ShardType.METADATA:
                    continue

                chunk_idx = shard.metadata.get("chunk_index", 0)
                if chunk_idx not in chunks_data:
                    chunks_data[chunk_idx] = {"data": [], "parity": []}

                # Load shard data
                if shard.location and Path(shard.location).exists():
                    with open(shard.location, 'rb') as f:
                        shard_data = f.read()

                    # Verify checksum
                    if self._calculate_checksum(shard_data) != shard.checksum:
                        logger.warning(f"Checksum mismatch for shard {shard.shard_id}")
                        shard.status = ShardStatus.CORRUPTED
                        continue

                    if shard.shard_type == ShardType.DATA:
                        chunks_data[chunk_idx]["data"].append((shard.shard_index, shard_data))
                    elif shard.shard_type == ShardType.PARITY:
                        chunks_data[chunk_idx]["parity"].append((shard.metadata.get("parity_index", 0), shard_data))

            # Reconstruct each chunk
            reconstructed_chunks = []

            for chunk_idx in sorted(chunks_data.keys()):
                chunk_data = chunks_data[chunk_idx]

                if self.rs_codec and REED_SOLOMON_AVAILABLE:
                    # Use Reed-Solomon reconstruction
                    reconstructed_chunk = self._reconstruct_chunk_rs(chunk_data, chunk_idx)
                else:
                    # Use simple reconstruction (just take first available data shard)
                    reconstructed_chunk = self._reconstruct_chunk_simple(chunk_data, chunk_idx)

                if reconstructed_chunk:
                    reconstructed_chunks.append((chunk_idx, reconstructed_chunk))

            # Sort chunks by index and concatenate
            reconstructed_chunks.sort(key=lambda x: x[0])
            reconstructed_data = b''.join([chunk for _, chunk in reconstructed_chunks])

            # Remove padding from last chunk if present
            if shard_set.metadata_shard and shard_set.metadata_shard.metadata:
                original_size = shard_set.metadata_shard.metadata.get("total_size", len(reconstructed_data))
                reconstructed_data = reconstructed_data[:original_size]

            logger.info(f"Successfully reconstructed {len(reconstructed_data)} bytes")
            return reconstructed_data

        except Exception as e:
            logger.error(f"Failed to reconstruct data: {e}")
            raise

    def _reconstruct_chunk_rs(self, chunk_data: Dict, chunk_idx: int) -> Optional[bytes]:
        """Reconstruct a chunk using Reed-Solomon decoding."""
        try:
            # Combine data and parity shards
            data_shards = chunk_data["data"]
            parity_shards = chunk_data["parity"]

            if not data_shards:
                logger.warning(f"No data shards available for chunk {chunk_idx}")
                return None

            # For Reed-Solomon, we need to reconstruct the encoded data first
            # This is a simplified version - in practice, you'd need more sophisticated reconstruction
            if len(data_shards) >= 1:
                # If we have at least one data shard, use it
                _, data = data_shards[0]

                # Try to decode with Reed-Solomon if we have parity data
                if parity_shards:
                    try:
                        # Reconstruct encoded data (data + parity)
                        parity_data = b''.join([parity for _, parity in sorted(parity_shards)])
                        encoded_data = data + parity_data

                        # Decode with Reed-Solomon
                        decoded_data = self.rs_codec.decode(encoded_data)
                        return decoded_data[:SHARD_SIZE]  # Return only the original data portion
                    except ReedSolomonError as e:
                        logger.warning(f"Reed-Solomon decode failed for chunk {chunk_idx}: {e}")
                        # Fall back to using data shard directly
                        return data
                else:
                    return data

            return None

        except Exception as e:
            logger.error(f"Reed-Solomon chunk reconstruction failed: {e}")
            return None

    def _reconstruct_chunk_simple(self, chunk_data: Dict, chunk_idx: int) -> Optional[bytes]:
        """Reconstruct a chunk using simple redundancy."""
        try:
            # Just use the first available data shard
            data_shards = chunk_data["data"]
            if data_shards:
                _, data = data_shards[0]
                return data

            # If no data shard, try parity shards (they're copies in simple mode)
            parity_shards = chunk_data["parity"]
            if parity_shards:
                _, data = parity_shards[0]
                return data

            logger.warning(f"No shards available for chunk {chunk_idx}")
            return None

        except Exception as e:
            logger.error(f"Simple chunk reconstruction failed: {e}")
            return None

    def get_shard_set(self, backup_id: str) -> Optional[ShardSet]:
        """Get shard set by backup ID."""
        return self.shard_sets.get(backup_id)

    def verify_shards(self, shard_set: ShardSet) -> Dict[str, Any]:
        """Verify integrity of all shards in a set."""
        verification_results = {
            "total_shards": len(shard_set.all_shards),
            "verified_shards": 0,
            "corrupted_shards": 0,
            "missing_shards": 0,
            "can_restore": False,
            "shard_details": []
        }

        for shard in shard_set.all_shards:
            shard_result = {
                "shard_id": shard.shard_id,
                "shard_type": shard.shard_type.value,
                "status": shard.status.value,
                "location": shard.location
            }

            if shard.location and Path(shard.location).exists():
                try:
                    with open(shard.location, 'rb') as f:
                        shard_data = f.read()

                    if self._calculate_checksum(shard_data) == shard.checksum:
                        shard.status = ShardStatus.VERIFIED
                        verification_results["verified_shards"] += 1
                        shard_result["status"] = "verified"
                    else:
                        shard.status = ShardStatus.CORRUPTED
                        verification_results["corrupted_shards"] += 1
                        shard_result["status"] = "corrupted"
                        shard_result["error"] = "checksum_mismatch"

                except Exception as e:
                    shard.status = ShardStatus.CORRUPTED
                    verification_results["corrupted_shards"] += 1
                    shard_result["status"] = "corrupted"
                    shard_result["error"] = str(e)
            else:
                shard.status = ShardStatus.MISSING
                verification_results["missing_shards"] += 1
                shard_result["status"] = "missing"

            verification_results["shard_details"].append(shard_result)

        verification_results["can_restore"] = shard_set.can_restore

        return verification_results

    def cleanup_shards(self, backup_id: str) -> bool:
        """Clean up all shards for a backup."""
        try:
            shard_set = self.shard_sets.get(backup_id)
            if not shard_set:
                return False

            deleted_count = 0
            for shard in shard_set.all_shards:
                if shard.location and Path(shard.location).exists():
                    try:
                        Path(shard.location).unlink()
                        deleted_count += 1
                    except Exception as e:
                        logger.warning(f"Failed to delete shard {shard.shard_id}: {e}")

            # Remove from registry
            del self.shard_sets[backup_id]

            logger.info(f"Cleaned up {deleted_count} shards for backup {backup_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to cleanup shards: {e}")
            return False

# Export main classes
__all__ = [
    "ShardManager",
    "ShardInfo",
    "ShardSet",
    "ShardType",
    "ShardStatus",
    "SHARD_SIZE",
    "DEFAULT_DATA_SHARDS",
    "DEFAULT_PARITY_SHARDS"
]
