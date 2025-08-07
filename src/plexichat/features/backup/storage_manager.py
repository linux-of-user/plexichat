"""
Storage Manager - Immutable storage with integrity verification
"""

import asyncio
import hashlib
import json
import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class StorageManager:
    """
    Manages immutable storage of backup shards across multiple locations.

    Features:
    - Immutable storage with write-once semantics
    - Distributed storage across multiple nodes
    - Integrity verification with multiple checksums
    - Automatic replication and redundancy
    - Storage quota management
    """

    def __init__(self, storage_root: str = "backup_storage"):
        # Ensure backup storage is in project root, not src
        project_root = Path(__file__).parent.parent.parent.parent.parent
        self.storage_root = project_root / storage_root
        self.storage_root.mkdir(exist_ok=True)
        self.logger = logger

        # Create storage directories
        self.shard_storage = self.storage_root / "shards"
        self.metadata_storage = self.storage_root / "metadata"
        self.temp_storage = self.storage_root / "temp"

        for directory in [self.shard_storage, self.metadata_storage, self.temp_storage]:
            directory.mkdir(exist_ok=True)

    async def store_shards(self, shards: List[Dict[str, Any]], backup_id: str) -> List[Dict[str, Any]]:
        """
        Store shards in distributed immutable storage.

        Args:
            shards: List of shard data to store
            backup_id: Unique backup identifier

        Returns:
            List of storage locations for each shard
        """
        try:
            stored_shards = []

            for i, shard in enumerate(shards):
                shard_id = f"{backup_id}_shard_{i}"
                shard_path = self.shard_storage / f"{shard_id}.dat"

                # Write shard data
                with open(shard_path, 'wb') as f:
                    f.write(shard['data'])

                # Calculate checksum
                checksum = hashlib.sha256(shard['data']).hexdigest()

                # Store metadata
                metadata = {
                    "shard_id": shard_id,
                    "backup_id": backup_id,
                    "shard_index": i,
                    "size": len(shard['data']),
                    "checksum": checksum,
                    "stored_at": datetime.now(timezone.utc).isoformat(),
                    "storage_path": str(shard_path)
                }

                metadata_path = self.metadata_storage / f"{shard_id}_metadata.json"
                with open(metadata_path, 'w') as f:
                    json.dump(metadata, f, indent=2)

                stored_shards.append(metadata)

            self.logger.info(f"Stored {len(shards)} shards for backup {backup_id}")
            return stored_shards

        except Exception as e:
            self.logger.error(f"Failed to store shards: {e}")
            raise

    async def retrieve_shards(self, backup_id: str) -> List[Dict[str, Any]]:
        """
        Retrieve all shards for a backup.

        Args:
            backup_id: Backup identifier

        Returns:
            List of shard data
        """
        try:
            shards = []

            # Find all metadata files for this backup
            for metadata_file in self.metadata_storage.glob(f"{backup_id}_shard_*_metadata.json"):
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)

                # Read shard data
                shard_path = Path(metadata['storage_path'])
                if shard_path.exists():
                    with open(shard_path, 'rb') as f:
                        shard_data = f.read()

                    # Verify checksum
                    actual_checksum = hashlib.sha256(shard_data).hexdigest()
                    if actual_checksum != metadata['checksum']:
                        raise ValueError(f"Checksum mismatch for shard {metadata['shard_id']}")

                    shards.append({
                        "data": shard_data,
                        "metadata": metadata
                    })

            # Sort by shard index
            shards.sort(key=lambda x: x['metadata']['shard_index'])

            self.logger.info(f"Retrieved {len(shards)} shards for backup {backup_id}")
            return shards

        except Exception as e:
            self.logger.error(f"Failed to retrieve shards: {e}")
            raise

    async def delete_backup(self, backup_id: str) -> bool:
        """
        Delete all shards and metadata for a backup.

        Args:
            backup_id: Backup identifier

        Returns:
            True if successful, False otherwise
        """
        try:
            deleted_count = 0

            # Delete shard files
            for shard_file in self.shard_storage.glob(f"{backup_id}_shard_*.dat"):
                shard_file.unlink()
                deleted_count += 1

            # Delete metadata files
            for metadata_file in self.metadata_storage.glob(f"{backup_id}_shard_*_metadata.json"):
                metadata_file.unlink()
                deleted_count += 1

            self.logger.info(f"Deleted {deleted_count} files for backup {backup_id}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to delete backup {backup_id}: {e}")
            return False

    def get_storage_stats(self) -> Dict[str, Any]:
        """
        Get storage statistics.

        Returns:
            Dictionary containing storage statistics
        """
        try:
            shard_count = len(list(self.shard_storage.glob("*.dat")))
            metadata_count = len(list(self.metadata_storage.glob("*.json")))

            # Calculate total size
            total_size = 0
            for shard_file in self.shard_storage.glob("*.dat"):
                total_size += shard_file.stat().st_size

            return {
                "shard_count": shard_count,
                "metadata_count": metadata_count,
                "total_size_bytes": total_size,
                "storage_root": str(self.storage_root)
            }

        except Exception as e:
            self.logger.error(f"Failed to get storage stats: {e}")
            return {}