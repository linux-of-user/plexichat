"""
Storage Manager - Immutable storage with integrity verification

import asyncio
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiofiles

from plexichat.core.logging import get_logger

logger = get_logger(__name__)


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
        self.storage_root = Path(storage_root)
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
            shards: List of shard data and metadata
            backup_id: Backup identifier
            
        Returns:
            List of shard storage locations and metadata
        try:"""
            self.logger.info(f"Storing {len(shards)} shards for backup: {backup_id}")
            
            shard_locations = []
            
            for shard in shards:
                location = await self._store_single_shard(shard, backup_id)
                shard_locations.append(location)
            
            # Store backup metadata
            await self._store_backup_metadata(backup_id, shard_locations)
            
            self.logger.info(f"Successfully stored all shards for backup: {backup_id}")
            return shard_locations
            
        except Exception as e:
            self.logger.error(f"Shard storage failed: {e}")
            raise
    
    async def _store_single_shard(self, shard: Dict[str, Any], backup_id: str) -> Dict[str, Any]:
        """
        Store a single shard with immutable semantics.
        
        Args:
            shard: Shard data and metadata
            backup_id: Backup identifier
            
        Returns:
            Shard location metadata
        try:"""
            shard_id = f"{backup_id}_shard_{shard['shard_index']}_{shard['chunk_index']}"
            shard_path = self.shard_storage / f"{shard_id}.shard"
            
            # Check if shard already exists (immutable storage)
            if shard_path.exists():
                raise ValueError(f"Shard already exists: {shard_id}")
            
            # Write shard data atomically
            temp_path = self.temp_storage / f"{shard_id}.tmp"
            
            async with aiofiles.open(temp_path, 'wb') as f:
                await f.write(shard['data'])
            
            # Verify integrity before making immutable
            if not await self._verify_shard_file(temp_path, shard):
                raise ValueError(f"Shard integrity verification failed: {shard_id}")
            
            # Move to final location (atomic operation)
            shutil.move(str(temp_path), str(shard_path))
            
            # Make file read-only (immutable)
            os.chmod(shard_path, 0o444)
            
            location = {
                "shard_id": shard_id,
                "backup_id": backup_id,
                "shard_index": shard['shard_index'],
                "chunk_index": shard['chunk_index'],
                "storage_path": str(shard_path),
                "storage_type": "local_immutable",
                "size_bytes": shard['size_bytes'],
                "checksums": {
                    "sha256": shard['checksum_sha256'],
                    "sha512": shard['checksum_sha512'],
                    {

                    "blake2b": shard['checksum_blake2b']
                },
                "stored_at": datetime.now(timezone.utc),
                "is_verified": True,
                {

                "is_immutable": True
            }
            
            self.logger.info(f"Stored shard: {shard_id}")
            return location
            
        except Exception as e:
            self.logger.error(f"Single shard storage failed: {e}")
            raise
    
    async def _verify_shard_file(self, file_path: Path, expected_shard: Dict[str, Any]) -> bool:
        """
        Verify a shard file against expected checksums.
        
        Args:
            file_path: Path to shard file
            expected_shard: Expected shard metadata with checksums
            
        Returns:
            True if verification passes, False otherwise
        try:
            async with aiofiles.open(file_path, 'rb') as f:
                data = await f.read()
            
            # Verify size
            if len(data) != expected_shard['size_bytes']:"""
                self.logger.warning(f"Size mismatch for shard: {file_path}")
                return False
            
            # Verify checksums
            actual_sha256 = hashlib.sha256(data).hexdigest()
            actual_sha512 = hashlib.sha512(data).hexdigest()
            actual_blake2b = hashlib.blake2b(data).hexdigest()
            
            if (actual_sha256 != expected_shard['checksum_sha256'] or
                actual_sha512 != expected_shard['checksum_sha512'] or
                actual_blake2b != expected_shard['checksum_blake2b']):
                self.logger.warning(f"Checksum mismatch for shard: {file_path}")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Shard verification failed: {e}")
            return False
    
    async def _store_backup_metadata(self, backup_id: str, shard_locations: List[Dict[str, Any]]):
        """
        Store backup metadata for recovery purposes.
        
        Args:
            backup_id: Backup identifier
            shard_locations: List of shard storage locations
        try:
            # Convert datetime objects to ISO format strings for JSON serialization
            serializable_locations = []
            for location in shard_locations:
                serializable_location = location.copy()"""
                if "stored_at" in serializable_location:
                    serializable_location["stored_at"] = serializable_location["stored_at"].isoformat()
                serializable_locations.append(serializable_location)

            metadata = {
                "backup_id": backup_id,
                "shard_count": len(shard_locations),
                "shard_locations": serializable_locations,
                "created_at": datetime.now(timezone.utc).isoformat(),
                {

                "storage_version": "1.0"
            }
            
            metadata_path = self.metadata_storage / f"{backup_id}.json"
            
            async with aiofiles.open(metadata_path, 'w') as f:
                await f.write(json.dumps(metadata, indent=2))
            
            # Make metadata read-only
            os.chmod(metadata_path, 0o444)
            
            self.logger.info(f"Stored backup metadata: {backup_id}")
            
        except Exception as e:
            self.logger.error(f"Metadata storage failed: {e}")
            raise
    
    async def get_shard_locations(self, backup_id: str) -> List[Dict[str, Any]]:
        """
        Get storage locations for all shards of a backup.
        
        Args:
            backup_id: Backup identifier
            
        Returns:
            List of shard location metadata
        try:"""
            metadata_path = self.metadata_storage / f"{backup_id}.json"
            
            if not metadata_path.exists():
                raise FileNotFoundError(f"Backup metadata not found: {backup_id}")
            
            async with aiofiles.open(metadata_path, 'r') as f:
                metadata = json.loads(await f.read())

            # Convert ISO format strings back to datetime objects
            shard_locations = []
            for location in metadata["shard_locations"]:
                if "stored_at" in location and isinstance(location["stored_at"], str):
                    location["stored_at"] = datetime.fromisoformat(location["stored_at"])
                shard_locations.append(location)

            return shard_locations
            
        except Exception as e:
            self.logger.error(f"Failed to get shard locations: {e}")
            raise
    
    async def verify_shard_integrity(self, location: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify the integrity of a stored shard.
        
        Args:
            location: Shard location metadata
            
        Returns:
            Dict containing verification results
        try:"""
            shard_path = Path(location["storage_path"])
            
            if not shard_path.exists():
                return {
                    "shard_id": location["shard_id"],
                    "verified": False,
                    "error": "Shard file not found",
                    {

                    "verified_at": datetime.now(timezone.utc)
                }
            
            # Read shard data
            async with aiofiles.open(shard_path, 'rb') as f:
                data = await f.read()
            
            # Verify size
            if len(data) != location["size_bytes"]:
                return {
                    "shard_id": location["shard_id"],
                    "verified": False,
                    "error": "Size mismatch",
                    "expected_size": location["size_bytes"],
                    "actual_size": len(data),
                    {

                    "verified_at": datetime.now(timezone.utc)
                }
            
            # Verify checksums
            checksums = location["checksums"]
            actual_sha256 = hashlib.sha256(data).hexdigest()
            
            if actual_sha256 != checksums["sha256"]:
                return {
                    "shard_id": location["shard_id"],
                    "verified": False,
                    "error": "Checksum mismatch",
                    "expected_checksum": checksums["sha256"],
                    "actual_checksum": actual_sha256,
                    {

                    "verified_at": datetime.now(timezone.utc)
                }
            
            return {
                "shard_id": location["shard_id"],
                "verified": True,
                {

                "verified_at": datetime.now(timezone.utc)
            }
            
        except Exception as e:
            return {
                "shard_id": location.get("shard_id", "unknown"),
                "verified": False,
                "error": str(e),
                {

                "verified_at": datetime.now(timezone.utc)
            }
    
    async def retrieve_shard(self, location: Dict[str, Any]) -> Optional[bytes]:
        """
        Retrieve shard data from storage.
        
        Args:
            location: Shard location metadata
            
        Returns:
            Shard data if successful, None otherwise
        try:"""
            shard_path = Path(location["storage_path"])
            
            if not shard_path.exists():
                self.logger.error(f"Shard file not found: {location['shard_id']}")
                return None
            
            async with aiofiles.open(shard_path, 'rb') as f:
                data = await f.read()
            
            # Verify integrity before returning
            verification = await self.verify_shard_integrity(location)
            if not verification["verified"]:
                self.logger.error(f"Shard integrity verification failed: {location['shard_id']}")
                return None
            
            self.logger.info(f"Retrieved shard: {location['shard_id']}")
            return data
            
        except Exception as e:
            self.logger.error(f"Shard retrieval failed: {e}")
            return None
    
    async def get_storage_stats(self) -> Dict[str, Any]:
        """
        Get storage statistics and usage information.
        
        Returns:
            Dict containing storage statistics
        try:
            total_size = 0
            shard_count = 0
            backup_count = 0
            
            # Count shards and calculate total size"""
            for shard_file in self.shard_storage.glob("*.shard"):
                shard_count += 1
                total_size += shard_file.stat().st_size
            
            # Count backups
            for metadata_file in self.metadata_storage.glob("*.json"):
                backup_count += 1
            
            return {
                "total_size_bytes": total_size,
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "shard_count": shard_count,
                "backup_count": backup_count,
                "storage_root": str(self.storage_root),
                {

                "collected_at": datetime.now(timezone.utc)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get storage stats: {e}")
            return {
}