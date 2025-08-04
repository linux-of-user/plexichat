#!/usr/bin/env python3
"""
PlexiChat Distributed Backup System

Advanced distributed backup system with sharding, encryption, versioning,
and cross-user distribution. Provides immutable backups with Reed-Solomon
error correction and message edit diffs.
"""

import asyncio
import gzip
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

# Check if config system is available
try:
    import plexichat.core.config.simple_config
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False

# Import database system
try:
    from plexichat.core.database.manager import database_manager
    DATABASE_AVAILABLE = True
except ImportError:
    try:
        from plexichat.core.database import database_manager
        DATABASE_AVAILABLE = True
    except ImportError:
        DATABASE_AVAILABLE = False
        database_manager = None

# Import distributed backup components
try:
    from .shard_manager import ShardManager, ShardSet, ShardInfo, ShardType, ShardStatus
    from .encryption_manager import EncryptionManager, EncryptedData, EncryptionAlgorithm
    from .version_manager import VersionManager, VersionInfo, VersionType, MessageDiff
    from .distribution_manager import DistributionManager, StorageNode, DistributionStrategy
    DISTRIBUTED_COMPONENTS_AVAILABLE = True
except ImportError:
    DISTRIBUTED_COMPONENTS_AVAILABLE = False
    logger.warning("Distributed backup components not available, using simple backup")

logger = logging.getLogger(__name__)

# Exceptions
class BackupError(Exception):
    """Backup operation error."""
    pass

class RestoreError(Exception):
    """Restore operation error."""
    pass

class BackupType(Enum):
    """Types of backups."""
    DATABASE = "database"
    FILES = "files"
    FULL = "full"
    CONFIG = "config"
    LOGS = "logs"

class BackupStatus(Enum):
    """Backup operation status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class BackupInfo:
    """Information about a backup."""
    
    def __init__(self, backup_id: str, backup_type: BackupType, name: str, 
                 file_path: str, size: int = 0, created_at: datetime = None):
        self.backup_id = backup_id
        self.backup_type = backup_type
        self.name = name
        self.file_path = file_path
        self.size = size
        self.created_at = created_at or datetime.now(timezone.utc)
        self.status = BackupStatus.PENDING
        self.error_message = None
        self.checksum = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {}}
            "backup_id": self.backup_id,
            "backup_type": self.backup_type.value,
            "name": self.name,
            "file_path": self.file_path,
            "size": self.size,
            "created_at": self.created_at.isoformat(),
            "status": self.status.value,
            "error_message": self.error_message,
            "checksum": self.checksum
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BackupInfo':
        """Create from dictionary."""
        backup = cls(
            backup_id=data["backup_id"],
            backup_type=BackupType(data["backup_type"]),
            name=data["name"],
            file_path=data["file_path"],
            size=data["size"],
            created_at=datetime.fromisoformat(data["created_at"])
        )
        backup.status = BackupStatus(data["status"])
        backup.error_message = data.get("error_message")
        backup.checksum = data.get("checksum")
        return backup

class DistributedBackupManager:
    """Advanced distributed backup manager for PlexiChat."""

    def __init__(self):
        self.config = get_config() if CONFIG_AVAILABLE else None
        self.backup_dir = self._get_backup_directory()
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        # Initialize distributed components
        if DISTRIBUTED_COMPONENTS_AVAILABLE:
            self.shard_manager = ShardManager(
                storage_dir=self.backup_dir / "shards",
                data_shards=self._get_config_value("data_shards", 5),
                parity_shards=self._get_config_value("parity_shards", 3)
            )

            self.encryption_manager = EncryptionManager(
                key_storage_dir=self.backup_dir / "keys"
            )

            self.version_manager = VersionManager(
                storage_dir=self.backup_dir / "versions"
            )

            self.distribution_manager = DistributionManager(
                storage_dir=self.backup_dir / "distribution"
            )

            logger.info("Distributed backup system initialized")
        else:
            # Fallback to simple components
            self.shard_manager = None
            self.encryption_manager = None
            self.version_manager = None
            self.distribution_manager = None
            logger.warning("Using simple backup fallback")

        # Backup registry
        self.registry_file = self.backup_dir / "backup_registry.json"
        self.backups: Dict[str, BackupInfo] = {}

        # Configuration
        self.max_backups = self._get_config_value("max_backups", 30)
        self.compression_enabled = self._get_config_value("compression_enabled", True)
        self.retention_days = self._get_config_value("retention_days", 30)
        self.distributed_enabled = self._get_config_value("distributed_enabled", True)

        # Load existing backups
        self._load_backup_registry()
    
    def _get_backup_directory(self) -> Path:
        """Get backup directory from config."""
        if self.config and hasattr(self.config, 'system') and hasattr(self.config.system, 'backup_directory'):
            return Path(self.config.system.backup_directory)
        return Path("backups")
    
    def _get_config_value(self, key: str, default: Any) -> Any:
        """Get configuration value with fallback."""
        if self.config and hasattr(self.config, 'system'):
            return getattr(self.config.system, key, default)
        return default
    
    def _load_backup_registry(self):
        """Load backup registry from file."""
        try:
            if self.registry_file.exists():
                with open(self.registry_file, 'r') as f:
                    data = json.load(f)
                    for backup_data in data.get("backups", []):
                        backup = BackupInfo.from_dict(backup_data)
                        self.backups[backup.backup_id] = backup
                logger.info(f"Loaded {len(self.backups)} backups from registry")
        except Exception as e:
            logger.error(f"Failed to load backup registry: {e}")
    
    def _save_backup_registry(self):
        """Save backup registry to file."""
        try:
            data = {
                "version": "1.0",
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "backups": [backup.to_dict() for backup in self.backups.values()]
            }
            with open(self.registry_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save backup registry: {e}")
    
    def _calculate_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate checksum for {file_path}: {e}")
            return ""
    
    async def create_database_backup(self, name: Optional[str] = None) -> Optional[BackupInfo]:
        """Create a distributed database backup with sharding and encryption."""
        try:
            backup_id = str(uuid4())
            name = name or f"database_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            backup = BackupInfo(backup_id, BackupType.DATABASE, name, "")
            backup.status = BackupStatus.RUNNING
            self.backups[backup_id] = backup

            logger.info(f"Starting distributed database backup: {name}")

            # Export database to memory
            database_data = await self._export_database_to_bytes()

            if not database_data:
                backup.status = BackupStatus.FAILED
                backup.error_message = "Database export failed"
                self._save_backup_registry()
                return None

            # Use distributed backup if available
            if self.distributed_enabled and DISTRIBUTED_COMPONENTS_AVAILABLE:
                success = await self._create_distributed_backup(backup_id, database_data, BackupType.DATABASE)
            else:
                # Fallback to simple backup
                success = await self._create_simple_backup(backup_id, database_data, name)

            if success:
                backup.size = len(database_data)
                backup.checksum = hashlib.sha256(database_data).hexdigest()
                backup.status = BackupStatus.COMPLETED
                logger.info(f"Database backup completed: {name} ({backup.size} bytes)")
            else:
                backup.status = BackupStatus.FAILED
                backup.error_message = "Backup creation failed"
                logger.error(f"Database backup failed: {name}")

            self._save_backup_registry()
            return backup if success else None

        except Exception as e:
            logger.error(f"Database backup error: {e}")
            if backup_id in self.backups:
                self.backups[backup_id].status = BackupStatus.FAILED
                self.backups[backup_id].error_message = str(e)
                self._save_backup_registry()
            return None

    async def _create_distributed_backup(self, backup_id: str, data: bytes, backup_type: BackupType) -> bool:
        """Create a distributed backup with sharding, encryption, and distribution."""
        try:
            logger.info(f"Creating distributed backup {backup_id} with {len(data)} bytes")

            # Create version
            version_info = self.version_manager.create_version(
                backup_id=backup_id,
                data=data,
                version_type=VersionType.FULL,
                metadata={"backup_type": backup_type.value}
            )

            # Create shards with Reed-Solomon encoding
            shard_set = self.shard_manager.create_shards(
                data=data,
                backup_id=backup_id,
                version_id=version_info.version_id
            )

            # Encrypt each shard
            encrypted_shards = {}
            for shard in shard_set.all_shards:
                if shard.location and Path(shard.location).exists():
                    with open(shard.location, 'rb') as f:
                        shard_data = f.read()

                    encrypted_data = self.encryption_manager.encrypt_shard(shard_data, shard.shard_id)
                    encrypted_shards[shard.shard_id] = encrypted_data.data

                    # Update shard with encryption info
                    shard.encryption_key_id = encrypted_data.key_id
                    shard.metadata["encryption_algorithm"] = encrypted_data.algorithm.value

            # Create distribution plan
            distribution_plan = self.distribution_manager.create_distribution_plan(
                shard_set=shard_set,
                strategy=DistributionStrategy.LOAD_BALANCED
            )

            # Execute distribution
            distribution_success = await self.distribution_manager.execute_distribution_plan(
                plan=distribution_plan,
                shard_data=encrypted_shards
            )

            if distribution_success:
                logger.info(f"Distributed backup {backup_id} created successfully")
                return True
            else:
                logger.error(f"Failed to distribute backup {backup_id}")
                return False

        except Exception as e:
            logger.error(f"Distributed backup creation failed: {e}")
            return False

    async def _create_simple_backup(self, backup_id: str, data: bytes, name: str) -> bool:
        """Create a simple backup (fallback when distributed components unavailable)."""
        try:
            backup_file = self.backup_dir / f"{name}.backup"

            if self.compression_enabled:
                with gzip.open(f"{backup_file}.gz", 'wb') as f:
                    f.write(data)
                backup_file = Path(f"{backup_file}.gz")
            else:
                with open(backup_file, 'wb') as f:
                    f.write(data)

            return backup_file.exists()

        except Exception as e:
            logger.error(f"Simple backup creation failed: {e}")
            return False

    async def _export_database_to_bytes(self) -> Optional[bytes]:
        """Export database to bytes."""
        try:
            if DATABASE_AVAILABLE and database_manager:
                # Use database manager to export to memory
                temp_file = tempfile.NamedTemporaryFile(delete=False)
                try:
                    success = await database_manager.export_to_file(temp_file.name)
                    if success:
                        with open(temp_file.name, 'rb') as f:
                            return f.read()
                finally:
                    os.unlink(temp_file.name)
            else:
                # Fallback: try to find and read SQLite database
                db_files = list(Path(".").glob("*.db")) + list(Path("data").glob("*.db"))
                if db_files:
                    with open(db_files[0], 'rb') as f:
                        return f.read()

            return None

        except Exception as e:
            logger.error(f"Database export to bytes failed: {e}")
            return None

    async def create_message_diff_backup(self, message_id: str, old_content: str,
                                       new_content: str, user_id: str) -> Optional[BackupInfo]:
        """Create a backup for a message edit diff."""
        try:
            if not (self.distributed_enabled and DISTRIBUTED_COMPONENTS_AVAILABLE):
                logger.warning("Message diff backups require distributed components")
                return None

            backup_id = str(uuid4())
            name = f"message_diff_{message_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            backup = BackupInfo(backup_id, BackupType.DIFF, name, "")
            backup.status = BackupStatus.RUNNING
            self.backups[backup_id] = backup

            logger.info(f"Creating message diff backup for message {message_id}")

            # Create message diff version
            version_info = self.version_manager.create_message_diff(
                message_id=message_id,
                old_content=old_content,
                new_content=new_content,
                user_id=user_id,
                backup_id=backup_id
            )

            if version_info:
                backup.size = version_info.size
                backup.checksum = version_info.checksum
                backup.status = BackupStatus.COMPLETED
                backup.metadata = {
                    "message_id": message_id,
                    "user_id": user_id,
                    "version_id": version_info.version_id
                }
                logger.info(f"Message diff backup completed: {name}")
            else:
                backup.status = BackupStatus.FAILED
                backup.error_message = "Message diff creation failed"
                logger.error(f"Message diff backup failed: {name}")

            self._save_backup_registry()
            return backup if version_info else None

        except Exception as e:
            logger.error(f"Message diff backup error: {e}")
            if backup_id in self.backups:
                self.backups[backup_id].status = BackupStatus.FAILED
                self.backups[backup_id].error_message = str(e)
                self._save_backup_registry()
            return None
    
    async def _export_database(self, backup_file: str) -> bool:
        """Export database to backup file."""
        try:
            if DATABASE_AVAILABLE and database_manager:
                # Use database manager to export
                return await database_manager.export_to_file(backup_file)
            else:
                # Fallback: try to find and copy SQLite database
                db_files = list(Path(".").glob("*.db")) + list(Path("data").glob("*.db"))
                if db_files:
                    source_db = db_files[0]
                    if self.compression_enabled and backup_file.endswith('.gz'):
                        with open(source_db, 'rb') as f_in:
                            with gzip.open(backup_file, 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                    else:
                        shutil.copy2(source_db, backup_file)
                    return True
                else:
                    logger.warning("No database files found for backup")
                    return False
        except Exception as e:
            logger.error(f"Database export error: {e}")
            return False

    async def create_files_backup(self, name: Optional[str] = None,
                                 include_paths: Optional[List[str]] = None) -> Optional[BackupInfo]:
        """Create a files backup."""
        try:
            backup_id = str(uuid4())
            name = name or f"files_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            # Create backup file path
            backup_file = self.backup_dir / f"{name}.tar.gz"

            backup = BackupInfo(backup_id, BackupType.FILES, name, str(backup_file))
            backup.status = BackupStatus.RUNNING
            self.backups[backup_id] = backup

            logger.info(f"Starting files backup: {name}")

            # Create files archive
            success = await self._create_files_archive(str(backup_file), include_paths)

            if success:
                backup.size = backup_file.stat().st_size if backup_file.exists() else 0
                backup.checksum = self._calculate_checksum(str(backup_file))
                backup.status = BackupStatus.COMPLETED
                logger.info(f"Files backup completed: {name} ({backup.size} bytes)")
            else:
                backup.status = BackupStatus.FAILED
                backup.error_message = "Files archive creation failed"
                logger.error(f"Files backup failed: {name}")

            self._save_backup_registry()
            return backup if success else None

        except Exception as e:
            logger.error(f"Files backup error: {e}")
            if backup_id in self.backups:
                self.backups[backup_id].status = BackupStatus.FAILED
                self.backups[backup_id].error_message = str(e)
                self._save_backup_registry()
            return None

    async def _create_files_archive(self, backup_file: str, include_paths: Optional[List[str]] = None) -> bool:
        """Create files archive."""
        try:
            # Default paths to backup
            default_paths = [
                "uploads",
                "logs",
                "config",
                "data"
            ]

            paths_to_backup = include_paths or default_paths

            with tarfile.open(backup_file, 'w:gz') as tar:
                for path_str in paths_to_backup:
                    path = Path(path_str)
                    if path.exists():
                        if path.is_file():
                            tar.add(path, arcname=path.name)
                        elif path.is_dir():
                            tar.add(path, arcname=path.name)
                        logger.debug(f"Added {path} to backup archive")
                    else:
                        logger.debug(f"Path {path} does not exist, skipping")

            return True

        except Exception as e:
            logger.error(f"Files archive creation error: {e}")
            return False

    async def create_config_backup(self, name: Optional[str] = None) -> Optional[BackupInfo]:
        """Create a configuration backup."""
        try:
            backup_id = str(uuid4())
            name = name or f"config_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            # Create backup file path
            backup_file = self.backup_dir / f"{name}.json"
            if self.compression_enabled:
                backup_file = backup_file.with_suffix('.json.gz')

            backup = BackupInfo(backup_id, BackupType.CONFIG, name, str(backup_file))
            backup.status = BackupStatus.RUNNING
            self.backups[backup_id] = backup

            logger.info(f"Starting config backup: {name}")

            # Export configuration
            success = await self._export_config(str(backup_file))

            if success:
                backup.size = backup_file.stat().st_size if backup_file.exists() else 0
                backup.checksum = self._calculate_checksum(str(backup_file))
                backup.status = BackupStatus.COMPLETED
                logger.info(f"Config backup completed: {name} ({backup.size} bytes)")
            else:
                backup.status = BackupStatus.FAILED
                backup.error_message = "Configuration export failed"
                logger.error(f"Config backup failed: {name}")

            self._save_backup_registry()
            return backup if success else None

        except Exception as e:
            logger.error(f"Config backup error: {e}")
            if backup_id in self.backups:
                self.backups[backup_id].status = BackupStatus.FAILED
                self.backups[backup_id].error_message = str(e)
                self._save_backup_registry()
            return None

    async def _export_config(self, backup_file: str) -> bool:
        """Export configuration to backup file."""
        try:
            if self.config:
                config_data = self.config.export_config(include_sensitive=False)
            else:
                # Fallback: backup config files
                config_data = {"note": "Configuration export not available"}

            if self.compression_enabled and backup_file.endswith('.gz'):
                with gzip.open(backup_file, 'wt') as f:
                    json.dump(config_data, f, indent=2)
            else:
                with open(backup_file, 'w') as f:
                    json.dump(config_data, f, indent=2)

            return True

        except Exception as e:
            logger.error(f"Config export error: {e}")
            return False

    async def create_full_backup(self, name: Optional[str] = None) -> Optional[BackupInfo]:
        """Create a full system backup."""
        try:
            backup_id = str(uuid4())
            name = name or f"full_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            # Create backup directory for full backup
            full_backup_dir = self.backup_dir / name
            full_backup_dir.mkdir(exist_ok=True)

            backup = BackupInfo(backup_id, BackupType.FULL, name, str(full_backup_dir))
            backup.status = BackupStatus.RUNNING
            self.backups[backup_id] = backup

            logger.info(f"Starting full backup: {name}")

            # Create individual backups
            db_backup = await self.create_database_backup(f"{name}_database")
            files_backup = await self.create_files_backup(f"{name}_files")
            config_backup = await self.create_config_backup(f"{name}_config")

            # Check if all backups succeeded
            success = all([db_backup, files_backup, config_backup])

            if success:
                # Calculate total size
                total_size = 0
                if db_backup:
                    total_size += db_backup.size
                if files_backup:
                    total_size += files_backup.size
                if config_backup:
                    total_size += config_backup.size

                backup.size = total_size
                backup.status = BackupStatus.COMPLETED
                logger.info(f"Full backup completed: {name} ({backup.size} bytes)")
            else:
                backup.status = BackupStatus.FAILED
                backup.error_message = "One or more component backups failed"
                logger.error(f"Full backup failed: {name}")

            self._save_backup_registry()
            return backup if success else None

        except Exception as e:
            logger.error(f"Full backup error: {e}")
            if backup_id in self.backups:
                self.backups[backup_id].status = BackupStatus.FAILED
                self.backups[backup_id].error_message = str(e)
                self._save_backup_registry()
            return None

    async def restore_backup(self, backup_id: str, restore_path: Optional[str] = None) -> bool:
        """Restore a distributed backup from shards."""
        try:
            if backup_id not in self.backups:
                raise RestoreError(f"Backup {backup_id} not found")

            backup = self.backups[backup_id]

            if backup.status != BackupStatus.COMPLETED:
                raise RestoreError(f"Backup {backup_id} is not completed")

            logger.info(f"Starting restore of distributed backup: {backup.name}")

            # Use distributed restore if available
            if self.distributed_enabled and DISTRIBUTED_COMPONENTS_AVAILABLE:
                success = await self._restore_distributed_backup(backup_id, restore_path)
            else:
                # Fallback to simple restore
                success = await self._restore_simple_backup(backup, restore_path)

            if success:
                logger.info(f"Backup restored successfully: {backup.name}")
            else:
                logger.error(f"Backup restore failed: {backup.name}")

            return success

        except Exception as e:
            logger.error(f"Restore error: {e}")
            return False

    async def _restore_distributed_backup(self, backup_id: str, restore_path: Optional[str] = None) -> bool:
        """Restore a backup from distributed shards."""
        try:
            # Get shard set
            shard_set = self.shard_manager.get_shard_set(backup_id)
            if not shard_set:
                logger.error(f"No shard set found for backup {backup_id}")
                return False

            # Verify we have enough shards for restoration
            if not shard_set.can_restore:
                logger.error(f"Insufficient shards for restoration: need {shard_set.min_shards_required}, have {len(shard_set.available_shards)}")
                return False

            # Collect encrypted shard data
            encrypted_shards = {}

            for shard in shard_set.available_shards:
                if shard.shard_type == ShardType.METADATA:
                    continue

                # Retrieve shard data from distribution
                shard_data = await self.distribution_manager.retrieve_shard(shard.shard_id)
                if shard_data:
                    encrypted_shards[shard.shard_id] = shard_data
                else:
                    logger.warning(f"Failed to retrieve shard {shard.shard_id}")

            # Decrypt shards
            decrypted_shards = {}

            for shard in shard_set.available_shards:
                if shard.shard_type == ShardType.METADATA:
                    continue

                if shard.shard_id in encrypted_shards:
                    try:
                        encrypted_data = EncryptedData(
                            data=encrypted_shards[shard.shard_id],
                            key_id=shard.encryption_key_id,
                            algorithm=EncryptionAlgorithm(shard.metadata.get("encryption_algorithm", "aes-256-gcm"))
                        )

                        decrypted_data = self.encryption_manager.decrypt_shard(encrypted_data)

                        # Save decrypted shard temporarily
                        temp_shard_file = self.backup_dir / "temp" / f"{shard.shard_id}.shard"
                        temp_shard_file.parent.mkdir(exist_ok=True)

                        with open(temp_shard_file, 'wb') as f:
                            f.write(decrypted_data)

                        shard.location = str(temp_shard_file)

                    except Exception as e:
                        logger.error(f"Failed to decrypt shard {shard.shard_id}: {e}")
                        continue

            # Reconstruct data from shards
            reconstructed_data = self.shard_manager.reconstruct_data(shard_set)

            if not reconstructed_data:
                logger.error("Failed to reconstruct data from shards")
                return False

            # Save reconstructed data
            if restore_path:
                output_file = Path(restore_path)
            else:
                output_file = self.backup_dir / f"restored_{backup_id}.data"

            output_file.parent.mkdir(parents=True, exist_ok=True)

            with open(output_file, 'wb') as f:
                f.write(reconstructed_data)

            # Clean up temporary files
            temp_dir = self.backup_dir / "temp"
            if temp_dir.exists():
                shutil.rmtree(temp_dir)

            logger.info(f"Distributed backup restored to {output_file}")
            return True

        except Exception as e:
            logger.error(f"Distributed restore failed: {e}")
            return False

    async def _restore_simple_backup(self, backup: BackupInfo, restore_path: Optional[str] = None) -> bool:
        """Restore a simple backup (fallback)."""
        try:
            backup_file = Path(backup.file_path)
            if not backup_file.exists():
                logger.error(f"Backup file not found: {backup.file_path}")
                return False

            # Verify checksum if available
            if backup.checksum:
                current_checksum = self._calculate_checksum(backup.file_path)
                if current_checksum != backup.checksum:
                    raise RestoreError(f"Backup file checksum mismatch")

            # Restore based on backup type
            if backup.backup_type == BackupType.DATABASE:
                return await self._restore_database(backup.file_path, restore_path)
            elif backup.backup_type == BackupType.FILES:
                return await self._restore_files(backup.file_path, restore_path)
            elif backup.backup_type == BackupType.CONFIG:
                return await self._restore_config(backup.file_path, restore_path)
            elif backup.backup_type == BackupType.FULL:
                return await self._restore_full(backup.file_path, restore_path)
            else:
                raise RestoreError(f"Unsupported backup type: {backup.backup_type}")

        except Exception as e:
            logger.error(f"Simple restore failed: {e}")
            return False

    async def _restore_database(self, backup_file: str, restore_path: Optional[str] = None) -> bool:
        """Restore database from backup."""
        try:
            if DATABASE_AVAILABLE and database_manager:
                return await database_manager.import_from_file(backup_file)
            else:
                # Fallback: restore SQLite database
                target_path = restore_path or "data/plexichat_restored.db"
                Path(target_path).parent.mkdir(parents=True, exist_ok=True)

                if backup_file.endswith('.gz'):
                    with gzip.open(backup_file, 'rb') as f_in:
                        with open(target_path, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                else:
                    shutil.copy2(backup_file, target_path)

                return True
        except Exception as e:
            logger.error(f"Database restore error: {e}")
            return False

    async def _restore_files(self, backup_file: str, restore_path: Optional[str] = None) -> bool:
        """Restore files from backup."""
        try:
            target_dir = Path(restore_path or "restored_files")
            target_dir.mkdir(parents=True, exist_ok=True)

            with tarfile.open(backup_file, 'r:gz') as tar:
                tar.extractall(path=target_dir)

            return True
        except Exception as e:
            logger.error(f"Files restore error: {e}")
            return False

    async def _restore_config(self, backup_file: str, restore_path: Optional[str] = None) -> bool:
        """Restore configuration from backup."""
        try:
            if backup_file.endswith('.gz'):
                with gzip.open(backup_file, 'rt') as f:
                    config_data = json.load(f)
            else:
                with open(backup_file, 'r') as f:
                    config_data = json.load(f)

            # Save to specified path or default
            target_file = restore_path or "config/restored_config.json"
            Path(target_file).parent.mkdir(parents=True, exist_ok=True)

            with open(target_file, 'w') as f:
                json.dump(config_data, f, indent=2)

            return True
        except Exception as e:
            logger.error(f"Config restore error: {e}")
            return False

    async def _restore_full(self, backup_path: str, restore_path: Optional[str] = None) -> bool:
        """Restore full backup."""
        try:
            # For full backups, the backup_path is a directory
            backup_dir = Path(backup_path)
            if not backup_dir.is_dir():
                return False

            # Find component backups
            db_backups = list(backup_dir.glob("*database*"))
            files_backups = list(backup_dir.glob("*files*"))
            config_backups = list(backup_dir.glob("*config*"))

            success = True

            # Restore each component
            if db_backups:
                success &= await self._restore_database(str(db_backups[0]), restore_path)
            if files_backups:
                success &= await self._restore_files(str(files_backups[0]), restore_path)
            if config_backups:
                success &= await self._restore_config(str(config_backups[0]), restore_path)

            return success
        except Exception as e:
            logger.error(f"Full restore error: {e}")
            return False

    def list_backups(self, backup_type: Optional[BackupType] = None) -> List[BackupInfo]:
        """List all backups, optionally filtered by type."""
        backups = list(self.backups.values())

        if backup_type:
            backups = [b for b in backups if b.backup_type == backup_type]

        # Sort by creation date (newest first)
        backups.sort(key=lambda x: x.created_at, reverse=True)

        return backups

    def get_backup(self, backup_id: str) -> Optional[BackupInfo]:
        """Get backup information by ID."""
        return self.backups.get(backup_id)

    def delete_backup(self, backup_id: str) -> bool:
        """Delete a backup."""
        try:
            if backup_id not in self.backups:
                return False

            backup = self.backups[backup_id]
            backup_path = Path(backup.file_path)

            # Delete backup file(s)
            if backup_path.exists():
                if backup_path.is_file():
                    backup_path.unlink()
                elif backup_path.is_dir():
                    shutil.rmtree(backup_path)

            # Remove from registry
            del self.backups[backup_id]
            self._save_backup_registry()

            logger.info(f"Deleted backup: {backup.name}")
            return True

        except Exception as e:
            logger.error(f"Delete backup error: {e}")
            return False

    def cleanup_old_backups(self) -> int:
        """Clean up old backups based on retention policy."""
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
            deleted_count = 0

            # Find old backups
            old_backups = [
                backup for backup in self.backups.values()
                if backup.created_at < cutoff_date
            ]

            # Keep at least a few recent backups
            if len(self.backups) - len(old_backups) < 3:
                old_backups = old_backups[:-3]  # Keep 3 most recent

            # Delete old backups
            for backup in old_backups:
                if self.delete_backup(backup.backup_id):
                    deleted_count += 1

            logger.info(f"Cleaned up {deleted_count} old backups")
            return deleted_count

        except Exception as e:
            logger.error(f"Cleanup error: {e}")
            return 0

    def get_backup_stats(self) -> Dict[str, Any]:
        """Get backup statistics."""
        total_backups = len(self.backups)
        completed_backups = len([b for b in self.backups.values() if b.status == BackupStatus.COMPLETED])
        failed_backups = len([b for b in self.backups.values() if b.status == BackupStatus.FAILED])
        total_size = sum(b.size for b in self.backups.values() if b.status == BackupStatus.COMPLETED)

        return {}}
            "total_backups": total_backups,
            "completed_backups": completed_backups,
            "failed_backups": failed_backups,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "retention_days": self.retention_days,
            "compression_enabled": self.compression_enabled
        }

# Backward compatibility alias
BackupManager = DistributedBackupManager

# Global backup manager instance
_backup_manager: Optional[DistributedBackupManager] = None

def get_backup_manager() -> DistributedBackupManager:
    """Get the global distributed backup manager instance."""
    global _backup_manager
    if _backup_manager is None:
        _backup_manager = DistributedBackupManager()
    return _backup_manager

# Convenience functions
async def create_database_backup(name: Optional[str] = None) -> Optional[BackupInfo]:
    """Create a database backup."""
    return await get_backup_manager().create_database_backup(name)

async def create_files_backup(name: Optional[str] = None,
                             include_paths: Optional[List[str]] = None) -> Optional[BackupInfo]:
    """Create a files backup."""
    return await get_backup_manager().create_files_backup(name, include_paths)

async def create_full_backup(name: Optional[str] = None) -> Optional[BackupInfo]:
    """Create a full backup."""
    return await get_backup_manager().create_full_backup(name)

async def restore_backup(backup_id: str, restore_path: Optional[str] = None) -> bool:
    """Restore a backup."""
    return await get_backup_manager().restore_backup(backup_id, restore_path)

def list_backups(backup_type: Optional[BackupType] = None) -> List[BackupInfo]:
    """List all backups."""
    return get_backup_manager().list_backups(backup_type)

# Export main classes and functions
__all__ = [
    "DistributedBackupManager",
    "BackupManager",  # Alias for backward compatibility
    "BackupInfo",
    "BackupType",
    "BackupStatus",
    "BackupError",
    "RestoreError",
    "get_backup_manager",
    "create_database_backup",
    "create_files_backup",
    "create_full_backup",
    "restore_backup",
    "list_backups"
]
