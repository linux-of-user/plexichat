#!/usr/bin/env python3
"""
PlexiChat Unified Backup System

A clean, simple, and effective backup system that integrates with the unified
configuration system and provides reliable backup and restore functionality.


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

logger = logging.getLogger(__name__)

# Exceptions
class BackupError(Exception):
    """Backup operation error."""
        pass

class RestoreError(Exception):
    Restore operation error."""
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
    """Information about a backup.
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
        self.metadata = {}  # Additional metadata for the backup
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "backup_id": self.backup_id,
            "backup_type": self.backup_type.value,
            "name": self.name,
            "file_path": self.file_path,
            "size": self.size,
            "created_at": self.created_at.isoformat(),
            "status": self.status.value,
            "error_message": self.error_message,
            "checksum": self.checksum,
            "metadata": self.metadata
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
        backup.metadata = data.get("metadata", {})
        return backup

class BackupManager:
    """Unified backup manager for PlexiChat."""
        def __init__(self):
        try:
            if CONFIG_AVAILABLE:
                from ...config.simple_config import get_config
                self.config = get_config()
                self._config = self.config  # Add _config alias
            else:
                self.config = None
                self._config = None
        except Exception:
            self.config = None
            self._config = None
        self.backup_dir = self._get_backup_directory()
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        # Backup registry file
        self.registry_file = self.backup_dir / "backup_registry.json"
        self.backups: Dict[str, BackupInfo] = {}

        # Configuration
        self.max_backups = self._get_config_value("max_backups", 30)
        self.compression_enabled = self._get_config_value("compression_enabled", True)
        self.retention_days = self._get_config_value("retention_days", 30)

        # Distributed backup components (initialize as None for basic mode)
        self.distributed_enabled = False
        self.shard_manager = None
        self.encryption_manager = None
        self.version_manager = None
        self.distribution_manager = None
        self.p2p_manager = None
        self.recovery_manager = None
        self.key_manager = None

        # Try to initialize distributed components if available
        self._initialize_distributed_components()

        # Load existing backups
        self._load_backup_registry()

    def _initialize_distributed_components(self):
        """Initialize distributed backup components if available."""
        try:
            # Try to import and initialize distributed components
            from .shard_manager import EnhancedShardManager
            from .encryption_manager import EncryptionManager
            from .distribution_manager import DistributionManager
            from .recovery_manager import RecoveryManager
            from .distributed_key_manager import DistributedKeyManager
            from .p2p_network_manager import P2PNetworkManager
            from .version_manager import VersionManager

            # Initialize components
            self.shard_manager = EnhancedShardManager(self.backup_dir / "shards")
            self.key_manager = DistributedKeyManager(self.backup_dir / "keys")
            self.encryption_manager = EncryptionManager(self.backup_dir / "encryption")
            self.p2p_manager = P2PNetworkManager()
            self.distribution_manager = DistributionManager(self.backup_dir / "distribution", self.p2p_manager)
            self.recovery_manager = RecoveryManager(self.shard_manager, self.distribution_manager, self.p2p_manager)
            self.version_manager = VersionManager(self.backup_dir / "versions")

            self.distributed_enabled = True
            logger.info("Distributed backup components initialized successfully")

        except ImportError as e:
            logger.info(f"Distributed backup components not available: {e}")
            self.distributed_enabled = False
        except Exception as e:
            logger.warning(f"Failed to initialize distributed backup components: {e}")
            self.distributed_enabled = False

    def _get_backup_directory(self) -> Path:
        """Get backup directory from config."""
        if self.config and hasattr(self.config, 'system') and hasattr(self.config.system, 'backup_directory'):
            return Path(self.config.system.backup_directory)
        return Path("backups")
    
    def _get_config_value(self, key: str, default: Any) -> Any:
        """Get configuration value with fallback.
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
        """Create a database backup."""
        try:
            backup_id = str(uuid4())
            name = name or f"database_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Create backup file path
            backup_file = self.backup_dir / f"{name}.sql"
            if self.compression_enabled:
                backup_file = backup_file.with_suffix('.sql.gz')
            
            backup = BackupInfo(backup_id, BackupType.DATABASE, name, str(backup_file))
            backup.status = BackupStatus.RUNNING
            self.backups[backup_id] = backup
            
            logger.info(f"Starting database backup: {name}")
            
            # Export database
            success = await self._export_database(str(backup_file))
            
            if success:
                backup.size = backup_file.stat().st_size if backup_file.exists() else 0
                backup.checksum = self._calculate_checksum(str(backup_file))
                backup.status = BackupStatus.COMPLETED
                logger.info(f"Database backup completed: {name} ({backup.size} bytes)")
            else:
                backup.status = BackupStatus.FAILED
                backup.error_message = "Database export failed"
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

    async def create_message_diff_backup(self, name: Optional[str] = None,
                                    since_timestamp: Optional[datetime] = None) -> Optional[BackupInfo]:
        """Create a differential backup of messages since a specific timestamp."""
        try:
            backup_id = str(uuid4())
            name = name or f"message_diff_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            # Create backup file
            backup_file = self.backup_dir / f"{name}.json"
            if self.compression_enabled:
                backup_file = backup_file.with_suffix('.json.gz')

            backup = BackupInfo(backup_id, BackupType.DATABASE, name, str(backup_file))
            backup.status = BackupStatus.RUNNING
            self.backups[backup_id] = backup

            logger.info(f"Starting message diff backup: {name}")

            # For now, create a placeholder diff backup
            # In a real implementation, this would query the database for messages since timestamp
            diff_data = {
                "backup_type": "message_diff",
                "since_timestamp": since_timestamp.isoformat() if since_timestamp else None,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "messages": []  # Would contain actual message data
            }

            # Save diff data
            if self.compression_enabled and backup_file.suffix == '.gz':
                with gzip.open(backup_file, 'wt', encoding='utf-8') as f:
                    json.dump(diff_data, f, indent=2)
            else:
                with open(backup_file, 'w', encoding='utf-8') as f:
                    json.dump(diff_data, f, indent=2)

            backup.size = backup_file.stat().st_size
            backup.checksum = self._calculate_checksum(str(backup_file))
            backup.status = BackupStatus.COMPLETED

            self._save_backup_registry()
            logger.info(f"Message diff backup completed: {name}")
            return backup

        except Exception as e:
            logger.error(f"Message diff backup failed: {e}")
            return None

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
        """Restore a backup."""
        try:
            if backup_id not in self.backups:
                raise RestoreError(f"Backup {backup_id} not found")

            backup = self.backups[backup_id]

            if backup.status != BackupStatus.COMPLETED:
                raise RestoreError(f"Backup {backup_id} is not completed")

            backup_file = Path(backup.file_path)
            if not backup_file.exists():
                raise RestoreError(f"Backup file {backup.file_path} not found")

            logger.info(f"Starting restore of backup: {backup.name}")

            # Verify checksum if available
            if backup.checksum:
                current_checksum = self._calculate_checksum(backup.file_path)
                if current_checksum != backup.checksum:
                    raise RestoreError(f"Backup file checksum mismatch")

            # Restore based on backup type
            if backup.backup_type == BackupType.DATABASE:
                success = await self._restore_database(backup.file_path, restore_path)
            elif backup.backup_type == BackupType.FILES:
                success = await self._restore_files(backup.file_path, restore_path)
            elif backup.backup_type == BackupType.CONFIG:
                success = await self._restore_config(backup.file_path, restore_path)
            elif backup.backup_type == BackupType.FULL:
                success = await self._restore_full(backup.file_path, restore_path)
            else:
                raise RestoreError(f"Unsupported backup type: {backup.backup_type}")

            if success:
                logger.info(f"Backup restored successfully: {backup.name}")
            else:
                logger.error(f"Backup restore failed: {backup.name}")

            return success

        except Exception as e:
            logger.error(f"Restore error: {e}")
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
        """List all backups, optionally filtered by type.
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
        Delete a backup."""
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

    async def register_storage_node(self, node_id: str, endpoint: str, capacity_gb: float,
                                location: str, user_id: Optional[str] = None) -> bool:
        """Register a storage node (simplified for API compatibility)."""
        try:
            # For now, just log the registration
            logger.info(f"Storage node registration: {node_id} at {endpoint} ({capacity_gb}GB)")
            return True
        except Exception as e:
            logger.error(f"Failed to register storage node: {e}")
            return False

    def get_network_status(self) -> Dict[str, Any]:
        """Get network status (simplified for API compatibility)."""
        return {
            "available": False,
            "reason": "P2P network not fully implemented in this version",
            "basic_backup": True,
            "distributed_backup": self.distributed_enabled
        }

    async def create_massive_database_backup(self, name: Optional[str] = None,
                                        streaming: bool = True) -> Optional[BackupInfo]:
        """Create massive database backup (fallback to regular backup for now)."""
        try:
            logger.info(f"Creating massive database backup (streaming: {streaming})")
            # For now, fallback to regular database backup
            return await self.create_database_backup(name)
        except Exception as e:
            logger.error(f"Massive database backup failed: {e}")
            return None

    async def restore_massive_backup(self, backup_id: str, target_path: Optional[str] = None,
                                verify_integrity: bool = True) -> Optional[str]:
        """Restore massive backup (fallback to regular restore for now)."""
        try:
            logger.info(f"Restoring massive backup {backup_id} (verify: {verify_integrity})")
            # For now, fallback to regular restore
            success = await self.restore_backup(backup_id, target_path)
            return target_path if success else None
        except Exception as e:
            logger.error(f"Massive restore failed: {e}")
            return None

    def get_backup_stats(self) -> Dict[str, Any]:
        """Get backup statistics."""
        total_backups = len(self.backups)
        completed_backups = len([b for b in self.backups.values() if b.status == BackupStatus.COMPLETED])
        failed_backups = len([b for b in self.backups.values() if b.status == BackupStatus.FAILED])
        total_size = sum(b.size for b in self.backups.values() if b.status == BackupStatus.COMPLETED)

        return {
            "total_backups": total_backups,
            "completed_backups": completed_backups,
            "failed_backups": failed_backups,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "retention_days": self.retention_days,
            "compression_enabled": self.compression_enabled
        }

# Global backup manager instance
_backup_manager: Optional[BackupManager] = None

def get_backup_manager() -> BackupManager:
    """Get the global backup manager instance.
    global _backup_manager
    if _backup_manager is None:
        _backup_manager = BackupManager()
    return _backup_manager

# Convenience functions
async def create_database_backup(name: Optional[str] = None) -> Optional[BackupInfo]:
    """Create a database backup."""
    return await get_backup_manager().create_database_backup(name)

async def create_files_backup(name: Optional[str] = None,
                            include_paths: Optional[List[str]] = None) -> Optional[BackupInfo]:
    Create a files backup."""
    return await get_backup_manager().create_files_backup(name, include_paths)

async def create_full_backup(name: Optional[str] = None) -> Optional[BackupInfo]:
    """Create a full backup.
    return await get_backup_manager().create_full_backup(name)

async def restore_backup(backup_id: str, restore_path: Optional[str] = None) -> bool:
    """Restore a backup."""
    return await get_backup_manager().restore_backup(backup_id, restore_path)

def list_backups(backup_type: Optional[BackupType] = None) -> List[BackupInfo]:
    List all backups."""
    return get_backup_manager().list_backups(backup_type)

# Export main classes and functions
__all__ = [
    "BackupManager",
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
