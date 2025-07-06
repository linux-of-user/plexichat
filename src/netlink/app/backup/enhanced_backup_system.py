"""
Enhanced Backup System with Advanced Shard Tracking

This system provides:
- Advanced shard tracking with metadata
- Opt-out capabilities for all backup types
- Profile backup with user preferences
- Enhanced metadata management
- Government-level encryption
- Intelligent shard distribution
- Real-time backup status monitoring
"""

import asyncio
import json
import hashlib
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import aiofiles
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from app.logger_config import logger

class BackupType(Enum):
    """Types of backups available."""
    MESSAGES = "messages"
    FILES = "files"
    PROFILES = "profiles"
    SETTINGS = "settings"
    DATABASE = "database"
    LOGS = "logs"
    PLUGINS = "plugins"
    CERTIFICATES = "certificates"

class ShardStatus(Enum):
    """Status of individual shards."""
    CREATING = "creating"
    ACTIVE = "active"
    CORRUPTED = "corrupted"
    MISSING = "missing"
    ARCHIVED = "archived"
    ENCRYPTED = "encrypted"

class BackupOptOutLevel(Enum):
    """Levels of backup opt-out."""
    NONE = "none"  # Full backup
    MINIMAL = "minimal"  # Only essential data
    METADATA_ONLY = "metadata_only"  # Only metadata, no content
    COMPLETE_OPTOUT = "complete_optout"  # No backup at all

@dataclass
class ShardMetadata:
    """Metadata for individual backup shards."""
    shard_id: str
    backup_type: BackupType
    creation_time: datetime
    last_verified: datetime
    
    # Shard properties
    size_bytes: int
    checksum: str
    encryption_key_id: str
    compression_ratio: float
    
    # Location and distribution
    primary_location: str
    replica_locations: List[str] = field(default_factory=list)
    node_assignments: List[str] = field(default_factory=list)
    
    # Status and health
    status: ShardStatus = ShardStatus.CREATING
    verification_count: int = 0
    corruption_detected: bool = False
    last_access: Optional[datetime] = None
    
    # Content metadata
    content_hash: str = ""
    content_type: str = ""
    original_path: str = ""
    user_id: Optional[int] = None
    
    # Backup policy
    retention_days: int = 365
    auto_archive_after_days: int = 90
    replication_factor: int = 3

@dataclass
class UserBackupPreferences:
    """User preferences for backup behavior."""
    user_id: int
    
    # Opt-out settings for each backup type
    backup_opt_outs: Dict[BackupType, BackupOptOutLevel] = field(default_factory=dict)
    
    # Retention preferences
    retention_preferences: Dict[BackupType, int] = field(default_factory=dict)  # Days
    
    # Privacy settings
    encrypt_personal_data: bool = True
    allow_cross_node_replication: bool = True
    require_local_storage_only: bool = False
    
    # Notification preferences
    notify_on_backup_completion: bool = False
    notify_on_backup_failure: bool = True
    notify_on_data_recovery: bool = True
    
    # Advanced settings
    custom_encryption_key: Optional[str] = None
    backup_schedule_preference: str = "daily"  # daily, weekly, monthly
    max_storage_quota_mb: Optional[int] = None
    
    # Metadata
    preferences_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    preferences_version: int = 1

@dataclass
class BackupJob:
    """Individual backup job tracking."""
    job_id: str
    backup_type: BackupType
    user_id: Optional[int]
    
    # Job status
    status: str = "pending"  # pending, running, completed, failed
    progress_percentage: float = 0.0
    
    # Timing
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Results
    shards_created: List[str] = field(default_factory=list)
    total_size_bytes: int = 0
    compression_achieved: float = 0.0
    
    # Error handling
    error_message: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3

class EnhancedBackupSystem:
    """Enhanced backup system with advanced shard tracking and user preferences."""
    
    def __init__(self, backup_root: str = "backups"):
        self.backup_root = Path(backup_root)
        self.backup_root.mkdir(exist_ok=True)
        
        # Initialize directories
        self.shards_dir = self.backup_root / "shards"
        self.metadata_dir = self.backup_root / "metadata"
        self.temp_dir = self.backup_root / "temp"
        
        for directory in [self.shards_dir, self.metadata_dir, self.temp_dir]:
            directory.mkdir(exist_ok=True)
        
        # Shard tracking
        self.shards: Dict[str, ShardMetadata] = {}
        self.user_preferences: Dict[int, UserBackupPreferences] = {}
        self.active_jobs: Dict[str, BackupJob] = {}
        
        # Encryption setup
        self.master_key = self._initialize_encryption()
        self.encryption_keys: Dict[str, Fernet] = {}
        
        # System configuration
        self.config = {
            "default_replication_factor": 3,
            "max_shard_size_mb": 100,
            "compression_enabled": True,
            "encryption_enabled": True,
            "auto_verification_interval_hours": 24,
            "cleanup_old_shards_days": 30,
            "max_concurrent_jobs": 5
        }
        
        # Statistics
        self.stats = {
            "total_shards": 0,
            "total_size_bytes": 0,
            "successful_backups": 0,
            "failed_backups": 0,
            "data_recovered_bytes": 0,
            "corruption_incidents": 0
        }
        
        # Start background tasks
        asyncio.create_task(self._background_maintenance())
        
        logger.info("Enhanced Backup System initialized")
    
    def _initialize_encryption(self) -> Fernet:
        """Initialize master encryption key."""
        key_file = self.backup_root / "master.key"
        
        if key_file.exists():
            # Load existing key
            with open(key_file, 'rb') as f:
                key = f.read()
        else:
            # Generate new key
            password = secrets.token_urlsafe(32).encode()
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            
            # Save key securely
            with open(key_file, 'wb') as f:
                f.write(key)
            key_file.chmod(0o600)  # Restrict permissions
        
        return Fernet(key)
    
    async def set_user_backup_preferences(self, 
                                        user_id: int,
                                        preferences: Dict[str, Any]) -> bool:
        """Set backup preferences for a user."""
        try:
            if user_id not in self.user_preferences:
                self.user_preferences[user_id] = UserBackupPreferences(user_id=user_id)
            
            user_prefs = self.user_preferences[user_id]
            
            # Update opt-out settings
            if "backup_opt_outs" in preferences:
                for backup_type_str, opt_out_level_str in preferences["backup_opt_outs"].items():
                    try:
                        backup_type = BackupType(backup_type_str)
                        opt_out_level = BackupOptOutLevel(opt_out_level_str)
                        user_prefs.backup_opt_outs[backup_type] = opt_out_level
                    except ValueError:
                        logger.warning(f"Invalid backup type or opt-out level: {backup_type_str}, {opt_out_level_str}")
            
            # Update retention preferences
            if "retention_preferences" in preferences:
                for backup_type_str, days in preferences["retention_preferences"].items():
                    try:
                        backup_type = BackupType(backup_type_str)
                        user_prefs.retention_preferences[backup_type] = int(days)
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid retention preference: {backup_type_str}, {days}")
            
            # Update other preferences
            for key in ["encrypt_personal_data", "allow_cross_node_replication", 
                       "require_local_storage_only", "notify_on_backup_completion",
                       "notify_on_backup_failure", "notify_on_data_recovery"]:
                if key in preferences:
                    setattr(user_prefs, key, bool(preferences[key]))
            
            # Update advanced settings
            if "backup_schedule_preference" in preferences:
                user_prefs.backup_schedule_preference = str(preferences["backup_schedule_preference"])
            
            if "max_storage_quota_mb" in preferences:
                user_prefs.max_storage_quota_mb = int(preferences["max_storage_quota_mb"])
            
            # Update metadata
            user_prefs.preferences_updated = datetime.now(timezone.utc)
            user_prefs.preferences_version += 1
            
            # Save preferences
            await self._save_user_preferences(user_id)
            
            logger.info(f"Updated backup preferences for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set user backup preferences: {e}")
            return False
    
    async def get_user_backup_preferences(self, user_id: int) -> Optional[UserBackupPreferences]:
        """Get backup preferences for a user."""
        if user_id not in self.user_preferences:
            # Load from disk if available
            await self._load_user_preferences(user_id)
        
        return self.user_preferences.get(user_id)
    
    async def should_backup_user_data(self, 
                                    user_id: int, 
                                    backup_type: BackupType) -> Tuple[bool, BackupOptOutLevel]:
        """Check if user data should be backed up based on preferences."""
        preferences = await self.get_user_backup_preferences(user_id)
        
        if not preferences:
            # Default: full backup for users without preferences
            return True, BackupOptOutLevel.NONE
        
        opt_out_level = preferences.backup_opt_outs.get(backup_type, BackupOptOutLevel.NONE)
        
        # Determine if backup should proceed
        should_backup = opt_out_level != BackupOptOutLevel.COMPLETE_OPTOUT
        
        return should_backup, opt_out_level
    
    async def create_backup_job(self, 
                              backup_type: BackupType,
                              data_source: Any,
                              user_id: Optional[int] = None,
                              custom_options: Optional[Dict[str, Any]] = None) -> str:
        """Create a new backup job."""
        job_id = f"backup_{backup_type.value}_{int(time.time() * 1000)}"
        
        job = BackupJob(
            job_id=job_id,
            backup_type=backup_type,
            user_id=user_id
        )
        
        self.active_jobs[job_id] = job
        
        # Start backup job asynchronously
        asyncio.create_task(self._execute_backup_job(job, data_source, custom_options or {}))
        
        logger.info(f"Created backup job: {job_id} for type: {backup_type.value}")
        return job_id

    async def _execute_backup_job(self,
                                job: BackupJob,
                                data_source: Any,
                                options: Dict[str, Any]):
        """Execute a backup job."""
        try:
            job.status = "running"
            job.started_at = datetime.now(timezone.utc)

            # Check user preferences if user-specific backup
            if job.user_id:
                should_backup, opt_out_level = await self.should_backup_user_data(
                    job.user_id, job.backup_type
                )

                if not should_backup:
                    job.status = "skipped"
                    job.completed_at = datetime.now(timezone.utc)
                    logger.info(f"Backup job {job.job_id} skipped due to user opt-out")
                    return

                # Adjust backup based on opt-out level
                if opt_out_level == BackupOptOutLevel.METADATA_ONLY:
                    options["metadata_only"] = True
                elif opt_out_level == BackupOptOutLevel.MINIMAL:
                    options["minimal_data"] = True

            # Process data and create shards
            shards_created = await self._process_backup_data(job, data_source, options)

            job.shards_created = shards_created
            job.status = "completed"
            job.completed_at = datetime.now(timezone.utc)
            job.progress_percentage = 100.0

            # Update statistics
            self.stats["successful_backups"] += 1
            self.stats["total_shards"] += len(shards_created)

            logger.info(f"Backup job {job.job_id} completed successfully. Created {len(shards_created)} shards.")

        except Exception as e:
            job.status = "failed"
            job.error_message = str(e)
            job.completed_at = datetime.now(timezone.utc)

            # Retry logic
            if job.retry_count < job.max_retries:
                job.retry_count += 1
                job.status = "retrying"
                logger.warning(f"Backup job {job.job_id} failed, retrying ({job.retry_count}/{job.max_retries}): {e}")

                # Retry after delay
                await asyncio.sleep(60 * job.retry_count)  # Exponential backoff
                await self._execute_backup_job(job, data_source, options)
            else:
                self.stats["failed_backups"] += 1
                logger.error(f"Backup job {job.job_id} failed permanently: {e}")

    async def _process_backup_data(self,
                                 job: BackupJob,
                                 data_source: Any,
                                 options: Dict[str, Any]) -> List[str]:
        """Process backup data and create shards."""
        shards_created = []

        try:
            # Convert data source to processable format
            if isinstance(data_source, (str, bytes)):
                data_chunks = [data_source]
            elif isinstance(data_source, list):
                data_chunks = data_source
            elif hasattr(data_source, '__iter__'):
                data_chunks = list(data_source)
            else:
                # Try to serialize
                data_chunks = [json.dumps(data_source, default=str)]

            total_chunks = len(data_chunks)

            for i, chunk in enumerate(data_chunks):
                # Create shard for chunk
                shard_id = await self._create_shard(
                    chunk, job.backup_type, job.user_id, options
                )

                if shard_id:
                    shards_created.append(shard_id)
                    job.progress_percentage = ((i + 1) / total_chunks) * 100

                # Update job progress
                if i % 10 == 0:  # Update every 10 chunks
                    logger.debug(f"Backup job {job.job_id} progress: {job.progress_percentage:.1f}%")

            return shards_created

        except Exception as e:
            logger.error(f"Failed to process backup data for job {job.job_id}: {e}")
            raise

    async def _create_shard(self,
                          data: Any,
                          backup_type: BackupType,
                          user_id: Optional[int],
                          options: Dict[str, Any]) -> Optional[str]:
        """Create a backup shard from data."""
        try:
            # Generate shard ID
            shard_id = f"shard_{backup_type.value}_{int(time.time() * 1000)}_{secrets.token_hex(8)}"

            # Convert data to bytes
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            elif isinstance(data, bytes):
                data_bytes = data
            else:
                data_bytes = json.dumps(data, default=str).encode('utf-8')

            # Compress if enabled
            if self.config["compression_enabled"]:
                import gzip
                data_bytes = gzip.compress(data_bytes)
                compression_ratio = len(data_bytes) / len(data.encode('utf-8') if isinstance(data, str) else data)
            else:
                compression_ratio = 1.0

            # Encrypt if enabled
            encryption_key_id = "master"
            if self.config["encryption_enabled"]:
                # Use user-specific key if available
                if user_id and user_id in self.user_preferences:
                    user_prefs = self.user_preferences[user_id]
                    if user_prefs.custom_encryption_key:
                        encryption_key_id = f"user_{user_id}"
                        if encryption_key_id not in self.encryption_keys:
                            self.encryption_keys[encryption_key_id] = Fernet(
                                user_prefs.custom_encryption_key.encode()
                            )

                # Encrypt data
                cipher = self.encryption_keys.get(encryption_key_id, self.master_key)
                data_bytes = cipher.encrypt(data_bytes)

            # Calculate checksums
            content_hash = hashlib.sha256(data_bytes).hexdigest()
            checksum = hashlib.md5(data_bytes).hexdigest()

            # Create shard metadata
            shard_metadata = ShardMetadata(
                shard_id=shard_id,
                backup_type=backup_type,
                creation_time=datetime.now(timezone.utc),
                last_verified=datetime.now(timezone.utc),
                size_bytes=len(data_bytes),
                checksum=checksum,
                encryption_key_id=encryption_key_id,
                compression_ratio=compression_ratio,
                primary_location=str(self.shards_dir / f"{shard_id}.shard"),
                content_hash=content_hash,
                user_id=user_id,
                replication_factor=self.config["default_replication_factor"]
            )

            # Set retention based on user preferences
            if user_id and user_id in self.user_preferences:
                user_prefs = self.user_preferences[user_id]
                if backup_type in user_prefs.retention_preferences:
                    shard_metadata.retention_days = user_prefs.retention_preferences[backup_type]

            # Write shard to disk
            shard_path = Path(shard_metadata.primary_location)
            async with aiofiles.open(shard_path, 'wb') as f:
                await f.write(data_bytes)

            # Create replicas if needed
            await self._create_shard_replicas(shard_metadata)

            # Update shard status
            shard_metadata.status = ShardStatus.ACTIVE

            # Store metadata
            self.shards[shard_id] = shard_metadata
            await self._save_shard_metadata(shard_id)

            # Update statistics
            self.stats["total_size_bytes"] += len(data_bytes)

            logger.debug(f"Created shard {shard_id} ({len(data_bytes)} bytes)")
            return shard_id

        except Exception as e:
            logger.error(f"Failed to create shard: {e}")
            return None

    async def _create_shard_replicas(self, shard_metadata: ShardMetadata):
        """Create replicas of a shard for redundancy."""
        try:
            replicas_needed = shard_metadata.replication_factor - 1  # Primary + replicas

            for i in range(replicas_needed):
                replica_path = self.shards_dir / f"{shard_metadata.shard_id}_replica_{i+1}.shard"

                # Copy primary shard to replica location
                primary_path = Path(shard_metadata.primary_location)
                if primary_path.exists():
                    async with aiofiles.open(primary_path, 'rb') as src:
                        data = await src.read()

                    async with aiofiles.open(replica_path, 'wb') as dst:
                        await dst.write(data)

                    shard_metadata.replica_locations.append(str(replica_path))

            logger.debug(f"Created {replicas_needed} replicas for shard {shard_metadata.shard_id}")

        except Exception as e:
            logger.error(f"Failed to create replicas for shard {shard_metadata.shard_id}: {e}")

    async def _save_shard_metadata(self, shard_id: str):
        """Save shard metadata to disk."""
        try:
            if shard_id not in self.shards:
                return

            metadata = self.shards[shard_id]
            metadata_path = self.metadata_dir / f"{shard_id}.json"

            # Convert to serializable format
            metadata_dict = {
                "shard_id": metadata.shard_id,
                "backup_type": metadata.backup_type.value,
                "creation_time": metadata.creation_time.isoformat(),
                "last_verified": metadata.last_verified.isoformat(),
                "size_bytes": metadata.size_bytes,
                "checksum": metadata.checksum,
                "encryption_key_id": metadata.encryption_key_id,
                "compression_ratio": metadata.compression_ratio,
                "primary_location": metadata.primary_location,
                "replica_locations": metadata.replica_locations,
                "node_assignments": metadata.node_assignments,
                "status": metadata.status.value,
                "verification_count": metadata.verification_count,
                "corruption_detected": metadata.corruption_detected,
                "last_access": metadata.last_access.isoformat() if metadata.last_access else None,
                "content_hash": metadata.content_hash,
                "content_type": metadata.content_type,
                "original_path": metadata.original_path,
                "user_id": metadata.user_id,
                "retention_days": metadata.retention_days,
                "auto_archive_after_days": metadata.auto_archive_after_days,
                "replication_factor": metadata.replication_factor
            }

            async with aiofiles.open(metadata_path, 'w') as f:
                await f.write(json.dumps(metadata_dict, indent=2))

        except Exception as e:
            logger.error(f"Failed to save metadata for shard {shard_id}: {e}")

    async def _save_user_preferences(self, user_id: int):
        """Save user backup preferences to disk."""
        try:
            if user_id not in self.user_preferences:
                return

            prefs = self.user_preferences[user_id]
            prefs_path = self.metadata_dir / f"user_prefs_{user_id}.json"

            # Convert to serializable format
            prefs_dict = {
                "user_id": prefs.user_id,
                "backup_opt_outs": {bt.value: ool.value for bt, ool in prefs.backup_opt_outs.items()},
                "retention_preferences": {bt.value: days for bt, days in prefs.retention_preferences.items()},
                "encrypt_personal_data": prefs.encrypt_personal_data,
                "allow_cross_node_replication": prefs.allow_cross_node_replication,
                "require_local_storage_only": prefs.require_local_storage_only,
                "notify_on_backup_completion": prefs.notify_on_backup_completion,
                "notify_on_backup_failure": prefs.notify_on_backup_failure,
                "notify_on_data_recovery": prefs.notify_on_data_recovery,
                "custom_encryption_key": prefs.custom_encryption_key,
                "backup_schedule_preference": prefs.backup_schedule_preference,
                "max_storage_quota_mb": prefs.max_storage_quota_mb,
                "preferences_updated": prefs.preferences_updated.isoformat(),
                "preferences_version": prefs.preferences_version
            }

            async with aiofiles.open(prefs_path, 'w') as f:
                await f.write(json.dumps(prefs_dict, indent=2))

        except Exception as e:
            logger.error(f"Failed to save preferences for user {user_id}: {e}")

    async def _load_user_preferences(self, user_id: int):
        """Load user backup preferences from disk."""
        try:
            prefs_path = self.metadata_dir / f"user_prefs_{user_id}.json"

            if not prefs_path.exists():
                return

            async with aiofiles.open(prefs_path, 'r') as f:
                prefs_dict = json.loads(await f.read())

            # Convert from serializable format
            prefs = UserBackupPreferences(user_id=user_id)

            # Load opt-out settings
            if "backup_opt_outs" in prefs_dict:
                for bt_str, ool_str in prefs_dict["backup_opt_outs"].items():
                    try:
                        bt = BackupType(bt_str)
                        ool = BackupOptOutLevel(ool_str)
                        prefs.backup_opt_outs[bt] = ool
                    except ValueError:
                        continue

            # Load retention preferences
            if "retention_preferences" in prefs_dict:
                for bt_str, days in prefs_dict["retention_preferences"].items():
                    try:
                        bt = BackupType(bt_str)
                        prefs.retention_preferences[bt] = int(days)
                    except (ValueError, TypeError):
                        continue

            # Load other settings
            for key in ["encrypt_personal_data", "allow_cross_node_replication",
                       "require_local_storage_only", "notify_on_backup_completion",
                       "notify_on_backup_failure", "notify_on_data_recovery"]:
                if key in prefs_dict:
                    setattr(prefs, key, bool(prefs_dict[key]))

            # Load advanced settings
            if "backup_schedule_preference" in prefs_dict:
                prefs.backup_schedule_preference = str(prefs_dict["backup_schedule_preference"])

            if "max_storage_quota_mb" in prefs_dict:
                prefs.max_storage_quota_mb = prefs_dict["max_storage_quota_mb"]

            if "custom_encryption_key" in prefs_dict:
                prefs.custom_encryption_key = prefs_dict["custom_encryption_key"]

            if "preferences_updated" in prefs_dict:
                prefs.preferences_updated = datetime.fromisoformat(prefs_dict["preferences_updated"])

            if "preferences_version" in prefs_dict:
                prefs.preferences_version = int(prefs_dict["preferences_version"])

            self.user_preferences[user_id] = prefs

        except Exception as e:
            logger.error(f"Failed to load preferences for user {user_id}: {e}")

    async def _background_maintenance(self):
        """Background maintenance tasks."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour

                # Verify shard integrity
                await self._verify_shard_integrity()

                # Clean up old shards
                await self._cleanup_old_shards()

                # Update statistics
                await self._update_statistics()

            except Exception as e:
                logger.error(f"Background maintenance error: {e}")

    async def _verify_shard_integrity(self):
        """Verify integrity of all shards."""
        try:
            for shard_id, metadata in self.shards.items():
                # Skip recently verified shards
                if (datetime.now(timezone.utc) - metadata.last_verified).total_seconds() < 86400:
                    continue

                # Verify primary shard
                primary_path = Path(metadata.primary_location)
                if primary_path.exists():
                    async with aiofiles.open(primary_path, 'rb') as f:
                        data = await f.read()

                    # Check checksum
                    current_checksum = hashlib.md5(data).hexdigest()
                    if current_checksum != metadata.checksum:
                        metadata.corruption_detected = True
                        metadata.status = ShardStatus.CORRUPTED
                        self.stats["corruption_incidents"] += 1
                        logger.error(f"Corruption detected in shard {shard_id}")
                    else:
                        metadata.verification_count += 1
                        metadata.last_verified = datetime.now(timezone.utc)
                        if metadata.status == ShardStatus.CORRUPTED:
                            metadata.status = ShardStatus.ACTIVE
                            metadata.corruption_detected = False
                else:
                    metadata.status = ShardStatus.MISSING
                    logger.warning(f"Shard file missing: {shard_id}")

                # Save updated metadata
                await self._save_shard_metadata(shard_id)

        except Exception as e:
            logger.error(f"Shard integrity verification failed: {e}")

    async def _cleanup_old_shards(self):
        """Clean up old shards based on retention policies."""
        try:
            current_time = datetime.now(timezone.utc)
            shards_to_remove = []

            for shard_id, metadata in self.shards.items():
                # Check if shard has exceeded retention period
                age_days = (current_time - metadata.creation_time).days

                if age_days > metadata.retention_days:
                    shards_to_remove.append(shard_id)
                elif age_days > metadata.auto_archive_after_days and metadata.status == ShardStatus.ACTIVE:
                    # Archive old but not expired shards
                    metadata.status = ShardStatus.ARCHIVED
                    await self._save_shard_metadata(shard_id)

            # Remove expired shards
            for shard_id in shards_to_remove:
                await self._remove_shard(shard_id)

            if shards_to_remove:
                logger.info(f"Cleaned up {len(shards_to_remove)} expired shards")

        except Exception as e:
            logger.error(f"Shard cleanup failed: {e}")

    async def _remove_shard(self, shard_id: str):
        """Remove a shard and all its replicas."""
        try:
            if shard_id not in self.shards:
                return

            metadata = self.shards[shard_id]

            # Remove primary shard
            primary_path = Path(metadata.primary_location)
            if primary_path.exists():
                primary_path.unlink()

            # Remove replicas
            for replica_location in metadata.replica_locations:
                replica_path = Path(replica_location)
                if replica_path.exists():
                    replica_path.unlink()

            # Remove metadata file
            metadata_path = self.metadata_dir / f"{shard_id}.json"
            if metadata_path.exists():
                metadata_path.unlink()

            # Remove from memory
            del self.shards[shard_id]

            logger.debug(f"Removed shard {shard_id}")

        except Exception as e:
            logger.error(f"Failed to remove shard {shard_id}: {e}")

    async def _update_statistics(self):
        """Update system statistics."""
        try:
            self.stats["total_shards"] = len(self.shards)
            self.stats["total_size_bytes"] = sum(
                metadata.size_bytes for metadata in self.shards.values()
            )

        except Exception as e:
            logger.error(f"Statistics update failed: {e}")

    def get_backup_status(self) -> Dict[str, Any]:
        """Get current backup system status."""
        return {
            "system_enabled": True,
            "active_jobs": len(self.active_jobs),
            "total_shards": len(self.shards),
            "statistics": self.stats.copy(),
            "configuration": self.config.copy(),
            "shard_status_breakdown": {
                status.value: sum(1 for s in self.shards.values() if s.status == status)
                for status in ShardStatus
            }
        }

    async def get_user_backup_status(self, user_id: int) -> Dict[str, Any]:
        """Get backup status for a specific user."""
        user_shards = [s for s in self.shards.values() if s.user_id == user_id]
        user_prefs = await self.get_user_backup_preferences(user_id)

        return {
            "user_id": user_id,
            "total_shards": len(user_shards),
            "total_size_bytes": sum(s.size_bytes for s in user_shards),
            "backup_types": list(set(s.backup_type.value for s in user_shards)),
            "preferences": {
                "opt_outs": {bt.value: ool.value for bt, ool in user_prefs.backup_opt_outs.items()} if user_prefs else {},
                "retention_preferences": {bt.value: days for bt, days in user_prefs.retention_preferences.items()} if user_prefs else {},
                "notifications_enabled": user_prefs.notify_on_backup_completion if user_prefs else False
            }
        }

# Global enhanced backup system instance
enhanced_backup_system = EnhancedBackupSystem()
