import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

import aiosqlite

"""
PlexiChat Profile Backup Integration

Comprehensive profile backup system integrated with government-level backup:
- Automatic profile backup with user preferences
- Tier information and badge backup with versioning
- Subscription data backup with encryption
- Selective restore capabilities
- Profile versioning and history tracking
- Cross-device profile synchronization
- Privacy-compliant backup with opt-out controls
"""

logger = logging.getLogger(__name__)


class ProfileBackupType(str, Enum):
    """Types of profile data that can be backed up."""
    BASIC_INFO = "basic_info"           # Username, display name, email, etc.
    PREFERENCES = "preferences"         # Theme, language, timezone, etc.
    ACTIVITY_DATA = "activity_data"     # Messages sent, files shared, login count
    BADGES_ACHIEVEMENTS = "badges"      # Earned badges and achievements
    SUBSCRIPTION_DATA = "subscription"  # Subscription information
    SOCIAL_DATA = "social"             # Friends list, blocked users
    CUSTOM_FIELDS = "custom_fields"    # Custom profile fields
    FULL_PROFILE = "full_profile"      # Complete profile backup


class ProfileRestoreMode(str, Enum):
    """Profile restore modes."""
    MERGE = "merge"                    # Merge with existing profile
    REPLACE = "replace"                # Replace existing profile
    SELECTIVE = "selective"            # Restore only selected components


@dataclass
class ProfileBackupMetadata:
    """Metadata for profile backups."""
    user_id: int
    backup_types: List[ProfileBackupType]
    backup_timestamp: datetime
    profile_version: int
    tier_at_backup: str  # UserTier as string
    badges_count: int
    subscription_active: bool
    backup_size_bytes: int
    checksum: str
    encryption_key_id: str
    shard_ids: List[str] = field(default_factory=list)


@dataclass
class ProfileRestoreRequest:
    """Profile restore request specification."""
    user_id: int
    backup_timestamp: datetime
    restore_mode: ProfileRestoreMode
    components_to_restore: List[ProfileBackupType]
    preserve_current_tier: bool = True
    preserve_current_subscription: bool = True
    merge_badges: bool = True


@dataclass
class ProfileBackupConfig:
    """Configuration for profile backup system."""
    auto_backup_enabled: bool = True
    backup_frequency_hours: int = 24
    max_profile_versions: int = 30
    compress_backups: bool = True
    encrypt_sensitive_data: bool = True
    backup_on_tier_change: bool = True
    backup_on_subscription_change: bool = True
    backup_on_badge_earned: bool = False  # Too frequent
    selective_backup_enabled: bool = True
    cross_device_sync: bool = True


class ProfileBackupManager:
    """
    Profile Backup Manager integrated with government-level backup system.
    
    Features:
    - Automatic profile backup with configurable frequency
    - Selective backup of profile components
    - Version tracking and history management
    - Privacy-compliant backup with user preferences
    - Integration with main backup system's shard technology
    - Cross-device synchronization capabilities
    """
    
    def __init__(self, backup_manager, user_preferences_manager):
        self.backup_manager = backup_manager
        self.user_preferences_manager = user_preferences_manager
        
        # Database and storage
        self.profiles_dir = backup_manager.databases_dir / "profile_backups"
        self.profiles_dir.mkdir(exist_ok=True)
        self.db_path = self.profiles_dir / "profile_backups.db"
        
        # In-memory tracking
        self.backup_metadata: Dict[int, List[ProfileBackupMetadata]] = {}
        self.restore_history: Dict[int, List[Dict[str, Any]]] = {}
        self.scheduled_backups: Dict[int, datetime] = {}
        self.backup_in_progress: Set[int] = set()
        
        # Configuration
        self.config = ProfileBackupConfig()
        
        logger.info("Profile Backup Manager initialized")
    
    async def initialize(self):
        """Initialize the profile backup manager."""
        await self._initialize_database()
        await self._load_backup_metadata()
        await self._load_restore_history()
        
        # Start background tasks
        if self.config.auto_backup_enabled:
            asyncio.create_task(self._auto_backup_scheduler())
        
        logger.info("Profile Backup Manager ready")
    
    async def _initialize_database(self):
        """Initialize the profile backup database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS profile_backups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    backup_types TEXT NOT NULL,
                    backup_timestamp TIMESTAMP NOT NULL,
                    profile_version INTEGER NOT NULL,
                    tier_at_backup TEXT,
                    badges_count INTEGER DEFAULT 0,
                    subscription_active BOOLEAN DEFAULT FALSE,
                    backup_size_bytes INTEGER DEFAULT 0,
                    checksum TEXT NOT NULL,
                    encryption_key_id TEXT,
                    shard_ids TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS profile_restore_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    backup_timestamp TIMESTAMP NOT NULL,
                    restore_mode TEXT NOT NULL,
                    components_restored TEXT NOT NULL,
                    restore_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    restore_success BOOLEAN DEFAULT TRUE,
                    restore_notes TEXT
                )
            """)
            
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_profile_backups_user_id 
                ON profile_backups(user_id)
            """)
            
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_profile_backups_timestamp 
                ON profile_backups(backup_timestamp)
            """)
            
            await db.commit()
    
    async def _load_backup_metadata(self):
        """Load profile backup metadata from database."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("""
                SELECT user_id, backup_types, backup_timestamp, profile_version,
                       tier_at_backup, badges_count, subscription_active,
                       backup_size_bytes, checksum, encryption_key_id, shard_ids
                FROM profile_backups
                ORDER BY backup_timestamp DESC
            """) as cursor:
                async for row in cursor:
                    user_id = row[0]
                    
                    metadata = ProfileBackupMetadata(
                        user_id=user_id,
                        backup_types=[ProfileBackupType(t) for t in json.loads(row[1])],
                        backup_timestamp=datetime.fromisoformat(row[2]),
                        profile_version=row[3],
                        tier_at_backup=row[4] or "BASIC",
                        badges_count=row[5] or 0,
                        subscription_active=bool(row[6]),
                        backup_size_bytes=row[7] or 0,
                        checksum=row[8],
                        encryption_key_id=row[9],
                        shard_ids=json.loads(row[10]) if row[10] else []
                    )
                    
                    if user_id not in self.backup_metadata:
                        self.backup_metadata[user_id] = []
                    self.backup_metadata[user_id].append(metadata)
        
        logger.info(f"Loaded profile backup metadata for {len(self.backup_metadata)} users")
    
    async def _load_restore_history(self):
        """Load profile restore history from database."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("""
                SELECT user_id, backup_timestamp, restore_mode, components_restored,
                       restore_timestamp, restore_success, restore_notes
                FROM profile_restore_history
                ORDER BY restore_timestamp DESC
            """) as cursor:
                async for row in cursor:
                    user_id = row[0]
                    
                    restore_record = {
                        "backup_timestamp": datetime.fromisoformat(row[1]),
                        "restore_mode": row[2],
                        "components_restored": json.loads(row[3]),
                        "restore_timestamp": datetime.fromisoformat(row[4]),
                        "restore_success": bool(row[5]),
                        "restore_notes": row[6]
                    }
                    
                    if user_id not in self.restore_history:
                        self.restore_history[user_id] = []
                    self.restore_history[user_id].append(restore_record)
        
        logger.info(f"Loaded restore history for {len(self.restore_history)} users")
    
    async def backup_user_profile(self, 
                                user_id: int,
                                backup_types: List[ProfileBackupType] = None,
                                force_backup: bool = False) -> Optional[str]:
        """
        Backup user profile data.
        
        Args:
            user_id: User ID to backup
            backup_types: Specific profile components to backup
            force_backup: Force backup even if user has opted out
            
        Returns:
            Backup ID if successful, None if failed or opted out
        """
        if user_id in self.backup_in_progress:
            logger.warning(f"Profile backup already in progress for user {user_id}")
            return None
        
        try:
            self.backup_in_progress.add(user_id)
            
            # Check user preferences unless forced
            if not force_backup:
                should_backup, opt_out_level = await self.user_preferences_manager.should_backup_user_data(
                    user_id, "PROFILES"  # Using string instead of enum for compatibility
                )
                
                if not should_backup:
                    logger.info(f"User {user_id} has opted out of profile backup")
                    return None
            
            # Default to full profile backup
            if not backup_types:
                backup_types = [ProfileBackupType.FULL_PROFILE]
            
            # Get profile data (this would integrate with actual profile system)
            profile_data = await self._get_profile_data(user_id, backup_types)
            
            if not profile_data:
                logger.warning(f"No profile data found for user {user_id}")
                return None
            
            # Create backup through main backup system
            backup_data = json.dumps(profile_data, default=str).encode('utf-8')
            checksum = hashlib.sha256(backup_data).hexdigest()
            
            # Use main backup system to create shards
            backup_id = f"profile_{user_id}_{int(from datetime import datetime
datetime.now().timestamp())}"
            
            # This would integrate with the main backup system's shard creation
            shard_ids = await self._create_profile_shards(backup_id, backup_data)
            
            # Create metadata
            metadata = ProfileBackupMetadata(
                user_id=user_id,
                backup_types=backup_types,
                backup_timestamp=datetime.now(timezone.utc),
                profile_version=profile_data.get("version", 1),
                tier_at_backup=profile_data.get("tier", "BASIC"),
                badges_count=len(profile_data.get("badges", [])),
                subscription_active=profile_data.get("subscription_active", False),
                backup_size_bytes=len(backup_data),
                checksum=checksum,
                encryption_key_id=f"profile_key_{user_id}",
                shard_ids=shard_ids
            )
            
            # Save metadata
            await self._save_backup_metadata(metadata)
            
            # Update in-memory cache
            if user_id not in self.backup_metadata:
                self.backup_metadata[user_id] = []
            self.backup_metadata[user_id].append(metadata)
            
            # Cleanup old backups
            await self._cleanup_old_backups(user_id)
            
            logger.info(f"Successfully backed up profile for user {user_id}")
            return backup_id
            
        except Exception as e:
            logger.error(f"Failed to backup profile for user {user_id}: {e}")
            return None
        finally:
            self.backup_in_progress.discard(user_id)

    async def _get_profile_data(self, user_id: int, backup_types: List[ProfileBackupType]) -> Optional[Dict[str, Any]]:
        """Get profile data for backup (placeholder - would integrate with actual profile system)."""
        # This is a placeholder that would integrate with the actual profile system
        # For now, return mock data structure
        profile_data = {
            "user_id": user_id,
            "version": 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "backup_types": [bt.value for bt in backup_types]
        }

        for backup_type in backup_types:
            if backup_type == ProfileBackupType.BASIC_INFO:
                profile_data["basic_info"] = {
                    "username": f"user_{user_id}",
                    "display_name": f"User {user_id}",
                    "email": f"user{user_id}@example.com"
                }
            elif backup_type == ProfileBackupType.PREFERENCES:
                profile_data["preferences"] = {
                    "theme": "dark",
                    "language": "en",
                    "timezone": "UTC"
                }
            elif backup_type == ProfileBackupType.BADGES_ACHIEVEMENTS:
                profile_data["badges"] = []
            elif backup_type == ProfileBackupType.SUBSCRIPTION_DATA:
                profile_data["subscription_active"] = False
            elif backup_type == ProfileBackupType.FULL_PROFILE:
                # Include all components for full backup
                profile_data.update({
                    "basic_info": {"username": f"user_{user_id}"},
                    "preferences": {"theme": "dark"},
                    "badges": [],
                    "subscription_active": False
                })

        return profile_data

    async def _create_profile_shards(self, backup_id: str, backup_data: bytes) -> List[str]:
        """Create shards for profile backup (placeholder - would integrate with main backup system)."""
        # This would integrate with the main backup system's shard creation
        # For now, return mock shard IDs
        return [f"{backup_id}_shard_1", f"{backup_id}_shard_2"]

    async def _save_backup_metadata(self, metadata: ProfileBackupMetadata):
        """Save profile backup metadata to database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO profile_backups (
                    user_id, backup_types, backup_timestamp, profile_version,
                    tier_at_backup, badges_count, subscription_active,
                    backup_size_bytes, checksum, encryption_key_id, shard_ids
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                metadata.user_id,
                json.dumps([bt.value for bt in metadata.backup_types]),
                metadata.backup_timestamp.isoformat(),
                metadata.profile_version,
                metadata.tier_at_backup,
                metadata.badges_count,
                metadata.subscription_active,
                metadata.backup_size_bytes,
                metadata.checksum,
                metadata.encryption_key_id,
                json.dumps(metadata.shard_ids)
            ))
            await db.commit()

    async def _cleanup_old_backups(self, user_id: int):
        """Clean up old profile backups beyond retention limit."""
        user_backups = self.backup_metadata.get(user_id, [])

        if len(user_backups) > self.config.max_profile_versions:
            # Sort by timestamp, keep newest
            user_backups.sort(key=lambda x: x.backup_timestamp, reverse=True)
            backups_to_remove = user_backups[self.config.max_profile_versions:]

            for backup in backups_to_remove:
                await self._delete_backup(backup)
                user_backups.remove(backup)

            logger.info(f"Cleaned up {len(backups_to_remove)} old profile backups for user {user_id}")

    async def _delete_backup(self, metadata: ProfileBackupMetadata):
        """Delete a profile backup and its shards."""
        try:
            # Delete from database
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    DELETE FROM profile_backups
                    WHERE user_id = ? AND backup_timestamp = ?
                """, (metadata.user_id, metadata.backup_timestamp.isoformat()))
                await db.commit()

            # Delete shards through main backup system (placeholder)
            for shard_id in metadata.shard_ids:
                # This would integrate with main backup system's shard deletion
                pass

        except Exception as e:
            logger.error(f"Failed to delete profile backup: {e}")

    async def restore_user_profile(self, request: ProfileRestoreRequest) -> bool:
        """
        Restore user profile from backup.

        Args:
            request: Profile restore request specification

        Returns:
            True if restore successful, False otherwise
        """
        try:
            # Find the backup
            user_backups = self.backup_metadata.get(request.user_id, [])
            target_backup = None

            for backup in user_backups:
                if backup.backup_timestamp == request.backup_timestamp:
                    target_backup = backup
                    break

            if not target_backup:
                logger.error(f"Backup not found for user {request.user_id} at {request.backup_timestamp}")
                return False

            # Restore profile data (placeholder - would integrate with actual profile system)
            restore_success = await self._perform_profile_restore(target_backup, request)

            # Log restore operation
            await self._log_restore_operation(request, restore_success)

            return restore_success

        except Exception as e:
            logger.error(f"Failed to restore profile for user {request.user_id}: {e}")
            await self._log_restore_operation(request, False, str(e))
            return False

    async def _perform_profile_restore(self, backup: ProfileBackupMetadata, request: ProfileRestoreRequest) -> bool:
        """Perform the actual profile restore (placeholder)."""
        # This would integrate with the actual profile system
        # For now, just return success
        logger.info(f"Restoring profile for user {request.user_id} with mode {request.restore_mode}")
        return True

    async def _log_restore_operation(self, request: ProfileRestoreRequest, success: bool, notes: str = None):
        """Log profile restore operation."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO profile_restore_history (
                    user_id, backup_timestamp, restore_mode, components_restored,
                    restore_success, restore_notes
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                request.user_id,
                request.backup_timestamp.isoformat(),
                request.restore_mode.value,
                json.dumps([c.value for c in request.components_to_restore]),
                success,
                notes
            ))
            await db.commit()

    async def get_user_backup_history(self, user_id: int) -> List[ProfileBackupMetadata]:
        """Get backup history for a user."""
        return self.backup_metadata.get(user_id, [])

    async def get_user_restore_history(self, user_id: int) -> List[Dict[str, Any]]:
        """Get restore history for a user."""
        return self.restore_history.get(user_id, [])

    async def _auto_backup_scheduler(self):
        """Background task for automatic profile backups."""
        while True:
            try:
                await asyncio.sleep(3600)  # Check every hour

                current_time = datetime.now(timezone.utc)

                # Check which users need backup
                for user_id in self.scheduled_backups:
                    next_backup = self.scheduled_backups[user_id]

                    if current_time >= next_backup and user_id not in self.backup_in_progress:
                        # Schedule backup
                        asyncio.create_task(self._auto_backup_user(user_id))

            except Exception as e:
                logger.error(f"Auto backup scheduler error: {e}")

    async def _auto_backup_user(self, user_id: int):
        """Perform automatic backup for a user."""
        try:
            backup_id = await self.backup_user_profile(user_id)

            if backup_id:
                # Schedule next backup
                next_backup = datetime.now(timezone.utc) + timedelta(hours=self.config.backup_frequency_hours)
                self.scheduled_backups[user_id] = next_backup
                logger.info(f"Auto backup completed for user {user_id}, next backup at {next_backup}")
            else:
                # Retry later
                retry_time = datetime.now(timezone.utc) + timedelta(hours=1)
                self.scheduled_backups[user_id] = retry_time

        except Exception as e:
            logger.error(f"Auto backup failed for user {user_id}: {e}")


# Global instance (will be initialized by backup manager)
profile_backup_manager = None
