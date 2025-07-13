"""
PlexiChat Backup User Preferences System

Comprehensive user preference management for backup operations:
- Granular opt-out controls for different backup types
- Privacy and retention preferences
- Notification settings
- Custom encryption and storage quotas
- Compliance with data protection regulations

Integrated with the government-level backup system.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import aiosqlite

logger = logging.getLogger(__name__)


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


class BackupOptOutLevel(Enum):
    """Levels of backup opt-out."""
    NONE = "none"                    # Full backup participation
    METADATA_ONLY = "metadata_only"  # Only backup metadata, not content
    ANONYMIZED = "anonymized"        # Backup with personal data removed
    COMPLETE_OPTOUT = "complete_optout"  # No backup at all


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
class BackupPolicy:
    """System-wide backup policy configuration."""
    backup_type: BackupType
    
    # Default settings
    default_retention_days: int = 365
    auto_archive_after_days: int = 90
    replication_factor: int = 3
    
    # Compliance settings
    allow_user_optout: bool = True
    minimum_retention_days: int = 30  # Legal/compliance minimum
    maximum_retention_days: int = 2555  # 7 years
    
    # Privacy settings
    anonymization_enabled: bool = True
    gdpr_compliance: bool = True
    ccpa_compliance: bool = True


class UserPreferencesManager:
    """
    Manages user backup preferences with government-level security.
    
    Features:
    - Granular opt-out controls
    - Privacy-first design
    - Compliance with data protection regulations
    - Integration with main backup system
    - Audit logging for preference changes
    """
    
    def __init__(self, backup_manager):
        self.backup_manager = backup_manager
        self.preferences_dir = backup_manager.databases_dir / "user_preferences"
        self.preferences_dir.mkdir(exist_ok=True)
        
        # Database for preferences
        self.db_path = self.preferences_dir / "user_preferences.db"
        
        # In-memory cache
        self.user_preferences: Dict[int, UserBackupPreferences] = {}
        self.backup_policies: Dict[BackupType, BackupPolicy] = {}
        
        # Default policies
        self._initialize_default_policies()
        
        logger.info("User Preferences Manager initialized")
    
    async def initialize(self):
        """Initialize the preferences manager."""
        await self._initialize_database()
        await self._load_user_preferences()
        await self._load_backup_policies()
        
        logger.info("User Preferences Manager ready")
    
    def _initialize_default_policies(self):
        """Initialize default backup policies."""
        for backup_type in BackupType:
            self.backup_policies[backup_type] = BackupPolicy(
                backup_type=backup_type,
                default_retention_days=365,
                auto_archive_after_days=90,
                replication_factor=3,
                allow_user_optout=True,
                minimum_retention_days=30,
                maximum_retention_days=2555,
                anonymization_enabled=True,
                gdpr_compliance=True,
                ccpa_compliance=True
            )
    
    async def _initialize_database(self):
        """Initialize the preferences database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS user_preferences (
                    user_id INTEGER PRIMARY KEY,
                    backup_opt_outs TEXT,
                    retention_preferences TEXT,
                    encrypt_personal_data BOOLEAN DEFAULT TRUE,
                    allow_cross_node_replication BOOLEAN DEFAULT TRUE,
                    require_local_storage_only BOOLEAN DEFAULT FALSE,
                    notify_on_backup_completion BOOLEAN DEFAULT FALSE,
                    notify_on_backup_failure BOOLEAN DEFAULT TRUE,
                    notify_on_data_recovery BOOLEAN DEFAULT TRUE,
                    custom_encryption_key TEXT,
                    backup_schedule_preference TEXT DEFAULT 'daily',
                    max_storage_quota_mb INTEGER,
                    preferences_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    preferences_version INTEGER DEFAULT 1
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS backup_policies (
                    backup_type TEXT PRIMARY KEY,
                    default_retention_days INTEGER,
                    auto_archive_after_days INTEGER,
                    replication_factor INTEGER,
                    allow_user_optout BOOLEAN,
                    minimum_retention_days INTEGER,
                    maximum_retention_days INTEGER,
                    anonymization_enabled BOOLEAN,
                    gdpr_compliance BOOLEAN,
                    ccpa_compliance BOOLEAN,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS preference_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    change_type TEXT,
                    old_value TEXT,
                    new_value TEXT,
                    changed_by TEXT,
                    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    user_agent TEXT
                )
            """)
            
            await db.commit()
    
    async def _load_user_preferences(self):
        """Load user preferences from database."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT * FROM user_preferences") as cursor:
                async for row in cursor:
                    user_id = row[0]
                    
                    # Parse JSON fields
                    backup_opt_outs = json.loads(row[1]) if row[1] else {}
                    retention_preferences = json.loads(row[2]) if row[2] else {}
                    
                    # Convert string keys back to enums
                    backup_opt_outs = {
                        BackupType(k): BackupOptOutLevel(v) 
                        for k, v in backup_opt_outs.items()
                    }
                    retention_preferences = {
                        BackupType(k): v 
                        for k, v in retention_preferences.items()
                    }
                    
                    preferences = UserBackupPreferences(
                        user_id=user_id,
                        backup_opt_outs=backup_opt_outs,
                        retention_preferences=retention_preferences,
                        encrypt_personal_data=bool(row[3]),
                        allow_cross_node_replication=bool(row[4]),
                        require_local_storage_only=bool(row[5]),
                        notify_on_backup_completion=bool(row[6]),
                        notify_on_backup_failure=bool(row[7]),
                        notify_on_data_recovery=bool(row[8]),
                        custom_encryption_key=row[9],
                        backup_schedule_preference=row[10] or "daily",
                        max_storage_quota_mb=row[11],
                        preferences_updated=datetime.fromisoformat(row[12]) if row[12] else datetime.now(timezone.utc),
                        preferences_version=row[13] or 1
                    )
                    
                    self.user_preferences[user_id] = preferences
        
        logger.info(f"Loaded preferences for {len(self.user_preferences)} users")
    
    async def _load_backup_policies(self):
        """Load backup policies from database."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT * FROM backup_policies") as cursor:
                async for row in cursor:
                    backup_type = BackupType(row[0])
                    
                    policy = BackupPolicy(
                        backup_type=backup_type,
                        default_retention_days=row[1],
                        auto_archive_after_days=row[2],
                        replication_factor=row[3],
                        allow_user_optout=bool(row[4]),
                        minimum_retention_days=row[5],
                        maximum_retention_days=row[6],
                        anonymization_enabled=bool(row[7]),
                        gdpr_compliance=bool(row[8]),
                        ccpa_compliance=bool(row[9])
                    )
                    
                    self.backup_policies[backup_type] = policy
        
        logger.info(f"Loaded {len(self.backup_policies)} backup policies")

    async def get_user_preferences(self, user_id: int) -> Optional[UserBackupPreferences]:
        """Get user backup preferences."""
        return self.user_preferences.get(user_id)

    async def set_user_preferences(self,
                                 user_id: int,
                                 preferences: UserBackupPreferences,
                                 changed_by: str = "system",
                                 ip_address: str = None,
                                 user_agent: str = None) -> bool:
        """Set user backup preferences with audit logging."""
        try:
            old_preferences = self.user_preferences.get(user_id)

            # Update timestamp and version
            preferences.preferences_updated = datetime.now(timezone.utc)
            if old_preferences:
                preferences.preferences_version = old_preferences.preferences_version + 1

            # Save to database
            await self._save_user_preferences(preferences)

            # Update cache
            self.user_preferences[user_id] = preferences

            # Audit log
            await self._log_preference_change(
                user_id, "preferences_updated",
                old_preferences, preferences,
                changed_by, ip_address, user_agent
            )

            logger.info(f"Updated preferences for user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to set user preferences: {e}")
            return False

    async def should_backup_user_data(self,
                                    user_id: int,
                                    backup_type: BackupType) -> tuple[bool, BackupOptOutLevel]:
        """Check if user data should be backed up based on preferences."""
        preferences = await self.get_user_preferences(user_id)

        if not preferences:
            # Default: full backup for users without preferences
            return True, BackupOptOutLevel.NONE

        opt_out_level = preferences.backup_opt_outs.get(backup_type, BackupOptOutLevel.NONE)

        # Determine if backup should proceed
        should_backup = opt_out_level != BackupOptOutLevel.COMPLETE_OPTOUT

        return should_backup, opt_out_level

    async def get_user_retention_period(self, user_id: int, backup_type: BackupType) -> int:
        """Get retention period for user data based on preferences and policy."""
        preferences = await self.get_user_preferences(user_id)
        policy = self.backup_policies.get(backup_type)

        if not policy:
            return 365  # Default 1 year

        # User preference
        if preferences and backup_type in preferences.retention_preferences:
            user_retention = preferences.retention_preferences[backup_type]

            # Enforce policy limits
            return max(
                policy.minimum_retention_days,
                min(user_retention, policy.maximum_retention_days)
            )

        # Default policy
        return policy.default_retention_days

    async def _save_user_preferences(self, preferences: UserBackupPreferences):
        """Save user preferences to database."""
        # Convert enums to strings for JSON storage
        backup_opt_outs_json = json.dumps({
            k.value: v.value for k, v in preferences.backup_opt_outs.items()
        })
        retention_preferences_json = json.dumps({
            k.value: v for k, v in preferences.retention_preferences.items()
        })

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO user_preferences (
                    user_id, backup_opt_outs, retention_preferences,
                    encrypt_personal_data, allow_cross_node_replication,
                    require_local_storage_only, notify_on_backup_completion,
                    notify_on_backup_failure, notify_on_data_recovery,
                    custom_encryption_key, backup_schedule_preference,
                    max_storage_quota_mb, preferences_updated, preferences_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                preferences.user_id,
                backup_opt_outs_json,
                retention_preferences_json,
                preferences.encrypt_personal_data,
                preferences.allow_cross_node_replication,
                preferences.require_local_storage_only,
                preferences.notify_on_backup_completion,
                preferences.notify_on_backup_failure,
                preferences.notify_on_data_recovery,
                preferences.custom_encryption_key,
                preferences.backup_schedule_preference,
                preferences.max_storage_quota_mb,
                preferences.preferences_updated.isoformat(),
                preferences.preferences_version
            ))
            await db.commit()

    async def _log_preference_change(self,
                                   user_id: int,
                                   change_type: str,
                                   old_value: Any,
                                   new_value: Any,
                                   changed_by: str,
                                   ip_address: str = None,
                                   user_agent: str = None):
        """Log preference changes for audit purposes."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO preference_audit_log (
                    user_id, change_type, old_value, new_value,
                    changed_by, ip_address, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id, change_type,
                json.dumps(str(old_value)) if old_value else None,
                json.dumps(str(new_value)) if new_value else None,
                changed_by, ip_address, user_agent
            ))
            await db.commit()

    async def get_users_for_backup_type(self, backup_type: BackupType) -> List[int]:
        """Get list of users who should be included in backup for given type."""
        eligible_users = []

        for user_id, preferences in self.user_preferences.items():
            should_backup, _ = await self.should_backup_user_data(user_id, backup_type)
            if should_backup:
                eligible_users.append(user_id)

        return eligible_users

    async def cleanup_expired_preferences(self):
        """Clean up old preference audit logs."""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=365)

        async with aiosqlite.connect(self.db_path) as db:
            result = await db.execute("""
                DELETE FROM preference_audit_log
                WHERE changed_at < ?
            """, (cutoff_date.isoformat(),))

            deleted_count = result.rowcount
            await db.commit()

            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old preference audit logs")


# Global instance (will be initialized by backup manager)
user_preferences_manager = None
