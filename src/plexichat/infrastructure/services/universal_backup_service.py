import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import aiosqlite

from ...backup.core.encryption_manager import QuantumResistantEncryptionManager
from ...backup.core.shard_location_database import EnhancedShardLocationDatabase
from ...backup.core.shard_manager import ImmutableShardManager
from ..models.message import Message
from ..models.user import User


"""
Universal Backup Service

Extends the shard system to backup all data types (users, messages, etc.)
with opt-out capabilities and enhanced security features.
"""

logger = logging.getLogger(__name__)


class BackupDataType(Enum):
    """Types of data that can be backed up."""
    USER_PROFILE = "user_profile"
    USER_SETTINGS = "user_settings"
    MESSAGE_CONTENT = "message_content"
    MESSAGE_METADATA = "message_metadata"
    CHANNEL_DATA = "channel_data"
    SERVER_CONFIG = "server_config"
    PERMISSIONS = "permissions"
    RELATIONSHIPS = "relationships"


class BackupOptOutLevel(Enum):
    """Levels of backup opt-out."""
    FULL_PARTICIPATION = "full_participation"  # All data backed up
    METADATA_ONLY = "metadata_only"  # Only metadata, no content
    MINIMAL_BACKUP = "minimal_backup"  # Only essential data
    COMPLETE_OPT_OUT = "complete_opt_out"  # No backup at all


@dataclass
class UserBackupPreferences:
    """User preferences for backup participation."""
    user_id: str
    opt_out_level: BackupOptOutLevel
    excluded_data_types: Set[BackupDataType] = field(default_factory=set)
    retention_days: int = 365
    allow_cross_server: bool = True
    encryption_preference: str = "quantum-resistant"
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class UniversalBackupService:
    """
    Universal backup service that extends shard system to all data types.
    
    Features:
    - Backup users, messages, and all system data
    - User opt-out capabilities at various levels
    - SHA-512 checksums for all data
    - Individual shard encryption keys
    - Backup node API key restrictions
    - Confusing shard filenames
    """
    
    def __init__(self, data_dir: Path):
        self.data_dir = from pathlib import Path
Path(data_dir)
        self.backup_dir = self.data_dir / "universal_backup"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize core components
        self.encryption_manager = QuantumResistantEncryptionManager(self.backup_dir)
        self.shard_manager = ImmutableShardManager(self.backup_dir, self.encryption_manager)
        self.location_database = EnhancedShardLocationDatabase(self.backup_dir, self.encryption_manager)
        
        # User preferences
        self.user_preferences: Dict[str, UserBackupPreferences] = {}
        self.preferences_db_path = self.backup_dir / "user_backup_preferences.db"
        
        # Statistics
        self.stats = {
            'total_backups_created': 0,
            'users_backed_up': 0,
            'messages_backed_up': 0,
            'opt_out_users': 0,
            'total_shards_created': 0,
            'backup_size_bytes': 0
        }
        
        self._initialized = False

    async def initialize(self):
        """Initialize the universal backup service."""
        if self._initialized:
            return
        
        logger.info("Initializing Universal Backup Service")
        
        # Initialize core components
        await self.encryption_manager.initialize()
        await self.shard_manager.initialize()
        await self.location_database.initialize()
        
        # Initialize preferences database
        await self._initialize_preferences_database()
        
        # Load user preferences
        await self._load_user_preferences()
        
        self._initialized = True
        logger.info("Universal Backup Service initialized")

    async def _initialize_preferences_database(self):
        """Initialize user backup preferences database."""
        async with aiosqlite.connect(self.preferences_db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS user_backup_preferences (
                    user_id TEXT PRIMARY KEY,
                    opt_out_level TEXT NOT NULL,
                    excluded_data_types TEXT,
                    retention_days INTEGER DEFAULT 365,
                    allow_cross_server BOOLEAN DEFAULT TRUE,
                    encryption_preference TEXT DEFAULT 'quantum-resistant',
                    last_updated TEXT NOT NULL
                )
            """)
            await db.commit()

    async def backup_user_data(self, user: User, data_types: Optional[List[BackupDataType]] = None,
                             backup_node_api_key: Optional[str] = None) -> Optional[str]:
        """
        Backup user data with respect to their opt-out preferences.
        
        Args:
            user: User to backup
            data_types: Specific data types to backup (None for all)
            backup_node_api_key: API key for backup node operations
            
        Returns:
            Backup ID if successful, None otherwise
        """
        try:
            # Check user preferences
            preferences = await self.get_user_backup_preferences(user.id)
            
            # Check if user has completely opted out
            if preferences.opt_out_level == BackupOptOutLevel.COMPLETE_OPT_OUT:
                logger.info(f"User {user.id} has completely opted out of backup")
                return None
            
            # Determine what data to backup based on preferences
            allowed_data_types = self._filter_data_types_by_preferences(
                data_types or list(BackupDataType), preferences
            )
            
            if not allowed_data_types:
                logger.info(f"No data types allowed for backup for user {user.id}")
                return None
            
            # Collect user data
            user_data = await self._collect_user_data(user, allowed_data_types, preferences)
            
            if not user_data:
                logger.warning(f"No data collected for user {user.id}")
                return None
            
            # Create backup with shard system
            backup_id = f"user_{user.id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
            
            # Convert to JSON and backup through shard system
            backup_json = json.dumps(user_data, default=str)
            backup_data = backup_json.encode('utf-8')
            
            # Create shards with advanced encryption
            shards = await self.shard_manager.create_immutable_shards(
                data=backup_data,
                backup_id=backup_id,
                shard_type="user_backup",
                backup_node_only=True,  # User data requires backup node access
                require_minimum_shards=True  # Require multiple shards for decryption
            )
            
            # Store shard locations with access control
            for shard in shards:
                await self.location_database.store_shard_location(
                    shard_id=shard.shard_id,
                    location_data={
                        "backup_id": backup_id,
                        "user_id": user.id,
                        "data_types": [dt.value for dt in allowed_data_types],
                        "shard_path": str(self.backup_dir / shard.metadata['confusing_filename']),
                        "created_at": datetime.now(timezone.utc).isoformat()
                    },
                    backup_node_only=True,
                    api_key=backup_node_api_key
                )
            
            # Update statistics
            self.stats['users_backed_up'] += 1
            self.stats['total_backups_created'] += 1
            self.stats['total_shards_created'] += len(shards)
            self.stats['backup_size_bytes'] += len(backup_data)
            
            logger.info(f"Successfully backed up user {user.id} with {len(shards)} shards")
            return backup_id
            
        except Exception as e:
            logger.error(f"Failed to backup user {user.id}: {e}")
            return None

    async def backup_message_data(self, messages: List[Message], 
                                backup_node_api_key: Optional[str] = None) -> Optional[str]:
        """
        Backup message data with user opt-out respect.
        
        Args:
            messages: Messages to backup
            backup_node_api_key: API key for backup node operations
            
        Returns:
            Backup ID if successful, None otherwise
        """
        try:
            # Filter messages based on user preferences
            allowed_messages = []
            
            for message in messages:
                user_prefs = await self.get_user_backup_preferences(message.author_id)
                
                # Skip if user opted out completely
                if user_prefs.opt_out_level == BackupOptOutLevel.COMPLETE_OPT_OUT:
                    continue
                
                # Check if message content is allowed
                if user_prefs.opt_out_level == BackupOptOutLevel.METADATA_ONLY:
                    # Only backup metadata, not content
                    message_data = {
                        "id": message.id,
                        "author_id": message.author_id,
                        "channel_id": message.channel_id,
                        "timestamp": message.created_at.isoformat(),
                        "content": "[CONTENT_OPTED_OUT]",  # Placeholder
                        "metadata_only": True
                    }
                elif BackupDataType.MESSAGE_CONTENT in user_prefs.excluded_data_types:
                    # Skip content but keep metadata
                    message_data = {
                        "id": message.id,
                        "author_id": message.author_id,
                        "channel_id": message.channel_id,
                        "timestamp": message.created_at.isoformat(),
                        "content": "[CONTENT_EXCLUDED]",
                        "metadata_only": True
                    }
                else:
                    # Full message backup allowed
                    message_data = {
                        "id": message.id,
                        "author_id": message.author_id,
                        "channel_id": message.channel_id,
                        "content": message.content,
                        "timestamp": message.created_at.isoformat(),
                        "attachments": getattr(message, 'attachments', []),
                        "metadata_only": False
                    }
                
                allowed_messages.append(message_data)
            
            if not allowed_messages:
                logger.info("No messages allowed for backup after filtering")
                return None
            
            # Create backup
            backup_id = f"messages_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
            
            backup_data = {
                "backup_type": "messages",
                "backup_id": backup_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "message_count": len(allowed_messages),
                "messages": allowed_messages
            }
            
            # Convert to bytes and create shards
            backup_json = json.dumps(backup_data, default=str)
            backup_bytes = backup_json.encode('utf-8')
            
            # Create shards with advanced encryption
            shards = await self.shard_manager.create_immutable_shards(
                data=backup_bytes,
                backup_id=backup_id,
                shard_type="message_backup",
                backup_node_only=True,
                require_minimum_shards=True
            )
            
            # Store shard locations
            for shard in shards:
                await self.location_database.store_shard_location(
                    shard_id=shard.shard_id,
                    location_data={
                        "backup_id": backup_id,
                        "backup_type": "messages",
                        "message_count": len(allowed_messages),
                        "shard_path": str(self.backup_dir / shard.metadata['confusing_filename']),
                        "created_at": datetime.now(timezone.utc).isoformat()
                    },
                    backup_node_only=True,
                    api_key=backup_node_api_key
                )
            
            # Update statistics
            self.stats['messages_backed_up'] += len(allowed_messages)
            self.stats['total_backups_created'] += 1
            self.stats['total_shards_created'] += len(shards)
            self.stats['backup_size_bytes'] += len(backup_bytes)
            
            logger.info(f"Successfully backed up {len(allowed_messages)} messages with {len(shards)} shards")
            return backup_id

        except Exception as e:
            logger.error(f"Failed to backup messages: {e}")
            return None

    async def set_user_backup_preferences(self, user_id: str, preferences: UserBackupPreferences) -> bool:
        """Set user backup preferences."""
        try:
            self.user_preferences[user_id] = preferences

            # Save to database
            async with aiosqlite.connect(self.preferences_db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO user_backup_preferences
                    (user_id, opt_out_level, excluded_data_types, retention_days,
                     allow_cross_server, encryption_preference, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_id,
                    preferences.opt_out_level.value,
                    json.dumps([dt.value for dt in preferences.excluded_data_types]),
                    preferences.retention_days,
                    preferences.allow_cross_server,
                    preferences.encryption_preference,
                    preferences.last_updated.isoformat()
                ))
                await db.commit()

            # Update statistics
            if preferences.opt_out_level == BackupOptOutLevel.COMPLETE_OPT_OUT:
                self.stats['opt_out_users'] += 1

            logger.info(f"Updated backup preferences for user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to set backup preferences for user {user_id}: {e}")
            return False

    async def get_user_backup_preferences(self, user_id: str) -> UserBackupPreferences:
        """Get user backup preferences, with defaults if not set."""
        if user_id in self.user_preferences:
            return self.user_preferences[user_id]

        # Try to load from database
        try:
            async with aiosqlite.connect(self.preferences_db_path) as db:
                async with db.execute("""
                    SELECT opt_out_level, excluded_data_types, retention_days,
                           allow_cross_server, encryption_preference, last_updated
                    FROM user_backup_preferences WHERE user_id = ?
                """, (user_id,)) as cursor:
                    row = await cursor.fetchone()

                    if row:
                        excluded_types = set()
                        if row[1]:
                            excluded_types = {BackupDataType(dt) for dt in json.loads(row[1])}

                        preferences = UserBackupPreferences(
                            user_id=user_id,
                            opt_out_level=BackupOptOutLevel(row[0]),
                            excluded_data_types=excluded_types,
                            retention_days=row[2],
                            allow_cross_server=bool(row[3]),
                            encryption_preference=row[4],
                            last_updated=datetime.fromisoformat(row[5])
                        )

                        self.user_preferences[user_id] = preferences
                        return preferences
        except Exception as e:
            logger.error(f"Failed to load preferences for user {user_id}: {e}")

        # Return default preferences
        default_preferences = UserBackupPreferences(
            user_id=user_id,
            opt_out_level=BackupOptOutLevel.FULL_PARTICIPATION
        )
        self.user_preferences[user_id] = default_preferences
        return default_preferences

    def _filter_data_types_by_preferences(self, data_types: List[BackupDataType],
                                        preferences: UserBackupPreferences) -> List[BackupDataType]:
        """Filter data types based on user preferences."""
        if preferences.opt_out_level == BackupOptOutLevel.COMPLETE_OPT_OUT:
            return []

        if preferences.opt_out_level == BackupOptOutLevel.MINIMAL_BACKUP:
            # Only essential data
            essential_types = {BackupDataType.USER_PROFILE}
            return [dt for dt in data_types if dt in essential_types]

        # Filter out excluded types
        return [dt for dt in data_types if dt not in preferences.excluded_data_types]

    async def _collect_user_data(self, user: User, data_types: List[BackupDataType],
                               preferences: UserBackupPreferences) -> Dict[str, Any]:
        """Collect user data based on allowed data types and preferences."""
        user_data = {
            "user_id": user.id,
            "backup_timestamp": datetime.now(timezone.utc).isoformat(),
            "data_types": [dt.value for dt in data_types],
            "opt_out_level": preferences.opt_out_level.value
        }

        for data_type in data_types:
            if data_type == BackupDataType.USER_PROFILE:
                user_data["profile"] = {
                    "username": user.username,
                    "email": user.email if preferences.opt_out_level != BackupOptOutLevel.METADATA_ONLY else "[REDACTED]",
                    "created_at": user.created_at.isoformat() if hasattr(user, 'created_at') else None,
                    "last_active": getattr(user, 'last_active', None)
                }

            elif data_type == BackupDataType.USER_SETTINGS:
                # Collect user settings (implementation depends on your user model)
                user_data["settings"] = getattr(user, 'settings', {})

            # Add other data types as needed

        return user_data

    async def _load_user_preferences(self):
        """Load all user preferences from database."""
        try:
            async with aiosqlite.connect(self.preferences_db_path) as db:
                async with db.execute("""
                    SELECT user_id, opt_out_level, excluded_data_types, retention_days,
                           allow_cross_server, encryption_preference, last_updated
                    FROM user_backup_preferences
                """) as cursor:
                    async for row in cursor:
                        excluded_types = set()
                        if row[2]:
                            excluded_types = {BackupDataType(dt) for dt in json.loads(row[2])}

                        preferences = UserBackupPreferences(
                            user_id=row[0],
                            opt_out_level=BackupOptOutLevel(row[1]),
                            excluded_data_types=excluded_types,
                            retention_days=row[3],
                            allow_cross_server=bool(row[4]),
                            encryption_preference=row[5],
                            last_updated=datetime.fromisoformat(row[6])
                        )

                        self.user_preferences[row[0]] = preferences

            logger.info(f"Loaded {len(self.user_preferences)} user backup preferences")
        except Exception as e:
            logger.error(f"Failed to load user preferences: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get backup service statistics."""
        return {
            **self.stats,
            'users_with_preferences': len(self.user_preferences),
            'shard_manager_stats': self.shard_manager.get_statistics(),
            'location_database_stats': self.location_database.get_statistics()
        }
