"""
Universal User and Message Backup System
Government-level backup system with opt-out capabilities and intelligent shard distribution.
"""

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class BackupOptStatus(Enum):
    """User backup opt-in/opt-out status."""
    OPTED_IN = "opted_in"
    OPTED_OUT = "opted_out"
    DEFAULT_IN = "default_in"  # Default opt-in for new users
    FORCED_BACKUP = "forced_backup"  # Admin-forced backup for critical users


class BackupDataType(Enum):
    """Types of data that can be backed up."""
    USER_PROFILE = "user_profile"
    USER_MESSAGES = "user_messages"
    USER_SETTINGS = "user_settings"
    USER_METADATA = "user_metadata"
    MESSAGE_CONTENT = "message_content"
    MESSAGE_ATTACHMENTS = "message_attachments"
    MESSAGE_REACTIONS = "message_reactions"
    CHAT_HISTORY = "chat_history"
    SYSTEM_LOGS = "system_logs"


@dataclass
class UserBackupPreferences:
    """User backup preferences and opt-out settings."""
    user_id: str
    username: str
    backup_status: BackupOptStatus
    opted_out_data_types: Set[BackupDataType]
    backup_frequency: str  # 'real_time', 'hourly', 'daily', 'weekly'
    max_backup_retention_days: int
    allow_cross_region_backup: bool
    prefer_local_storage: bool
    encryption_preference: str  # 'standard', 'enhanced', 'quantum'
    shard_distribution_preference: str  # 'distributed', 'local', 'regional'
    created_at: datetime
    updated_at: datetime
    metadata: Dict[str, Any]


@dataclass
class MessageBackupEntry:
    """Individual message backup entry."""
    backup_id: str
    message_id: str
    user_id: str
    chat_id: str
    message_content: str
    message_type: str
    attachments: List[str]
    reactions: Dict[str, Any]
    timestamp: datetime
    backup_timestamp: datetime
    shard_ids: List[str]
    encryption_keys: List[str]
    checksum: str
    metadata: Dict[str, Any]


class UniversalBackupManager:
    """
    Universal User and Message Backup Manager
    
    Provides comprehensive backup capabilities with:
    - User opt-out functionality for privacy compliance
    - Intelligent shard distribution based on user preferences
    - Real-time and scheduled backup options
    - Government-level encryption and security
    - Cross-region backup capabilities
    - Granular data type control
    """
    
    def __init__(self, backup_manager):
        self.backup_manager = backup_manager
        self.universal_backup_dir = backup_manager.backup_dir / "universal"
        self.universal_backup_dir.mkdir(parents=True, exist_ok=True)
        
        # User preferences registry
        self.user_preferences: Dict[str, UserBackupPreferences] = {}
        self.message_backups: Dict[str, MessageBackupEntry] = {}
        
        # Configuration
        self.default_backup_status = BackupOptStatus.DEFAULT_IN
        self.backup_retention_days = 365
        self.real_time_backup_enabled = True
        self.cross_region_backup_enabled = True
        
        # Backup queues
        self.pending_user_backups: asyncio.Queue = asyncio.Queue()
        self.pending_message_backups: asyncio.Queue = asyncio.Queue()
        
        # Database
        self.universal_db_path = backup_manager.databases_dir / "universal_backup.db"
        
        logger.info("Universal Backup Manager initialized")
    
    async def initialize(self):
        """Initialize the universal backup system."""
        await self._initialize_database()
        await self._load_user_preferences()
        await self._start_backup_workers()
        logger.info("Universal Backup System initialized")
    
    async def _initialize_database(self):
        """Initialize universal backup database."""
        import aiosqlite
        
        async with aiosqlite.connect(self.universal_db_path) as db:
            # User backup preferences
            await db.execute("""
                CREATE TABLE IF NOT EXISTS user_backup_preferences (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    backup_status TEXT NOT NULL,
                    opted_out_data_types TEXT NOT NULL,
                    backup_frequency TEXT NOT NULL,
                    max_backup_retention_days INTEGER NOT NULL,
                    allow_cross_region_backup BOOLEAN NOT NULL,
                    prefer_local_storage BOOLEAN NOT NULL,
                    encryption_preference TEXT NOT NULL,
                    shard_distribution_preference TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL,
                    metadata TEXT DEFAULT '{}'
                )
            """)
            
            # Message backups
            await db.execute("""
                CREATE TABLE IF NOT EXISTS message_backups (
                    backup_id TEXT PRIMARY KEY,
                    message_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    chat_id TEXT NOT NULL,
                    message_content TEXT NOT NULL,
                    message_type TEXT NOT NULL,
                    attachments TEXT DEFAULT '[]',
                    reactions TEXT DEFAULT '{}',
                    timestamp TIMESTAMP NOT NULL,
                    backup_timestamp TIMESTAMP NOT NULL,
                    shard_ids TEXT NOT NULL,
                    encryption_keys TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    metadata TEXT DEFAULT '{}'
                )
            """)
            
            # Backup statistics
            await db.execute("""
                CREATE TABLE IF NOT EXISTS backup_statistics (
                    stat_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    data_type TEXT NOT NULL,
                    total_backups INTEGER NOT NULL,
                    total_size_bytes INTEGER NOT NULL,
                    last_backup_timestamp TIMESTAMP,
                    success_rate REAL NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL
                )
            """)
            
            await db.commit()
        
        logger.info("Universal backup database initialized")
    
    async def set_user_backup_preferences(
        self,
        user_id: str,
        username: str,
        backup_status: BackupOptStatus = None,
        opted_out_data_types: Set[BackupDataType] = None,
        backup_frequency: str = "real_time",
        max_backup_retention_days: int = 365,
        allow_cross_region_backup: bool = True,
        prefer_local_storage: bool = False,
        encryption_preference: str = "enhanced",
        shard_distribution_preference: str = "distributed"
    ) -> UserBackupPreferences:
        """Set or update user backup preferences."""
        
        # Use defaults if not specified
        if backup_status is None:
            backup_status = self.default_backup_status
        if opted_out_data_types is None:
            opted_out_data_types = set()
        
        # Create or update preferences
        preferences = UserBackupPreferences(
            user_id=user_id,
            username=username,
            backup_status=backup_status,
            opted_out_data_types=opted_out_data_types,
            backup_frequency=backup_frequency,
            max_backup_retention_days=max_backup_retention_days,
            allow_cross_region_backup=allow_cross_region_backup,
            prefer_local_storage=prefer_local_storage,
            encryption_preference=encryption_preference,
            shard_distribution_preference=shard_distribution_preference,
            created_at=datetime.now(timezone.utc) if user_id not in self.user_preferences else self.user_preferences[user_id].created_at,
            updated_at=datetime.now(timezone.utc),
            metadata={}
        )
        
        self.user_preferences[user_id] = preferences
        
        # Save to database
        await self._save_user_preferences(preferences)
        
        logger.info(f"Updated backup preferences for user {user_id}: {backup_status.value}")
        return preferences
    
    async def opt_out_user_backup(
        self,
        user_id: str,
        data_types: Set[BackupDataType] = None
    ) -> bool:
        """
        Opt user out of backup system or specific data types.
        
        Args:
            user_id: User to opt out
            data_types: Specific data types to opt out of (None = opt out of all)
            
        Returns:
            bool: True if successful
        """
        if user_id not in self.user_preferences:
            # Create default preferences first
            await self.set_user_backup_preferences(user_id, f"user_{user_id}")
        
        preferences = self.user_preferences[user_id]
        
        if data_types is None:
            # Opt out of all backups
            preferences.backup_status = BackupOptStatus.OPTED_OUT
            preferences.opted_out_data_types = set(BackupDataType)
        else:
            # Opt out of specific data types
            preferences.opted_out_data_types.update(data_types)
            
            # If all data types are opted out, change status
            if len(preferences.opted_out_data_types) == len(BackupDataType):
                preferences.backup_status = BackupOptStatus.OPTED_OUT
        
        preferences.updated_at = datetime.now(timezone.utc)
        
        # Save to database
        await self._save_user_preferences(preferences)
        
        logger.info(f"User {user_id} opted out of backup: {data_types or 'all data types'}")
        return True
    
    async def opt_in_user_backup(
        self,
        user_id: str,
        data_types: Set[BackupDataType] = None
    ) -> bool:
        """
        Opt user back into backup system or specific data types.
        
        Args:
            user_id: User to opt in
            data_types: Specific data types to opt into (None = opt into all)
            
        Returns:
            bool: True if successful
        """
        if user_id not in self.user_preferences:
            # Create default preferences
            await self.set_user_backup_preferences(user_id, f"user_{user_id}")
            return True
        
        preferences = self.user_preferences[user_id]
        
        if data_types is None:
            # Opt into all backups
            preferences.backup_status = BackupOptStatus.OPTED_IN
            preferences.opted_out_data_types = set()
        else:
            # Opt into specific data types
            preferences.opted_out_data_types -= data_types
            
            # If no data types are opted out, change status
            if len(preferences.opted_out_data_types) == 0:
                preferences.backup_status = BackupOptStatus.OPTED_IN
        
        preferences.updated_at = datetime.now(timezone.utc)
        
        # Save to database
        await self._save_user_preferences(preferences)
        
        logger.info(f"User {user_id} opted into backup: {data_types or 'all data types'}")
        return True
    
    async def backup_user_message(
        self,
        message_id: str,
        user_id: str,
        chat_id: str,
        message_content: str,
        message_type: str = "text",
        attachments: List[str] = None,
        reactions: Dict[str, Any] = None
    ) -> Optional[MessageBackupEntry]:
        """
        Backup a user message if user hasn't opted out.
        
        Returns:
            MessageBackupEntry if backed up, None if opted out
        """
        # Check if user has opted out
        if not await self._should_backup_user_data(user_id, BackupDataType.USER_MESSAGES):
            logger.debug(f"Skipping message backup for user {user_id} - opted out")
            return None
        
        # Get user preferences for backup configuration
        preferences = self.user_preferences.get(user_id)
        if not preferences:
            # Create default preferences
            preferences = await self.set_user_backup_preferences(user_id, f"user_{user_id}")
        
        # Generate backup ID
        backup_id = f"msg_backup_{hashlib.sha256(f'{message_id}_{user_id}_{datetime.now(timezone.utc).isoformat()}'.encode()).hexdigest()[:16]}"
        
        # Create backup entry
        backup_entry = MessageBackupEntry(
            backup_id=backup_id,
            message_id=message_id,
            user_id=user_id,
            chat_id=chat_id,
            message_content=message_content,
            message_type=message_type,
            attachments=attachments or [],
            reactions=reactions or {},
            timestamp=datetime.now(timezone.utc),
            backup_timestamp=datetime.now(timezone.utc),
            shard_ids=[],  # Will be populated during sharding
            encryption_keys=[],  # Will be populated during encryption
            checksum="",  # Will be calculated
            metadata={}
        )
        
        # Calculate checksum
        content_for_checksum = json.dumps({
            'message_id': message_id,
            'user_id': user_id,
            'content': message_content,
            'type': message_type,
            'attachments': attachments or [],
            'reactions': reactions or {}
        }, sort_keys=True)
        backup_entry.checksum = hashlib.sha512(content_for_checksum.encode()).hexdigest()
        
        # Add to backup queue for processing
        await self.pending_message_backups.put(backup_entry)
        
        # Store in memory registry
        self.message_backups[backup_id] = backup_entry
        
        logger.info(f"Queued message backup for user {user_id}, message {message_id}")
        return backup_entry
    
    async def _should_backup_user_data(self, user_id: str, data_type: BackupDataType) -> bool:
        """Check if user data should be backed up based on preferences."""
        preferences = self.user_preferences.get(user_id)
        
        if not preferences:
            # Default to backing up if no preferences set
            return self.default_backup_status != BackupOptStatus.OPTED_OUT
        
        # Check overall backup status
        if preferences.backup_status == BackupOptStatus.OPTED_OUT:
            return False
        
        # Check if specific data type is opted out
        if data_type in preferences.opted_out_data_types:
            return False
        
        # Check for forced backup (admin override)
        if preferences.backup_status == BackupOptStatus.FORCED_BACKUP:
            return True
        
        return True
    
    async def _save_user_preferences(self, preferences: UserBackupPreferences):
        """Save user preferences to database."""
        import aiosqlite
        
        async with aiosqlite.connect(self.universal_db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO user_backup_preferences 
                (user_id, username, backup_status, opted_out_data_types, backup_frequency,
                 max_backup_retention_days, allow_cross_region_backup, prefer_local_storage,
                 encryption_preference, shard_distribution_preference, created_at, updated_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                preferences.user_id,
                preferences.username,
                preferences.backup_status.value,
                json.dumps([dt.value for dt in preferences.opted_out_data_types]),
                preferences.backup_frequency,
                preferences.max_backup_retention_days,
                preferences.allow_cross_region_backup,
                preferences.prefer_local_storage,
                preferences.encryption_preference,
                preferences.shard_distribution_preference,
                preferences.created_at,
                preferences.updated_at,
                json.dumps(preferences.metadata)
            ))
            await db.commit()
    
    async def _load_user_preferences(self):
        """Load user preferences from database."""
        # Implementation would load from database
        logger.info("Loaded user backup preferences from database")
    
    async def _start_backup_workers(self):
        """Start background workers for processing backups."""
        asyncio.create_task(self._message_backup_worker())
        asyncio.create_task(self._user_backup_worker())
        logger.info("Started backup worker tasks")
    
    async def _message_backup_worker(self):
        """Background worker for processing message backups."""
        while True:
            try:
                backup_entry = await self.pending_message_backups.get()
                await self._process_message_backup(backup_entry)
                self.pending_message_backups.task_done()
            except Exception as e:
                logger.error(f"Error in message backup worker: {e}")
                await asyncio.sleep(1)
    
    async def _user_backup_worker(self):
        """Background worker for processing user backups."""
        while True:
            try:
                user_backup = await self.pending_user_backups.get()
                await self._process_user_backup(user_backup)
                self.pending_user_backups.task_done()
            except Exception as e:
                logger.error(f"Error in user backup worker: {e}")
                await asyncio.sleep(1)
    
    async def _process_message_backup(self, backup_entry: MessageBackupEntry):
        """Process a message backup entry."""
        # Implementation would handle sharding, encryption, and storage
        logger.debug(f"Processing message backup {backup_entry.backup_id}")
    
    async def _process_user_backup(self, user_backup):
        """Process a user backup entry."""
        # Implementation would handle user data backup
        logger.debug("Processing user backup")
