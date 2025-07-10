"""
User and Message Backup System

Comprehensive backup system for user data and messages using the shard system
with privacy controls and opt-out capabilities.

Features:
- Automatic user profile backup
- Message backup with full history
- Privacy-first opt-out system
- Granular backup controls
- Encrypted storage through shard system
- Compliance with data protection regulations
"""

import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import aiosqlite
import hashlib

# Import PlexiChat backup components
from .core.shard_manager import ImmutableShardManager, ShardType
from .core.encryption_manager import QuantumResistantEncryptionManager

logger = logging.getLogger(__name__)


class BackupType(Enum):
    """Types of data that can be backed up."""
    USER_PROFILE = "user_profile"
    USER_MESSAGES = "user_messages"
    USER_SETTINGS = "user_settings"
    USER_METADATA = "user_metadata"
    MESSAGE_CONTENT = "message_content"
    MESSAGE_ATTACHMENTS = "message_attachments"
    MESSAGE_REACTIONS = "message_reactions"


class OptOutLevel(Enum):
    """Levels of opt-out from backup system."""
    NONE = "none"                    # Full backup enabled
    MESSAGES_ONLY = "messages_only"  # Only messages excluded
    PROFILE_ONLY = "profile_only"    # Only profile excluded
    METADATA_ONLY = "metadata_only"  # Only metadata excluded
    COMPLETE = "complete"            # Complete opt-out from all backups


@dataclass
class BackupPreferences:
    """User backup preferences and opt-out settings."""
    user_id: str
    server_id: str
    opt_out_level: OptOutLevel = OptOutLevel.NONE
    excluded_backup_types: Set[BackupType] = field(default_factory=set)
    retention_days: int = 365
    auto_delete_enabled: bool = True
    encryption_preference: str = "quantum-resistant"
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    consent_given: bool = False
    consent_date: Optional[datetime] = None


class UserMessageBackupSystem:
    """
    Comprehensive backup system for user data and messages.
    
    Provides privacy-first backup with granular controls and opt-out capabilities.
    """
    
    def __init__(self, data_dir: Path, shard_manager: ImmutableShardManager):
        self.data_dir = Path(data_dir)
        self.backup_dir = self.data_dir / "user_message_backups"
        self.preferences_db = self.backup_dir / "backup_preferences.db"
        
        # Create directories
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Backup system integration
        self.shard_manager = shard_manager
        
        # User preferences and opt-out tracking
        self.user_preferences: Dict[str, BackupPreferences] = {}
        self.opted_out_users: Set[str] = set()
        
        # Backup tracking
        self.backup_history: Dict[str, List[Dict[str, Any]]] = {}
        
        # Statistics
        self.stats = {
            'total_users_backed_up': 0,
            'total_messages_backed_up': 0,
            'opted_out_users': 0,
            'backup_operations': 0,
            'storage_used_bytes': 0,
            'last_backup_run': None,
            'compliance_reports_generated': 0
        }
        
        self._initialized = False
    
    async def initialize(self):
        """Initialize the user message backup system."""
        if self._initialized:
            return
        
        logger.info("Initializing User Message Backup System")
        
        await self._initialize_database()
        await self._load_user_preferences()
        
        # Start background tasks
        asyncio.create_task(self._automatic_backup_task())
        asyncio.create_task(self._cleanup_expired_backups_task())
        
        self._initialized = True
        logger.info("User Message Backup System initialized successfully")
    
    async def set_user_backup_preferences(self, user_id: str, server_id: str, 
                                        preferences: Dict[str, Any]) -> bool:
        """
        Set user backup preferences and opt-out settings.
        
        Args:
            user_id: User ID
            server_id: Server ID
            preferences: Backup preferences dictionary
            
        Returns:
            True if preferences set successfully
        """
        try:
            # Create backup preferences object
            backup_prefs = BackupPreferences(
                user_id=user_id,
                server_id=server_id,
                opt_out_level=OptOutLevel(preferences.get('opt_out_level', 'none')),
                excluded_backup_types=set(BackupType(t) for t in preferences.get('excluded_types', [])),
                retention_days=preferences.get('retention_days', 365),
                auto_delete_enabled=preferences.get('auto_delete_enabled', True),
                encryption_preference=preferences.get('encryption_preference', 'quantum-resistant'),
                consent_given=preferences.get('consent_given', False),
                consent_date=datetime.now(timezone.utc) if preferences.get('consent_given') else None
            )
            
            # Store preferences
            pref_key = f"{user_id}_{server_id}"
            self.user_preferences[pref_key] = backup_prefs
            
            # Update opted out users set
            if backup_prefs.opt_out_level == OptOutLevel.COMPLETE:
                self.opted_out_users.add(pref_key)
            else:
                self.opted_out_users.discard(pref_key)
            
            # Save to database
            await self._save_user_preferences(backup_prefs)
            
            logger.info(f"Updated backup preferences for user {user_id} in server {server_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set backup preferences for user {user_id}: {e}")
            return False
    
    async def backup_user_profile(self, user_id: str, server_id: str, 
                                profile_data: Dict[str, Any]) -> Optional[str]:
        """
        Backup user profile data.
        
        Args:
            user_id: User ID
            server_id: Server ID
            profile_data: User profile data
            
        Returns:
            Backup ID if successful, None otherwise
        """
        pref_key = f"{user_id}_{server_id}"
        
        # Check if user has opted out
        if not await self._can_backup_user_data(pref_key, BackupType.USER_PROFILE):
            logger.debug(f"User {user_id} has opted out of profile backup")
            return None
        
        try:
            # Prepare backup data
            backup_data = {
                'type': BackupType.USER_PROFILE.value,
                'user_id': user_id,
                'server_id': server_id,
                'profile_data': profile_data,
                'backup_timestamp': datetime.now(timezone.utc).isoformat(),
                'data_hash': self._calculate_data_hash(profile_data)
            }
            
            # Create backup through shard system
            backup_id = f"user_profile_{user_id}_{server_id}_{int(datetime.now().timestamp())}"
            backup_json = json.dumps(backup_data).encode()
            
            # Create shards with enhanced security
            shards = await self.shard_manager.create_shards(
                backup_id=backup_id,
                data=backup_json,
                redundancy_factor=5,
                shard_type=ShardType.IMMUTABLE,
                backup_node_only=False,  # Allow regular nodes for user data
                require_minimum_shards=2
            )
            
            if shards:
                # Track backup
                await self._track_backup_operation(user_id, server_id, backup_id, BackupType.USER_PROFILE)
                
                self.stats['total_users_backed_up'] += 1
                self.stats['backup_operations'] += 1
                
                logger.info(f"Backed up user profile for {user_id} in server {server_id}")
                return backup_id
            
        except Exception as e:
            logger.error(f"Failed to backup user profile for {user_id}: {e}")
        
        return None
    
    async def backup_user_messages(self, user_id: str, server_id: str, 
                                 messages: List[Dict[str, Any]]) -> Optional[str]:
        """
        Backup user messages.
        
        Args:
            user_id: User ID
            server_id: Server ID
            messages: List of message data
            
        Returns:
            Backup ID if successful, None otherwise
        """
        pref_key = f"{user_id}_{server_id}"
        
        # Check if user has opted out of message backup
        if not await self._can_backup_user_data(pref_key, BackupType.USER_MESSAGES):
            logger.debug(f"User {user_id} has opted out of message backup")
            return None
        
        try:
            # Filter messages based on user preferences
            filtered_messages = await self._filter_messages_by_preferences(pref_key, messages)
            
            if not filtered_messages:
                logger.debug(f"No messages to backup for user {user_id} after filtering")
                return None
            
            # Prepare backup data
            backup_data = {
                'type': BackupType.USER_MESSAGES.value,
                'user_id': user_id,
                'server_id': server_id,
                'messages': filtered_messages,
                'message_count': len(filtered_messages),
                'backup_timestamp': datetime.now(timezone.utc).isoformat(),
                'data_hash': self._calculate_data_hash(filtered_messages)
            }
            
            # Create backup through shard system
            backup_id = f"user_messages_{user_id}_{server_id}_{int(datetime.now().timestamp())}"
            backup_json = json.dumps(backup_data).encode()
            
            # Create shards with enhanced security
            shards = await self.shard_manager.create_shards(
                backup_id=backup_id,
                data=backup_json,
                redundancy_factor=5,
                shard_type=ShardType.IMMUTABLE,
                backup_node_only=False,
                require_minimum_shards=2
            )
            
            if shards:
                # Track backup
                await self._track_backup_operation(user_id, server_id, backup_id, BackupType.USER_MESSAGES)
                
                self.stats['total_messages_backed_up'] += len(filtered_messages)
                self.stats['backup_operations'] += 1
                
                logger.info(f"Backed up {len(filtered_messages)} messages for {user_id} in server {server_id}")
                return backup_id
            
        except Exception as e:
            logger.error(f"Failed to backup messages for user {user_id}: {e}")
        
        return None
    
    async def delete_user_backups(self, user_id: str, server_id: str) -> bool:
        """
        Delete all backups for a user (GDPR compliance).
        
        Args:
            user_id: User ID
            server_id: Server ID
            
        Returns:
            True if deletion successful
        """
        try:
            pref_key = f"{user_id}_{server_id}"
            
            # Get all backups for this user
            user_backups = self.backup_history.get(pref_key, [])
            
            deletion_count = 0
            for backup_info in user_backups:
                backup_id = backup_info.get('backup_id')
                if backup_id:
                    # Delete shards associated with this backup
                    deleted = await self.shard_manager.delete_backup_shards(backup_id)
                    if deleted:
                        deletion_count += 1
            
            # Clear backup history
            if pref_key in self.backup_history:
                del self.backup_history[pref_key]
            
            # Remove from database
            await self._delete_user_backup_records(user_id, server_id)
            
            logger.info(f"Deleted {deletion_count} backups for user {user_id} in server {server_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete backups for user {user_id}: {e}")
            return False
    
    async def generate_compliance_report(self, server_id: str) -> Dict[str, Any]:
        """Generate compliance report for data protection regulations."""
        try:
            report = {
                'server_id': server_id,
                'report_generated': datetime.now(timezone.utc).isoformat(),
                'total_users': 0,
                'users_with_backups': 0,
                'opted_out_users': 0,
                'consent_given_users': 0,
                'backup_types_distribution': {},
                'retention_compliance': {},
                'encryption_compliance': True
            }
            
            # Analyze user preferences for this server
            server_users = [prefs for prefs in self.user_preferences.values() 
                          if prefs.server_id == server_id]
            
            report['total_users'] = len(server_users)
            report['users_with_backups'] = len([u for u in server_users 
                                              if u.opt_out_level != OptOutLevel.COMPLETE])
            report['opted_out_users'] = len([u for u in server_users 
                                           if u.opt_out_level == OptOutLevel.COMPLETE])
            report['consent_given_users'] = len([u for u in server_users if u.consent_given])
            
            # Backup types distribution
            for backup_type in BackupType:
                excluded_count = len([u for u in server_users 
                                    if backup_type in u.excluded_backup_types])
                report['backup_types_distribution'][backup_type.value] = {
                    'total_users': len(server_users),
                    'excluded_users': excluded_count,
                    'backup_enabled_users': len(server_users) - excluded_count
                }
            
            self.stats['compliance_reports_generated'] += 1
            
            logger.info(f"Generated compliance report for server {server_id}")
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate compliance report: {e}")
            return {}
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get backup system statistics."""
        # Update current statistics
        self.stats['opted_out_users'] = len(self.opted_out_users)
        
        return {
            **self.stats,
            'total_preferences_configured': len(self.user_preferences),
            'backup_history_entries': sum(len(history) for history in self.backup_history.values())
        }
