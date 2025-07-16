# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


from pathlib import Path
from pathlib import Path


from pathlib import Path
from pathlib import Path

from plexichat.backup.core.shard_manager import ImmutableShardManager

"""
PlexiChat Archive System Plugin

Advanced archival system that provides message and user versioning
through the shard system. Uses base files and difference shards
for efficient storage and retrieval of historical data.

Features:
- Message versioning with full history
- User profile versioning
- Efficient storage using shard system
- Server-by-server activation
- Permission-based access (paying users)
- Restoration capabilities
- Archive search and filtering
"""

# Import PlexiChat backup system components
sys.path.append(str(from pathlib import Path
Path(__file__).parent.parent / "src"))

logger = logging.getLogger(__name__)


class ArchiveType(Enum):
    """Types of data that can be archived."""
    MESSAGE = "message"
    USER_PROFILE = "user_profile"
    CHANNEL_STATE = "channel_state"
    SERVER_CONFIG = "server_config"
    CUSTOM_DATA = "custom_data"


class ArchiveStatus(Enum):
    """Status of archived items."""
    ACTIVE = "active"
    ARCHIVED = "archived"
    DELETED = "deleted"
    RESTORED = "restored"


@dataclass
class ArchiveEntry:
    """Represents an archived item."""
    archive_id: str
    server_id: str
    archive_type: ArchiveType
    original_id: str  # Original message/user ID
    version: int
    base_shard_id: Optional[str]  # Base version shard
    diff_shard_ids: List[str] = field(default_factory=list)  # Difference shards
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    archived_at: Optional[datetime] = None
    status: ArchiveStatus = ArchiveStatus.ACTIVE
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


class ArchiveSystemPlugin:
    """
    Advanced archive system plugin for PlexiChat.
    
    Provides comprehensive archival capabilities using the shard system
    for efficient storage and retrieval of versioned data.
    """
    
    def __init__(self, data_dir: Path, shard_manager: ImmutableShardManager):
        self.from pathlib import Path
data_dir = Path()(data_dir)
        self.archive_dir = self.data_dir / "archives"
        self.db_path = self.archive_dir / "archive_system.db"
        
        # Create directories
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        
        # Backup system integration
        self.shard_manager = shard_manager
        
        # Archive registry
        self.archives: Dict[str, ArchiveEntry] = {}
        self.server_configs: Dict[str, Dict[str, Any]] = {}
        
        # Statistics
        self.stats = {
            'total_archives': 0,
            'active_archives': 0,
            'total_versions': 0,
            'storage_saved_bytes': 0,
            'servers_enabled': 0,
            'last_cleanup': None
        }
        
        self._initialized = False
    
    async def initialize(self):
        """Initialize the archive system."""
        if self._initialized:
            return
        
        logger.info("Initializing Archive System Plugin")
        
        await self._initialize_database()
        await self._load_archives()
        await self._load_server_configs()
        
        # Start background tasks
        asyncio.create_task(self._background_cleanup_task())
        
        self._initialized = True
        logger.info("Archive System Plugin initialized successfully")
    
    async def enable_for_server(self, server_id: str, config: Dict[str, Any]) -> bool:
        """
        Enable archive system for a specific server.
        
        Args:
            server_id: Server to enable archiving for
            config: Archive configuration for the server
            
        Returns:
            True if enabled successfully
        """
        try:
            default_config = {
                'enabled': True,
                'max_versions_per_item': 50,
                'auto_archive_after_days': 30,
                'max_archive_age_days': 365,
                'archive_types': [ArchiveType.MESSAGE.value, ArchiveType.USER_PROFILE.value],
                'require_permission': True,
                'allowed_roles': ['premium', 'admin'],
                'compression_enabled': True,
                'encryption_level': 'quantum-resistant'
            }
            
            # Merge with provided config
            server_config = {**default_config, **config}
            self.server_configs[server_id] = server_config
            
            # Save to database
            await self._save_server_config(server_id, server_config)
            
            self.stats['servers_enabled'] += 1
            logger.info(f"Archive system enabled for server {server_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to enable archive system for server {server_id}: {e}")
            return False
    
    async def archive_message(self, server_id: str, message_id: str, message_data: Dict[str, Any],
                            user_id: str, tags: Optional[List[str]] = None) -> Optional[str]:
        """
        Archive a message with versioning support.
        
        Args:
            server_id: Server ID
            message_id: Original message ID
            message_data: Message content and metadata
            user_id: User who created/modified the message
            tags: Optional tags for categorization
            
        Returns:
            Archive ID if successful, None otherwise
        """
        if not await self._is_archiving_enabled(server_id, ArchiveType.MESSAGE):
            return None
        
        if not await self._user_has_permission(server_id, user_id):
            logger.warning(f"User {user_id} lacks permission for archiving in server {server_id}")
            return None
        
        try:
            # Check if this message already has archives
            existing_archives = await self._get_message_archives(server_id, message_id)
            
            if not existing_archives:
                # Create base archive
                return await self._create_base_archive(
                    server_id, message_id, ArchiveType.MESSAGE, message_data, tags or []
                )
            else:
                # Create difference archive
                latest_archive = max(existing_archives, key=lambda x: x.version)
                return await self._create_diff_archive(
                    server_id, message_id, ArchiveType.MESSAGE, message_data, 
                    latest_archive, tags or []
                )
                
        except Exception as e:
            logger.error(f"Failed to archive message {message_id}: {e}")
            return None
    
    async def archive_user_profile(self, server_id: str, user_id: str, profile_data: Dict[str, Any],
                                 tags: Optional[List[str]] = None) -> Optional[str]:
        """Archive user profile with versioning."""
        if not await self._is_archiving_enabled(server_id, ArchiveType.USER_PROFILE):
            return None
        
        if not await self._user_has_permission(server_id, user_id):
            return None
        
        try:
            existing_archives = await self._get_user_archives(server_id, user_id)
            
            if not existing_archives:
                return await self._create_base_archive(
                    server_id, user_id, ArchiveType.USER_PROFILE, profile_data, tags or []
                )
            else:
                latest_archive = max(existing_archives, key=lambda x: x.version)
                return await self._create_diff_archive(
                    server_id, user_id, ArchiveType.USER_PROFILE, profile_data,
                    latest_archive, tags or []
                )
                
        except Exception as e:
            logger.error(f"Failed to archive user profile {user_id}: {e}")
            return None
    
    async def restore_version(self, archive_id: str, target_version: int) -> Optional[Dict[str, Any]]:
        """
        Restore a specific version of archived data.
        
        Args:
            archive_id: Archive entry ID
            target_version: Version number to restore
            
        Returns:
            Restored data if successful, None otherwise
        """
        try:
            archive_entry = self.archives.get(archive_id)
            if not archive_entry:
                logger.error(f"Archive entry not found: {archive_id}")
                return None
            
            # Get all versions up to target version
            versions = await self._get_archive_versions(archive_entry.server_id, 
                                                      archive_entry.original_id,
                                                      archive_entry.archive_type)
            
            target_versions = [v for v in versions if v.version <= target_version]
            if not target_versions:
                logger.error(f"Target version {target_version} not found")
                return None
            
            # Start with base version
            base_version = min(target_versions, key=lambda x: x.version)
            if not base_version.base_shard_id:
                logger.error("Base shard not found")
                return None
            
            # Restore base data
            base_shard = await self.shard_manager.get_shard(base_version.base_shard_id)
            if not base_shard:
                logger.error(f"Base shard not found: {base_version.base_shard_id}")
                return None
            
            # Decrypt and deserialize base data
            base_data = await self._decrypt_shard_data(base_shard)
            current_data = json.loads(base_data.decode())
            
            # Apply difference shards in order
            diff_versions = sorted([v for v in target_versions if v.version > base_version.version],
                                 key=lambda x: x.version)
            
            for diff_version in diff_versions:
                for diff_shard_id in diff_version.diff_shard_ids:
                    diff_shard = await self.shard_manager.get_shard(diff_shard_id)
                    if diff_shard:
                        diff_data = await self._decrypt_shard_data(diff_shard)
                        diff_operations = json.loads(diff_data.decode())
                        current_data = self._apply_diff_operations(current_data, diff_operations)
            
            logger.info(f"Restored version {target_version} of archive {archive_id}")
            return current_data
            
        except Exception as e:
            logger.error(f"Failed to restore version {target_version} of archive {archive_id}: {e}")
            return None
    
    async def search_archives(self, server_id: str, query: Dict[str, Any]) -> List[ArchiveEntry]:
        """
        Search archives based on criteria.
        
        Args:
            server_id: Server to search in
            query: Search criteria
            
        Returns:
            List of matching archive entries
        """
        try:
            results = []
            
            for archive in self.archives.values():
                if archive.server_id != server_id:
                    continue
                
                # Apply filters
                if 'archive_type' in query and archive.archive_type.value != query['archive_type']:
                    continue
                
                if 'original_id' in query and archive.original_id != query['original_id']:
                    continue
                
                if 'tags' in query:
                    required_tags = query['tags']
                    if not all(tag in archive.tags for tag in required_tags):
                        continue
                
                if 'date_from' in query:
                    date_from = datetime.fromisoformat(query['date_from'])
                    if archive.created_at < date_from:
                        continue
                
                if 'date_to' in query:
                    date_to = datetime.fromisoformat(query['date_to'])
                    if archive.created_at > date_to:
                        continue
                
                results.append(archive)
            
            # Sort by creation date (newest first)
            results.sort(key=lambda x: x.created_at, reverse=True)
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to search archives: {e}")
            return []
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get archive system statistics."""
        # Update current statistics
        self.stats['total_archives'] = len(self.archives)
        self.stats['active_archives'] = len([a for a in self.archives.values() 
                                           if a.status == ArchiveStatus.ACTIVE])
        self.stats['total_versions'] = sum(len(a.diff_shard_ids) + (1 if a.base_shard_id else 0) 
                                         for a in self.archives.values())
        
        return {
            **self.stats,
            'servers_configured': len(self.server_configs),
            'archive_types_distribution': self._get_archive_type_distribution()
        }
