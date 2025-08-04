"""
PlexiChat Backup System

Unified backup and restore functionality for PlexiChat.
"""

from .backup_system import (
    BackupManager,
    BackupInfo,
    BackupType,
    BackupStatus,
    BackupError,
    RestoreError,
    get_backup_manager,
    create_database_backup,
    create_files_backup,
    create_full_backup,
    restore_backup,
    list_backups
)

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

# Provides a single, unified interface for all backup operations with:
# - Government-level security and quantum encryption
# - Distributed shard management with Reed-Solomon encoding
# - User privacy controls and opt-out capabilities
# - Real-time monitoring and verification
# - Advanced recovery capabilities

import warnings
import logging
from typing import Any, Dict, List, Optional

# Import unified backup system (NEW SINGLE SOURCE OF TRUTH)
try:
    from .backup_system import (
        # Main classes
        BackupManager,
        get_backup_manager,

        # Data classes
        BackupInfo,
        BackupType,
        BackupStatus,

        # Main functions
        create_database_backup,
        create_files_backup,
        create_full_backup,
        restore_backup,
        list_backups,

        # Exceptions
        BackupError,
        RestoreError,
    )

    # Backward compatibility aliases (lazy initialization to prevent circular imports)
    _backup_manager = None

    def get_global_backup_manager():
        """Get the global backup manager instance."""
        global _backup_manager
        if _backup_manager is None:
            _backup_manager = get_backup_manager()
        return _backup_manager

    UnifiedBackupManager = BackupManager

    logger = logging.getLogger(__name__)
    logger.info("Unified backup system imported successfully")

except ImportError as e:
    # Fallback definitions if unified backup system fails to import
    import logging

    warnings.warn(
        f"Failed to import unified backup system: {e}. Using fallback backup.",
        ImportWarning,
        stacklevel=2
    )

    logger = logging.getLogger(__name__)

    class BackupError(Exception):
        pass

    class RestoreError(Exception):
        pass

    class BackupType:
        DATABASE = "database"
        FILES = "files"
        FULL = "full"
        USER_DATA = "user_data"

    class BackupStatus:
        PENDING = "pending"
        RUNNING = "running"
        COMPLETED = "completed"
        FAILED = "failed"

    class BackupInfo:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class BackupManager:
        def __init__(self):
            self.initialized = False
            self.backup_history = []

        async def initialize(self) -> bool:
            logger.warning("Using fallback backup manager")
            self.initialized = True
            return True

        async def create_database_backup(self, backup_name: Optional[str] = None) -> Optional[BackupInfo]:
            logger.warning("Database backup not available in fallback mode")
            return None

        async def create_files_backup(self, backup_name: Optional[str] = None, **kwargs) -> Optional[BackupInfo]:
            logger.warning("Files backup not available in fallback mode")
            return None

        async def create_full_backup(self, backup_name: Optional[str] = None) -> Optional[BackupInfo]:
            logger.warning("Full backup not available in fallback mode")
            return None

        async def restore_backup(self, backup_id: str, **kwargs) -> bool:
            logger.warning("Backup restore not available in fallback mode")
            return False

        def list_backups(self, **kwargs) -> List[BackupInfo]:
            return self.backup_history

        def get_backup_stats(self) -> Dict[str, Any]:
            return {}}"backups_created": 0, "backups_restored": 0}

    _backup_manager = BackupManager()
    backup_manager = _backup_manager
    UnifiedBackupManager = BackupManager

    def get_backup_manager():
        return _backup_manager

    async def create_database_backup(backup_name: Optional[str] = None) -> Optional[BackupInfo]:
        return await _backup_manager.create_database_backup(backup_name)

    async def create_files_backup(backup_name: Optional[str] = None, **kwargs) -> Optional[BackupInfo]:
        return await _backup_manager.create_files_backup(backup_name, **kwargs)

    async def create_full_backup(backup_name: Optional[str] = None) -> Optional[BackupInfo]:
        return await _backup_manager.create_full_backup(backup_name)

    async def restore_backup(backup_id: str, **kwargs) -> bool:
        return await _backup_manager.restore_backup(backup_id, **kwargs)

    def list_backups(**kwargs) -> List[BackupInfo]:
        return _backup_manager.list_backups(**kwargs)

    # Fallback classes
    class ShardManager:
        pass

    class UserBackupManager:
        pass

    class BackupOperation:
        pass

    class ShardInfo:
        pass

    class UserBackupPreferences:
        pass

    class BackupOptStatus:
        pass

    class ShardState:
        pass

# Export all the main classes and functions
__all__ = [
    # Main backup system
    "BackupManager",
    "get_backup_manager",
    "get_global_backup_manager",

    # Data classes
    "BackupInfo",
    "BackupType",
    "BackupStatus",

    # Main functions
    "create_database_backup",
    "create_files_backup",
    "create_full_backup",
    "restore_backup",
    "list_backups",

    # Exceptions
    "BackupError",
    "RestoreError",

    # Backward compatibility
    "UnifiedBackupManager",
]

__version__ = "3.0.0"
