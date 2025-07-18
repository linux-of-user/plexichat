# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Core Backup System - SINGLE SOURCE OF TRUTH

Consolidates ALL backup functionality from:
- core/backup/backup_manager.py - INTEGRATED
- features/backup/ (all modules) - INTEGRATED
- Related backup components - INTEGRATED

Provides a single, unified interface for all backup operations with:
- Government-level security and quantum encryption
- Distributed shard management with Reed-Solomon encoding
- User privacy controls and opt-out capabilities
- Real-time monitoring and verification
- Advanced recovery capabilities
"""

import warnings
import logging
from typing import Any, Dict, List, Optional

# Import unified backup system (NEW SINGLE SOURCE OF TRUTH)
try:
    from .unified_backup_system import ()
        # Main classes
        UnifiedBackupManager,
        unified_backup_manager,
        ShardManager,
        UserBackupManager,
        BackupOperation,

        # Data classes
        BackupInfo,
        ShardInfo,
        UserBackupPreferences,
        BackupType,
        BackupStatus,
        BackupOptStatus,
        ShardState,

        # Main functions
        create_database_backup,
        create_files_backup,
        create_full_backup,
        restore_backup,
        list_backups,
        get_backup_manager,

        # Exceptions
        BackupError,
        RestoreError,
    )

    # Backward compatibility aliases
    backup_manager = unified_backup_manager
    BackupManager = UnifiedBackupManager

    logger = logging.getLogger(__name__)
    logger.info("Unified backup system imported successfully")

except ImportError as e:
    # Fallback definitions if unified backup system fails to import
    import logging

    warnings.warn()
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

    class UnifiedBackupManager:
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
            return {"backups_created": 0, "backups_restored": 0}

    unified_backup_manager = UnifiedBackupManager()
    backup_manager = unified_backup_manager
    BackupManager = UnifiedBackupManager

    async def create_database_backup(backup_name: Optional[str] = None) -> Optional[BackupInfo]:
        return await unified_backup_manager.create_database_backup(backup_name)

    async def create_files_backup(backup_name: Optional[str] = None, **kwargs) -> Optional[BackupInfo]:
        return await unified_backup_manager.create_files_backup(backup_name, **kwargs)

    async def create_full_backup(backup_name: Optional[str] = None) -> Optional[BackupInfo]:
        return await unified_backup_manager.create_full_backup(backup_name)

    async def restore_backup(backup_id: str, **kwargs) -> bool:
        return await unified_backup_manager.restore_backup(backup_id, **kwargs)

    def list_backups(**kwargs) -> List[BackupInfo]:
        return unified_backup_manager.list_backups(**kwargs)

    def get_backup_manager():
        return unified_backup_manager

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
    # Unified backup system (NEW SINGLE SOURCE OF TRUTH)
    "UnifiedBackupManager",
    "unified_backup_manager",
    "ShardManager",
    "UserBackupManager",
    "BackupOperation",

    # Data classes
    "BackupInfo",
    "ShardInfo",
    "UserBackupPreferences",
    "BackupType",
    "BackupStatus",
    "BackupOptStatus",
    "ShardState",

    # Main functions
    "create_database_backup",
    "create_files_backup",
    "create_full_backup",
    "restore_backup",
    "list_backups",
    "get_backup_manager",

    # Backward compatibility aliases
    "backup_manager",
    "BackupManager",

    # Exceptions
    "BackupError",
    "RestoreError",
]

__version__ = "3.0.0"
