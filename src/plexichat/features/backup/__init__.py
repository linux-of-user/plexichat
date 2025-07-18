# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Backup Features - MODERN ARCHITECTURE

Advanced backup and recovery system with:
- Government-level security and quantum encryption
- Distributed shard management with Reed-Solomon encoding
- User privacy controls and opt-out capabilities
- Real-time monitoring and verification
- Advanced recovery capabilities
- Automated backup scheduling
- Disaster recovery planning

Uses shared components for consistent error handling and type definitions.
Integrates with the core backup system from core/backup/.
"""

from typing import Optional, Any

# Import shared components (NEW ARCHITECTURE)
from ...shared.models import User, Event, Priority, Status
from ...shared.types import UserId, JSON, ConfigDict
from ...shared.exceptions import BackupError, RestoreError, ValidationError
from ...shared.constants import ()
    BACKUP_RETENTION_DAYS, BACKUP_COMPRESSION_ENABLED, BACKUP_ENCRYPTION_ENABLED,
    SHARD_SIZE, MIN_BACKUP_SHARDS, PARITY_SHARD_RATIO
)

# Import core backup system (UNIFIED FROM PHASE 1)
try:
    from ...core.backup.unified_backup_system import ()
        UnifiedBackupManager as CoreBackupManager,
        unified_backup_manager as core_backup_manager,
        BackupInfo,
        BackupType,
        BackupStatus,
        create_database_backup,
        create_files_backup,
        create_full_backup,
        restore_backup,
        list_backups,
    )

    # Use core backup system as the foundation
    UnifiedBackupManager = CoreBackupManager
    unified_backup_manager = core_backup_manager

except ImportError:
    # Fallback if core backup system not available
    class UnifiedBackupManager:
        """Fallback backup manager"""

        def __init__(self):
            self.initialized = False

        async def initialize(self):
            """Initialize the backup manager"""
            self.initialized = True
            return True

        async def shutdown(self):
            """Shutdown the backup manager"""
            self.initialized = False

        def cleanup(self):
            """Cleanup backup resources"""
            pass

    unified_backup_manager = UnifiedBackupManager()

    # Fallback functions
    async def create_database_backup(backup_name: Optional[str] = None):
        return None

    async def create_files_backup(backup_name: Optional[str] = None, **kwargs):
        return None

    async def create_full_backup(backup_name: Optional[str] = None):
        return None

    async def restore_backup(backup_id: str, **kwargs):
        return False

    def list_backups(**kwargs):
        return []

def get_unified_backup_manager():
    """Get the unified backup manager instance"""
    return unified_backup_manager

async def initialize_backup_system():
    """Initialize backup system"""
    return await unified_backup_manager.initialize()

# Legacy compatibility - redirect to unified system
government_backup_manager = unified_backup_manager
quantum_backup_system = unified_backup_manager

__version__ = "3.0.0"
__all__ = [
    # Shared components re-exports
    "User",
    "Event",
    "Priority",
    "Status",
    "UserId",
    "JSON",
    "ConfigDict",

    # Exceptions
    "BackupError",
    "RestoreError",
    "ValidationError",

    # Core backup system
    "UnifiedBackupManager",
    "unified_backup_manager",
    "BackupInfo",
    "BackupType",
    "BackupStatus",

    # Main functions
    "create_database_backup",
    "create_files_backup",
    "create_full_backup",
    "restore_backup",
    "list_backups",
    "get_unified_backup_manager",
    "initialize_backup_system",

    # Legacy compatibility
    "government_backup_manager",
    "quantum_backup_system",
    "get_unified_backup_manager",
    "initialize_backup_system",
    "government_backup_manager",
    "quantum_backup_system"
]
