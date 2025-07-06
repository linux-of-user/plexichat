"""
NetLink Government-Level Backup System

The defining feature of NetLink - a revolutionary backup system with:
- Government-level security and encryption
- Immutable shard technology
- Zero data loss guarantees
- AI-powered intelligent distribution
- Quantum-resistant encryption
- Real-time monitoring and recovery
"""

from .core.backup_manager import government_backup_manager
from .core.shard_manager import ImmutableShardManager
from .core.encryption_manager import QuantumEncryptionManager
from .core.distribution_manager import IntelligentDistributionManager
from .core.recovery_manager import AdvancedRecoveryManager
from .core.proxy_manager import DatabaseProxyManager
from .core.backup_node_auth import BackupNodeAuthManager, NodePermissionLevel, APIKeyStatus
from .core.user_message_backup import UniversalBackupManager, BackupOptStatus, BackupDataType
from .core.backup_node_client import BackupNodeClient, BackupNodeManager, BackupNodeInfo, ShardInfo, NodeStatus, ShardStatus
from .core.backup_node_server import BackupNodeServer, BackupNodeConfig, create_backup_node_server
from .core.user_preferences import UserPreferencesManager, UserBackupPreferences, BackupOptOutLevel, user_preferences_manager
from .core.profile_backup import ProfileBackupManager, ProfileBackupMetadata, ProfileRestoreRequest, profile_backup_manager
from .plugins.archive_system import ArchiveSystemPlugin, ArchiveType, ArchiveStatus
from .services import (
    BackupStatusMonitor, BackupCoverageReport, DeviceStatus, ShardStatus,
    PerformanceMetrics, BackupHealthStatus, RedundancyLevel, backup_status_monitor
)

# Import new quantum backup system
from .quantum_backup_system import (
    QuantumBackupSystem,
    quantum_backup_system,
    BackupSecurity,
    ShardDistribution,
    BackupStatus,
    QuantumShard,
    QuantumBackup
)

__version__ = "2.0.0"
__all__ = [
    # Core backup system
    "government_backup_manager",
    "ImmutableShardManager",
    "QuantumEncryptionManager",
    "IntelligentDistributionManager",
    "AdvancedRecoveryManager",
    "DatabaseProxyManager",

    # Authentication and authorization
    "BackupNodeAuthManager",
    "NodePermissionLevel",
    "APIKeyStatus",

    # User and message backup
    "UniversalBackupManager",
    "BackupOptStatus",
    "BackupDataType",

    # Backup node client and server
    "BackupNodeClient",
    "BackupNodeManager",
    "BackupNodeInfo",
    "ShardInfo",
    "NodeStatus",
    "ShardStatus",
    "BackupNodeServer",
    "BackupNodeConfig",
    "create_backup_node_server",

    # Archive system plugin
    "ArchiveSystemPlugin",
    "ArchiveType",
    "ArchiveStatus",

    # User preferences and profile backup
    "UserPreferencesManager",
    "UserBackupPreferences",
    "BackupOptOutLevel",
    "user_preferences_manager",
    "ProfileBackupManager",
    "ProfileBackupMetadata",
    "ProfileRestoreRequest",
    "profile_backup_manager",

    # Services layer
    "BackupStatusMonitor",
    "BackupCoverageReport",
    "DeviceStatus",
    "ShardStatus",
    "PerformanceMetrics",
    "BackupHealthStatus",
    "RedundancyLevel",
    "backup_status_monitor",

    # Quantum backup system
    "QuantumBackupSystem",
    "quantum_backup_system",
    "BackupSecurity",
    "ShardDistribution",
    "BackupStatus",
    "QuantumShard",
    "QuantumBackup"
]
