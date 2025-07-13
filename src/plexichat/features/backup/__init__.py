"""
PlexiChat Unified Backup System

Next-generation backup system with consolidated architecture, quantum encryption,
distributed shards, and zero data loss guarantees.

This unified system replaces all previous backup implementations with a single,
comprehensive solution that provides:
- Government-level security with post-quantum cryptography
- Intelligent shard distribution with AI optimization
- Granular recovery capabilities
- Real-time monitoring and analytics
- Zero-trust security architecture
- GDPR compliance and user privacy controls
"""

# Import unified backup system
from .core.unified_backup_manager import (
    BackupOperation,
    BackupPriority,
    BackupStatus,
    BackupType,
    DistributionStrategy,
    SecurityLevel,
    SystemHealth,
    UnifiedBackupManager,
    UnifiedShard,
    get_unified_backup_manager,
)
from .core.unified_shard_manager import ShardMetadata, ShardState, ShardType, UnifiedShardManager

# Legacy compatibility - redirect to unified system
government_backup_manager = get_unified_backup_manager()

# Import legacy managers for backward compatibility (deprecated)
from .core.backup_manager import government_backup_manager as legacy_government_backup_manager
from .core.backup_node_auth import APIKeyStatus, BackupNodeAuthManager, NodePermissionLevel
from .core.backup_node_client import (
    BackupNodeClient,
    BackupNodeInfo,
    BackupNodeManager,
    NodeStatus,
    ShardInfo,
    ShardStatus,
)
from .core.backup_node_server import BackupNodeConfig, BackupNodeServer, create_backup_node_server
from .core.distribution_manager import IntelligentDistributionManager
from .core.encryption_manager import QuantumEncryptionManager
from .core.profile_backup import (
    ProfileBackupManager,
    ProfileBackupMetadata,
    ProfileRestoreRequest,
    profile_backup_manager,
)
from .core.proxy_manager import DatabaseProxyManager
from .core.recovery_manager import AdvancedRecoveryManager
from .core.shard_manager import ImmutableShardManager
from .core.user_message_backup import BackupDataType, BackupOptStatus, UniversalBackupManager
from .core.user_preferences import (
    BackupOptOutLevel,
    UserBackupPreferences,
    UserPreferencesManager,
    user_preferences_manager,
)
from .plugins.archive_system import ArchiveStatus, ArchiveSystemPlugin, ArchiveType

# Import quantum backup system for compatibility
from .quantum_backup_system import BackupSecurity, QuantumBackup, QuantumBackupSystem, QuantumShard
from .services import (
    BackupCoverageReport,
    BackupHealthStatus,
    BackupStatusMonitor,
    DeviceStatus,
    PerformanceMetrics,
    RedundancyLevel,
    ShardStatus,
    backup_status_monitor,
)

# Alias quantum system to unified system
quantum_backup_system = get_unified_backup_manager()

__version__ = "3.0.0"
__all__ = [
    # Unified backup system
    "UnifiedBackupManager",
    "get_unified_backup_manager",
    "government_backup_manager",
    "quantum_backup_system",
    "BackupOperation",
    "UnifiedShard",
    "SystemHealth",
    "BackupPriority",
    "BackupType",
    "BackupStatus",
    "SecurityLevel",
    "DistributionStrategy",

    # Unified shard management
    "UnifiedShardManager",
    "ShardMetadata",
    "ShardState",
    "ShardType",

    # Legacy compatibility (deprecated)
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

    # Quantum backup system (legacy compatibility)
    "QuantumBackupSystem",
    "BackupSecurity",
    "QuantumShard",
    "QuantumBackup"
]
