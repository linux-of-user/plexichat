from .core.unified_backup_manager import (
from .core.unified_backup_manager import (
from .core.unified_backup_manager import (


    AI,
    GDPR,
    AdvancedRecoveryManager,
    APIKeyStatus,
    ArchiveStatus,
    ArchiveSystemPlugin,
    ArchiveType,
    Backup,
    BackupDataType,
    BackupNodeAuthManager,
    BackupNodeConfig,
    BackupNodeServer,
    BackupOperation,
    BackupOptStatus,
    BackupPriority,
    BackupSecurity,
    BackupStatus,
    BackupType,
    DatabaseProxyManager,
    DistributionStrategy,
    Government-level,
    Granular,
    ImmutableShardManager,
    Intelligent,
    IntelligentDistributionManager,
    Next-generation,
    NodePermissionLevel,
    PlexiChat,
    QuantumBackup,
    QuantumBackupSystem,
    QuantumEncryptionManager,
    QuantumShard,
    Real-time,
    SecurityLevel,
    ShardMetadata,
    ShardState,
    ShardType,
    System,
    SystemHealth,
    This,
    Unified,
    UnifiedBackupManager,
    UnifiedShard,
    UnifiedShardManager,
    UniversalBackupManager,
    Zero-trust,
    """,
    -,
    .core.backup_manager,
    .core.backup_node_auth,
    .core.backup_node_client,
    .core.backup_node_server,
    .core.distribution_manager,
    .core.encryption_manager,
    .core.profile_backup,
    .core.proxy_manager,
    .core.recovery_manager,
    .core.shard_manager,
    .core.unified_shard_manager,
    .core.user_message_backup,
    .core.user_preferences,
    .plugins.archive_system,
    .quantum_backup_system,
    .services,
    a,
    all,
    analytics,
    and,
    architecture,
    backup,
    capabilities,
    compliance,
    comprehensive,
    consolidated,
    controls,
    create_backup_node_server,
    cryptography,
    data,
    distributed,
    distribution,
    encryption,
    from,
    get_unified_backup_manager,
)
    government_backup_manager as legacy_government_backup_manager,  # Import unified backup system
)
    guarantees.,
    implementations,
    import,
    loss,
    monitoring,
    optimization,
    post-quantum,
    previous,
    privacy,
    provides:,
    quantum,
    recovery,
    replaces,
    security,
    shard,
    shards,
    single,
    solution,
    system,
    that,
    unified,
    user,
    with,
    zero,
)

# Legacy compatibility - redirect to unified system
government_backup_manager = get_unified_backup_manager()

# Import legacy managers for backward compatibility (deprecated)
    BackupNodeClient,
    BackupNodeInfo,
    BackupNodeManager,
    NodeStatus,
    ShardInfo,
    ShardStatus,
)
    ProfileBackupManager,
    ProfileBackupMetadata,
    ProfileRestoreRequest,
    profile_backup_manager,
)
    BackupOptOutLevel,
    UserBackupPreferences,
    UserPreferencesManager,
    user_preferences_manager,
)
# Import quantum backup system for compatibility
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
