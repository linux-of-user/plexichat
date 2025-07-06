"""
NetLink Unified Backup System - Core Module

Consolidated backup system combining all backup functionality into a single,
comprehensive module with government-level security, quantum encryption,
and distributed shard management.

This unified system replaces:
- src/netlink/backup/
- src/netlink/app/backup/
- src/netlink/app/core/backup/

Features:
- Quantum-proof encryption with post-quantum cryptography
- Distributed multi-key security architecture
- Intelligent shard distribution with AI-powered optimization
- Zero-knowledge backup protocol
- Multi-node redundancy with automatic failover
- Immutable shard management with cryptographic verification
- Real-time backup health monitoring
- Advanced recovery capabilities
"""

from .quantum_backup_manager import QuantumBackupManager, quantum_backup_manager
from .distributed_shard_system import DistributedShardSystem, distributed_shard_system
from .backup_node_network import BackupNodeNetwork, backup_node_network
from .zero_knowledge_protocol import ZeroKnowledgeProtocol, zero_knowledge_protocol
from .immutable_shard_manager import ImmutableShardManager, immutable_shard_manager
from .advanced_recovery_system import AdvancedRecoverySystem, advanced_recovery_system
from .backup_analytics import BackupAnalytics, backup_analytics

__version__ = "3.0.0"
__all__ = [
    # Core backup management
    "QuantumBackupManager",
    "quantum_backup_manager",
    
    # Distributed shard system
    "DistributedShardSystem", 
    "distributed_shard_system",
    
    # Backup node network
    "BackupNodeNetwork",
    "backup_node_network",
    
    # Zero-knowledge protocol
    "ZeroKnowledgeProtocol",
    "zero_knowledge_protocol",
    
    # Immutable shard management
    "ImmutableShardManager",
    "immutable_shard_manager",
    
    # Advanced recovery
    "AdvancedRecoverySystem",
    "advanced_recovery_system",
    
    # Analytics and monitoring
    "BackupAnalytics",
    "backup_analytics"
]

# Core system constants
BACKUP_SYSTEM_VERSION = "3.0.0"
MINIMUM_REDUNDANCY_FACTOR = 7  # Enhanced government-level redundancy
MAXIMUM_SHARD_SIZE = 25 * 1024 * 1024  # 25MB per shard for optimal distribution
QUANTUM_ENCRYPTION_ENABLED = True
ZERO_KNOWLEDGE_ENABLED = True
IMMUTABLE_SHARD_GUARANTEE = True
ZERO_DATA_LOSS_GUARANTEE = True

# Security levels
SECURITY_LEVELS = {
    'STANDARD': 1,
    'ENHANCED': 2, 
    'GOVERNMENT': 3,
    'MILITARY': 4,
    'QUANTUM_RESISTANT': 5,
    'ZERO_KNOWLEDGE': 6
}

# Default security level for new installations
DEFAULT_SECURITY_LEVEL = SECURITY_LEVELS['QUANTUM_RESISTANT']
