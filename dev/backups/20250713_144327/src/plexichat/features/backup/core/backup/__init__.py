from .backup_node_auth import BackupNodeAuthManager
from .backup_node_client import BackupNodeClient, BackupNodeManager
from .user_message_backup import UniversalBackupManager


"""
PlexiChat Unified Backup System - Core Module

Consolidated backup system combining all backup functionality into a single,
comprehensive module with government-level security, quantum encryption,
and distributed shard management.

This unified system replaces:
- src/plexichat/backup/
- src/plexichat/app/backup/
- src/plexichat/app/core/backup/

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

# Core backup components - CONSOLIDATED
# Note: Individual managers removed and consolidated into unified system
# Removed: backup_manager.py, shard_manager.py, encryption_manager.py
# Removed: distribution_manager.py, recovery_manager.py, proxy_manager.py
# All functionality now provided by ../unified_backup_manager.py
__version__ = "3.0.0"
__all__ = [
    # Note: Core backup managers consolidated into unified system
    # Legacy exports removed - use unified_backup_manager instead
    "BackupNodeAuthManager",
    "UniversalBackupManager",
    "BackupNodeClient",
    "BackupNodeManager",
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
    "STANDARD": 1,
    "ENHANCED": 2,
    "GOVERNMENT": 3,
    "MILITARY": 4,
    "QUANTUM_RESISTANT": 5,
    "ZERO_KNOWLEDGE": 6,
}

# Default security level for new installations
DEFAULT_SECURITY_LEVEL = SECURITY_LEVELS["QUANTUM_RESISTANT"]
