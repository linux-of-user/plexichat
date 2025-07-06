"""
NetLink Government-Level Backup System - Core Module

The heart of NetLink's revolutionary backup system that provides government-level
security, intelligent distribution, and zero data loss guarantees.

This module contains the core components that make NetLink's backup system
the most advanced and secure backup solution ever created.
"""

from .backup_manager import GovernmentBackupManager
from .shard_manager import ImmutableShardManager
from .encryption_manager import QuantumEncryptionManager
from .distribution_manager import IntelligentDistributionManager
from .recovery_manager import AdvancedRecoveryManager
from .proxy_manager import DatabaseProxyManager

__all__ = [
    'GovernmentBackupManager',
    'ImmutableShardManager', 
    'QuantumEncryptionManager',
    'IntelligentDistributionManager',
    'AdvancedRecoveryManager',
    'DatabaseProxyManager'
]

# Version information
__version__ = "2.0.0"
__author__ = "NetLink Security Team"
__description__ = "Government-Level Backup System with Quantum-Resistant Security"

# Core system constants
BACKUP_SYSTEM_VERSION = "2.0.0"
MINIMUM_REDUNDANCY_FACTOR = 5  # Government-level redundancy
MAXIMUM_SHARD_SIZE = 50 * 1024 * 1024  # 50MB per shard
QUANTUM_ENCRYPTION_ENABLED = True
IMMUTABLE_SHARD_GUARANTEE = True
ZERO_DATA_LOSS_GUARANTEE = True

# Security levels
SECURITY_LEVELS = {
    'STANDARD': 1,
    'ENHANCED': 2, 
    'GOVERNMENT': 3,
    'MILITARY': 4,
    'QUANTUM_RESISTANT': 5
}

# Default configuration
DEFAULT_CONFIG = {
    'security_level': SECURITY_LEVELS['GOVERNMENT'],
    'redundancy_factor': MINIMUM_REDUNDANCY_FACTOR,
    'encryption_algorithm': 'AES-256-GCM',
    'quantum_resistant': True,
    'immutable_shards': True,
    'intelligent_distribution': True,
    'real_time_monitoring': True,
    'proxy_mode_enabled': True,
    'audit_logging': True,
    'performance_optimization': True
}
