"""
PlexiChat Backup System Core Components

Core modules for the government-level backup system:
- backup_manager: Central orchestrator
- shard_manager: Immutable shard management
- encryption_manager: Quantum-resistant encryption
- distribution_manager: AI-powered distribution
- recovery_manager: Advanced recovery capabilities
- proxy_manager: Database proxy mode
"""

# Government-level security constants
MINIMUM_REDUNDANCY_FACTOR = 5
QUANTUM_ENCRYPTION_ENABLED = True
GOVERNMENT_SECURITY_LEVEL = 3
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
    'security_level': GOVERNMENT_SECURITY_LEVEL,
    'redundancy_factor': MINIMUM_REDUNDANCY_FACTOR,
    'quantum_encryption': QUANTUM_ENCRYPTION_ENABLED,
    'zero_data_loss': ZERO_DATA_LOSS_GUARANTEE,
    'backup_retention_days': 365,
    'health_check_interval': 300,  # 5 minutes
    'emergency_backup_threshold': 0.95
}

__version__ = "2.0.0"
