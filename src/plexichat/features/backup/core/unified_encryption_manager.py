from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Tuple

from ...core_system.logging import get_logger
from ...security import distributed_key_manager, quantum_encryption

"""
Unified Encryption Manager

Consolidates all encryption functionality for the backup system with:
- Post-quantum cryptography support
- Zero-trust security integration
- Hardware security module (HSM) support
- Key rotation and lifecycle management
"""

logger = get_logger(__name__)


class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms."""
    AES_256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"
    QUANTUM_RESISTANT = "quantum-resistant"
    POST_QUANTUM = "post-quantum"


class UnifiedEncryptionManager:
    """
    Unified Encryption Manager
    
    Provides enterprise-grade encryption services for the backup system
    with quantum-resistant algorithms and zero-trust security.
    """
    
    def __init__(self, backup_manager):
        self.backup_manager = backup_manager
        self.initialized = False
        
        # Configuration
        self.config = backup_manager.config.get("encryption", {})
        self.default_algorithm = EncryptionAlgorithm.QUANTUM_RESISTANT
        
        # Key management
        self.active_keys: Dict[str, Any] = {}
        
        logger.info("Unified Encryption Manager initialized")
    
    async def initialize(self) -> None:
        """Initialize the encryption manager."""
        if self.initialized:
            return
        
        # Initialize quantum encryption
        await quantum_encryption.initialize()
        
        # Initialize key manager
        await distributed_key_manager.initialize()
        
        self.initialized = True
        logger.info("Unified Encryption Manager initialized successfully")
    
    async def encrypt_backup_data(
        self, 
        data: bytes, 
        operation
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Encrypt backup data with quantum-resistant encryption."""
        if not self.initialized:
            await self.initialize()
        
        # Use quantum encryption with backup-specific key domain
        encrypted_data = await quantum_encryption.encrypt_data(
            data,
            key_domain=f"backup.{operation.backup_id}",
            classification=operation.security_level.name
        )
        
        encryption_metadata = {
            "algorithm": self.default_algorithm.value,
            "key_domain": f"backup.{operation.backup_id}",
            "classification": operation.security_level.name,
            "encrypted_at": datetime.now(timezone.utc).isoformat()
        }
        
        return encrypted_data, encryption_metadata
    
    async def decrypt_backup_data(
        self, 
        encrypted_data: bytes, 
        encryption_metadata: Dict[str, Any]
    ) -> bytes:
        """Decrypt backup data."""
        if not self.initialized:
            await self.initialize()
        
        return await quantum_encryption.decrypt_data(
            encrypted_data,
            key_domain=encryption_metadata["key_domain"],
            classification=encryption_metadata["classification"]
        )
