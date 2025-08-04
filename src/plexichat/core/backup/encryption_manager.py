#!/usr/bin/env python3
"""
Encryption Manager for Distributed Backup System

Handles individual shard encryption with unique keys per shard.
Provides quantum-resistant encryption options and key management.
"""

import base64
import hashlib
import logging
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, Optional, Tuple, Any
from uuid import uuid4

# Cryptography imports
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

logger = logging.getLogger(__name__)

class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms."""
    AES_256_GCM = "aes-256-gcm"
    AES_256_CBC = "aes-256-cbc"
    CHACHA20_POLY1305 = "chacha20-poly1305"
    FERNET = "fernet"

class KeyDerivationMethod(Enum):
    """Key derivation methods."""
    PBKDF2 = "pbkdf2"
    SCRYPT = "scrypt"
    DIRECT = "direct"

@dataclass
class EncryptionKey:
    """Encryption key information."""
    key_id: str
    algorithm: EncryptionAlgorithm
    key_data: bytes
    salt: bytes
    nonce: Optional[bytes] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (without sensitive key data)."""
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm.value,
            "salt": base64.b64encode(self.salt).decode('utf-8'),
            "nonce": base64.b64encode(self.nonce).decode('utf-8') if self.nonce else None,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata
        }

@dataclass
class EncryptedData:
    """Encrypted data with metadata."""
    data: bytes
    key_id: str
    algorithm: EncryptionAlgorithm
    nonce: Optional[bytes] = None
    tag: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class EncryptionManager:
    """Manages encryption and decryption of individual shards."""
    
    def __init__(self, key_storage_dir: Path, master_password: Optional[str] = None):
        self.key_storage_dir = Path(key_storage_dir)
        self.key_storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.master_password = master_password or self._generate_master_password()
        self.keys: Dict[str, EncryptionKey] = {}
        
        # Default encryption settings
        self.default_algorithm = EncryptionAlgorithm.AES_256_GCM
        self.key_derivation_method = KeyDerivationMethod.SCRYPT
        
        # Load existing keys
        self._load_keys()
        
        if not CRYPTO_AVAILABLE:
            logger.warning("Cryptography library not available, using basic encryption")
    
    def _generate_master_password(self) -> str:
        """Generate a secure master password."""
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')
    
    def _derive_key(self, password: str, salt: bytes, algorithm: EncryptionAlgorithm) -> bytes:
        """Derive encryption key from password and salt."""
        if not CRYPTO_AVAILABLE:
            # Fallback to simple hash-based key derivation
            return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)[:32]
        
        if self.key_derivation_method == KeyDerivationMethod.SCRYPT:
            kdf = Scrypt(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            )
        else:  # PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
        
        return kdf.derive(password.encode())
    
    def generate_shard_key(self, shard_id: str, algorithm: Optional[EncryptionAlgorithm] = None) -> EncryptionKey:
        """Generate a unique encryption key for a shard."""
        algorithm = algorithm or self.default_algorithm
        
        # Generate unique salt for this shard
        salt = secrets.token_bytes(32)
        
        # Derive key from master password + shard ID
        key_material = f"{self.master_password}:{shard_id}"
        key_data = self._derive_key(key_material, salt, algorithm)
        
        # Generate nonce for GCM mode
        nonce = secrets.token_bytes(12) if algorithm == EncryptionAlgorithm.AES_256_GCM else None
        
        encryption_key = EncryptionKey(
            key_id=str(uuid4()),
            algorithm=algorithm,
            key_data=key_data,
            salt=salt,
            nonce=nonce,
            metadata={"shard_id": shard_id}
        )
        
        # Store key
        self.keys[encryption_key.key_id] = encryption_key
        self._save_key(encryption_key)
        
        logger.debug(f"Generated encryption key {encryption_key.key_id} for shard {shard_id}")
        return encryption_key
    
    def encrypt_shard(self, data: bytes, shard_id: str) -> EncryptedData:
        """Encrypt shard data with a unique key."""
        try:
            # Generate or get existing key for this shard
            encryption_key = self.generate_shard_key(shard_id)
            
            if not CRYPTO_AVAILABLE:
                # Fallback to simple XOR encryption
                encrypted_data = self._xor_encrypt(data, encryption_key.key_data)
                return EncryptedData(
                    data=encrypted_data,
                    key_id=encryption_key.key_id,
                    algorithm=encryption_key.algorithm,
                    metadata={"encryption_method": "xor_fallback"}
                )
            
            if encryption_key.algorithm == EncryptionAlgorithm.AES_256_GCM:
                return self._encrypt_aes_gcm(data, encryption_key)
            elif encryption_key.algorithm == EncryptionAlgorithm.FERNET:
                return self._encrypt_fernet(data, encryption_key)
            else:
                raise ValueError(f"Unsupported encryption algorithm: {encryption_key.algorithm}")
                
        except Exception as e:
            logger.error(f"Failed to encrypt shard {shard_id}: {e}")
            raise
    
    def decrypt_shard(self, encrypted_data: EncryptedData) -> bytes:
        """Decrypt shard data."""
        try:
            encryption_key = self.keys.get(encrypted_data.key_id)
            if not encryption_key:
                raise ValueError(f"Encryption key {encrypted_data.key_id} not found")
            
            if not CRYPTO_AVAILABLE:
                # Fallback XOR decryption
                return self._xor_decrypt(encrypted_data.data, encryption_key.key_data)
            
            if encrypted_data.algorithm == EncryptionAlgorithm.AES_256_GCM:
                return self._decrypt_aes_gcm(encrypted_data, encryption_key)
            elif encrypted_data.algorithm == EncryptionAlgorithm.FERNET:
                return self._decrypt_fernet(encrypted_data, encryption_key)
            else:
                raise ValueError(f"Unsupported encryption algorithm: {encrypted_data.algorithm}")
                
        except Exception as e:
            logger.error(f"Failed to decrypt shard: {e}")
            raise
    
    def _encrypt_aes_gcm(self, data: bytes, key: EncryptionKey) -> EncryptedData:
        """Encrypt using AES-256-GCM."""
        cipher = Cipher(
            algorithms.AES(key.key_data),
            modes.GCM(key.nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return EncryptedData(
            data=ciphertext,
            key_id=key.key_id,
            algorithm=key.algorithm,
            nonce=key.nonce,
            tag=encryptor.tag
        )
    
    def _decrypt_aes_gcm(self, encrypted_data: EncryptedData, key: EncryptionKey) -> bytes:
        """Decrypt using AES-256-GCM."""
        cipher = Cipher(
            algorithms.AES(key.key_data),
            modes.GCM(encrypted_data.nonce, encrypted_data.tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data.data) + decryptor.finalize()
    
    def _encrypt_fernet(self, data: bytes, key: EncryptionKey) -> EncryptedData:
        """Encrypt using Fernet (symmetric encryption)."""
        fernet_key = base64.urlsafe_b64encode(key.key_data)
        f = Fernet(fernet_key)
        ciphertext = f.encrypt(data)
        
        return EncryptedData(
            data=ciphertext,
            key_id=key.key_id,
            algorithm=key.algorithm
        )
    
    def _decrypt_fernet(self, encrypted_data: EncryptedData, key: EncryptionKey) -> bytes:
        """Decrypt using Fernet."""
        fernet_key = base64.urlsafe_b64encode(key.key_data)
        f = Fernet(fernet_key)
        return f.decrypt(encrypted_data.data)
    
    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Simple XOR encryption fallback."""
        key_len = len(key)
        return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))
    
    def _xor_decrypt(self, data: bytes, key: bytes) -> bytes:
        """Simple XOR decryption fallback."""
        return self._xor_encrypt(data, key)  # XOR is symmetric
    
    def _save_key(self, key: EncryptionKey):
        """Save encryption key to storage (without sensitive data)."""
        try:
            key_file = self.key_storage_dir / f"{key.key_id}.key"
            key_data = key.to_dict()
            
            # Don't save the actual key data to disk for security
            with open(key_file, 'w') as f:
                import json
                json.dump(key_data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save key {key.key_id}: {e}")
    
    def _load_keys(self):
        """Load encryption keys from storage."""
        try:
            for key_file in self.key_storage_dir.glob("*.key"):
                try:
                    with open(key_file, 'r') as f:
                        import json
                        key_data = json.load(f)
                    
                    # Reconstruct key (we'll need to regenerate the actual key data)
                    # This is a simplified approach - in production, you'd want more secure key storage
                    logger.debug(f"Loaded key metadata for {key_data['key_id']}")
                    
                except Exception as e:
                    logger.warning(f"Failed to load key file {key_file}: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to load keys: {e}")
    
    def rotate_keys(self) -> int:
        """Rotate encryption keys (generate new master password)."""
        old_key_count = len(self.keys)
        
        # Generate new master password
        self.master_password = self._generate_master_password()
        
        # Clear existing keys (they'll be regenerated as needed)
        self.keys.clear()
        
        logger.info(f"Rotated encryption keys, cleared {old_key_count} old keys")
        return old_key_count
    
    def get_key_info(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Get key information (without sensitive data)."""
        key = self.keys.get(key_id)
        return key.to_dict() if key else None
    
    def cleanup_keys(self, key_ids: list) -> int:
        """Clean up specified encryption keys."""
        cleaned_count = 0
        
        for key_id in key_ids:
            if key_id in self.keys:
                del self.keys[key_id]
                
                # Remove key file
                key_file = self.key_storage_dir / f"{key_id}.key"
                if key_file.exists():
                    try:
                        key_file.unlink()
                        cleaned_count += 1
                    except Exception as e:
                        logger.warning(f"Failed to delete key file {key_file}: {e}")
        
        logger.info(f"Cleaned up {cleaned_count} encryption keys")
        return cleaned_count

# Export main classes
__all__ = [
    "EncryptionManager",
    "EncryptionKey",
    "EncryptedData",
    "EncryptionAlgorithm",
    "KeyDerivationMethod"
]
