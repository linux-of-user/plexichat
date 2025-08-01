"""
Time-Based Encryption System
Implements rotating encryption keys based on time intervals for maximum security.
"""

import time
import hashlib
import secrets
import logging
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import base64
import threading

logger = logging.getLogger(__name__)

class TimeBasedEncryption:
    """Time-based encryption with automatic key rotation."""
    
    def __init__(self, rotation_interval: int = 3600):  # 1 hour default
        self.rotation_interval = rotation_interval  # seconds
        self.master_key = self._generate_master_key()
        self.key_cache: Dict[int, bytes] = {}
        self.current_epoch = self._get_current_epoch()
        self.lock = threading.RLock()
        
        # Initialize current key
        self._ensure_key_exists(self.current_epoch)
        
        logger.info(f"Time-based encryption initialized with {rotation_interval}s rotation")
    
    def _generate_master_key(self) -> bytes:
        """Generate a master key for key derivation."""
        return secrets.token_bytes(32)
    
    def _get_current_epoch(self) -> int:
        """Get current time epoch based on rotation interval."""
        return int(time.time() // self.rotation_interval)
    
    def _derive_key_for_epoch(self, epoch: int) -> bytes:
        """Derive encryption key for specific epoch."""
        # Combine master key with epoch for unique key per time period
        epoch_bytes = epoch.to_bytes(8, byteorder='big')
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=epoch_bytes,
            iterations=100000,
        )
        
        return kdf.derive(self.master_key)
    
    def _ensure_key_exists(self, epoch: int) -> bytes:
        """Ensure key exists for given epoch."""
        with self.lock:
            if epoch not in self.key_cache:
                self.key_cache[epoch] = self._derive_key_for_epoch(epoch)
                
                # Clean old keys (keep last 3 epochs for decryption)
                current_epoch = self._get_current_epoch()
                old_epochs = [e for e in self.key_cache.keys() 
                             if e < current_epoch - 2]
                for old_epoch in old_epochs:
                    del self.key_cache[old_epoch]
                
                logger.debug(f"Generated key for epoch {epoch}")
            
            return self.key_cache[epoch]
    
    def encrypt(self, data: bytes, custom_epoch: Optional[int] = None) -> bytes:
        """Encrypt data with time-based key."""
        epoch = custom_epoch or self._get_current_epoch()
        key = self._ensure_key_exists(epoch)
        
        # Use ChaCha20Poly1305 for authenticated encryption
        cipher = ChaCha20Poly1305(key)
        nonce = secrets.token_bytes(12)
        
        # Prepend epoch and nonce to ciphertext
        epoch_bytes = epoch.to_bytes(8, byteorder='big')
        ciphertext = cipher.encrypt(nonce, data, None)
        
        return epoch_bytes + nonce + ciphertext
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using embedded epoch information."""
        if len(encrypted_data) < 20:  # 8 (epoch) + 12 (nonce) minimum
            raise ValueError("Invalid encrypted data format")
        
        # Extract epoch and nonce
        epoch = int.from_bytes(encrypted_data[:8], byteorder='big')
        nonce = encrypted_data[8:20]
        ciphertext = encrypted_data[20:]
        
        # Get key for epoch
        key = self._ensure_key_exists(epoch)
        cipher = ChaCha20Poly1305(key)
        
        try:
            return cipher.decrypt(nonce, ciphertext, None)
        except Exception as e:
            logger.error(f"Decryption failed for epoch {epoch}: {e}")
            raise
    
    def encrypt_string(self, text: str, custom_epoch: Optional[int] = None) -> str:
        """Encrypt string and return base64 encoded result."""
        encrypted_bytes = self.encrypt(text.encode('utf-8'), custom_epoch)
        return base64.urlsafe_b64encode(encrypted_bytes).decode('ascii')
    
    def decrypt_string(self, encrypted_text: str) -> str:
        """Decrypt base64 encoded string."""
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_text.encode('ascii'))
        decrypted_bytes = self.decrypt(encrypted_bytes)
        return decrypted_bytes.decode('utf-8')
    
    def get_current_key_info(self) -> Dict[str, Any]:
        """Get information about current encryption key."""
        current_epoch = self._get_current_epoch()
        return {
            'current_epoch': current_epoch,
            'rotation_interval': self.rotation_interval,
            'next_rotation': (current_epoch + 1) * self.rotation_interval,
            'cached_keys': len(self.key_cache),
            'time_until_rotation': ((current_epoch + 1) * self.rotation_interval) - time.time()
        }

class DatabaseTimeEncryption:
    """Time-based encryption specifically for database operations."""
    
    def __init__(self, rotation_interval: int = 1800):  # 30 minutes for DB
        self.encryption = TimeBasedEncryption(rotation_interval)
        self.field_encryption_map: Dict[str, bool] = {}
        
    def register_encrypted_field(self, table: str, field: str):
        """Register a field for automatic encryption."""
        key = f"{table}.{field}"
        self.field_encryption_map[key] = True
        logger.debug(f"Registered encrypted field: {key}")
    
    def should_encrypt_field(self, table: str, field: str) -> bool:
        """Check if field should be encrypted."""
        key = f"{table}.{field}"
        return self.field_encryption_map.get(key, False)
    
    def encrypt_field_value(self, table: str, field: str, value: Any) -> str:
        """Encrypt a field value if it should be encrypted."""
        if not self.should_encrypt_field(table, field):
            return value
        
        if value is None:
            return None
        
        # Convert value to string for encryption
        str_value = str(value)
        return self.encryption.encrypt_string(str_value)
    
    def decrypt_field_value(self, table: str, field: str, encrypted_value: str) -> str:
        """Decrypt a field value if it was encrypted."""
        if not self.should_encrypt_field(table, field) or encrypted_value is None:
            return encrypted_value
        
        try:
            return self.encryption.decrypt_string(encrypted_value)
        except Exception as e:
            logger.error(f"Failed to decrypt {table}.{field}: {e}")
            return "[DECRYPTION_FAILED]"

class PerformantTimeEncryption:
    """High-performance time-based encryption with caching."""
    
    def __init__(self, rotation_interval: int = 3600):
        self.base_encryption = TimeBasedEncryption(rotation_interval)
        self.cache_size = 1000
        self.encrypt_cache: Dict[str, str] = {}
        self.decrypt_cache: Dict[str, str] = {}
        self.cache_lock = threading.RLock()
        
    def _get_cache_key(self, data: str, epoch: int) -> str:
        """Generate cache key for data and epoch."""
        return hashlib.sha256(f"{data}:{epoch}".encode()).hexdigest()[:16]
    
    def encrypt_with_cache(self, text: str) -> str:
        """Encrypt with caching for performance."""
        current_epoch = self.base_encryption._get_current_epoch()
        cache_key = self._get_cache_key(text, current_epoch)
        
        with self.cache_lock:
            if cache_key in self.encrypt_cache:
                return self.encrypt_cache[cache_key]
            
            # Encrypt and cache
            encrypted = self.base_encryption.encrypt_string(text)
            
            # Manage cache size
            if len(self.encrypt_cache) >= self.cache_size:
                # Remove oldest entries (simple FIFO)
                oldest_keys = list(self.encrypt_cache.keys())[:100]
                for key in oldest_keys:
                    del self.encrypt_cache[key]
            
            self.encrypt_cache[cache_key] = encrypted
            return encrypted
    
    def decrypt_with_cache(self, encrypted_text: str) -> str:
        """Decrypt with caching for performance."""
        with self.cache_lock:
            if encrypted_text in self.decrypt_cache:
                return self.decrypt_cache[encrypted_text]
            
            # Decrypt and cache
            decrypted = self.base_encryption.decrypt_string(encrypted_text)
            
            # Manage cache size
            if len(self.decrypt_cache) >= self.cache_size:
                oldest_keys = list(self.decrypt_cache.keys())[:100]
                for key in oldest_keys:
                    del self.decrypt_cache[key]
            
            self.decrypt_cache[encrypted_text] = decrypted
            return decrypted
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        return {
            'encrypt_cache_size': len(self.encrypt_cache),
            'decrypt_cache_size': len(self.decrypt_cache),
            'cache_limit': self.cache_size,
            'key_info': self.base_encryption.get_current_key_info()
        }

# Global instances
time_encryption = TimeBasedEncryption()
db_time_encryption = DatabaseTimeEncryption()
performant_encryption = PerformantTimeEncryption()

__all__ = [
    'TimeBasedEncryption',
    'DatabaseTimeEncryption', 
    'PerformantTimeEncryption',
    'time_encryption',
    'db_time_encryption',
    'performant_encryption'
]
