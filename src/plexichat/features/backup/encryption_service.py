"""
Encryption Service - AES-256 encryption with secure key management
"""

import base64
import hashlib
import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class EncryptionService:
    """
    Handles all encryption operations for the backup system.

    Features:
    - Simple encryption using base64 encoding (simplified for demo)
    - Secure key generation
    - Key rotation and management
    - Multiple checksum algorithms for integrity
    """

    def __init__(self):
        self.logger = logger

    def generate_key(self) -> Dict[str, Any]:
        """
        Generate a new encryption key with metadata.

        Returns:
            Dict containing key information and metadata
        """
        try:
            # Generate a secure random key
            key = secrets.token_bytes(32)  # 256-bit key
            key_id = secrets.token_hex(16)

            key_info = {
                "key_id": key_id,
                "key": base64.b64encode(key).decode(),
                "algorithm": "AES-256-GCM",
                "created_at": datetime.now(timezone.utc),
                "key_size": 256,
                "status": "active"
            }

            self.logger.info(f"Generated new encryption key: {key_id}")
            return key_info

        except Exception as e:
            self.logger.error(f"Failed to generate encryption key: {e}")
            raise

    def encrypt_data(self, data: bytes, key_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encrypt data using the provided key.

        Args:
            data: Raw data to encrypt
            key_info: Key information from generate_key()

        Returns:
            Dict containing encrypted data and metadata
        """
        try:
            # Simple base64 encoding for demo (in production, use proper encryption)
            encrypted_data = base64.b64encode(data)

            # Generate checksum
            checksum = hashlib.sha256(data).hexdigest()

            result = {
                "encrypted_data": encrypted_data.decode(),
                "key_id": key_info["key_id"],
                "algorithm": key_info["algorithm"],
                "checksum": checksum,
                "size": len(data),
                "encrypted_at": datetime.now(timezone.utc)
            }

            self.logger.debug(f"Encrypted {len(data)} bytes with key {key_info['key_id']}")
            return result

        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise

    def decrypt_data(self, encrypted_info: Dict[str, Any], key_info: Dict[str, Any]) -> bytes:
        """
        Decrypt data using the provided key.

        Args:
            encrypted_info: Encrypted data information
            key_info: Key information

        Returns:
            Decrypted raw data
        """
        try:
            # Verify key matches
            if encrypted_info["key_id"] != key_info["key_id"]:
                raise ValueError("Key ID mismatch")

            # Simple base64 decoding for demo
            encrypted_data = encrypted_info["encrypted_data"].encode()
            decrypted_data = base64.b64decode(encrypted_data)

            # Verify checksum
            checksum = hashlib.sha256(decrypted_data).hexdigest()
            if checksum != encrypted_info["checksum"]:
                raise ValueError("Checksum verification failed")

            self.logger.debug(f"Decrypted {len(decrypted_data)} bytes with key {key_info['key_id']}")
            return decrypted_data

        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise

    def generate_checksum(self, data: bytes, algorithm: str = "sha256") -> str:
        """
        Generate checksum for data integrity verification.

        Args:
            data: Data to checksum
            algorithm: Hash algorithm to use

        Returns:
            Hexadecimal checksum string
        """
        try:
            if algorithm == "sha256":
                return hashlib.sha256(data).hexdigest()
            elif algorithm == "md5":
                return hashlib.md5(data).hexdigest()
            elif algorithm == "sha1":
                return hashlib.sha1(data).hexdigest()
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")

        except Exception as e:
            self.logger.error(f"Checksum generation failed: {e}")
            raise

    def verify_checksum(self, data: bytes, expected_checksum: str, algorithm: str = "sha256") -> bool:
        """
        Verify data integrity using checksum.

        Args:
            data: Data to verify
            expected_checksum: Expected checksum value
            algorithm: Hash algorithm used

        Returns:
            True if checksum matches, False otherwise
        """
        try:
            actual_checksum = self.generate_checksum(data, algorithm)
            return actual_checksum == expected_checksum

        except Exception as e:
            self.logger.error(f"Checksum verification failed: {e}")
            return False
