"""
Encrypted Inter-Node Communication Manager

Provides secure, encrypted communication between cluster nodes with:
- AES-256-GCM encryption for all inter-node traffic
- Automatic key rotation and management
- Certificate-based node authentication
- Hot update support without downtime
- Encrypted heartbeat and status messages
"""

import asyncio
import secrets
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
import aiosqlite
import json
import base64

# Cryptography imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

from . import (
    INTER_NODE_ENCRYPTION, ENCRYPTION_ALGORITHM, KEY_ROTATION_INTERVAL,
    HEARTBEAT_ENCRYPTION, HOT_UPDATE_SUPPORT
)

logger = logging.getLogger(__name__)


class MessageType(Enum):
    """Types of inter-node messages."""
    HEARTBEAT = "heartbeat"
    STATUS_UPDATE = "status_update"
    LOAD_BALANCE = "load_balance"
    FAILOVER = "failover"
    HOT_UPDATE = "hot_update"
    DATA_SYNC = "data_sync"
    COMMAND = "command"
    RESPONSE = "response"


@dataclass
class EncryptedMessage:
    """Encrypted message between nodes."""
    message_id: str
    sender_node_id: str
    recipient_node_id: str
    message_type: MessageType
    encrypted_payload: bytes
    signature: bytes
    timestamp: datetime
    nonce: bytes
    key_version: int


class EncryptedCommunicationManager:
    """
    Manages encrypted communication between cluster nodes.
    
    Features:
    - AES-256-GCM encryption for all messages
    - RSA key exchange and authentication
    - Automatic key rotation
    - Message integrity verification
    - Hot update support
    - Encrypted heartbeat system
    """
    
    def __init__(self, node_id: str, data_dir: Path):
        self.node_id = node_id
        self.data_dir = Path(data_dir)
        self.crypto_dir = self.data_dir / "crypto"
        self.keys_dir = self.crypto_dir / "keys"
        self.certs_dir = self.crypto_dir / "certs"
        
        # Create directories
        self.crypto_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        
        # Encryption keys and certificates
        self.symmetric_keys: Dict[int, bytes] = {}  # Version -> Key
        self.current_key_version = 1
        self.private_key = None
        self.public_key = None
        self.certificate = None
        
        # Node authentication
        self.trusted_nodes: Dict[str, x509.Certificate] = {}
        self.node_public_keys: Dict[str, Any] = {}
        
        # Message tracking
        self.sent_messages: Dict[str, EncryptedMessage] = {}
        self.received_messages: Dict[str, EncryptedMessage] = {}
        
        # Statistics
        self.stats = {
            'messages_sent': 0,
            'messages_received': 0,
            'encryption_operations': 0,
            'decryption_operations': 0,
            'key_rotations': 0,
            'authentication_failures': 0,
            'last_key_rotation': None
        }
        
        self._initialized = False
    
    async def initialize(self):
        """Initialize encrypted communication system."""
        if self._initialized:
            return
        
        logger.info(f"Initializing encrypted communication for node {self.node_id}")
        
        # Generate or load node keys and certificate
        await self._initialize_node_keys()
        await self._initialize_symmetric_keys()
        
        # Start background tasks
        if KEY_ROTATION_INTERVAL > 0:
            asyncio.create_task(self._key_rotation_task())
        
        self._initialized = True
        logger.info("Encrypted communication system initialized")
    
    async def send_encrypted_message(self, recipient_node_id: str, message_type: MessageType,
                                   payload: Dict[str, Any]) -> Optional[str]:
        """
        Send encrypted message to another node.
        
        Args:
            recipient_node_id: Target node ID
            message_type: Type of message
            payload: Message payload
            
        Returns:
            Message ID if sent successfully, None otherwise
        """
        if not INTER_NODE_ENCRYPTION:
            logger.warning("Inter-node encryption is disabled")
            return None
        
        try:
            # Generate message ID
            message_id = f"{self.node_id}_{recipient_node_id}_{secrets.token_hex(8)}"
            
            # Serialize payload
            payload_json = json.dumps(payload).encode()
            
            # Encrypt payload
            encrypted_payload, nonce = await self._encrypt_payload(payload_json)
            
            # Sign message
            signature = await self._sign_message(encrypted_payload, recipient_node_id)
            
            # Create encrypted message
            message = EncryptedMessage(
                message_id=message_id,
                sender_node_id=self.node_id,
                recipient_node_id=recipient_node_id,
                message_type=message_type,
                encrypted_payload=encrypted_payload,
                signature=signature,
                timestamp=datetime.now(timezone.utc),
                nonce=nonce,
                key_version=self.current_key_version
            )
            
            # Store sent message
            self.sent_messages[message_id] = message
            
            # Send message (implementation would depend on transport layer)
            await self._transmit_message(message)
            
            self.stats['messages_sent'] += 1
            self.stats['encryption_operations'] += 1
            
            logger.debug(f"Sent encrypted message {message_id} to {recipient_node_id}")
            return message_id
            
        except Exception as e:
            logger.error(f"Failed to send encrypted message to {recipient_node_id}: {e}")
            return None
    
    async def receive_encrypted_message(self, message_data: bytes) -> Optional[Dict[str, Any]]:
        """
        Receive and decrypt message from another node.
        
        Args:
            message_data: Raw encrypted message data
            
        Returns:
            Decrypted message payload if successful, None otherwise
        """
        try:
            # Deserialize message
            message = self._deserialize_message(message_data)
            
            # Verify sender authentication
            if not await self._verify_sender_authentication(message):
                self.stats['authentication_failures'] += 1
                logger.warning(f"Authentication failed for message from {message.sender_node_id}")
                return None
            
            # Verify message signature
            if not await self._verify_message_signature(message):
                logger.warning(f"Signature verification failed for message {message.message_id}")
                return None
            
            # Decrypt payload
            decrypted_payload = await self._decrypt_payload(
                message.encrypted_payload, message.nonce, message.key_version
            )
            
            # Deserialize payload
            payload = json.loads(decrypted_payload.decode())
            
            # Store received message
            self.received_messages[message.message_id] = message
            
            self.stats['messages_received'] += 1
            self.stats['decryption_operations'] += 1
            
            logger.debug(f"Received encrypted message {message.message_id} from {message.sender_node_id}")
            
            return {
                'message_id': message.message_id,
                'sender_node_id': message.sender_node_id,
                'message_type': message.message_type.value,
                'payload': payload,
                'timestamp': message.timestamp.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to receive encrypted message: {e}")
            return None
    
    async def send_heartbeat(self, recipient_node_id: str, status_data: Dict[str, Any]) -> bool:
        """Send encrypted heartbeat message."""
        if not HEARTBEAT_ENCRYPTION:
            return True  # Skip encryption for heartbeats if disabled
        
        heartbeat_payload = {
            'node_id': self.node_id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'status': status_data,
            'key_version': self.current_key_version
        }
        
        message_id = await self.send_encrypted_message(
            recipient_node_id, MessageType.HEARTBEAT, heartbeat_payload
        )
        
        return message_id is not None
    
    async def send_hot_update(self, recipient_node_id: str, update_data: Dict[str, Any]) -> bool:
        """Send hot update message for zero-downtime updates."""
        if not HOT_UPDATE_SUPPORT:
            logger.warning("Hot update support is disabled")
            return False
        
        update_payload = {
            'update_type': update_data.get('type', 'config'),
            'update_data': update_data,
            'requires_restart': update_data.get('requires_restart', False),
            'rollback_data': update_data.get('rollback_data'),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        message_id = await self.send_encrypted_message(
            recipient_node_id, MessageType.HOT_UPDATE, update_payload
        )
        
        return message_id is not None
    
    async def add_trusted_node(self, node_id: str, certificate_data: bytes) -> bool:
        """Add a trusted node certificate."""
        try:
            certificate = x509.load_pem_x509_certificate(certificate_data, default_backend())
            
            # Verify certificate validity
            if not self._verify_certificate(certificate):
                logger.error(f"Invalid certificate for node {node_id}")
                return False
            
            self.trusted_nodes[node_id] = certificate
            self.node_public_keys[node_id] = certificate.public_key()
            
            logger.info(f"Added trusted node: {node_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add trusted node {node_id}: {e}")
            return False
    
    async def rotate_keys(self) -> bool:
        """Rotate symmetric encryption keys."""
        try:
            # Generate new key
            new_key = secrets.token_bytes(32)  # 256-bit key for AES-256
            new_version = self.current_key_version + 1
            
            # Store new key
            self.symmetric_keys[new_version] = new_key
            self.current_key_version = new_version
            
            # Keep old keys for a transition period
            if len(self.symmetric_keys) > 5:  # Keep last 5 versions
                oldest_version = min(self.symmetric_keys.keys())
                del self.symmetric_keys[oldest_version]
            
            self.stats['key_rotations'] += 1
            self.stats['last_key_rotation'] = datetime.now(timezone.utc).isoformat()
            
            logger.info(f"Rotated encryption keys to version {new_version}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rotate keys: {e}")
            return False
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get communication statistics."""
        return {
            **self.stats,
            'current_key_version': self.current_key_version,
            'trusted_nodes': len(self.trusted_nodes),
            'active_keys': len(self.symmetric_keys),
            'encryption_enabled': INTER_NODE_ENCRYPTION,
            'heartbeat_encryption': HEARTBEAT_ENCRYPTION,
            'hot_update_support': HOT_UPDATE_SUPPORT
        }
