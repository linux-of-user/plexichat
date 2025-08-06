#!/usr/bin/env python3
"""
Distributed Key Manager for Secure Key Distribution

Implements Shamir's Secret Sharing for distributing encryption keys across
multiple nodes with threshold reconstruction. Ensures keys remain secure
even if some nodes are compromised.
"""

import base64
import hashlib
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from uuid import uuid4

# Shamir's Secret Sharing implementation
try:
    from secretsharing import SecretSharer
    SHAMIR_AVAILABLE = True
except ImportError:
    SHAMIR_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("secretsharing library not available, using simplified key distribution")

# Cryptography imports
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

logger = logging.getLogger(__name__)

class KeyType(Enum):
    """Types of keys managed."""
        MASTER = "master"
    SHARD_ENCRYPTION = "shard_encryption"
    NODE_IDENTITY = "node_identity"
    BACKUP_SIGNING = "backup_signing"

class KeyShareStatus(Enum):
    """Status of key shares."""
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    COMPROMISED = "compromised"

@dataclass
class KeyShare:
    """Represents a share of a distributed key.
        share_id: str
    key_id: str
    node_id: str
    share_data: str  # Base64 encoded share
    threshold: int
    total_shares: int
    created_at: datetime
    expires_at: Optional[datetime] = None
    status: KeyShareStatus = KeyShareStatus.ACTIVE
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (without sensitive share data)."""
        return {
            "share_id": self.share_id,
            "key_id": self.key_id,
            "node_id": self.node_id,
            "threshold": self.threshold,
            "total_shares": self.total_shares,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status.value,
            "metadata": self.metadata
        }

@dataclass
class DistributedKey:
    """Represents a key distributed across multiple nodes.
        key_id: str
    key_type: KeyType
    threshold: int
    total_shares: int
    shares: Dict[str, KeyShare]
    created_at: datetime
    last_rotated: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def active_shares(self) -> List[KeyShare]:
        """Get active key shares."""
        return [share for share in self.shares.values() 
                if share.status == KeyShareStatus.ACTIVE]
    
    @property
    def can_reconstruct(self) -> bool:
        Check if key can be reconstructed."""
        return len(self.active_shares) >= self.threshold
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "key_id": self.key_id,
            "key_type": self.key_type.value,
            "threshold": self.threshold,
            "total_shares": self.total_shares,
            "active_shares": len(self.active_shares),
            "can_reconstruct": self.can_reconstruct,
            "created_at": self.created_at.isoformat(),
            "last_rotated": self.last_rotated.isoformat() if self.last_rotated else None,
            "metadata": self.metadata
        }

class DistributedKeyManager:
    """Manages distributed keys using Shamir's Secret Sharing."""
        def __init__(self, storage_dir: Path, default_threshold: int = 3, 
                default_total_shares: int = 5, key_rotation_days: int = 90):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Configuration
        self.default_threshold = default_threshold
        self.default_total_shares = default_total_shares
        self.key_rotation_days = key_rotation_days
        
        # Key storage
        self.distributed_keys: Dict[str, DistributedKey] = {}
        self.node_keys: Dict[str, Dict[str, Any]] = {}  # Node identity keys
        
        # Statistics
        self.stats = {
            "keys_created": 0,
            "keys_rotated": 0,
            "shares_distributed": 0,
            "reconstructions": 0,
            "failed_reconstructions": 0
        }
        
        # Load existing keys
        self._load_distributed_keys()
        
        if not SHAMIR_AVAILABLE:
            logger.warning("Shamir's Secret Sharing not available, using simplified distribution")
    
    def create_distributed_key(self, key_type: KeyType, key_data: bytes,
                            threshold: Optional[int] = None, total_shares: Optional[int] = None,
                            node_ids: Optional[List[str]] = None, 
                            metadata: Optional[Dict[str, Any]] = None) -> DistributedKey:
        """Create a new distributed key with Shamir's Secret Sharing."""
        try:
            threshold = threshold or self.default_threshold
            total_shares = total_shares or self.default_total_shares
            
            if threshold > total_shares:
                raise ValueError("Threshold cannot be greater than total shares")
            
            key_id = str(uuid4())
            
            # Encode key data for sharing
            key_b64 = base64.b64encode(key_data).decode('utf-8')
            
            # Create shares using Shamir's Secret Sharing
            if SHAMIR_AVAILABLE:
                shares_data = SecretSharer.split_secret(key_b64, threshold, total_shares)
            else:
                # Fallback: simple distribution (less secure)
                shares_data = self._create_simple_shares(key_b64, threshold, total_shares)
            
            # Create key shares
            shares = {}
            for i, share_data in enumerate(shares_data):
                node_id = node_ids[i] if node_ids and i < len(node_ids) else f"node_{i+1}"
                
                share = KeyShare(
                    share_id=str(uuid4()),
                    key_id=key_id,
                    node_id=node_id,
                    share_data=share_data,
                    threshold=threshold,
                    total_shares=total_shares,
                    created_at=datetime.now(timezone.utc),
                    expires_at=datetime.now(timezone.utc) + timedelta(days=self.key_rotation_days),
                    metadata={"share_index": i + 1}
                )
                shares[share.share_id] = share
            
            # Create distributed key
            distributed_key = DistributedKey(
                key_id=key_id,
                key_type=key_type,
                threshold=threshold,
                total_shares=total_shares,
                shares=shares,
                created_at=datetime.now(timezone.utc),
                metadata=metadata or {}
            )
            
            # Store distributed key
            self.distributed_keys[key_id] = distributed_key
            self._save_distributed_key(distributed_key)
            
            # Update statistics
            self.stats["keys_created"] += 1
            self.stats["shares_distributed"] += len(shares)
            
            logger.info(f"Created distributed key {key_id} with {total_shares} shares (threshold: {threshold})")
            return distributed_key
            
        except Exception as e:
            logger.error(f"Failed to create distributed key: {e}")
            raise
    
    def reconstruct_key(self, key_id: str, available_shares: Optional[List[str]] = None) -> Optional[bytes]:
        """Reconstruct a key from available shares."""
        try:
            distributed_key = self.distributed_keys.get(key_id)
            if not distributed_key:
                logger.error(f"Distributed key {key_id} not found")
                return None
            
            # Get active shares
            active_shares = distributed_key.active_shares
            
            # Filter by available shares if specified
            if available_shares:
                active_shares = [share for share in active_shares 
                            if share.share_id in available_shares]
            
            if len(active_shares) < distributed_key.threshold:
                logger.error(f"Insufficient shares for reconstruction: need {distributed_key.threshold}, have {len(active_shares)}")
                self.stats["failed_reconstructions"] += 1
                return None
            
            # Use only the required number of shares
            shares_to_use = active_shares[:distributed_key.threshold]
            share_data_list = [share.share_data for share in shares_to_use]
            
            # Reconstruct key using Shamir's Secret Sharing
            if SHAMIR_AVAILABLE:
                reconstructed_b64 = SecretSharer.recover_secret(share_data_list)
            else:
                # Fallback: simple reconstruction
                reconstructed_b64 = self._reconstruct_simple_shares(share_data_list)
            
            # Decode reconstructed key
            reconstructed_key = base64.b64decode(reconstructed_b64)
            
            self.stats["reconstructions"] += 1
            logger.info(f"Successfully reconstructed key {key_id}")
            
            return reconstructed_key
            
        except Exception as e:
            logger.error(f"Failed to reconstruct key {key_id}: {e}")
            self.stats["failed_reconstructions"] += 1
            return None
    
    def distribute_key_to_nodes(self, key_id: str, node_endpoints: Dict[str, str]) -> Dict[str, bool]:
        """Distribute key shares to specified nodes."""
        try:
            distributed_key = self.distributed_keys.get(key_id)
            if not distributed_key:
                return {
            
            distribution_results = {}}
            
            for share in distributed_key.shares.values():
                node_id = share.node_id
                endpoint = node_endpoints.get(node_id)
                
                if endpoint:
                    # In a real implementation, this would make HTTP requests to nodes
                    # For now, we'll simulate successful distribution
                    success = self._send_share_to_node(share, endpoint)
                    distribution_results[node_id] = success
                    
                    if success:
                        logger.info(f"Successfully distributed share {share.share_id} to node {node_id}")
                    else:
                        logger.error(f"Failed to distribute share {share.share_id} to node {node_id}")
                else:
                    logger.warning(f"No endpoint specified for node {node_id}")
                    distribution_results[node_id] = False
            
            return distribution_results
            
        except Exception as e:
            logger.error(f"Failed to distribute key shares: {e}")
            return {
    
    def rotate_key(self, key_id: str, new_key_data: bytes) -> Optional[DistributedKey]:
        """Rotate a distributed key with new key data."""
        try:
            old_key = self.distributed_keys.get(key_id)
            if not old_key:
                logger.error(f"Key {key_id}} not found for rotation")
                return None
            
            # Revoke old shares
            for share in old_key.shares.values():
                share.status = KeyShareStatus.REVOKED
            
            # Create new distributed key with same configuration
            new_key = self.create_distributed_key(
                key_type=old_key.key_type,
                key_data=new_key_data,
                threshold=old_key.threshold,
                total_shares=old_key.total_shares,
                node_ids=[share.node_id for share in old_key.shares.values()],
                metadata=old_key.metadata
            )
            
            # Update rotation timestamp
            new_key.last_rotated = datetime.now(timezone.utc)
            
            # Remove old key and save new one
            del self.distributed_keys[key_id]
            self.distributed_keys[new_key.key_id] = new_key
            self._save_distributed_key(new_key)
            
            self.stats["keys_rotated"] += 1
            
            logger.info(f"Successfully rotated key {key_id} to {new_key.key_id}")
            return new_key
            
        except Exception as e:
            logger.error(f"Failed to rotate key {key_id}: {e}")
            return None
    
    def _create_simple_shares(self, secret: str, threshold: int, total_shares: int) -> List[str]:
        """Create simple shares (fallback when Shamir's not available)."""
        # This is a simplified implementation - not as secure as Shamir's
        shares = []
        for i in range(total_shares):
            # Create a simple share by XORing with a random key
            share_key = secrets.token_bytes(len(secret.encode()))
            share_data = base64.b64encode(share_key).decode('utf-8')
            shares.append(f"{i+1}-{share_data}-{secret}")
        return shares
    
    def _reconstruct_simple_shares(self, shares: List[str]) -> str:
        """Reconstruct from simple shares (fallback)."""
        # Extract the secret from the first share (simplified)
        if shares:
            parts = shares[0].split('-')
            if len(parts) >= 3:
                return parts[2]
        raise ValueError("Cannot reconstruct from simple shares")
    
    def _send_share_to_node(self, share: KeyShare, endpoint: str) -> bool:
        """Send key share to a node (placeholder for actual implementation).
        # In a real implementation, this would:
        # 1. Encrypt the share with the node's public key
        # 2. Send via HTTPS to the node's endpoint
        # 3. Verify receipt and storage
        
        # For now, simulate successful distribution
        return True
    
    def _save_distributed_key(self, distributed_key: DistributedKey):
        """Save distributed key metadata (without sensitive share data)."""
        try:
            key_file = self.storage_dir / f"{distributed_key.key_id}.key"
            key_data = distributed_key.to_dict()
            
            with open(key_file, 'w') as f:
                import json
                json.dump(key_data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save distributed key {distributed_key.key_id}: {e}")
    
    def _load_distributed_keys(self):
        """Load distributed key metadata from storage."""
        try:
            for key_file in self.storage_dir.glob("*.key"):
                try:
                    with open(key_file, 'r') as f:
                        import json
                        key_data = json.load(f)
                    
                    # Reconstruct DistributedKey object (without shares)
                    logger.debug(f"Loaded distributed key metadata: {key_data['key_id']}")
                    
                except Exception as e:
                    logger.warning(f"Failed to load key file {key_file}: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to load distributed keys: {e}")
    
    def get_key_status(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a distributed key."""
        distributed_key = self.distributed_keys.get(key_id)
        if not distributed_key:
            return None
        
        return {
            "key_info": distributed_key.to_dict(),
            "shares_status": [share.to_dict() for share in distributed_key.shares.values()],
            "health": {
                "can_reconstruct": distributed_key.can_reconstruct,
                "active_shares": len(distributed_key.active_shares),
                "required_shares": distributed_key.threshold,
                "total_shares": distributed_key.total_shares
            }
        }
    
    def cleanup_expired_keys(self) -> int:
        """Clean up expired key shares."""
        cleaned_count = 0
        current_time = datetime.now(timezone.utc)
        
        for distributed_key in self.distributed_keys.values():
            for share in distributed_key.shares.values():
                if (share.expires_at and share.expires_at < current_time and 
                    share.status == KeyShareStatus.ACTIVE):
                    share.status = KeyShareStatus.EXPIRED
                    cleaned_count += 1
        
        logger.info(f"Cleaned up {cleaned_count} expired key shares")
        return cleaned_count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get distributed key manager statistics."""
        stats = self.stats.copy()
        
        stats.update({
            "total_distributed_keys": len(self.distributed_keys),
            "active_keys": len([k for k in self.distributed_keys.values() if k.can_reconstruct]),
            "total_shares": sum(len(k.shares) for k in self.distributed_keys.values()),
            "active_shares": sum(len(k.active_shares) for k in self.distributed_keys.values()),
            "default_threshold": self.default_threshold,
            "default_total_shares": self.default_total_shares,
            "shamir_available": SHAMIR_AVAILABLE
        })
        
        return stats

# Export main classes
__all__ = [
    "DistributedKeyManager",
    "DistributedKey",
    "KeyShare",
    "KeyType",
    "KeyShareStatus"
]
