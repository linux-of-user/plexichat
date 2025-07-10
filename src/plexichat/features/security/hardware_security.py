"""
PlexiChat Hardware Security Modules (HSM) Integration

Secure key management and cryptographic operations using
hardware security modules for government-level security.
"""

import os
import secrets
import hashlib
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class HSMType(Enum):
    """Types of Hardware Security Modules."""
    NETWORK_ATTACHED = "network_attached"
    PCIe_CARD = "pcie_card"
    USB_TOKEN = "usb_token"
    CLOUD_HSM = "cloud_hsm"
    VIRTUAL_HSM = "virtual_hsm"


class KeyType(Enum):
    """Types of cryptographic keys."""
    AES = "aes"
    RSA = "rsa"
    ECDSA = "ecdsa"
    ECDH = "ecdh"
    HMAC = "hmac"
    QUANTUM_RESISTANT = "quantum_resistant"


class KeyUsage(Enum):
    """Key usage purposes."""
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNING = "signing"
    VERIFICATION = "verification"
    KEY_AGREEMENT = "key_agreement"
    KEY_DERIVATION = "key_derivation"


@dataclass
class HSMKey:
    """HSM-managed cryptographic key."""
    key_id: str
    key_type: KeyType
    key_size: int
    usage: List[KeyUsage]
    created_at: datetime
    expires_at: Optional[datetime] = None
    hsm_handle: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if key is expired."""
        if self.expires_at:
            return datetime.now(timezone.utc) > self.expires_at
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "key_id": self.key_id,
            "key_type": self.key_type.value,
            "key_size": self.key_size,
            "usage": [u.value for u in self.usage],
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "hsm_handle": self.hsm_handle,
            "metadata": self.metadata,
            "expired": self.is_expired()
        }


@dataclass
class HSMDevice:
    """Hardware Security Module device."""
    device_id: str
    device_type: HSMType
    manufacturer: str
    model: str
    firmware_version: str
    serial_number: str
    is_authenticated: bool = False
    is_available: bool = True
    capabilities: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "device_id": self.device_id,
            "device_type": self.device_type.value,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "firmware_version": self.firmware_version,
            "serial_number": self.serial_number,
            "is_authenticated": self.is_authenticated,
            "is_available": self.is_available,
            "capabilities": self.capabilities
        }


class HSMInterface:
    """Interface for Hardware Security Module operations."""
    
    def __init__(self, device: HSMDevice):
        self.device = device
        self.session_active = False
        self.keys: Dict[str, HSMKey] = {}
        
        # Simulated HSM capabilities
        self.max_keys = 1000
        self.supported_algorithms = {
            KeyType.AES: [128, 192, 256],
            KeyType.RSA: [2048, 3072, 4096],
            KeyType.ECDSA: [256, 384, 521],
            KeyType.HMAC: [256, 384, 512]
        }
    
    def authenticate(self, pin: str, admin_pin: Optional[str] = None) -> bool:
        """Authenticate with HSM."""
        # Simulated authentication (in production, use actual HSM API)
        if len(pin) >= 6:  # Basic PIN validation
            self.device.is_authenticated = True
            self.session_active = True
            logger.info(f"Authenticated with HSM {self.device.device_id}")
            return True
        
        logger.error(f"Authentication failed for HSM {self.device.device_id}")
        return False
    
    def generate_key(self, key_type: KeyType, key_size: int, 
                    usage: List[KeyUsage], expires_days: Optional[int] = None) -> Optional[HSMKey]:
        """Generate cryptographic key in HSM."""
        if not self.device.is_authenticated:
            logger.error("HSM not authenticated")
            return None
        
        if len(self.keys) >= self.max_keys:
            logger.error("HSM key storage full")
            return None
        
        if key_type not in self.supported_algorithms:
            logger.error(f"Key type {key_type} not supported")
            return None
        
        if key_size not in self.supported_algorithms[key_type]:
            logger.error(f"Key size {key_size} not supported for {key_type}")
            return None
        
        # Generate key
        key_id = f"hsm_{self.device.device_id}_{secrets.token_hex(8)}"
        hsm_handle = f"handle_{secrets.token_hex(16)}"
        
        expires_at = None
        if expires_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)
        
        key = HSMKey(
            key_id=key_id,
            key_type=key_type,
            key_size=key_size,
            usage=usage,
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at,
            hsm_handle=hsm_handle,
            metadata={
                "hsm_device": self.device.device_id,
                "generation_method": "hsm_native"
            }
        )
        
        self.keys[key_id] = key
        logger.info(f"Generated {key_type.value}-{key_size} key: {key_id}")
        return key
    
    def encrypt(self, key_id: str, plaintext: bytes) -> Optional[bytes]:
        """Encrypt data using HSM key."""
        if not self.device.is_authenticated:
            logger.error("HSM not authenticated")
            return None
        
        if key_id not in self.keys:
            logger.error(f"Key {key_id} not found")
            return None
        
        key = self.keys[key_id]
        if KeyUsage.ENCRYPTION not in key.usage:
            logger.error(f"Key {key_id} not authorized for encryption")
            return None
        
        if key.is_expired():
            logger.error(f"Key {key_id} is expired")
            return None
        
        # Simulated HSM encryption (in production, use actual HSM API)
        # This would perform hardware-based encryption
        key_material = hashlib.sha256(key.hsm_handle.encode()).digest()
        
        # Simple XOR encryption for simulation
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, key_material * (len(plaintext) // 32 + 1)))
        
        logger.debug(f"Encrypted {len(plaintext)} bytes with key {key_id}")
        return ciphertext
    
    def decrypt(self, key_id: str, ciphertext: bytes) -> Optional[bytes]:
        """Decrypt data using HSM key."""
        if not self.device.is_authenticated:
            logger.error("HSM not authenticated")
            return None
        
        if key_id not in self.keys:
            logger.error(f"Key {key_id} not found")
            return None
        
        key = self.keys[key_id]
        if KeyUsage.DECRYPTION not in key.usage:
            logger.error(f"Key {key_id} not authorized for decryption")
            return None
        
        if key.is_expired():
            logger.error(f"Key {key_id} is expired")
            return None
        
        # Simulated HSM decryption
        key_material = hashlib.sha256(key.hsm_handle.encode()).digest()
        
        # Simple XOR decryption for simulation
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, key_material * (len(ciphertext) // 32 + 1)))
        
        logger.debug(f"Decrypted {len(ciphertext)} bytes with key {key_id}")
        return plaintext
    
    def sign(self, key_id: str, data: bytes) -> Optional[bytes]:
        """Create digital signature using HSM key."""
        if not self.device.is_authenticated:
            logger.error("HSM not authenticated")
            return None
        
        if key_id not in self.keys:
            logger.error(f"Key {key_id} not found")
            return None
        
        key = self.keys[key_id]
        if KeyUsage.SIGNING not in key.usage:
            logger.error(f"Key {key_id} not authorized for signing")
            return None
        
        if key.is_expired():
            logger.error(f"Key {key_id} is expired")
            return None
        
        # Simulated HSM signing
        key_material = hashlib.sha256(key.hsm_handle.encode()).digest()
        data_hash = hashlib.sha256(data).digest()
        
        # Simulated signature
        signature = hashlib.sha256(key_material + data_hash).digest()
        
        logger.debug(f"Signed {len(data)} bytes with key {key_id}")
        return signature
    
    def verify(self, key_id: str, data: bytes, signature: bytes) -> bool:
        """Verify digital signature using HSM key."""
        if not self.device.is_authenticated:
            logger.error("HSM not authenticated")
            return False
        
        if key_id not in self.keys:
            logger.error(f"Key {key_id} not found")
            return False
        
        key = self.keys[key_id]
        if KeyUsage.VERIFICATION not in key.usage:
            logger.error(f"Key {key_id} not authorized for verification")
            return False
        
        # Simulated HSM verification
        key_material = hashlib.sha256(key.hsm_handle.encode()).digest()
        data_hash = hashlib.sha256(data).digest()
        
        # Simulated signature verification
        expected_signature = hashlib.sha256(key_material + data_hash).digest()
        
        is_valid = secrets.compare_digest(signature, expected_signature)
        logger.debug(f"Signature verification: {'valid' if is_valid else 'invalid'}")
        return is_valid
    
    def delete_key(self, key_id: str) -> bool:
        """Delete key from HSM."""
        if not self.device.is_authenticated:
            logger.error("HSM not authenticated")
            return False
        
        if key_id in self.keys:
            del self.keys[key_id]
            logger.info(f"Deleted key: {key_id}")
            return True
        
        return False
    
    def get_device_info(self) -> Dict[str, Any]:
        """Get HSM device information."""
        return {
            "device": self.device.to_dict(),
            "session_active": self.session_active,
            "key_count": len(self.keys),
            "max_keys": self.max_keys,
            "supported_algorithms": {k.value: v for k, v in self.supported_algorithms.items()}
        }


class HSMManager:
    """Hardware Security Module management system."""
    
    def __init__(self):
        self.devices: Dict[str, HSMInterface] = {}
        self.primary_hsm: Optional[str] = None
        
        # Initialize virtual HSM for development
        self._initialize_virtual_hsm()
    
    def _initialize_virtual_hsm(self):
        """Initialize virtual HSM for development/testing."""
        virtual_device = HSMDevice(
            device_id="virtual_hsm_001",
            device_type=HSMType.VIRTUAL_HSM,
            manufacturer="PlexiChat",
            model="Virtual HSM v1.0",
            firmware_version="1.0.0",
            serial_number="VHSM-001-DEV",
            capabilities=[
                "key_generation",
                "encryption",
                "decryption", 
                "signing",
                "verification",
                "key_management"
            ]
        )
        
        hsm_interface = HSMInterface(virtual_device)
        self.devices[virtual_device.device_id] = hsm_interface
        
        # Auto-authenticate virtual HSM
        hsm_interface.authenticate("123456")
        
        # Set as primary HSM
        self.primary_hsm = virtual_device.device_id
        
        logger.info("Initialized virtual HSM for development")
    
    def add_hsm_device(self, device: HSMDevice) -> bool:
        """Add HSM device to the system."""
        if device.device_id in self.devices:
            logger.error(f"HSM device {device.device_id} already exists")
            return False
        
        hsm_interface = HSMInterface(device)
        self.devices[device.device_id] = hsm_interface
        
        # Set as primary if it's the first real HSM
        if not self.primary_hsm or device.device_type != HSMType.VIRTUAL_HSM:
            self.primary_hsm = device.device_id
        
        logger.info(f"Added HSM device: {device.device_id}")
        return True
    
    def authenticate_hsm(self, device_id: str, pin: str, admin_pin: Optional[str] = None) -> bool:
        """Authenticate with specific HSM."""
        if device_id not in self.devices:
            logger.error(f"HSM device {device_id} not found")
            return False
        
        return self.devices[device_id].authenticate(pin, admin_pin)
    
    def generate_master_key(self, key_type: KeyType = KeyType.AES, 
                          key_size: int = 256) -> Optional[HSMKey]:
        """Generate master encryption key."""
        if not self.primary_hsm:
            logger.error("No primary HSM available")
            return None
        
        hsm = self.devices[self.primary_hsm]
        return hsm.generate_key(
            key_type=key_type,
            key_size=key_size,
            usage=[KeyUsage.ENCRYPTION, KeyUsage.DECRYPTION],
            expires_days=365
        )
    
    def generate_signing_key(self, key_type: KeyType = KeyType.ECDSA,
                           key_size: int = 256) -> Optional[HSMKey]:
        """Generate digital signing key."""
        if not self.primary_hsm:
            logger.error("No primary HSM available")
            return None
        
        hsm = self.devices[self.primary_hsm]
        return hsm.generate_key(
            key_type=key_type,
            key_size=key_size,
            usage=[KeyUsage.SIGNING, KeyUsage.VERIFICATION],
            expires_days=730  # 2 years
        )
    
    def encrypt_sensitive_data(self, data: str, key_id: Optional[str] = None) -> Optional[Dict[str, str]]:
        """Encrypt sensitive data using HSM."""
        if not self.primary_hsm:
            logger.error("No primary HSM available")
            return None
        
        hsm = self.devices[self.primary_hsm]
        
        # Use provided key or generate new one
        if not key_id:
            key = self.generate_master_key()
            if not key:
                return None
            key_id = key.key_id
        
        # Encrypt data
        plaintext = data.encode('utf-8')
        ciphertext = hsm.encrypt(key_id, plaintext)
        
        if ciphertext:
            return {
                "key_id": key_id,
                "ciphertext": ciphertext.hex(),
                "hsm_device": self.primary_hsm,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        return None
    
    def decrypt_sensitive_data(self, encrypted_package: Dict[str, str]) -> Optional[str]:
        """Decrypt sensitive data using HSM."""
        key_id = encrypted_package.get("key_id")
        ciphertext_hex = encrypted_package.get("ciphertext")
        hsm_device = encrypted_package.get("hsm_device")
        
        if not all([key_id, ciphertext_hex, hsm_device]):
            logger.error("Invalid encrypted package")
            return None
        
        if hsm_device not in self.devices:
            logger.error(f"HSM device {hsm_device} not available")
            return None
        
        hsm = self.devices[hsm_device]
        ciphertext = bytes.fromhex(ciphertext_hex)
        
        plaintext = hsm.decrypt(key_id, ciphertext)
        if plaintext:
            return plaintext.decode('utf-8')
        
        return None
    
    def create_digital_signature(self, data: str, key_id: Optional[str] = None) -> Optional[Dict[str, str]]:
        """Create digital signature using HSM."""
        if not self.primary_hsm:
            logger.error("No primary HSM available")
            return None
        
        hsm = self.devices[self.primary_hsm]
        
        # Use provided key or generate new one
        if not key_id:
            key = self.generate_signing_key()
            if not key:
                return None
            key_id = key.key_id
        
        # Sign data
        data_bytes = data.encode('utf-8')
        signature = hsm.sign(key_id, data_bytes)
        
        if signature:
            return {
                "key_id": key_id,
                "signature": signature.hex(),
                "hsm_device": self.primary_hsm,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        return None
    
    def verify_digital_signature(self, data: str, signature_package: Dict[str, str]) -> bool:
        """Verify digital signature using HSM."""
        key_id = signature_package.get("key_id")
        signature_hex = signature_package.get("signature")
        hsm_device = signature_package.get("hsm_device")
        
        if not all([key_id, signature_hex, hsm_device]):
            logger.error("Invalid signature package")
            return False
        
        if hsm_device not in self.devices:
            logger.error(f"HSM device {hsm_device} not available")
            return False
        
        hsm = self.devices[hsm_device]
        data_bytes = data.encode('utf-8')
        signature = bytes.fromhex(signature_hex)
        
        return hsm.verify(key_id, data_bytes, signature)
    
    def get_hsm_status(self) -> Dict[str, Any]:
        """Get comprehensive HSM system status."""
        device_status = {}
        total_keys = 0
        
        for device_id, hsm in self.devices.items():
            info = hsm.get_device_info()
            device_status[device_id] = info
            total_keys += info["key_count"]
        
        return {
            "hardware_security": {
                "total_devices": len(self.devices),
                "primary_hsm": self.primary_hsm,
                "total_keys": total_keys,
                "devices": device_status
            }
        }


# Global HSM manager
hsm_manager = HSMManager()
