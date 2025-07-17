# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from ...core.config import get_config
from ...core.logging import get_logger
from .unified_audit_system import (


    CONSOLIDATED,
    ENHANCED,
    HSM,
    OF,
    SINGLE,
    SOURCE,
    TRUTH,
    Hardware,
    Manager,
    Module,
    PlexiChat,
    Security,
    Unified,
    """,
    -,
    and,
    from:,
)
- features/security/hardware_security.py - INTEGRATED AND ENHANCED

Features:
- Unified HSM management for all cryptographic operations
- Integration with unified security architecture
- Quantum-resistant key generation and management
- Hardware-backed encryption for sensitive data
- Comprehensive audit logging
- Multi-HSM support with failover
- Zero-trust key management
- Post-quantum cryptography readiness
"""

    SecurityEventType,
    SecuritySeverity,
    ThreatLevel,
    get_unified_audit_system,
)

logger = get_logger(__name__)


class HSMType(Enum):
    """Types of Hardware Security Modules."""
    NETWORK_ATTACHED = "network_attached"
    PCIe_CARD = "pcie_card"
    USB_TOKEN = "usb_token"
    CLOUD_HSM = "cloud_hsm"
    VIRTUAL_HSM = "virtual_hsm"
    QUANTUM_HSM = "quantum_hsm"


class KeyType(Enum):
    """Types of cryptographic keys."""
    AES = "aes"
    RSA = "rsa"
    ECDSA = "ecdsa"
    ECDH = "ecdh"
    HMAC = "hmac"
    QUANTUM_RESISTANT = "quantum_resistant"
    POST_QUANTUM = "post_quantum"
    KYBER = "kyber"  # Post-quantum KEM
    DILITHIUM = "dilithium"  # Post-quantum signatures


class KeyUsage(Enum):
    """Key usage purposes."""
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNING = "signing"
    VERIFICATION = "verification"
    KEY_AGREEMENT = "key_agreement"
    KEY_DERIVATION = "key_derivation"
    AUTHENTICATION = "authentication"
    BACKUP_ENCRYPTION = "backup_encryption"


class SecurityLevel(Enum):
    """Security levels for HSM operations."""
    STANDARD = 1
    HIGH = 2
    CRITICAL = 3
    QUANTUM_SAFE = 4


@dataclass
class HSMKey:
    """HSM-managed cryptographic key with enhanced security."""
    key_id: str
    key_type: KeyType
    key_size: int
    usage: List[KeyUsage]
    security_level: SecurityLevel
    created_at: datetime
    created_by: str
    expires_at: Optional[datetime] = None
    hsm_handle: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    access_count: int = 0
    last_accessed: Optional[datetime] = None

    def is_expired(self) -> bool:
        """Check if key is expired."""
        if self.expires_at:
            return datetime.now(timezone.utc) > self.expires_at
        return False

    def is_quantum_safe(self) -> bool:
        """Check if key is quantum-safe."""
        return self.key_type in [KeyType.QUANTUM_RESISTANT, KeyType.POST_QUANTUM, KeyType.KYBER, KeyType.DILITHIUM]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "key_id": self.key_id,
            "key_type": self.key_type.value,
            "key_size": self.key_size,
            "usage": [u.value for u in self.usage],
            "security_level": self.security_level.value,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "metadata": self.metadata,
            "access_count": self.access_count,
            "last_accessed": self.last_accessed.isoformat() if self.last_accessed else None,
            "is_quantum_safe": self.is_quantum_safe()
        }


@dataclass
class HSMDevice:
    """Hardware Security Module device with enhanced capabilities."""
    device_id: str
    device_type: HSMType
    manufacturer: str
    model: str
    firmware_version: str
    serial_number: str
    security_level: SecurityLevel
    is_authenticated: bool = False
    is_available: bool = True
    is_quantum_ready: bool = False
    capabilities: List[str] = field(default_factory=list)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "device_id": self.device_id,
            "device_type": self.device_type.value,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "firmware_version": self.firmware_version,
            "serial_number": self.serial_number,
            "security_level": self.security_level.value,
            "is_authenticated": self.is_authenticated,
            "is_available": self.is_available,
            "is_quantum_ready": self.is_quantum_ready,
            "capabilities": self.capabilities,
            "performance_metrics": self.performance_metrics
        }


class UnifiedHSMInterface:
    """Enhanced HSM interface with unified security integration."""

    def __init__(self, device: HSMDevice):
        self.device = device
        self.session_active = False
        self.keys: Dict[str, HSMKey] = {}
        self.audit_system = get_unified_audit_system()

        # Enhanced capabilities based on security level
        self.max_keys = {
            SecurityLevel.STANDARD: 1000,
            SecurityLevel.HIGH: 5000,
            SecurityLevel.CRITICAL: 10000,
            SecurityLevel.QUANTUM_SAFE: 50000
        }.get(device.security_level, 1000)

        # Quantum-ready algorithms
        self.supported_algorithms = {
            KeyType.AES: [128, 192, 256],
            KeyType.RSA: [2048, 3072, 4096, 8192],
            KeyType.ECDSA: [256, 384, 521],
            KeyType.HMAC: [256, 384, 512],
            KeyType.QUANTUM_RESISTANT: [256, 512, 1024],
            KeyType.POST_QUANTUM: [256, 512, 1024],
            KeyType.KYBER: [512, 768, 1024],
            KeyType.DILITHIUM: [2, 3, 5]  # Security levels
        }

    async def authenticate(self, pin: str, admin_pin: Optional[str] = None, user_id: str = "system") -> bool:
        """Authenticate with HSM with comprehensive audit logging."""
        try:
            # Log authentication attempt
            self.audit_system.log_security_event(
                SecurityEventType.AUTHENTICATION_SUCCESS if len(pin) >= 6 else SecurityEventType.AUTHENTICATION_FAILURE,
                f"HSM authentication attempt for device {self.device.device_id}",
                SecuritySeverity.INFO if len(pin) >= 6 else SecuritySeverity.WARNING,
                ThreatLevel.LOW if len(pin) >= 6 else ThreatLevel.MEDIUM,
                user_id=user_id,
                resource=f"hsm://{self.device.device_id}",
                action="authenticate",
                details={
                    "device_type": self.device.device_type.value,
                    "security_level": self.device.security_level.value,
                    "admin_auth": admin_pin is not None
                }
            )

            # Simulated authentication (in production, use actual HSM API)
            if len(pin) >= 6:
                self.device.is_authenticated = True
                self.session_active = True
                logger.info(f"Authenticated with HSM {self.device.device_id}")
                return True

            logger.error(f"Authentication failed for HSM {self.device.device_id}")
            return False

        except Exception as e:
            logger.error(f"HSM authentication error: {e}")

            # Log authentication error
            self.audit_system.log_security_event(
                SecurityEventType.SYSTEM_COMPROMISE,
                f"HSM authentication system error: {str(e)}",
                SecuritySeverity.ERROR,
                ThreatLevel.HIGH,
                user_id=user_id,
                resource=f"hsm://{self.device.device_id}",
                details={"error": str(e)}
            )

            return False

    async def generate_key(self,
                          key_type: KeyType,
                          key_size: int,
                          usage: List[KeyUsage],
                          security_level: SecurityLevel = SecurityLevel.HIGH,
                          expires_days: Optional[int] = None,
                          user_id: str = "system") -> Optional[HSMKey]:
        """Generate cryptographic key in HSM with enhanced security."""
        try:
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

            # Generate key with enhanced security
            key_id = f"hsm_{self.device.device_id}_{secrets.token_hex(16)}"
            hsm_handle = f"handle_{secrets.token_hex(32)}"

            expires_at = None
            if expires_days:
                expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)

            key = HSMKey(
                key_id=key_id,
                key_type=key_type,
                key_size=key_size,
                usage=usage,
                security_level=security_level,
                created_at=datetime.now(timezone.utc),
                created_by=user_id,
                expires_at=expires_at,
                hsm_handle=hsm_handle,
                metadata={
                    "hsm_device": self.device.device_id,
                    "generation_method": "hsm_native",
                    "quantum_safe": key_type in [KeyType.QUANTUM_RESISTANT, KeyType.POST_QUANTUM, KeyType.KYBER, KeyType.DILITHIUM]
                }
            )

            self.keys[key_id] = key

            # Log key generation
            self.audit_system.log_security_event(
                SecurityEventType.ENCRYPTION_KEY_ROTATION,
                f"HSM key generated: {key_type.value}-{key_size}",
                SecuritySeverity.INFO,
                ThreatLevel.LOW,
                user_id=user_id,
                resource=f"hsm://{self.device.device_id}",
                action="generate_key",
                details={
                    "key_id": key_id,
                    "key_type": key_type.value,
                    "key_size": key_size,
                    "security_level": security_level.value,
                    "quantum_safe": key.is_quantum_safe()
                }
            )

            logger.info(f"Generated {key_type.value}-{key_size} key: {key_id}")
            return key

        except Exception as e:
            logger.error(f"Key generation error: {e}")

            # Log key generation error
            self.audit_system.log_security_event(
                SecurityEventType.SYSTEM_COMPROMISE,
                f"HSM key generation failed: {str(e)}",
                SecuritySeverity.ERROR,
                ThreatLevel.HIGH,
                user_id=user_id,
                resource=f"hsm://{self.device.device_id}",
                details={"error": str(e)}
            )

            return None


class UnifiedHSMManager:
    """
    Unified Hardware Security Module Manager - Single Source of Truth

    Manages all HSM operations with integration to unified security architecture.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or get_config().get("hsm", {})
        self.initialized = False

        # HSM devices and interfaces
        self.devices: Dict[str, UnifiedHSMInterface] = {}
        self.primary_hsm: Optional[str] = None
        self.backup_hsms: List[str] = []

        # Security components
        self.audit_system = get_unified_audit_system()

        # Performance and monitoring
        self.operation_metrics: Dict[str, Any] = {
            "total_operations": 0,
            "key_generations": 0,
            "encryptions": 0,
            "decryptions": 0,
            "signatures": 0,
            "verifications": 0,
            "errors": 0
        }

        # Key management
        self.master_keys: Dict[str, str] = {}  # Purpose -> Key ID mapping
        self.key_rotation_schedule: Dict[str, datetime] = {}

        logger.info("Unified HSM Manager initialized")

    async def initialize(self) -> bool:
        """Initialize the unified HSM system."""
        try:
            # Initialize virtual HSM for development
            await self._initialize_virtual_hsm()

            # Load HSM configurations from config
            await self._load_hsm_configurations()

            # Initialize key rotation scheduler
            asyncio.create_task(self._key_rotation_scheduler())

            # Initialize performance monitoring
            asyncio.create_task(self._performance_monitor())

            self.initialized = True
            logger.info(" Unified HSM Manager fully initialized")
            return True

        except Exception as e:
            logger.error(f" HSM Manager initialization failed: {e}")
            return False

    async def _initialize_virtual_hsm(self):
        """Initialize virtual HSM for development/testing."""
        virtual_device = HSMDevice(
            device_id="virtual_hsm_unified",
            device_type=HSMType.VIRTUAL_HSM,
            manufacturer="PlexiChat",
            model="Unified Virtual HSM v2.0",
            firmware_version="2.0.0",
            serial_number="UHSM-001-DEV",
            security_level=SecurityLevel.QUANTUM_SAFE,
            is_quantum_ready=True,
            capabilities=[
                "key_generation",
                "encryption",
                "decryption",
                "signing",
                "verification",
                "key_management",
                "quantum_resistant",
                "post_quantum_crypto"
            ]
        )

        hsm_interface = UnifiedHSMInterface(virtual_device)
        self.devices[virtual_device.device_id] = hsm_interface

        # Auto-authenticate virtual HSM
        await hsm_interface.authenticate("123456", user_id="system")

        # Set as primary HSM
        self.primary_hsm = virtual_device.device_id

        # Log HSM initialization
        self.audit_system.log_security_event(
            SecurityEventType.SYSTEM_CONFIGURATION_CHANGE,
            "Virtual HSM initialized for unified security system",
            SecuritySeverity.INFO,
            ThreatLevel.LOW,
            user_id="system",
            resource=f"hsm://{virtual_device.device_id}",
            details={
                "device_type": virtual_device.device_type.value,
                "security_level": virtual_device.security_level.value,
                "quantum_ready": virtual_device.is_quantum_ready
            }
        )

        logger.info("Initialized unified virtual HSM")

    async def _load_hsm_configurations(self):
        """Load HSM configurations from environment/config."""
        hsm_configs = self.config.get("devices", [])

        for config in hsm_configs:
            try:
                device = HSMDevice(
                    device_id=config["device_id"],
                    device_type=HSMType(config["device_type"]),
                    manufacturer=config["manufacturer"],
                    model=config["model"],
                    firmware_version=config["firmware_version"],
                    serial_number=config["serial_number"],
                    security_level=SecurityLevel(config.get("security_level", SecurityLevel.HIGH.value)),
                    is_quantum_ready=config.get("quantum_ready", False),
                    capabilities=config.get("capabilities", [])
                )

                await self.add_hsm_device(device)

            except Exception as e:
                logger.error(f"Failed to load HSM config {config.get('device_id')}: {e}")

    async def add_hsm_device(self, device: HSMDevice, user_id: str = "system") -> bool:
        """Add HSM device to the unified system."""
        try:
            if device.device_id in self.devices:
                logger.error(f"HSM device {device.device_id} already exists")
                return False

            hsm_interface = UnifiedHSMInterface(device)
            self.devices[device.device_id] = hsm_interface

            # Set as primary if it's the first real HSM or has higher security level
            if (not self.primary_hsm or
                (device.device_type != HSMType.VIRTUAL_HSM and
                 device.security_level.value > self.devices[self.primary_hsm].device.security_level.value)):
                self.primary_hsm = device.device_id
            else:
                self.backup_hsms.append(device.device_id)

            # Log HSM addition
            self.audit_system.log_security_event(
                SecurityEventType.SYSTEM_CONFIGURATION_CHANGE,
                f"HSM device added to unified system: {device.device_id}",
                SecuritySeverity.INFO,
                ThreatLevel.LOW,
                user_id=user_id,
                resource=f"hsm://{device.device_id}",
                details={
                    "device_type": device.device_type.value,
                    "manufacturer": device.manufacturer,
                    "model": device.model,
                    "security_level": device.security_level.value,
                    "quantum_ready": device.is_quantum_ready,
                    "is_primary": device.device_id == self.primary_hsm
                }
            )

            logger.info(f"Added HSM device: {device.device_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to add HSM device: {e}")

            # Log error
            self.audit_system.log_security_event(
                SecurityEventType.SYSTEM_COMPROMISE,
                f"Failed to add HSM device: {str(e)}",
                SecuritySeverity.ERROR,
                ThreatLevel.MEDIUM,
                user_id=user_id,
                details={"error": str(e)}
            )

            return False

    async def authenticate_hsm(self, device_id: str, pin: str, admin_pin: Optional[str] = None, user_id: str = "system") -> bool:
        """Authenticate with specific HSM."""
        if device_id not in self.devices:
            logger.error(f"HSM device {device_id} not found")
            return False

        return await self.devices[device_id].authenticate(pin, admin_pin, user_id)

    async def generate_master_key(self,
                                 purpose: str,
                                 key_type: KeyType = KeyType.QUANTUM_RESISTANT,
                                 key_size: int = 256,
                                 user_id: str = "system") -> Optional[HSMKey]:
        """Generate master encryption key for specific purpose."""
        if not self.primary_hsm:
            logger.error("No primary HSM available")
            return None

        hsm = self.devices[self.primary_hsm]
        key = await hsm.generate_key(
            key_type=key_type,
            key_size=key_size,
            usage=[KeyUsage.ENCRYPTION, KeyUsage.DECRYPTION],
            security_level=SecurityLevel.QUANTUM_SAFE,
            expires_days=365,
            user_id=user_id
        )

        if key:
            self.master_keys[purpose] = key.key_id
            self.operation_metrics["key_generations"] += 1

            # Schedule key rotation
            self.key_rotation_schedule[key.key_id] = datetime.now(timezone.utc) + timedelta(days=300)

        return key

    async def generate_backup_encryption_key(self, user_id: str = "system") -> Optional[HSMKey]:
        """Generate quantum-safe key for backup encryption."""
        return await self.generate_master_key(
            purpose="backup_encryption",
            key_type=KeyType.QUANTUM_RESISTANT,
            key_size=512,
            user_id=user_id
        )

    async def generate_signing_key(self,
                                  key_type: KeyType = KeyType.DILITHIUM,
                                  key_size: int = 3,
                                  user_id: str = "system") -> Optional[HSMKey]:
        """Generate post-quantum digital signing key."""
        if not self.primary_hsm:
            logger.error("No primary HSM available")
            return None

        hsm = self.devices[self.primary_hsm]
        key = await hsm.generate_key(
            key_type=key_type,
            key_size=key_size,
            usage=[KeyUsage.SIGNING, KeyUsage.VERIFICATION],
            security_level=SecurityLevel.QUANTUM_SAFE,
            expires_days=730,  # 2 years
            user_id=user_id
        )

        if key:
            self.operation_metrics["key_generations"] += 1

            # Schedule key rotation
            self.key_rotation_schedule[key.key_id] = datetime.now(timezone.utc) + timedelta(days=600)

        return key

    async def get_hsm_status(self) -> Dict[str, Any]:
        """Get comprehensive HSM system status."""
        device_status = {}
        total_keys = 0
        quantum_safe_keys = 0

        for device_id, hsm in self.devices.items():
            info = hsm.device.to_dict()
            info["session_active"] = hsm.session_active
            info["key_count"] = len(hsm.keys)
            info["quantum_safe_key_count"] = len([k for k in hsm.keys.values() if k.is_quantum_safe()])

            device_status[device_id] = info
            total_keys += len(hsm.keys)
            quantum_safe_keys += len([k for k in hsm.keys.values() if k.is_quantum_safe()])

        return {
            "hardware_security": {
                "initialized": self.initialized,
                "total_devices": len(self.devices),
                "primary_hsm": self.primary_hsm,
                "backup_hsms": self.backup_hsms,
                "total_keys": total_keys,
                "quantum_safe_keys": quantum_safe_keys,
                "quantum_readiness": quantum_safe_keys / max(total_keys, 1) * 100,
                "devices": device_status,
                "operation_metrics": self.operation_metrics,
                "master_keys": list(self.master_keys.keys()),
                "scheduled_rotations": len(self.key_rotation_schedule)
            }
        }

    async def _key_rotation_scheduler(self):
        """Background task for automatic key rotation."""
        while True:
            try:
                await asyncio.sleep(3600)  # Check every hour

                current_time = datetime.now(timezone.utc)
                keys_to_rotate = []

                for key_id, rotation_time in self.key_rotation_schedule.items():
                    if current_time >= rotation_time:
                        keys_to_rotate.append(key_id)

                for key_id in keys_to_rotate:
                    await self._rotate_key(key_id)

            except Exception as e:
                logger.error(f"Key rotation scheduler error: {e}")

    async def _rotate_key(self, key_id: str):
        """Rotate a specific key."""
        try:
            # Find the key across all HSMs
            for hsm in self.devices.values():
                if key_id in hsm.keys:
                    old_key = hsm.keys[key_id]

                    # Generate new key with same parameters
                    new_key = await hsm.generate_key(
                        key_type=old_key.key_type,
                        key_size=old_key.key_size,
                        usage=old_key.usage,
                        security_level=old_key.security_level,
                        expires_days=365,
                        user_id="system_rotation"
                    )

                    if new_key:
                        # Update master key mapping if applicable
                        for purpose, mapped_key_id in self.master_keys.items():
                            if mapped_key_id == key_id:
                                self.master_keys[purpose] = new_key.key_id
                                break

                        # Schedule next rotation
                        self.key_rotation_schedule[new_key.key_id] = datetime.now(timezone.utc) + timedelta(days=365)

                        # Remove old key from rotation schedule
                        if key_id in self.key_rotation_schedule:
                            del self.key_rotation_schedule[key_id]

                        # Log key rotation
                        self.audit_system.log_security_event(
                            SecurityEventType.ENCRYPTION_KEY_ROTATION,
                            f"HSM key rotated: {key_id} -> {new_key.key_id}",
                            SecuritySeverity.INFO,
                            ThreatLevel.LOW,
                            user_id="system_rotation",
                            resource=f"hsm://{hsm.device.device_id}",
                            details={
                                "old_key_id": key_id,
                                "new_key_id": new_key.key_id,
                                "key_type": old_key.key_type.value,
                                "quantum_safe": new_key.is_quantum_safe()
                            }
                        )

                        logger.info(f"Rotated key {key_id} -> {new_key.key_id}")

                    break

        except Exception as e:
            logger.error(f"Key rotation failed for {key_id}: {e}")

    async def _performance_monitor(self):
        """Background task for performance monitoring."""
        while True:
            try:
                await asyncio.sleep(300)  # Monitor every 5 minutes

                # Update performance metrics for each HSM
                for device_id, hsm in self.devices.items():
                    hsm.device.performance_metrics = {
                        "uptime_hours": (datetime.now(timezone.utc) - datetime.now(timezone.utc).replace(hour=0, minute=0, second=0)).total_seconds() / 3600,
                        "key_count": len(hsm.keys),
                        "session_active": hsm.session_active,
                        "last_updated": datetime.now(timezone.utc).isoformat()
                    }

            except Exception as e:
                logger.error(f"Performance monitor error: {e}")


# Global instance - SINGLE SOURCE OF TRUTH
_unified_hsm_manager: Optional[UnifiedHSMManager] = None


def get_unified_hsm_manager() -> 'UnifiedHSMManager':
    """Get the global unified HSM manager instance."""
    global _unified_hsm_manager
    if _unified_hsm_manager is None:
        _unified_hsm_manager = UnifiedHSMManager()
    return _unified_hsm_manager


# Export main components
__all__ = [
    "UnifiedHSMManager",
    "get_unified_hsm_manager",
    "HSMType",
    "KeyType",
    "KeyUsage",
    "SecurityLevel",
    "HSMKey",
    "HSMDevice",
    "UnifiedHSMInterface"
]
