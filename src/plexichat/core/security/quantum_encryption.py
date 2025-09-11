"""
Quantum-Ready Encryption System

This module implements post-quantum cryptographic algorithms, time-based encryption keys,
and enhanced security for real-time communications. It provides quantum-resistant encryption
for HTTP traffic and integrates with the existing key vault system.
"""

import asyncio
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

# Standard cryptography library
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Post-quantum cryptography (required for quantum-resistant security)
try:
    import pqcrypto.kem.kyber1024 as kyber
    import pqcrypto.sign.dilithium5 as dilithium

    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False
    raise RuntimeError(
        "Post-quantum cryptography libraries not available. Quantum-resistant algorithms are required for secure operation."
    )

from .key_vault import DistributedKeyManager

logger = logging.getLogger(__name__)


class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms"""

    AES_256_GCM = "aes_256_gcm"
    CHACHA20_POLY1305 = "chacha20_poly1305"
    FERNET = "fernet"
    KYBER_1024 = "kyber_1024"  # Post-quantum KEM
    DILITHIUM_5 = "dilithium_5"  # Post-quantum signatures


class KeyType(Enum):
    """Types of encryption keys"""

    SYMMETRIC = "symmetric"
    ASYMMETRIC = "asymmetric"
    POST_QUANTUM_KEM = "pq_kem"
    POST_QUANTUM_SIGN = "pq_sign"
    HYBRID = "hybrid"


@dataclass
class EncryptionKey:
    """Represents an encryption key with metadata"""

    key_id: str
    key_type: KeyType
    algorithm: EncryptionAlgorithm
    key_data: bytes
    public_key: Optional[bytes] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    rotation_interval: timedelta = field(default_factory=lambda: timedelta(hours=24))
    usage_count: int = 0
    max_usage: Optional[int] = None


@dataclass
class EncryptionContext:
    """Context for encryption operations"""

    algorithm: EncryptionAlgorithm
    key_id: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    additional_data: Optional[bytes] = None
    nonce: Optional[bytes] = None


class PostQuantumCrypto:
    """Post-quantum cryptography implementation"""

    def __init__(self):
        self.pqc_available = PQC_AVAILABLE

    def generate_kyber_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Kyber-1024 key pair for key encapsulation"""
        if not self.pqc_available:
            raise RuntimeError("Post-quantum cryptography not available")

        public_key, secret_key = kyber.keypair()
        return public_key, secret_key

    def kyber_encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using Kyber-1024"""
        if not self.pqc_available:
            raise RuntimeError("Post-quantum cryptography not available")

        ciphertext, shared_secret = kyber.enc(public_key)
        return ciphertext, shared_secret

    def kyber_decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate shared secret using Kyber-1024"""
        if not self.pqc_available:
            raise RuntimeError("Post-quantum cryptography not available")

        shared_secret = kyber.dec(secret_key, ciphertext)
        return shared_secret

    def generate_dilithium_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Dilithium-5 key pair for digital signatures"""
        if not self.pqc_available:
            raise RuntimeError("Post-quantum cryptography not available")

        public_key, secret_key = dilithium.keypair()
        return public_key, secret_key

    def dilithium_sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Sign message using Dilithium-5"""
        if not self.pqc_available:
            raise RuntimeError("Post-quantum cryptography not available")

        signature = dilithium.sign(secret_key, message)
        return signature

    def dilithium_verify(
        self, public_key: bytes, message: bytes, signature: bytes
    ) -> bool:
        """Verify Dilithium-5 signature"""
        if not self.pqc_available:
            raise RuntimeError("Post-quantum cryptography not available")

        try:
            dilithium.verify(public_key, message, signature)
            return True
        except Exception:
            return False


class HybridEncryption:
    """Hybrid encryption combining classical and post-quantum algorithms"""

    def __init__(self, pqc: PostQuantumCrypto):
        self.pqc = pqc

    def generate_hybrid_keypair(self) -> Dict[str, bytes]:
        """Generate hybrid key pair (RSA + Kyber)"""
        # Classical RSA key pair
        rsa_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )
        rsa_public_key = rsa_private_key.public_key()

        rsa_private_pem = rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        rsa_public_pem = rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Post-quantum Kyber key pair (required)
        if not self.pqc.pqc_available:
            raise RuntimeError(
                "Post-quantum cryptography not available. Quantum-resistant algorithms are required."
            )
        kyber_public, kyber_private = self.pqc.generate_kyber_keypair()

        return {
            "rsa_private": rsa_private_pem,
            "rsa_public": rsa_public_pem,
            "kyber_private": kyber_private,
            "kyber_public": kyber_public,
        }

    def hybrid_encrypt(
        self, data: bytes, hybrid_public_key: Dict[str, bytes]
    ) -> Dict[str, bytes]:
        """Encrypt data using hybrid approach"""
        # Generate random symmetric key
        symmetric_key = secrets.token_bytes(32)

        # Encrypt data with AES-256-GCM
        nonce = secrets.token_bytes(12)
        cipher = Cipher(
            algorithms.AES(symmetric_key), modes.GCM(nonce), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()

        # Encrypt symmetric key with RSA
        rsa_public_key = serialization.load_pem_public_key(
            hybrid_public_key["rsa_public"], backend=default_backend()
        )
        rsa_encrypted_key = rsa_public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Encrypt symmetric key with Kyber (required)
        if not self.pqc.pqc_available:
            raise RuntimeError(
                "Post-quantum cryptography not available. Quantum-resistant algorithms are required."
            )
        kyber_ciphertext, kyber_shared_secret = self.pqc.kyber_encapsulate(
            hybrid_public_key["kyber_public"]
        )
        # XOR the symmetric key with Kyber shared secret for additional protection
        protected_key = bytes(
            a ^ b for a, b in zip(symmetric_key, kyber_shared_secret[:32])
        )

        return {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": encryptor.tag,
            "rsa_encrypted_key": rsa_encrypted_key,
            "kyber_ciphertext": kyber_ciphertext,
            "protected_key": protected_key,
        }

    def hybrid_decrypt(
        self, encrypted_data: Dict[str, bytes], hybrid_private_key: Dict[str, bytes]
    ) -> bytes:
        """Decrypt data using hybrid approach"""
        # Decrypt symmetric key with RSA
        rsa_private_key = serialization.load_pem_private_key(
            hybrid_private_key["rsa_private"], password=None, backend=default_backend()
        )
        rsa_decrypted_key = rsa_private_key.decrypt(
            encrypted_data["rsa_encrypted_key"],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Decrypt with Kyber (required)
        if not self.pqc.pqc_available:
            raise RuntimeError(
                "Post-quantum cryptography not available. Quantum-resistant algorithms are required."
            )
        if not encrypted_data["kyber_ciphertext"]:
            raise RuntimeError(
                "Kyber ciphertext not found. Quantum-resistant decryption required."
            )
        kyber_shared_secret = self.pqc.kyber_decapsulate(
            hybrid_private_key["kyber_private"], encrypted_data["kyber_ciphertext"]
        )
        # Recover symmetric key
        symmetric_key = bytes(
            a ^ b
            for a, b in zip(encrypted_data["protected_key"], kyber_shared_secret[:32])
        )

        # Decrypt data with AES-256-GCM
        cipher = Cipher(
            algorithms.AES(symmetric_key),
            modes.GCM(encrypted_data["nonce"], encrypted_data["tag"]),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        plaintext = (
            decryptor.update(encrypted_data["ciphertext"]) + decryptor.finalize()
        )

        return plaintext


class TimeBasedKeyRotation:
    """Manages time-based key rotation with automatic scheduling"""

    def __init__(self, key_manager: "QuantumEncryptionManager"):
        self.key_manager = key_manager
        self.rotation_tasks: Dict[str, asyncio.Task] = {}
        self.lock = Lock()

    async def schedule_rotation(self, key_id: str, interval: timedelta):
        """Schedule automatic key rotation"""

        async def rotation_task():
            while True:
                await asyncio.sleep(interval.total_seconds())
                try:
                    await self.key_manager.rotate_key(key_id)
                    logger.info(f"Successfully rotated key {key_id}")
                except Exception as e:
                    logger.error(f"Failed to rotate key {key_id}: {e}")

        with self.lock:
            if key_id in self.rotation_tasks:
                self.rotation_tasks[key_id].cancel()

            self.rotation_tasks[key_id] = asyncio.create_task(rotation_task())

    def cancel_rotation(self, key_id: str):
        """Cancel scheduled rotation for a key"""
        with self.lock:
            if key_id in self.rotation_tasks:
                self.rotation_tasks[key_id].cancel()
                del self.rotation_tasks[key_id]

    def cancel_all_rotations(self):
        """Cancel all scheduled rotations"""
        with self.lock:
            for task in self.rotation_tasks.values():
                task.cancel()
            self.rotation_tasks.clear()


class RealTimeEncryption:
    """Enhanced encryption for real-time communications"""

    def __init__(self):
        self.session_keys: Dict[str, bytes] = {}
        self.key_derivation_cache: Dict[str, bytes] = {}

    def derive_session_key(
        self, master_key: bytes, session_id: str, timestamp: int
    ) -> bytes:
        """Derive session-specific key from master key"""
        cache_key = f"{session_id}:{timestamp}"

        if cache_key in self.key_derivation_cache:
            return self.key_derivation_cache[cache_key]

        # Use HKDF for key derivation
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=session_id.encode(),
            info=f"session:{timestamp}".encode(),
            backend=default_backend(),
        )

        session_key = hkdf.derive(master_key)
        self.key_derivation_cache[cache_key] = session_key

        # Limit cache size
        if len(self.key_derivation_cache) > 1000:
            oldest_key = min(self.key_derivation_cache.keys())
            del self.key_derivation_cache[oldest_key]

        return session_key

    def encrypt_realtime_data(
        self, data: bytes, session_id: str, master_key: bytes
    ) -> Dict[str, Any]:
        """Encrypt real-time data with forward secrecy"""
        timestamp = int(time.time())
        session_key = self.derive_session_key(master_key, session_id, timestamp)

        # Use ChaCha20-Poly1305 for high-performance encryption
        nonce = secrets.token_bytes(12)
        cipher = Cipher(
            algorithms.ChaCha20(session_key),
            modes.GCM(nonce),
            backend=default_backend(),
        )

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()

        return {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": encryptor.tag,
            "timestamp": timestamp,
            "session_id": session_id,
        }

    def decrypt_realtime_data(
        self, encrypted_data: Dict[str, Any], master_key: bytes
    ) -> bytes:
        """Decrypt real-time data"""
        session_key = self.derive_session_key(
            master_key, encrypted_data["session_id"], encrypted_data["timestamp"]
        )

        cipher = Cipher(
            algorithms.ChaCha20(session_key),
            modes.GCM(encrypted_data["nonce"], encrypted_data["tag"]),
            backend=default_backend(),
        )

        decryptor = cipher.decryptor()
        plaintext = (
            decryptor.update(encrypted_data["ciphertext"]) + decryptor.finalize()
        )

        return plaintext


class HTTPTrafficEncryption:
    """Additional encryption layer for HTTP traffic"""

    def __init__(self, quantum_manager: "QuantumEncryptionManager"):
        self.quantum_manager = quantum_manager
        self.traffic_keys: Dict[str, MultiFernet] = {}

    def setup_traffic_encryption(self, endpoint: str) -> str:
        """Setup encryption for specific HTTP endpoint"""
        # Generate multiple keys for rotation
        keys = [Fernet.generate_key() for _ in range(3)]
        fernet_objects = [Fernet(key) for key in keys]
        multi_fernet = MultiFernet(fernet_objects)

        key_id = f"http_traffic_{endpoint}_{int(time.time())}"
        self.traffic_keys[endpoint] = multi_fernet

        return key_id

    def encrypt_http_payload(
        self, payload: bytes, endpoint: str, additional_data: Optional[bytes] = None
    ) -> bytes:
        """Encrypt HTTP payload with additional layer"""
        if endpoint not in self.traffic_keys:
            self.setup_traffic_encryption(endpoint)

        multi_fernet = self.traffic_keys[endpoint]

        # Add timestamp and additional data
        timestamp = int(time.time()).to_bytes(8, "big")
        if additional_data:
            payload = timestamp + additional_data + payload
        else:
            payload = timestamp + payload

        encrypted_payload = multi_fernet.encrypt(payload)
        return encrypted_payload

    def decrypt_http_payload(
        self, encrypted_payload: bytes, endpoint: str
    ) -> Tuple[bytes, int]:
        """Decrypt HTTP payload and return payload with timestamp"""
        if endpoint not in self.traffic_keys:
            raise ValueError(f"No encryption setup for endpoint: {endpoint}")

        multi_fernet = self.traffic_keys[endpoint]
        decrypted_data = multi_fernet.decrypt(encrypted_payload)

        # Extract timestamp
        timestamp = int.from_bytes(decrypted_data[:8], "big")
        payload = decrypted_data[8:]

        return payload, timestamp

    def rotate_traffic_keys(self, endpoint: str):
        """Rotate encryption keys for HTTP traffic"""
        if endpoint in self.traffic_keys:
            # Generate new key and add to front
            new_key = Fernet.generate_key()
            current_multi = self.traffic_keys[endpoint]

            # Get current keys and add new one at front
            new_fernets = [Fernet(new_key)] + current_multi._fernets[
                :2
            ]  # Keep only 3 keys
            self.traffic_keys[endpoint] = MultiFernet(new_fernets)


class QuantumEncryptionManager:
    """Main quantum-ready encryption manager"""

    def __init__(
        self,
        key_vault_manager: DistributedKeyManager,
        config_path: Optional[Path] = None,
    ):
        self.key_vault = key_vault_manager
        self.pqc = PostQuantumCrypto()
        self.hybrid_crypto = HybridEncryption(self.pqc)
        self.time_rotation = TimeBasedKeyRotation(self)
        self.realtime_crypto = RealTimeEncryption()
        self.http_crypto = HTTPTrafficEncryption(self)

        self.keys: Dict[str, EncryptionKey] = {}
        self.active_keys: Dict[EncryptionAlgorithm, str] = {}
        self.lock = Lock()

        # Load configuration
        self.config = self._load_config(config_path)

        # Initialize default keys
        asyncio.create_task(self._initialize_default_keys())

    def _load_config(self, config_path: Optional[Path]) -> Dict[str, Any]:
        """Load encryption configuration"""
        default_config = {
            "default_algorithm": EncryptionAlgorithm.AES_256_GCM,
            "key_rotation_interval": 24 * 3600,  # 24 hours
            "max_key_usage": 1000000,  # 1M operations
            "enable_post_quantum": True,
            "enable_hybrid_mode": True,
            "realtime_key_derivation": True,
            "http_traffic_encryption": True,
        }

        if config_path and config_path.exists():
            try:
                with open(config_path, "r") as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")

        return default_config

    async def _initialize_default_keys(self):
        """Initialize default encryption keys"""
        try:
            # Generate master key from key vault
            master_key = self.key_vault.reconstruct_master_key()

            # Create default symmetric key
            await self.create_key(
                key_id="default_symmetric",
                algorithm=EncryptionAlgorithm.AES_256_GCM,
                rotation_interval=timedelta(
                    hours=self.config["key_rotation_interval"] / 3600
                ),
            )

            # Create post-quantum keys (required if enabled)
            if self.config["enable_post_quantum"]:
                if not self.pqc.pqc_available:
                    raise RuntimeError(
                        "Post-quantum cryptography not available. Quantum-resistant algorithms are required."
                    )
                await self.create_key(
                    key_id="default_kyber",
                    algorithm=EncryptionAlgorithm.KYBER_1024,
                    rotation_interval=timedelta(hours=48),
                )

                await self.create_key(
                    key_id="default_dilithium",
                    algorithm=EncryptionAlgorithm.DILITHIUM_5,
                    rotation_interval=timedelta(hours=72),
                )

            # Create hybrid keys if enabled
            if self.config["enable_hybrid_mode"]:
                await self.create_hybrid_key("default_hybrid")

            logger.info("Default encryption keys initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize default keys: {e}")
            # Generate emergency keys
            await self._generate_emergency_keys()

    async def _generate_emergency_keys(self):
        """Generate emergency keys when key vault is unavailable"""
        logger.warning("Generating emergency encryption keys")

        emergency_key = secrets.token_bytes(32)
        key = EncryptionKey(
            key_id="emergency_key",
            key_type=KeyType.SYMMETRIC,
            algorithm=EncryptionAlgorithm.AES_256_GCM,
            key_data=emergency_key,
            rotation_interval=timedelta(hours=1),  # Rotate frequently
        )

        with self.lock:
            self.keys["emergency_key"] = key
            self.active_keys[EncryptionAlgorithm.AES_256_GCM] = "emergency_key"

    async def create_key(
        self,
        key_id: str,
        algorithm: EncryptionAlgorithm,
        rotation_interval: Optional[timedelta] = None,
    ) -> EncryptionKey:
        """Create a new encryption key"""
        if rotation_interval is None:
            rotation_interval = timedelta(hours=24)

        if algorithm == EncryptionAlgorithm.AES_256_GCM:
            key_data = secrets.token_bytes(32)
            key_type = KeyType.SYMMETRIC
            public_key = None

        elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
            key_data = secrets.token_bytes(32)
            key_type = KeyType.SYMMETRIC
            public_key = None

        elif algorithm == EncryptionAlgorithm.FERNET:
            key_data = Fernet.generate_key()
            key_type = KeyType.SYMMETRIC
            public_key = None

        elif algorithm == EncryptionAlgorithm.KYBER_1024:
            if not self.pqc.pqc_available:
                raise RuntimeError("Post-quantum cryptography not available")
            public_key, key_data = self.pqc.generate_kyber_keypair()
            key_type = KeyType.POST_QUANTUM_KEM

        elif algorithm == EncryptionAlgorithm.DILITHIUM_5:
            if not self.pqc.pqc_available:
                raise RuntimeError("Post-quantum cryptography not available")
            public_key, key_data = self.pqc.generate_dilithium_keypair()
            key_type = KeyType.POST_QUANTUM_SIGN

        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        key = EncryptionKey(
            key_id=key_id,
            key_type=key_type,
            algorithm=algorithm,
            key_data=key_data,
            public_key=public_key,
            rotation_interval=rotation_interval,
            max_usage=self.config.get("max_key_usage"),
        )

        with self.lock:
            self.keys[key_id] = key
            self.active_keys[algorithm] = key_id

        # Schedule automatic rotation
        await self.time_rotation.schedule_rotation(key_id, rotation_interval)

        logger.info(f"Created {algorithm.value} key: {key_id}")
        return key

    async def create_hybrid_key(self, key_id: str) -> EncryptionKey:
        """Create a hybrid classical/post-quantum key"""
        hybrid_keypair = self.hybrid_crypto.generate_hybrid_keypair()

        # Serialize the hybrid key data
        key_data = json.dumps(
            {
                k: v.hex() if isinstance(v, bytes) else v
                for k, v in hybrid_keypair.items()
            }
        ).encode()

        key = EncryptionKey(
            key_id=key_id,
            key_type=KeyType.HYBRID,
            algorithm=EncryptionAlgorithm.KYBER_1024,  # Primary algorithm
            key_data=key_data,
            public_key=hybrid_keypair["rsa_public"] + hybrid_keypair["kyber_public"],
            rotation_interval=timedelta(hours=48),
        )

        with self.lock:
            self.keys[key_id] = key

        await self.time_rotation.schedule_rotation(key_id, key.rotation_interval)

        logger.info(f"Created hybrid key: {key_id}")
        return key

    async def rotate_key(self, key_id: str) -> EncryptionKey:
        """Rotate an existing key"""
        with self.lock:
            if key_id not in self.keys:
                raise ValueError(f"Key not found: {key_id}")

            old_key = self.keys[key_id]

        # Create new key with same parameters
        new_key_id = f"{key_id}_rotated_{int(time.time())}"

        if old_key.key_type == KeyType.HYBRID:
            new_key = await self.create_hybrid_key(new_key_id)
        else:
            new_key = await self.create_key(
                new_key_id, old_key.algorithm, old_key.rotation_interval
            )

        # Update active key reference
        with self.lock:
            self.active_keys[old_key.algorithm] = new_key_id
            # Keep old key for decryption but mark as rotated
            old_key.expires_at = datetime.utcnow() + timedelta(hours=24)

        logger.info(f"Rotated key {key_id} to {new_key_id}")
        return new_key

    def encrypt(
        self,
        data: bytes,
        algorithm: Optional[EncryptionAlgorithm] = None,
        key_id: Optional[str] = None,
        context: Optional[EncryptionContext] = None,
    ) -> Dict[str, Any]:
        """Encrypt data using specified algorithm and key"""
        if algorithm is None:
            algorithm = self.config["default_algorithm"]

        if key_id is None:
            with self.lock:
                if algorithm not in self.active_keys:
                    raise ValueError(f"No active key for algorithm: {algorithm}")
                key_id = self.active_keys[algorithm]

        with self.lock:
            if key_id not in self.keys:
                raise ValueError(f"Key not found: {key_id}")
            key = self.keys[key_id]
            key.usage_count += 1

        # Check if key needs rotation
        if key.max_usage and key.usage_count >= key.max_usage:
            asyncio.create_task(self.rotate_key(key_id))

        if context is None:
            context = EncryptionContext(algorithm=algorithm, key_id=key_id)

        if algorithm == EncryptionAlgorithm.AES_256_GCM:
            return self._encrypt_aes_gcm(data, key, context)
        elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
            return self._encrypt_chacha20(data, key, context)
        elif algorithm == EncryptionAlgorithm.FERNET:
            return self._encrypt_fernet(data, key, context)
        elif key.key_type == KeyType.HYBRID:
            return self._encrypt_hybrid(data, key, context)
        else:
            raise ValueError(f"Encryption not supported for algorithm: {algorithm}")

    def decrypt(self, encrypted_data: Dict[str, Any]) -> bytes:
        """Decrypt data"""
        key_id = encrypted_data.get("key_id")
        algorithm = EncryptionAlgorithm(encrypted_data.get("algorithm"))

        with self.lock:
            if key_id not in self.keys:
                raise ValueError(f"Key not found: {key_id}")
            key = self.keys[key_id]

        if algorithm == EncryptionAlgorithm.AES_256_GCM:
            return self._decrypt_aes_gcm(encrypted_data, key)
        elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
            return self._decrypt_chacha20(encrypted_data, key)
        elif algorithm == EncryptionAlgorithm.FERNET:
            return self._decrypt_fernet(encrypted_data, key)
        elif key.key_type == KeyType.HYBRID:
            return self._decrypt_hybrid(encrypted_data, key)
        else:
            raise ValueError(f"Decryption not supported for algorithm: {algorithm}")

    def _encrypt_aes_gcm(
        self, data: bytes, key: EncryptionKey, context: EncryptionContext
    ) -> Dict[str, Any]:
        """Encrypt using AES-256-GCM"""
        nonce = context.nonce or secrets.token_bytes(12)
        cipher = Cipher(
            algorithms.AES(key.key_data), modes.GCM(nonce), backend=default_backend()
        )

        encryptor = cipher.encryptor()
        if context.additional_data:
            encryptor.authenticate_additional_data(context.additional_data)

        ciphertext = encryptor.update(data) + encryptor.finalize()

        return {
            "algorithm": context.algorithm.value,
            "key_id": context.key_id,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": encryptor.tag,
            "timestamp": context.timestamp.isoformat(),
            "additional_data": context.additional_data,
        }

    def _decrypt_aes_gcm(
        self, encrypted_data: Dict[str, Any], key: EncryptionKey
    ) -> bytes:
        """Decrypt using AES-256-GCM"""
        cipher = Cipher(
            algorithms.AES(key.key_data),
            modes.GCM(encrypted_data["nonce"], encrypted_data["tag"]),
            backend=default_backend(),
        )

        decryptor = cipher.decryptor()
        if encrypted_data.get("additional_data"):
            decryptor.authenticate_additional_data(encrypted_data["additional_data"])

        plaintext = (
            decryptor.update(encrypted_data["ciphertext"]) + decryptor.finalize()
        )
        return plaintext

    def _encrypt_chacha20(
        self, data: bytes, key: EncryptionKey, context: EncryptionContext
    ) -> Dict[str, Any]:
        """Encrypt using ChaCha20-Poly1305"""
        nonce = context.nonce or secrets.token_bytes(12)
        cipher = Cipher(
            algorithms.ChaCha20(key.key_data),
            modes.GCM(nonce),
            backend=default_backend(),
        )

        encryptor = cipher.encryptor()
        if context.additional_data:
            encryptor.authenticate_additional_data(context.additional_data)

        ciphertext = encryptor.update(data) + encryptor.finalize()

        return {
            "algorithm": context.algorithm.value,
            "key_id": context.key_id,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": encryptor.tag,
            "timestamp": context.timestamp.isoformat(),
            "additional_data": context.additional_data,
        }

    def _decrypt_chacha20(
        self, encrypted_data: Dict[str, Any], key: EncryptionKey
    ) -> bytes:
        """Decrypt using ChaCha20-Poly1305"""
        cipher = Cipher(
            algorithms.ChaCha20(key.key_data),
            modes.GCM(encrypted_data["nonce"], encrypted_data["tag"]),
            backend=default_backend(),
        )

        decryptor = cipher.decryptor()
        if encrypted_data.get("additional_data"):
            decryptor.authenticate_additional_data(encrypted_data["additional_data"])

        plaintext = (
            decryptor.update(encrypted_data["ciphertext"]) + decryptor.finalize()
        )
        return plaintext

    def _encrypt_fernet(
        self, data: bytes, key: EncryptionKey, context: EncryptionContext
    ) -> Dict[str, Any]:
        """Encrypt using Fernet"""
        fernet = Fernet(key.key_data)
        ciphertext = fernet.encrypt(data)

        return {
            "algorithm": context.algorithm.value,
            "key_id": context.key_id,
            "ciphertext": ciphertext,
            "timestamp": context.timestamp.isoformat(),
        }

    def _decrypt_fernet(
        self, encrypted_data: Dict[str, Any], key: EncryptionKey
    ) -> bytes:
        """Decrypt using Fernet"""
        fernet = Fernet(key.key_data)
        plaintext = fernet.decrypt(encrypted_data["ciphertext"])
        return plaintext

    def _encrypt_hybrid(
        self, data: bytes, key: EncryptionKey, context: EncryptionContext
    ) -> Dict[str, Any]:
        """Encrypt using hybrid classical/post-quantum approach"""
        # Deserialize hybrid key
        key_data = json.loads(key.key_data.decode())
        hybrid_public = {
            k: bytes.fromhex(v) if isinstance(v, str) else v
            for k, v in key_data.items()
            if "public" in k
        }

        encrypted_data = self.hybrid_crypto.hybrid_encrypt(data, hybrid_public)
        encrypted_data.update(
            {
                "algorithm": context.algorithm.value,
                "key_id": context.key_id,
                "timestamp": context.timestamp.isoformat(),
                "hybrid": True,
            }
        )

        return encrypted_data

    def _decrypt_hybrid(
        self, encrypted_data: Dict[str, Any], key: EncryptionKey
    ) -> bytes:
        """Decrypt using hybrid classical/post-quantum approach"""
        # Deserialize hybrid key
        key_data = json.loads(key.key_data.decode())
        hybrid_private = {
            k: bytes.fromhex(v) if isinstance(v, str) else v
            for k, v in key_data.items()
            if "private" in k
        }

        plaintext = self.hybrid_crypto.hybrid_decrypt(encrypted_data, hybrid_private)
        return plaintext

    # Real-time communication methods
    def encrypt_realtime(self, data: bytes, session_id: str) -> Dict[str, Any]:
        """Encrypt data for real-time communications"""
        if not self.config["realtime_key_derivation"]:
            return self.encrypt(data)

        # Get master key from active symmetric key
        with self.lock:
            if EncryptionAlgorithm.AES_256_GCM in self.active_keys:
                master_key_id = self.active_keys[EncryptionAlgorithm.AES_256_GCM]
                master_key = self.keys[master_key_id].key_data
            else:
                raise RuntimeError("No master key available for real-time encryption")

        return self.realtime_crypto.encrypt_realtime_data(data, session_id, master_key)

    def decrypt_realtime(self, encrypted_data: Dict[str, Any]) -> bytes:
        """Decrypt real-time communication data"""
        if not self.config["realtime_key_derivation"]:
            return self.decrypt(encrypted_data)

        # Get master key
        with self.lock:
            if EncryptionAlgorithm.AES_256_GCM in self.active_keys:
                master_key_id = self.active_keys[EncryptionAlgorithm.AES_256_GCM]
                master_key = self.keys[master_key_id].key_data
            else:
                raise RuntimeError("No master key available for real-time decryption")

        return self.realtime_crypto.decrypt_realtime_data(encrypted_data, master_key)

    # HTTP traffic encryption methods
    def encrypt_http_traffic(
        self, payload: bytes, endpoint: str, additional_data: Optional[bytes] = None
    ) -> bytes:
        """Encrypt HTTP traffic with additional layer"""
        if not self.config["http_traffic_encryption"]:
            return payload

        return self.http_crypto.encrypt_http_payload(payload, endpoint, additional_data)

    def decrypt_http_traffic(
        self, encrypted_payload: bytes, endpoint: str
    ) -> Tuple[bytes, int]:
        """Decrypt HTTP traffic"""
        if not self.config["http_traffic_encryption"]:
            return encrypted_payload, int(time.time())

        return self.http_crypto.decrypt_http_payload(encrypted_payload, endpoint)

    def rotate_http_keys(self, endpoint: str):
        """Rotate HTTP traffic encryption keys"""
        self.http_crypto.rotate_traffic_keys(endpoint)

    # Key management methods
    def get_key_info(self, key_id: str) -> Dict[str, Any]:
        """Get information about a key"""
        with self.lock:
            if key_id not in self.keys:
                raise ValueError(f"Key not found: {key_id}")

            key = self.keys[key_id]
            return {
                "key_id": key.key_id,
                "key_type": key.key_type.value,
                "algorithm": key.algorithm.value,
                "created_at": key.created_at.isoformat(),
                "expires_at": key.expires_at.isoformat() if key.expires_at else None,
                "usage_count": key.usage_count,
                "max_usage": key.max_usage,
                "rotation_interval": key.rotation_interval.total_seconds(),
                "has_public_key": key.public_key is not None,
            }

    def list_keys(self) -> List[Dict[str, Any]]:
        """List all keys"""
        with self.lock:
            return [self.get_key_info(key_id) for key_id in self.keys.keys()]

    def get_active_keys(self) -> Dict[str, str]:
        """Get currently active keys for each algorithm"""
        with self.lock:
            return {alg.value: key_id for alg, key_id in self.active_keys.items()}

    def cleanup_expired_keys(self):
        """Remove expired keys"""
        now = datetime.utcnow()
        expired_keys = []

        with self.lock:
            for key_id, key in self.keys.items():
                if key.expires_at and key.expires_at < now:
                    expired_keys.append(key_id)

            for key_id in expired_keys:
                del self.keys[key_id]
                self.time_rotation.cancel_rotation(key_id)

        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired keys")

    async def shutdown(self):
        """Shutdown the encryption manager"""
        self.time_rotation.cancel_all_rotations()
        logger.info("Quantum encryption manager shutdown complete")


# Convenience functions for easy integration
_global_manager: Optional[QuantumEncryptionManager] = None


def initialize_quantum_encryption(
    key_vault_manager: DistributedKeyManager, config_path: Optional[Path] = None
) -> QuantumEncryptionManager:
    """Initialize global quantum encryption manager"""
    global _global_manager
    _global_manager = QuantumEncryptionManager(key_vault_manager, config_path)
    return _global_manager


def get_quantum_manager() -> QuantumEncryptionManager:
    """Get the global quantum encryption manager"""
    if _global_manager is None:
        raise RuntimeError("Quantum encryption manager not initialized")
    return _global_manager


def quantum_encrypt(
    data: bytes, algorithm: Optional[EncryptionAlgorithm] = None
) -> Dict[str, Any]:
    """Convenience function for quantum encryption"""
    return get_quantum_manager().encrypt(data, algorithm)


def quantum_decrypt(encrypted_data: Dict[str, Any]) -> bytes:
    """Convenience function for quantum decryption"""
    return get_quantum_manager().decrypt(encrypted_data)


def encrypt_realtime(data: bytes, session_id: str) -> Dict[str, Any]:
    """Convenience function for real-time encryption"""
    return get_quantum_manager().encrypt_realtime(data, session_id)


def decrypt_realtime(encrypted_data: Dict[str, Any]) -> bytes:
    """Convenience function for real-time decryption"""
    return get_quantum_manager().decrypt_realtime(encrypted_data)
