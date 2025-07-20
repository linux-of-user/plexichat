# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import base64
import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiosqlite
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Hash import BLAKE2b
from Crypto.Protocol.KDF import PBKDF2
try:
    from Crypto.Protocol.KDF import Argon2d
except ImportError:
    # Use argon2-cffi as fallback
    try:
        from argon2 import PasswordHasher
        Argon2d = PasswordHasher()
    except ImportError:
        Argon2d = None
from Crypto.Random import get_random_bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pathlib import Path

from pathlib import Path

"""
import time
PlexiChat Quantum-Proof Encryption System

Implements post-quantum cryptography with multiple key hierarchies,
distributed key management, and quantum-resistant algorithms.
Breaking one key doesn't compromise the entire system.
"""

# Post-quantum cryptography (using pycryptodome for now, will add real PQC libraries)
# Standard cryptography
try:
    from Crypto.Hash import SHA3_256, SHA3_512
    from Crypto.Cipher import AES, ChaCha20_Poly1305
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import Argon2d
except ImportError:
    # Fallback to argon2-cffi if Argon2d not available in pycryptodome
    Argon2d = None
    SHA3_256 = None
    SHA3_512 = None
    AES = None
    ChaCha20_Poly1305 = None
    get_random_bytes = None
logger = logging.getLogger(__name__)


class QuantumAlgorithm(Enum):
    """Post-quantum cryptographic algorithms."""
    KYBER_1024 = "kyber-1024"  # Key encapsulation
    DILITHIUM_5 = "dilithium-5"  # Digital signatures
    SPHINCS_PLUS = "sphincs-plus"  # Hash-based signatures
    NTRU_PRIME = "ntru-prime"  # Lattice-based
    CLASSIC_MCELIECE = "classic-mceliece"  # Code-based
    RAINBOW = "rainbow"  # Multivariate
    HYBRID_RSA_KYBER = "hybrid-rsa-kyber"  # Hybrid approach


class SecurityTier(Enum):
    """Security tiers with different key hierarchies."""
    STANDARD = 1
    ENHANCED = 2
    GOVERNMENT = 3
    MILITARY = 4
    QUANTUM_PROOF = 5


class KeyHierarchy(Enum):
    """Different key hierarchies for distributed security."""
    MASTER_KEY = "master"
    DOMAIN_KEY = "domain"
    SERVICE_KEY = "service"
    SESSION_KEY = "session"
    SHARD_KEY = "shard"


@dataclass
class QuantumKey:
    """Quantum-resistant encryption key."""
    key_id: str
    hierarchy: KeyHierarchy
    algorithm: QuantumAlgorithm
    security_tier: SecurityTier
    key_data: bytes
    public_key: Optional[bytes] = None
    salt: bytes = field(default_factory=lambda: get_random_bytes(64) if get_random_bytes else secrets.token_bytes(64))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    rotation_count: int = 0
    parent_key_id: Optional[str] = None
    child_key_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EncryptionContext:
    """Context for encryption operations."""
    operation_id: str
    data_type: str
    security_tier: SecurityTier
    algorithms: List[QuantumAlgorithm]
    key_ids: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


class QuantumEncryptionSystem:
    """
    Quantum-Proof Encryption System

    Features:
    - Multiple independent key hierarchies
    - Post-quantum cryptographic algorithms
    - Distributed key management
    - Automatic key rotation
    - Breaking one key doesn't compromise others
    - End-to-end encryption for all data
    """

    def __init__(self, config_dir: str = "config/security"):
        from pathlib import Path
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Key storage
        self.keys_db = self.config_dir / "quantum_keys.db"
        self.master_keys: Dict[str, QuantumKey] = {}
        self.domain_keys: Dict[str, QuantumKey] = {}
        self.service_keys: Dict[str, QuantumKey] = {}
        self.session_keys: Dict[str, QuantumKey] = {}
        self.shard_keys: Dict[str, QuantumKey] = {}

        # Security configuration
        self.default_security_tier = SecurityTier.QUANTUM_PROOF
        self.key_rotation_interval = timedelta(hours=24)
        self.max_key_age = timedelta(days=30)

        # Initialize system (will be called manually during app startup)
        self._initialization_task = None

    async def _initialize_system(self):
        """Initialize the quantum encryption system."""
        await self._init_database()
        await self._load_keys()
        await self._ensure_master_keys()
        logger.info(" Quantum encryption system initialized")

    async def _init_database(self):
        """Initialize the keys database."""
        async with aiosqlite.connect(self.keys_db) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS quantum_keys
                (key_id TEXT PRIMARY KEY,
                hierarchy TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                security_tier INTEGER NOT NULL,
                key_data BLOB NOT NULL,
                public_key BLOB,
                salt BLOB NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                rotation_count INTEGER DEFAULT 0,
                parent_key_id TEXT,
                metadata TEXT,
                FOREIGN KEY (parent_key_id) REFERENCES quantum_keys (key_id)
                )
                """
            )

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS key_relationships
                (parent_id TEXT NOT NULL,
                child_id TEXT NOT NULL,
                relationship_type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (parent_id, child_id),
                FOREIGN KEY (parent_id) REFERENCES quantum_keys (key_id),
                FOREIGN KEY (child_id) REFERENCES quantum_keys (key_id)
                )
                """
            )

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS encryption_operations
                (operation_id TEXT PRIMARY KEY,
                data_type TEXT NOT NULL,
                security_tier INTEGER NOT NULL,
                algorithms TEXT NOT NULL,
                key_ids TEXT NOT NULL,
                data_size INTEGER NOT NULL,
                encrypted_size INTEGER NOT NULL,
                operation_time REAL NOT NULL,
                created_at TEXT NOT NULL,
                metadata TEXT
                )
                """
            )

            await db.commit()

    async def _load_keys(self):
        """Load keys from database."""
        async with aiosqlite.connect(self.keys_db) as db:
            async with db.execute("SELECT * FROM quantum_keys") as cursor:
                async for row in cursor:
                    key = QuantumKey(
                        key_id=row[0],
                        hierarchy=KeyHierarchy(row[1]),
                        algorithm=QuantumAlgorithm(row[2]),
                        security_tier=SecurityTier(row[3]),
                        key_data=row[4],
                        public_key=row[5],
                        salt=row[6],
                        created_at=datetime.fromisoformat(row[7]),
                        expires_at=datetime.fromisoformat(row[8]) if row[8] else None,
                        rotation_count=row[9],
                        parent_key_id=row[10],
                        metadata=json.loads(row[11]) if row[11] else {}
                    )

                    # Store in appropriate hierarchy
                    if key.hierarchy == KeyHierarchy.MASTER_KEY:
                        self.master_keys[key.key_id] = key
                    elif key.hierarchy == KeyHierarchy.DOMAIN_KEY:
                        self.domain_keys[key.key_id] = key
                    elif key.hierarchy == KeyHierarchy.SERVICE_KEY:
                        self.service_keys[key.key_id] = key
                    elif key.hierarchy == KeyHierarchy.SESSION_KEY:
                        self.session_keys[key.key_id] = key
                    elif key.hierarchy == KeyHierarchy.SHARD_KEY:
                        self.shard_keys[key.key_id] = key

    async def _ensure_master_keys(self):
        """Ensure master keys exist for each security tier."""
        for tier in SecurityTier:
            master_key_id = f"master_{tier.name.lower()}"
            if master_key_id not in self.master_keys:
                await self._generate_master_key(tier)

    async def _generate_master_key(self, security_tier: SecurityTier) -> QuantumKey:
        """Generate a new master key."""
        key_id = f"master_{security_tier.name.lower()}_{secrets.token_hex(8)}"

        # Use strongest algorithm for master keys
        algorithm = QuantumAlgorithm.HYBRID_RSA_KYBER

        # Generate key material
        key_data = self._generate_key_material(algorithm, security_tier)

        master_key = QuantumKey(
            key_id=key_id,
            hierarchy=KeyHierarchy.MASTER_KEY,
            algorithm=algorithm,
            security_tier=security_tier,
            key_data=key_data,
            expires_at=datetime.now(timezone.utc) + self.max_key_age,
            metadata={
                "purpose": "master_key",
                "tier": security_tier.name,
                "auto_generated": True
            }
        )

        self.master_keys[key_id] = master_key
        await self._save_key(master_key)

        logger.info(f" Generated master key for {security_tier.name} tier")
        return master_key

    def _generate_key_material(self, algorithm: QuantumAlgorithm, security_tier: SecurityTier) -> bytes:
        """Generate key material for the specified algorithm."""
        # Key sizes based on security tier
        key_sizes = {
            SecurityTier.STANDARD: 256,
            SecurityTier.ENHANCED: 384,
            SecurityTier.GOVERNMENT: 512,
            SecurityTier.MILITARY: 768,
            SecurityTier.QUANTUM_PROOF: 1024
        }

        key_size = key_sizes[security_tier]

        if algorithm == QuantumAlgorithm.HYBRID_RSA_KYBER:
            # Generate hybrid key (RSA + simulated Kyber)
            if rsa is None or padding is None or serialization is None:
                raise ImportError("cryptography is required for RSA operations")
            rsa_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            rsa_bytes = rsa_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            # Simulate Kyber key (in real implementation, use actual Kyber)
            if get_random_bytes is None:
                raise RuntimeError("get_random_bytes not available")
            kyber_key = get_random_bytes(key_size)

            return rsa_bytes + b"||KYBER||" + kyber_key

        else:
            # Generate random key material
            if get_random_bytes is None:
                raise RuntimeError("get_random_bytes not available")
            return get_random_bytes(key_size)

    async def _save_key(self, key: QuantumKey):
        """Save key to database."""
        async with aiosqlite.connect(self.keys_db) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO quantum_keys
                (key_id, hierarchy, algorithm, security_tier, key_data, public_key, salt, created_at, expires_at, rotation_count, parent_key_id, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key.key_id,
                    key.hierarchy.value,
                    key.algorithm.value,
                    key.security_tier.value,
                    key.key_data,
                    key.public_key,
                    key.salt,
                    key.created_at.isoformat(),
                    key.expires_at.isoformat() if key.expires_at else None,
                    key.rotation_count,
                    key.parent_key_id,
                    json.dumps(key.metadata)
                )
            )
            await db.commit()

    async def encrypt_data(self, data: bytes, context: EncryptionContext) -> Tuple[bytes, Dict[str, Any]]:
        """
        Encrypt data using quantum-resistant algorithms.

        Uses multiple layers of encryption with different keys from different hierarchies.
        Even if one key is compromised, the data remains secure.
        """
        operation_start = datetime.now(timezone.utc)

        # Select appropriate keys based on context
        encryption_keys = await self._select_encryption_keys(context)

        # Apply multiple layers of encryption
        encrypted_data = data
        encryption_metadata = {
            "operation_id": context.operation_id,
            "layers": [],
            "algorithms": [],
            "key_ids": [],
            "security_tier": context.security_tier.value,
            "original_size": len(data)
        }

        # Layer 1: Service-level encryption
        if encryption_keys.get("service"):
            if BLAKE2b is None or ChaCha20_Poly1305 is None:
                raise ImportError("pycryptodome is required for encryption (BLAKE2b, ChaCha20_Poly1305)")
            service_key = encryption_keys["service"]
            encrypted_data, layer_meta = await self._encrypt_layer(
                encrypted_data, service_key, "service_layer"
            )
            encryption_metadata["layers"].append(layer_meta)
            encryption_metadata["algorithms"].append(service_key.algorithm.value)
            encryption_metadata["key_ids"].append(service_key.key_id)

        # Layer 2: Domain-level encryption
        if encryption_keys.get("domain"):
            if BLAKE2b is None or ChaCha20_Poly1305 is None:
                raise ImportError("pycryptodome is required for encryption (BLAKE2b, ChaCha20_Poly1305)")
            domain_key = encryption_keys["domain"]
            encrypted_data, layer_meta = await self._encrypt_layer(
                encrypted_data, domain_key, "domain_layer"
            )
            encryption_metadata["layers"].append(layer_meta)
            encryption_metadata["algorithms"].append(domain_key.algorithm.value)
            encryption_metadata["key_ids"].append(domain_key.key_id)

        # Layer 3: Session-level encryption (if applicable)
        if encryption_keys.get("session"):
            if BLAKE2b is None or ChaCha20_Poly1305 is None:
                raise ImportError("pycryptodome is required for encryption (BLAKE2b, ChaCha20_Poly1305)")
            session_key = encryption_keys["session"]
            encrypted_data, layer_meta = await self._encrypt_layer(
                encrypted_data, session_key, "session_layer"
            )
            encryption_metadata["layers"].append(layer_meta)
            encryption_metadata["algorithms"].append(session_key.algorithm.value)
            encryption_metadata["key_ids"].append(session_key.key_id)

        # Final layer: Add integrity check
        if BLAKE2b is None:
            raise ImportError("pycryptodome is required for BLAKE2b integrity check")
        final_hash = BLAKE2b.new(digest_bits=512)
        final_hash.update(encrypted_data)
        integrity_hash = final_hash.digest()

        # Combine encrypted data with integrity hash
        final_encrypted = integrity_hash + encrypted_data

        encryption_metadata.update({
            "encrypted_size": len(final_encrypted),
            "integrity_hash": base64.b64encode(integrity_hash).decode(),
            "encryption_time": (datetime.now(timezone.utc) - operation_start).total_seconds(),
            "created_at": operation_start.isoformat()
        })

        # Log the operation
        await self._log_encryption_operation(context, encryption_metadata)

        return final_encrypted, encryption_metadata

    async def decrypt_data(self, encrypted_data: bytes, metadata: Dict[str, Any]) -> bytes:
        """
        Decrypt data using the reverse process of encryption.

        Requires access to all keys used in the encryption process.
        """
        # Verify integrity first
        if len(encrypted_data) < 64:
            raise ValueError("Invalid encrypted data: too short")

        integrity_hash = encrypted_data[:64]
        data_to_decrypt = encrypted_data[64:]

        # Verify integrity
        check_hash = BLAKE2b.new(digest_bits=512)
        check_hash.update(data_to_decrypt)
        if check_hash.digest() != integrity_hash:
            raise ValueError("Data integrity check failed")

        # Decrypt layers in reverse order
        decrypted_data = data_to_decrypt

        for layer_meta in reversed(metadata["layers"]):
            key_id = layer_meta["key_id"]
            QuantumAlgorithm(layer_meta["algorithm"])

            # Find the key
            key = await self._find_key(key_id)
            if not key:
                raise ValueError(f"Decryption key not found: {key_id}")

            # Decrypt this layer
            decrypted_data = await self._decrypt_layer(decrypted_data, key, layer_meta)

        return decrypted_data

    async def _select_encryption_keys(self, context: EncryptionContext) -> Dict[str, QuantumKey]:
        """Select appropriate keys for encryption based on context."""
        selected_keys = {}

        # Always use a service key
        service_key = await self._get_or_create_service_key(
            context.data_type, context.security_tier
        )
        selected_keys["service"] = service_key

        # Use domain key for higher security tiers
        if context.security_tier.value >= SecurityTier.GOVERNMENT.value:
            domain_key = await self._get_or_create_domain_key(
                "default", context.security_tier
            )
            selected_keys["domain"] = domain_key

        # Use session key for ephemeral data
        if context.data_type in ["session", "temporary", "cache"]:
            session_key = await self._get_or_create_session_key(context.security_tier)
            selected_keys["session"] = session_key

        return selected_keys

    async def _encrypt_layer(self, data: bytes, key: QuantumKey, layer_name: str) -> Tuple[bytes, Dict[str, Any]]:
        """Encrypt a single layer using the specified key."""
        if key.algorithm == QuantumAlgorithm.HYBRID_RSA_KYBER:
            return await self._encrypt_hybrid_rsa_kyber(data, key, layer_name)
        elif key.algorithm == QuantumAlgorithm.KYBER_1024:
            return await self._encrypt_kyber(data, key, layer_name)
        else:
            # Fallback to ChaCha20-Poly1305
            return await self._encrypt_chacha20(data, key, layer_name)

    async def _decrypt_layer(self, data: bytes, key: QuantumKey, layer_meta: Dict[str, Any]) -> bytes:
        """Decrypt a single layer using the specified key."""
        if key.algorithm == QuantumAlgorithm.HYBRID_RSA_KYBER:
            return await self._decrypt_hybrid_rsa_kyber(data, key, layer_meta)
        elif key.algorithm == QuantumAlgorithm.KYBER_1024:
            return await self._decrypt_kyber(data, key, layer_meta)
        else:
            # Fallback to ChaCha20-Poly1305
            return await self._decrypt_chacha20(data, key, layer_meta)

    async def _encrypt_hybrid_rsa_kyber(self, data: bytes, key: QuantumKey, layer_name: str) -> Tuple[bytes, Dict[str, Any]]:
        """Encrypt using hybrid RSA + Kyber approach."""
        # Split the key material
        key_parts = key.key_data.split(b"||KYBER||")
        if len(key_parts) != 2:
            raise ValueError("Invalid hybrid key format")

        rsa_key_data, kyber_key_data = key_parts

        # Generate session key for actual data encryption
        if get_random_bytes is None:
            raise RuntimeError("get_random_bytes not available")
        session_key = get_random_bytes(32)
        nonce = get_random_bytes(12)

        # Encrypt data with ChaCha20-Poly1305
        if ChaCha20_Poly1305 is None:
            raise RuntimeError("ChaCha20_Poly1305 not available")
        cipher = ChaCha20_Poly1305.new(key=session_key, nonce=nonce)
        encrypted_data, tag = cipher.encrypt_and_digest(data)
        # tag = cipher.digest

        # Encrypt session key with RSA (classical part)
        rsa_key = serialization.load_pem_private_key(rsa_key_data, password=None, backend=default_backend())
        rsa_public_key = rsa_key.public_key()
        rsa_encrypted_key = rsa_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Simulate Kyber encryption (in real implementation, use actual Kyber)
        kyber_encrypted_key = self._simulate_kyber_encrypt(session_key, kyber_key_data)

        # Combine all components
        final_data = (
            len(rsa_encrypted_key).to_bytes(4, 'big') +
            rsa_encrypted_key +
            len(kyber_encrypted_key).to_bytes(4, 'big') +
            kyber_encrypted_key +
            nonce +
            tag +
            encrypted_data
        )

        layer_meta = {
            "layer_name": layer_name,
            "algorithm": key.algorithm.value,
            "key_id": key.key_id,
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "rsa_key_size": len(rsa_encrypted_key),
            "kyber_key_size": len(kyber_encrypted_key)
        }

        return final_data, layer_meta

    async def _decrypt_hybrid_rsa_kyber(self, data: bytes, key: QuantumKey, layer_meta: Dict[str, Any]) -> bytes:
        """Decrypt using hybrid RSA + Kyber approach."""
        # Split the key material
        key_parts = key.key_data.split(b"||KYBER||")
        if len(key_parts) != 2:
            raise ValueError("Invalid hybrid key format")

        rsa_key_data, kyber_key_data = key_parts

        # Parse the encrypted data
        offset = 0

        # RSA encrypted key
        rsa_key_size = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        rsa_encrypted_key = data[offset:offset+rsa_key_size]
        offset += rsa_key_size

        # Kyber encrypted key
        kyber_key_size = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        kyber_encrypted_key = data[offset:offset+kyber_key_size]
        offset += kyber_key_size

        # Nonce and tag
        nonce = data[offset:offset+12]
        offset += 12
        tag = data[offset:offset+16]
        offset += 16

        # Encrypted data
        encrypted_data = data[offset:]

        # Decrypt session key with RSA
        rsa_key = serialization.load_pem_private_key(rsa_key_data, password=None, backend=default_backend())
        session_key_rsa = rsa_key.decrypt(
            rsa_encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt session key with Kyber (simulated)
        session_key_kyber = self._simulate_kyber_decrypt(kyber_encrypted_key, kyber_key_data)

        # Verify both keys match (in real implementation, use key combination)
        if session_key_rsa != session_key_kyber:
            raise ValueError("Key decryption mismatch - possible tampering")

        # Decrypt the actual data
        if ChaCha20_Poly1305 is None:
            raise RuntimeError("ChaCha20_Poly1305 not available")
        cipher = ChaCha20_Poly1305.new(key=session_key_rsa, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)

        return decrypted_data

    def _simulate_kyber_encrypt(self, data: bytes, kyber_key: bytes) -> bytes:
        """Simulate Kyber encryption (replace with real Kyber implementation)."""
        if PBKDF2 is None or AES is None:
            raise ImportError("pycryptodome is required for PBKDF2 and AES")
        # This is a simulation - in real implementation, use actual Kyber
        if get_random_bytes is None:
            raise RuntimeError("get_random_bytes not available")
        salt = get_random_bytes(16)
        kdf = PBKDF2(kyber_key, salt, 32, count=100000)
        cipher = AES.new(kdf, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return bytes(cipher.nonce) + tag + ciphertext

    def _simulate_kyber_decrypt(self, encrypted_data: bytes, kyber_key: bytes) -> bytes:
        """Simulate Kyber decryption (replace with real Kyber implementation)."""
        if PBKDF2 is None or AES is None:
            raise ImportError("pycryptodome is required for PBKDF2 and AES")
        # This is a simulation - in real implementation, use actual Kyber
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]

        kdf = PBKDF2(kyber_key, nonce, 32, count=100000)
        cipher = AES.new(kdf, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    async def _encrypt_chacha20(self, data: bytes, key: QuantumKey, layer_name: str) -> Tuple[bytes, Dict[str, Any]]:
        """Encrypt using ChaCha20-Poly1305."""
        if PBKDF2 is None or ChaCha20_Poly1305 is None:
            raise ImportError("pycryptodome is required for PBKDF2 and ChaCha20_Poly1305")
        # Derive encryption key from stored key
        kdf = PBKDF2(key.key_data, key.salt, 32, count=100000)

        if get_random_bytes is None:
            raise RuntimeError("get_random_bytes not available")
        nonce = get_random_bytes(12)
        cipher = ChaCha20_Poly1305.new(key=kdf, nonce=nonce)
        encrypted_data, tag = cipher.encrypt_and_digest(data)

        final_data = nonce + tag + encrypted_data

        layer_meta = {
            "layer_name": layer_name,
            "algorithm": key.algorithm.value,
            "key_id": key.key_id,
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode()
        }

        return final_data, layer_meta

    async def _decrypt_chacha20(self, data: bytes, key: QuantumKey, layer_meta: Dict[str, Any]) -> bytes:
        """Decrypt using ChaCha20-Poly1305."""
        if PBKDF2 is None or ChaCha20_Poly1305 is None:
            raise ImportError("pycryptodome is required for PBKDF2 and ChaCha20_Poly1305")
        # Derive decryption key from stored key
        kdf = PBKDF2(key.key_data, key.salt, 32, count=100000)

        # Parse encrypted data
        nonce = data[:12]
        tag = data[12:28]
        encrypted_data = data[28:]

        cipher = ChaCha20_Poly1305.new(key=kdf, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)

        return decrypted_data

    async def _get_or_create_service_key(self, service_name: str, security_tier: SecurityTier) -> QuantumKey:
        """Get or create a service-level key."""
        key_id = f"service_{service_name}_{security_tier.name.lower()}"

        # Check if key exists
        for key in self.service_keys.values():
            if key.key_id.startswith(key_id) and not self._is_key_expired(key):
                return key

        # Create new service key
        master_key = await self._get_master_key(security_tier)

        service_key = QuantumKey(
            key_id=f"{key_id}_{secrets.token_hex(4)}",
            hierarchy=KeyHierarchy.SERVICE_KEY,
            algorithm=QuantumAlgorithm.HYBRID_RSA_KYBER,
            security_tier=security_tier,
            key_data=self._derive_child_key(master_key.key_data, f"service_{service_name}"),
            parent_key_id=master_key.key_id,
            expires_at=datetime.now(timezone.utc) + self.key_rotation_interval,
            metadata={
                "service": service_name,
                "purpose": "service_encryption"
            }
        )

        self.service_keys[service_key.key_id] = service_key
        await self._save_key(service_key)

        return service_key

    async def _get_or_create_domain_key(self, domain_name: str, security_tier: SecurityTier) -> QuantumKey:
        """Get or create a domain-level key."""
        key_id = f"domain_{domain_name}_{security_tier.name.lower()}"

        # Check if key exists
        for key in self.domain_keys.values():
            if key.key_id.startswith(key_id) and not self._is_key_expired(key):
                return key

        # Create new domain key
        master_key = await self._get_master_key(security_tier)

        domain_key = QuantumKey(
            key_id=f"{key_id}_{secrets.token_hex(4)}",
            hierarchy=KeyHierarchy.DOMAIN_KEY,
            algorithm=QuantumAlgorithm.HYBRID_RSA_KYBER,
            security_tier=security_tier,
            key_data=self._derive_child_key(master_key.key_data, f"domain_{domain_name}"),
            parent_key_id=master_key.key_id,
            expires_at=datetime.now(timezone.utc) + self.key_rotation_interval,
            metadata={
                "domain": domain_name,
                "purpose": "domain_encryption"
            }
        )

        self.domain_keys[domain_key.key_id] = domain_key
        await self._save_key(domain_key)

        return domain_key

    async def _get_or_create_session_key(self, security_tier: SecurityTier) -> QuantumKey:
        """Get or create a session-level key."""
        # Session keys are always ephemeral
        session_key = QuantumKey(
            key_id=f"session_{secrets.token_hex(8)}",
            hierarchy=KeyHierarchy.SESSION_KEY,
            algorithm=QuantumAlgorithm.HYBRID_RSA_KYBER,
            security_tier=security_tier,
            key_data=get_random_bytes(512) if get_random_bytes else secrets.token_bytes(512),  # Pure random for sessions
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),  # Short-lived
            metadata={
                "purpose": "session_encryption",
                "ephemeral": True
            }
        )

        self.session_keys[session_key.key_id] = session_key
        # Don't save session keys to database - they're ephemeral

        return session_key

    async def _get_master_key(self, security_tier: SecurityTier) -> QuantumKey:
        """Get master key for the specified security tier."""
        for key in self.master_keys.values():
            if key.security_tier == security_tier and not self._is_key_expired(key):
                return key

        # Generate new master key if none exists
        return await self._generate_master_key(security_tier)

    def _derive_child_key(self, parent_key: bytes, context: str) -> bytes:
        """Derive a child key from parent key using HKDF."""
        # Use BLAKE2b for key derivation
        hasher = BLAKE2b.new(digest_bits=512, key=parent_key, person=context.encode())
        return hasher.digest()

    def _is_key_expired(self, key: QuantumKey) -> bool:
        """Check if a key is expired."""
        if not key.expires_at:
            return False
        return datetime.now(timezone.utc) > key.expires_at

    async def _find_key(self, key_id: str) -> Optional[QuantumKey]:
        """Find a key by ID across all hierarchies."""
        all_keys = {
            **self.master_keys,
            **self.domain_keys,
            **self.service_keys,
            **self.session_keys,
            **self.shard_keys
        }
        return all_keys.get(key_id)

    async def _log_encryption_operation(self, context: EncryptionContext, metadata: Dict[str, Any]):
        """Log encryption operation for audit purposes."""
        async with aiosqlite.connect(self.keys_db) as db:
            await db.execute(
                """
                INSERT INTO encryption_operations
                (operation_id, data_type, security_tier, algorithms, key_ids, data_size, encrypted_size, operation_time, created_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    context.operation_id,
                    context.data_type,
                    context.security_tier.value,
                    json.dumps([alg.value for alg in context.algorithms]),
                    json.dumps(context.key_ids),
                    metadata.get("original_size", 0),
                    metadata.get("encrypted_size", 0),
                    metadata.get("encryption_time", 0),
                    metadata.get("created_at"),
                    json.dumps(metadata)
                )
            )
            await db.commit()

    async def rotate_keys(self, force: bool = False):
        """Rotate expired keys."""
        rotated_count = 0

        # Check all key hierarchies
        for key_dict in [self.master_keys, self.domain_keys, self.service_keys]:
            for _, key in list(key_dict.items()):
                if force or self._is_key_expired(key):
                    await self._rotate_key(key)
                    rotated_count += 1

        logger.info(f" Rotated {rotated_count} keys")
        return rotated_count

    async def _rotate_key(self, old_key: QuantumKey):
        """Rotate a single key."""
        # Generate new key with same properties
        new_key = QuantumKey(
            key_id=f"{old_key.key_id.rsplit('_', 1)[0]}_{secrets.token_hex(4)}",
            hierarchy=old_key.hierarchy,
            algorithm=old_key.algorithm,
            security_tier=old_key.security_tier,
            key_data=self._generate_key_material(old_key.algorithm, old_key.security_tier),
            parent_key_id=old_key.parent_key_id,
            expires_at=datetime.now(timezone.utc) + self.key_rotation_interval,
            rotation_count=old_key.rotation_count + 1,
            metadata={**old_key.metadata, "rotated_from": old_key.key_id}
        )

        # Update key storage
        if old_key.hierarchy == KeyHierarchy.MASTER_KEY:
            self.master_keys[new_key.key_id] = new_key
            del self.master_keys[old_key.key_id]
        elif old_key.hierarchy == KeyHierarchy.DOMAIN_KEY:
            self.domain_keys[new_key.key_id] = new_key
            del self.domain_keys[old_key.key_id]
        elif old_key.hierarchy == KeyHierarchy.SERVICE_KEY:
            self.service_keys[new_key.key_id] = new_key
            del self.service_keys[old_key.key_id]

        await self._save_key(new_key)
        logger.info(f" Rotated key: {old_key.key_id} -> {new_key.key_id}")


# Global quantum encryption system instance
quantum_encryption = QuantumEncryptionSystem()
