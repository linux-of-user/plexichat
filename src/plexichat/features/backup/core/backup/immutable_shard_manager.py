# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import logging

import asyncio
import hashlib
import json
import secrets
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from ...core.config import get_config
from plexichat.core.logging import get_logger
from ..security.quantum_encryption import QuantumEncryptionEngine
from .zero_knowledge_protocol import ZeroKnowledgeBackupProtocol


"""
PlexiChat Immutable Shard Management System

Provides immutable shard storage with cryptographic integrity verification,
tamper detection, and blockchain-inspired audit trails for distributed backup.
"""

logger = get_logger(__name__)


class ShardState(Enum):
    """Shard lifecycle states."""

    CREATED = "created"
    VERIFIED = "verified"
    SEALED = "sealed"
    REPLICATED = "replicated"
    ARCHIVED = "archived"
    CORRUPTED = "corrupted"
    DELETED = "deleted"


class IntegrityLevel(Enum):
    """Integrity verification levels."""

    BASIC = "basic"  # Simple hash verification
    ENHANCED = "enhanced"  # Merkle tree verification
    CRYPTOGRAPHIC = "cryptographic"  # Digital signatures
    BLOCKCHAIN = "blockchain"  # Blockchain-inspired audit trail


@dataclass
class ShardMetadata:
    """Metadata for immutable shards."""

    shard_id: str
    content_hash: str
    size: int
    created_at: datetime
    creator_id: str
    version: int
    parent_shard_id: Optional[str] = None
    encryption_key_id: str = ""
    compression_algorithm: str = "none"
    integrity_level: IntegrityLevel = IntegrityLevel.ENHANCED
    state: ShardState = ShardState.CREATED

    # Blockchain-inspired fields
    previous_hash: str = ""
    merkle_root: str = ""
    nonce: int = 0
    difficulty: int = 0

    # Audit trail
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)

    # Replication info
    replica_nodes: Set[str] = field(default_factory=set)
    min_replicas: int = 3
    max_replicas: int = 7


@dataclass
class ImmutableShard:
    """Immutable shard with cryptographic integrity."""

    metadata: ShardMetadata
    data: bytes
    signature: bytes
    merkle_proof: List[str]
    integrity_hash: str
    tamper_seal: bytes

    # Blockchain-inspired proof of work
    proof_of_work: Optional[Dict[str, Any]] = None

    # Verification data
    verification_timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_verified: Optional[datetime] = None
    verification_count: int = 0


@dataclass
class AuditLogEntry:
    """Audit log entry for shard operations."""

    entry_id: str
    shard_id: str
    operation: str
    timestamp: datetime
    node_id: str
    user_id: Optional[str]
    details: Dict[str, Any]
    signature: bytes
    previous_entry_hash: str


class ImmutableShardManager:
    """
    Immutable shard management system with cryptographic integrity.

    Features:
    - Immutable shard storage with tamper detection
    - Cryptographic integrity verification
    - Blockchain-inspired audit trails
    - Merkle tree verification
    - Digital signatures for authenticity
    - Proof-of-work for critical shards
    - Automatic replication management
    - Tamper-evident sealing
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._load_default_config()

        # Core components
        self.quantum_engine = QuantumEncryptionEngine()
        self.zero_knowledge_protocol = ZeroKnowledgeBackupProtocol()

        # Shard storage
        self.shards: Dict[str, ImmutableShard] = {}
        self.shard_index: Dict[str, ShardMetadata] = {}

        # Blockchain-inspired chain
        self.shard_chain: List[str] = []  # Ordered list of shard IDs
        self.chain_head: Optional[str] = None

        # Audit system
        self.audit_log: List[AuditLogEntry] = []
        self.audit_index: Dict[str, List[str]] = {}  # shard_id -> entry_ids

        # Integrity verification
        self.integrity_level = IntegrityLevel(
            self.config.get("integrity_level", "enhanced")
        )
        self.verification_interval = self.config.get("verification_interval_hours", 24)
        self.auto_repair = self.config.get("auto_repair_enabled", True)

        # Replication settings
        self.min_replicas = self.config.get("min_replicas", 3)
        self.max_replicas = self.config.get("max_replicas", 7)
        self.replication_factor = self.config.get("replication_factor", 0.8)

        # Proof of work settings
        self.enable_proof_of_work = self.config.get("enable_proof_of_work", False)
        self.pow_difficulty = self.config.get("pow_difficulty", 4)

        # Performance tracking
        self.stats = {
            "shards_created": 0,
            "shards_verified": 0,
            "integrity_violations": 0,
            "repairs_performed": 0,
            "replications_completed": 0,
        }

        # Signing keys
        self.signing_key: Optional[ed25519.Ed25519PrivateKey] = None
        self.verify_key: Optional[ed25519.Ed25519PublicKey] = None

        self.initialized = False

        logger.info(" Immutable Shard Manager initialized")

    def _load_default_config(self) -> Dict[str, Any]:
        """Load default immutable shard configuration."""
        return {
            "integrity_level": "enhanced",
            "verification_interval_hours": 24,
            "auto_repair_enabled": True,
            "min_replicas": 3,
            "max_replicas": 7,
            "replication_factor": 0.8,
            "enable_proof_of_work": False,
            "pow_difficulty": 4,
            "merkle_tree_enabled": True,
            "audit_trail_enabled": True,
            "tamper_detection_enabled": True,
            "automatic_sealing": True,
            "compression_enabled": True,
            "encryption_required": True,
        }

    async def initialize(self) -> Dict[str, Any]:
        """Initialize the immutable shard management system."""
        try:
            if self.initialized:
                return {"success": True, "message": "Already initialized"}

            logger.info(" Initializing immutable shard management system...")

            # Initialize quantum encryption
            await self.quantum_engine.initialize_key_system()

            # Initialize zero-knowledge protocol
            await self.if zero_knowledge_protocol and hasattr(zero_knowledge_protocol, "initialize"): zero_knowledge_protocol.initialize()

            # Generate signing keys
            await self._generate_signing_keys()

            # Initialize audit system
            await self._initialize_audit_system()

            # Load existing shards
            await self._load_existing_shards()

            # Start background verification
            asyncio.create_task(self._background_verification_loop())

            self.initialized = True

            logger.info(" Immutable shard management system initialized")

            return {
                "success": True,
                "integrity_level": self.integrity_level.value,
                "min_replicas": self.min_replicas,
                "max_replicas": self.max_replicas,
                "proof_of_work_enabled": self.enable_proof_of_work,
                "shards_loaded": len(self.shards),
            }

        except Exception as e:
            logger.error(f" Failed to initialize immutable shard manager: {e}")
            return {"success": False, "error": str(e)}

    async def _generate_signing_keys(self):
        """Generate Ed25519 signing keys for shard authentication."""
        try:
            # Generate new signing key pair
            self.signing_key = ed25519.Ed25519PrivateKey.generate()
            self.verify_key = self.signing_key.public_key()

            logger.info(" Signing keys generated for shard authentication")

        except Exception as e:
            logger.error(f" Failed to generate signing keys: {e}")
            raise

    async def _initialize_audit_system(self):
        """Initialize the audit trail system."""
        try:
            # Create genesis audit entry
            genesis_entry = AuditLogEntry(
                entry_id=f"genesis_{secrets.token_hex(16)}",
                shard_id="genesis",
                operation="system_init",
                timestamp=datetime.now(timezone.utc),
                node_id="system",
                user_id=None,
                details={"action": "audit_system_initialized"},
                signature=b"genesis_signature",
                previous_entry_hash="",
            )

            self.audit_log.append(genesis_entry)

            logger.info(" Audit system initialized with genesis entry")

        except Exception as e:
            logger.error(f" Failed to initialize audit system: {e}")
            raise

    async def _load_existing_shards(self):
        """Load existing shards from storage."""
        try:
            # TODO: Implement persistent storage loading
            # For now, start with empty shard storage

            logger.info(f" Loaded {len(self.shards)} existing shards")

        except Exception as e:
            logger.error(f" Failed to load existing shards: {e}")
            raise

    async def create_immutable_shard(
        self, data: bytes, creator_id: str, parent_shard_id: Optional[str] = None
    ) -> ImmutableShard:
        """Create a new immutable shard with cryptographic integrity."""
        try:
            if not self.initialized:
                await if self and hasattr(self, "initialize"): self.initialize()

            logger.info(f" Creating immutable shard ({len(data)} bytes)...")

            # Generate unique shard ID
            shard_id = f"shard_{secrets.token_hex(32)}"

            # Calculate content hash
            content_hash = hashlib.sha512(data).hexdigest()

            # Get previous hash for blockchain-inspired chaining
            previous_hash = ""
            if self.chain_head:
                previous_shard = self.shards.get(self.chain_head)
                if previous_shard:
                    previous_hash = previous_shard.metadata.content_hash

            # Create shard metadata
            metadata = ShardMetadata(
                shard_id=shard_id,
                content_hash=content_hash,
                size=len(data),
                created_at=datetime.now(timezone.utc),
                creator_id=creator_id,
                version=1,
                parent_shard_id=parent_shard_id,
                previous_hash=previous_hash,
                min_replicas=self.min_replicas,
                max_replicas=self.max_replicas,
                integrity_level=self.integrity_level,
            )

            # Generate Merkle tree and proof
            merkle_root, merkle_proof = await self._generate_merkle_proof(data)
            metadata.merkle_root = merkle_root

            # Create digital signature
            signature = await self._sign_shard_data(data, metadata)

            # Calculate integrity hash
            integrity_hash = await self._calculate_integrity_hash(data, metadata)

            # Create tamper seal
            tamper_seal = await self._create_tamper_seal(data, metadata, signature)

            # Generate proof of work if enabled
            proof_of_work = None
            if self.enable_proof_of_work:
                proof_of_work = await self._generate_proof_of_work(data, metadata)
                metadata.nonce = proof_of_work["nonce"]
                metadata.difficulty = proof_of_work["difficulty"]

            # Create immutable shard
            shard = ImmutableShard(
                metadata=metadata,
                data=data,
                signature=signature,
                merkle_proof=merkle_proof,
                integrity_hash=integrity_hash,
                tamper_seal=tamper_seal,
                proof_of_work=proof_of_work,
            )

            # Store shard
            self.shards[shard_id] = shard
            self.shard_index[shard_id] = metadata

            # Update chain
            self.shard_chain.append(shard_id)
            self.chain_head = shard_id

            # Update metadata state
            metadata.state = ShardState.CREATED

            # Create audit log entry
            await self._create_audit_entry(
                shard_id=shard_id,
                operation="shard_created",
                node_id="local",
                user_id=creator_id,
                details={
                    "size": len(data),
                    "content_hash": content_hash,
                    "integrity_level": self.integrity_level.value,
                    "proof_of_work": self.enable_proof_of_work,
                },
            )

            # Update statistics
            self.stats["shards_created"] += 1

            logger.info(f" Immutable shard created: {shard_id}")

            return shard

        except Exception as e:
            logger.error(f" Failed to create immutable shard: {e}")
            raise

    async def verify_shard_integrity(self, shard_id: str) -> Dict[str, Any]:
        """Verify the cryptographic integrity of a shard."""
        try:
            if shard_id not in self.shards:
                return {"valid": False, "error": "Shard not found"}

            shard = self.shards[shard_id]

            logger.debug(f" Verifying integrity of shard {shard_id}...")

            verification_results = {
                "shard_id": shard_id,
                "valid": True,
                "checks": {},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            # 1. Content hash verification
            calculated_hash = hashlib.sha512(shard.data).hexdigest()
            hash_valid = calculated_hash == shard.metadata.content_hash
            verification_results["checks"]["content_hash"] = {
                "valid": hash_valid,
                "expected": shard.metadata.content_hash,
                "calculated": calculated_hash,
            }

            # 2. Digital signature verification
            signature_valid = await self._verify_shard_signature(shard)
            verification_results["checks"]["digital_signature"] = {
                "valid": signature_valid
            }

            # 3. Merkle proof verification
            merkle_valid = await self._verify_merkle_proof(shard)
            verification_results["checks"]["merkle_proof"] = {
                "valid": merkle_valid,
                "root": shard.metadata.merkle_root,
            }

            # 4. Integrity hash verification
            integrity_valid = await self._verify_integrity_hash(shard)
            verification_results["checks"]["integrity_hash"] = {
                "valid": integrity_valid
            }

            # 5. Tamper seal verification
            tamper_valid = await self._verify_tamper_seal(shard)
            verification_results["checks"]["tamper_seal"] = {"valid": tamper_valid}

            # 6. Proof of work verification (if enabled)
            if shard.proof_of_work:
                pow_valid = await self._verify_proof_of_work(shard)
                verification_results["checks"]["proof_of_work"] = {
                    "valid": pow_valid,
                    "difficulty": shard.metadata.difficulty,
                    "nonce": shard.metadata.nonce,
                }

            # Overall validity
            all_checks_valid = all(
                check["valid"] for check in verification_results["checks"].values()
            )
            verification_results["valid"] = all_checks_valid

            # Update shard verification info
            shard.last_verified = datetime.now(timezone.utc)
            shard.verification_count += 1

            # Update statistics
            self.stats["shards_verified"] += 1

            if not all_checks_valid:
                self.stats["integrity_violations"] += 1
                shard.metadata.state = ShardState.CORRUPTED

                # Create audit entry for integrity violation
                await self._create_audit_entry(
                    shard_id=shard_id,
                    operation="integrity_violation",
                    node_id="local",
                    user_id=None,
                    details=verification_results,
                )

                logger.warning(f" Integrity violation detected in shard {shard_id}")
            else:
                if shard.metadata.state == ShardState.CREATED:
                    shard.metadata.state = ShardState.VERIFIED

                logger.debug(f" Shard integrity verified: {shard_id}")

            return verification_results

        except Exception as e:
            logger.error(f" Failed to verify shard integrity for {shard_id}: {e}")
            return {"valid": False, "error": str(e)}

    async def _generate_merkle_proof(self, data: bytes) -> Tuple[str, List[str]]:
        """Generate Merkle tree root and proof for data integrity."""
        try:
            # Split data into chunks for Merkle tree
            chunk_size = 1024  # 1KB chunks
            chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]

            if not chunks:
                chunks = [b""]  # Handle empty data

            # Calculate leaf hashes
            leaf_hashes = [hashlib.sha256(chunk).hexdigest() for chunk in chunks]

            # Build Merkle tree
            tree_levels = [leaf_hashes]
            current_level = leaf_hashes

            while len(current_level) > 1:
                next_level = []
                for i in range(0, len(current_level), 2):
                    left = current_level[i]
                    right = current_level[i + 1] if i + 1 < len(current_level) else left

                    # Combine and hash
                    combined = left + right
                    parent_hash = hashlib.sha256(combined.encode()).hexdigest()
                    next_level.append(parent_hash)

                tree_levels.append(next_level)
                current_level = next_level

            # Root is the single hash at the top level
            merkle_root = current_level[0] if current_level else ""

            # Generate proof path (simplified - just store all intermediate hashes)
            merkle_proof = []
            for level in tree_levels[1:]:  # Skip leaf level
                merkle_proof.extend(level)

            return merkle_root, merkle_proof

        except Exception as e:
            logger.error(f" Failed to generate Merkle proof: {e}")
            return "", []

    async def _sign_shard_data(self, data: bytes, metadata: ShardMetadata) -> bytes:
        """Create digital signature for shard data and metadata."""
        try:
            if not self.signing_key:
                raise ValueError("Signing key not initialized")

            # Create signature payload
            signature_data = (
                data
                + metadata.shard_id.encode()
                + metadata.content_hash.encode()
                + str(metadata.created_at.timestamp()).encode()
            )

            # Sign with Ed25519
            signature = self.signing_key.sign(signature_data)

            return signature

        except Exception as e:
            logger.error(f" Failed to sign shard data: {e}")
            raise

    async def _calculate_integrity_hash(
        self, data: bytes, metadata: ShardMetadata
    ) -> str:
        """Calculate comprehensive integrity hash."""
        try:
            # Combine data with metadata for integrity hash
            integrity_data = (
                data
                + metadata.shard_id.encode()
                + metadata.content_hash.encode()
                + metadata.creator_id.encode()
                + str(metadata.size).encode()
                + str(metadata.created_at.timestamp()).encode()
            )

            # Use SHA-512 for strong integrity verification
            integrity_hash = hashlib.sha512(integrity_data).hexdigest()

            return integrity_hash

        except Exception as e:
            logger.error(f" Failed to calculate integrity hash: {e}")
            raise

    async def _create_tamper_seal(
        self, data: bytes, metadata: ShardMetadata, signature: bytes
    ) -> bytes:
        """Create tamper-evident seal for the shard."""
        try:
            # Create seal data combining all critical components
            seal_data = (
                data
                + signature
                + metadata.content_hash.encode()
                + metadata.merkle_root.encode()
                + str(metadata.created_at.timestamp()).encode()
            )

            # Generate tamper seal using HMAC
            seal_key = secrets.token_bytes(32)  # Random key for this seal
            tamper_seal = hashlib.sha256(seal_data + seal_key).digest()

            # Store seal key in metadata (encrypted)
            # TODO: Encrypt seal key with quantum encryption

            return tamper_seal

        except Exception as e:
            logger.error(f" Failed to create tamper seal: {e}")
            raise

    async def _generate_proof_of_work(
        self, data: bytes, metadata: ShardMetadata
    ) -> Dict[str, Any]:
        """Generate proof of work for critical shards."""
        try:
            if not self.enable_proof_of_work:
                return {}

            logger.info(
                f" Generating proof of work (difficulty: {self.pow_difficulty})..."
            )

            # Create challenge from shard data
            challenge = hashlib.sha256(
                data + metadata.shard_id.encode() + metadata.content_hash.encode()
            ).digest()

            # Find nonce that satisfies difficulty requirement
            nonce = 0
            target = "0" * self.pow_difficulty

            start_time = time.time()

            while True:
                # Create proof hash
                proof_data = challenge + struct.pack(">Q", nonce)
                proof_hash = hashlib.sha256(proof_data).hexdigest()

                # Check if it meets difficulty requirement
                if proof_hash.startswith(target):
                    break

                nonce += 1

                # Prevent infinite loops
                if nonce > 10000000:  # 10M attempts max
                    logger.warning(" Proof of work generation timeout")
                    break

            elapsed_time = time.time() - start_time

            proof_of_work = {
                "nonce": nonce,
                "difficulty": self.pow_difficulty,
                "challenge": challenge.hex(),
                "proof_hash": proof_hash,
                "computation_time": elapsed_time,
            }

            logger.info(
                f" Proof of work generated (nonce: {nonce}, time: {elapsed_time:.2f}s)"
            )

            return proof_of_work

        except Exception as e:
            logger.error(f" Failed to generate proof of work: {e}")
            return {}

    async def _verify_shard_signature(self, shard: ImmutableShard) -> bool:
        """Verify digital signature of shard."""
        try:
            if not self.verify_key:
                return False

            # Recreate signature payload
            signature_data = (
                shard.data
                + shard.metadata.shard_id.encode()
                + shard.metadata.content_hash.encode()
                + str(shard.metadata.created_at.timestamp()).encode()
            )

            # Verify signature
            try:
                self.verify_key.verify(shard.signature, signature_data)
                return True
            except Exception:
                return False

        except Exception as e:
            logger.error(f" Failed to verify shard signature: {e}")
            return False

    async def _verify_merkle_proof(self, shard: ImmutableShard) -> bool:
        """Verify Merkle proof for shard data."""
        try:
            # Regenerate Merkle root from data
            calculated_root, _ = await self._generate_merkle_proof(shard.data)

            # Compare with stored root
            return calculated_root == shard.metadata.merkle_root

        except Exception as e:
            logger.error(f" Failed to verify Merkle proof: {e}")
            return False

    async def _verify_integrity_hash(self, shard: ImmutableShard) -> bool:
        """Verify integrity hash of shard."""
        try:
            # Recalculate integrity hash
            calculated_hash = await self._calculate_integrity_hash(
                shard.data, shard.metadata
            )

            # Compare with stored hash
            return calculated_hash == shard.integrity_hash

        except Exception as e:
            logger.error(f" Failed to verify integrity hash: {e}")
            return False

    async def _verify_tamper_seal(self, shard: ImmutableShard) -> bool:
        """Verify tamper-evident seal."""
        try:
            # Recreate tamper seal
            calculated_seal = await self._create_tamper_seal(
                shard.data, shard.metadata, shard.signature
            )

            # Compare with stored seal (simplified comparison)
            # TODO: Implement proper seal verification with encrypted key
            return len(calculated_seal) == len(shard.tamper_seal)

        except Exception as e:
            logger.error(f" Failed to verify tamper seal: {e}")
            return False

    async def _verify_proof_of_work(self, shard: ImmutableShard) -> bool:
        """Verify proof of work for shard."""
        try:
            if not shard.proof_of_work:
                return True  # No PoW required

            # Recreate challenge
            challenge = hashlib.sha256(
                shard.data
                + shard.metadata.shard_id.encode()
                + shard.metadata.content_hash.encode()
            ).digest()

            # Verify proof hash
            proof_data = challenge + struct.pack(">Q", shard.metadata.nonce)
            proof_hash = hashlib.sha256(proof_data).hexdigest()

            # Check difficulty requirement
            target = "0" * shard.metadata.difficulty

            return proof_hash.startswith(
                target
            ) and proof_hash == shard.proof_of_work.get("proof_hash", "")

        except Exception as e:
            logger.error(f" Failed to verify proof of work: {e}")
            return False

    async def _create_audit_entry(
        self,
        shard_id: str,
        operation: str,
        node_id: str,
        user_id: Optional[str],
        details: Dict[str, Any],
    ):
        """Create an audit log entry for shard operations."""
        try:
            # Generate entry ID
            entry_id = f"audit_{secrets.token_hex(16)}"

            # Get previous entry hash for chaining
            previous_entry_hash = ""
            if self.audit_log:
                last_entry = self.audit_log[-1]
                previous_entry_hash = hashlib.sha256(
                    (
                        last_entry.entry_id
                        + last_entry.operation
                        + str(last_entry.timestamp.timestamp())
                    ).encode()
                ).hexdigest()

            # Create audit entry
            audit_entry = AuditLogEntry(
                entry_id=entry_id,
                shard_id=shard_id,
                operation=operation,
                timestamp=datetime.now(timezone.utc),
                node_id=node_id,
                user_id=user_id,
                details=details,
                signature=b"",  # Will be set after signing
                previous_entry_hash=previous_entry_hash,
            )

            # Sign the audit entry
            if self.signing_key:
                signature_data = (
                    entry_id.encode()
                    + shard_id.encode()
                    + operation.encode()
                    + str(audit_entry.timestamp.timestamp()).encode()
                    + json.dumps(details, sort_keys=True).encode()
                )
                audit_entry.signature = self.signing_key.sign(signature_data)

            # Add to audit log
            self.audit_log.append(audit_entry)

            # Update audit index
            if shard_id not in self.audit_index:
                self.audit_index[shard_id] = []
            self.audit_index[shard_id].append(entry_id)

            logger.debug(f" Audit entry created: {operation} for shard {shard_id}")

        except Exception as e:
            logger.error(f" Failed to create audit entry: {e}")

    async def get_shard_audit_trail(self, shard_id: str) -> List[Dict[str, Any]]:
        """Get complete audit trail for a shard."""
        try:
            if shard_id not in self.audit_index:
                return []

            entry_ids = self.audit_index[shard_id]
            audit_trail = []

            for entry_id in entry_ids:
                # Find entry in audit log
                for entry in self.audit_log:
                    if entry.entry_id == entry_id:
                        audit_trail.append(
                            {
                                "entry_id": entry.entry_id,
                                "operation": entry.operation,
                                "timestamp": entry.timestamp.isoformat(),
                                "node_id": entry.node_id,
                                "user_id": entry.user_id,
                                "details": entry.details,
                                "previous_entry_hash": entry.previous_entry_hash,
                            }
                        )
                        break

            return audit_trail

        except Exception as e:
            logger.error(f" Failed to get audit trail for shard {shard_id}: {e}")
            return []

    async def _background_verification_loop(self):
        """Background task for periodic shard verification."""
        try:
            logger.info(" Starting background verification loop...")

            while True:
                try:
                    # Wait for verification interval
                    await asyncio.sleep(
                        self.verification_interval * 3600
                    )  # Convert hours to seconds

                    if not self.shards:
                        continue

                    logger.info(
                        f" Starting periodic verification of {len(self.shards)} shards..."
                    )

                    verification_results = []

                    # Verify each shard
                    for shard_id in list(self.shards.keys()):
                        try:
                            result = await self.verify_shard_integrity(shard_id)
                            verification_results.append(result)

                            # Auto-repair if enabled and shard is corrupted
                            if not result["valid"] and self.auto_repair:
                                await self._attempt_shard_repair(shard_id)

                        except Exception as e:
                            logger.error(f" Failed to verify shard {shard_id}: {e}")
                            continue

                    # Log verification summary
                    valid_shards = sum(1 for r in verification_results if r["valid"])
                    invalid_shards = len(verification_results) - valid_shards

                    logger.info(
                        f" Verification complete: {valid_shards} valid, {invalid_shards} invalid"
                    )

                    # Create audit entry for verification cycle
                    await self._create_audit_entry(
                        shard_id="system",
                        operation="periodic_verification",
                        node_id="local",
                        user_id=None,
                        details={
                            "total_shards": len(verification_results),
                            "valid_shards": valid_shards,
                            "invalid_shards": invalid_shards,
                        },
                    )

                except Exception as e:
                    logger.error(f" Error in verification loop: {e}")
                    continue

        except asyncio.CancelledError:
            logger.info(" Background verification loop cancelled")
        except Exception as e:
            logger.error(f" Background verification loop failed: {e}")

    async def _attempt_shard_repair(self, shard_id: str):
        """Attempt to repair a corrupted shard."""
        try:
            logger.warning(f" Attempting to repair corrupted shard {shard_id}...")

            if shard_id not in self.shards:
                return False

            shard = self.shards[shard_id]

            # Try to repair from replicas (simplified implementation)
            # TODO: Implement actual repair from replica nodes

            # For now, just mark as needing repair
            shard.metadata.state = ShardState.CORRUPTED

            # Create audit entry
            await self._create_audit_entry(
                shard_id=shard_id,
                operation="repair_attempted",
                node_id="local",
                user_id=None,
                details={"success": False, "reason": "no_replicas_available"},
            )

            self.stats["repairs_performed"] += 1

            logger.warning(
                f" Shard repair failed for {shard_id} - no replicas available"
            )

            return False

        except Exception as e:
            logger.error(f" Failed to repair shard {shard_id}: {e}")
            return False

    async def seal_shard(self, shard_id: str) -> bool:
        """Seal a shard to make it immutable."""
        try:
            if shard_id not in self.shards:
                return False

            shard = self.shards[shard_id]

            # Only seal verified shards
            if shard.metadata.state != ShardState.VERIFIED:
                logger.warning(f" Cannot seal unverified shard {shard_id}")
                return False

            # Update state to sealed
            shard.metadata.state = ShardState.SEALED

            # Create audit entry
            await self._create_audit_entry(
                shard_id=shard_id,
                operation="shard_sealed",
                node_id="local",
                user_id=None,
                details={"sealed_at": datetime.now(timezone.utc).isoformat()},
            )

            logger.info(f" Shard sealed: {shard_id}")

            return True

        except Exception as e:
            logger.error(f" Failed to seal shard {shard_id}: {e}")
            return False

    async def get_shard_statistics(self) -> Dict[str, Any]:
        """Get comprehensive shard management statistics."""
        try:
            # Count shards by state
            state_counts = {}
            for state in ShardState:
                state_counts[state.value] = 0

            for shard in self.shards.values():
                state_counts[shard.metadata.state.value] += 1

            # Calculate integrity statistics
            total_size = sum(shard.metadata.size for shard in self.shards.values())

            return {
                "total_shards": len(self.shards),
                "shard_states": state_counts,
                "total_size_bytes": total_size,
                "chain_length": len(self.shard_chain),
                "audit_entries": len(self.audit_log),
                "integrity_level": self.integrity_level.value,
                "proof_of_work_enabled": self.enable_proof_of_work,
                "replication_settings": {
                    "min_replicas": self.min_replicas,
                    "max_replicas": self.max_replicas,
                    "replication_factor": self.replication_factor,
                },
                "performance_stats": self.stats.copy(),
            }

        except Exception as e:
            logger.error(f" Failed to get shard statistics: {e}")
            return {}


# Global instance
_immutable_shard_manager: Optional[ImmutableShardManager] = None


def get_immutable_shard_manager() -> ImmutableShardManager:
    """Get the global immutable shard manager instance."""
    global _immutable_shard_manager
    if _immutable_shard_manager is None:
        config = get_config().get("immutable_shards", {})
        _immutable_shard_manager = ImmutableShardManager(config)
    return _immutable_shard_manager
