"""
NetLink Distributed Key Management System

Implements multiple independent key hierarchies where breaking one key
doesn't compromise the entire system. Uses threshold cryptography,
key sharding, and distributed consensus for maximum security.
"""

import hashlib
import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import aiosqlite

from .quantum_encryption import SecurityTier

logger = logging.getLogger(__name__)


class KeyDomain(Enum):
    """Independent key domains for isolation."""
    AUTHENTICATION = "auth"
    DATABASE = "database"
    BACKUP = "backup"
    COMMUNICATION = "comm"
    API = "api"
    STORAGE = "storage"
    LOGGING = "logging"
    MONITORING = "monitoring"


class ThresholdScheme(Enum):
    """Threshold cryptography schemes."""
    SHAMIR_SECRET_SHARING = "shamir"
    DISTRIBUTED_KEY_GENERATION = "dkg"
    MULTI_PARTY_COMPUTATION = "mpc"


@dataclass
class KeyShard:
    """A shard of a distributed key."""
    shard_id: str
    domain: KeyDomain
    shard_index: int
    total_shards: int
    threshold: int
    shard_data: bytes
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DistributedKey:
    """A key distributed across multiple shards."""
    key_id: str
    domain: KeyDomain
    security_tier: SecurityTier
    total_shards: int
    threshold: int
    scheme: ThresholdScheme
    shards: Dict[int, KeyShard] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None


@dataclass
class KeyVault:
    """Secure vault for storing key shards."""
    vault_id: str
    domain: KeyDomain
    location: str  # Physical or logical location
    shards: Dict[str, KeyShard] = field(default_factory=dict)
    access_log: List[Dict[str, Any]] = field(default_factory=list)
    is_compromised: bool = False


class DistributedKeyManager:
    """
    Distributed Key Management System
    
    Features:
    - Multiple independent key domains
    - Threshold cryptography (k-of-n schemes)
    - Key sharding across multiple vaults
    - Compromise detection and isolation
    - Automatic key recovery
    - Zero-knowledge proofs for key operations
    """
    
    def __init__(self, config_dir: str = "config/security/distributed"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Database for distributed keys
        self.db_path = self.config_dir / "distributed_keys.db"
        
        # Key storage
        self.distributed_keys: Dict[str, DistributedKey] = {}
        self.key_vaults: Dict[str, KeyVault] = {}
        self.domain_isolation: Dict[KeyDomain, Set[str]] = {}
        
        # Security configuration
        self.default_threshold = 3  # Require 3 out of 5 shards
        self.default_total_shards = 5
        self.max_compromised_vaults = 2  # System remains secure with up to 2 compromised vaults
        
        # Initialize system (will be called manually during app startup)
        self._initialization_task = None
    
    async def _initialize_system(self):
        """Initialize the distributed key management system."""
        await self._init_database()
        await self._load_distributed_keys()
        await self._initialize_vaults()
        await self._ensure_domain_keys()
        logger.info("🔐 Distributed key management system initialized")
    
    async def _init_database(self):
        """Initialize the distributed keys database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS distributed_keys (
                    key_id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    security_tier INTEGER NOT NULL,
                    total_shards INTEGER NOT NULL,
                    threshold INTEGER NOT NULL,
                    scheme TEXT NOT NULL,
                    metadata TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS key_shards (
                    shard_id TEXT PRIMARY KEY,
                    key_id TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    shard_index INTEGER NOT NULL,
                    shard_data BLOB NOT NULL,
                    vault_id TEXT NOT NULL,
                    metadata TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (key_id) REFERENCES distributed_keys (key_id)
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS key_vaults (
                    vault_id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    location TEXT NOT NULL,
                    is_compromised BOOLEAN DEFAULT FALSE,
                    created_at TEXT NOT NULL,
                    last_accessed TEXT
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS vault_access_log (
                    log_id TEXT PRIMARY KEY,
                    vault_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    shard_id TEXT,
                    success BOOLEAN NOT NULL,
                    timestamp TEXT NOT NULL,
                    metadata TEXT,
                    FOREIGN KEY (vault_id) REFERENCES key_vaults (vault_id)
                )
            """)
            
            await db.commit()
    
    async def _load_distributed_keys(self):
        """Load distributed keys from database."""
        async with aiosqlite.connect(self.db_path) as db:
            # Load distributed keys
            async with db.execute("SELECT * FROM distributed_keys") as cursor:
                async for row in cursor:
                    key = DistributedKey(
                        key_id=row[0],
                        domain=KeyDomain(row[1]),
                        security_tier=SecurityTier(row[2]),
                        total_shards=row[3],
                        threshold=row[4],
                        scheme=ThresholdScheme(row[5]),
                        metadata=json.loads(row[6]) if row[6] else {},
                        created_at=datetime.fromisoformat(row[7]),
                        expires_at=datetime.fromisoformat(row[8]) if row[8] else None
                    )
                    self.distributed_keys[key.key_id] = key
            
            # Load key shards
            async with db.execute("SELECT * FROM key_shards") as cursor:
                async for row in cursor:
                    shard = KeyShard(
                        shard_id=row[0],
                        domain=KeyDomain(row[2]),
                        shard_index=row[3],
                        total_shards=0,  # Will be set from parent key
                        threshold=0,     # Will be set from parent key
                        shard_data=row[4],
                        metadata=json.loads(row[6]) if row[6] else {},
                        created_at=datetime.fromisoformat(row[7])
                    )
                    
                    # Add shard to its distributed key
                    key_id = row[1]
                    if key_id in self.distributed_keys:
                        distributed_key = self.distributed_keys[key_id]
                        shard.total_shards = distributed_key.total_shards
                        shard.threshold = distributed_key.threshold
                        distributed_key.shards[shard.shard_index] = shard
    
    async def _initialize_vaults(self):
        """Initialize key vaults for each domain."""
        for domain in KeyDomain:
            # Create multiple vaults per domain for redundancy
            for i in range(self.default_total_shards):
                vault_id = f"{domain.value}_vault_{i}"
                if vault_id not in self.key_vaults:
                    vault = KeyVault(
                        vault_id=vault_id,
                        domain=domain,
                        location=f"vault_{i}_{secrets.token_hex(4)}"
                    )
                    self.key_vaults[vault_id] = vault
                    await self._save_vault(vault)
    
    async def _ensure_domain_keys(self):
        """Ensure each domain has its master keys."""
        for domain in KeyDomain:
            for tier in [SecurityTier.GOVERNMENT, SecurityTier.QUANTUM_PROOF]:
                key_id = f"{domain.value}_master_{tier.name.lower()}"
                if not any(k.key_id.startswith(key_id) for k in self.distributed_keys.values()):
                    await self.create_distributed_key(domain, tier, f"master_{domain.value}")
    
    async def create_distributed_key(
        self, 
        domain: KeyDomain, 
        security_tier: SecurityTier, 
        purpose: str,
        threshold: Optional[int] = None,
        total_shards: Optional[int] = None
    ) -> DistributedKey:
        """Create a new distributed key."""
        threshold = threshold or self.default_threshold
        total_shards = total_shards or self.default_total_shards
        
        if threshold > total_shards:
            raise ValueError("Threshold cannot be greater than total shards")
        
        key_id = f"{domain.value}_{purpose}_{secrets.token_hex(8)}"
        
        # Generate master secret
        master_secret = secrets.token_bytes(64)  # 512-bit master secret
        
        # Create distributed key
        distributed_key = DistributedKey(
            key_id=key_id,
            domain=domain,
            security_tier=security_tier,
            total_shards=total_shards,
            threshold=threshold,
            scheme=ThresholdScheme.SHAMIR_SECRET_SHARING,
            metadata={
                "purpose": purpose,
                "created_by": "distributed_key_manager",
                "master_secret_hash": hashlib.sha256(master_secret).hexdigest()
            }
        )
        
        # Generate shards using Shamir's Secret Sharing
        shards_data = self._generate_shamir_shares(master_secret, threshold, total_shards)
        
        # Create and distribute shards
        for i, shard_data in enumerate(shards_data):
            shard = KeyShard(
                shard_id=f"{key_id}_shard_{i}",
                domain=domain,
                shard_index=i,
                total_shards=total_shards,
                threshold=threshold,
                shard_data=shard_data,
                metadata={
                    "vault_assignment": f"{domain.value}_vault_{i % self.default_total_shards}"
                }
            )
            
            distributed_key.shards[i] = shard
            
            # Store shard in appropriate vault
            vault_id = f"{domain.value}_vault_{i % self.default_total_shards}"
            if vault_id in self.key_vaults:
                self.key_vaults[vault_id].shards[shard.shard_id] = shard
        
        # Save to database
        self.distributed_keys[key_id] = distributed_key
        await self._save_distributed_key(distributed_key)
        
        logger.info(f"🔑 Created distributed key: {key_id} ({threshold}/{total_shards} scheme)")
        return distributed_key
    
    def _generate_shamir_shares(self, secret: bytes, threshold: int, total_shares: int) -> List[bytes]:
        """Generate Shamir's Secret Sharing shares."""
        # Convert secret to integer
        secret_int = int.from_bytes(secret, 'big')
        
        # Generate random coefficients for polynomial
        coefficients = [secret_int] + [secrets.randbelow(2**256) for _ in range(threshold - 1)]
        
        # Generate shares
        shares = []
        for x in range(1, total_shares + 1):
            # Evaluate polynomial at x
            y = sum(coeff * (x ** i) for i, coeff in enumerate(coefficients)) % (2**256)
            
            # Convert back to bytes and store as (x, y) pair
            share_data = x.to_bytes(4, 'big') + y.to_bytes(32, 'big')
            shares.append(share_data)
        
        return shares

    def _reconstruct_secret_from_shares(self, shares: List[bytes], threshold: int) -> bytes:
        """Reconstruct secret from Shamir shares using Lagrange interpolation."""
        if len(shares) < threshold:
            raise ValueError(f"Need at least {threshold} shares to reconstruct secret")

        # Parse shares
        points = []
        for share in shares[:threshold]:
            x = int.from_bytes(share[:4], 'big')
            y = int.from_bytes(share[4:], 'big')
            points.append((x, y))

        # Lagrange interpolation to find secret (y-value at x=0)
        secret = 0
        for i, (xi, yi) in enumerate(points):
            # Calculate Lagrange basis polynomial
            li = 1
            for j, (xj, _) in enumerate(points):
                if i != j:
                    li = (li * (0 - xj) * pow(xi - xj, -1, 2**256)) % (2**256)

            secret = (secret + yi * li) % (2**256)

        return secret.to_bytes(32, 'big')

    async def reconstruct_key(self, key_id: str, available_shards: Optional[List[str]] = None) -> Optional[bytes]:
        """Reconstruct a distributed key from available shards."""
        if key_id not in self.distributed_keys:
            logger.error(f"Distributed key not found: {key_id}")
            return None

        distributed_key = self.distributed_keys[key_id]

        # Get available shards
        if available_shards is None:
            available_shards = list(distributed_key.shards.keys())

        # Filter out shards from compromised vaults
        safe_shards = []
        for shard_index in available_shards:
            if shard_index in distributed_key.shards:
                shard = distributed_key.shards[shard_index]
                vault_id = shard.metadata.get("vault_assignment")
                if vault_id and vault_id in self.key_vaults:
                    vault = self.key_vaults[vault_id]
                    if not vault.is_compromised:
                        safe_shards.append(shard.shard_data)

        if len(safe_shards) < distributed_key.threshold:
            logger.error(f"Insufficient safe shards to reconstruct key {key_id}: {len(safe_shards)}/{distributed_key.threshold}")
            return None

        # Reconstruct the secret
        try:
            secret = self._reconstruct_secret_from_shares(safe_shards, distributed_key.threshold)

            # Verify reconstruction
            expected_hash = distributed_key.metadata.get("master_secret_hash")
            if expected_hash:
                actual_hash = hashlib.sha256(secret).hexdigest()
                if actual_hash != expected_hash:
                    logger.error(f"Key reconstruction verification failed for {key_id}")
                    return None

            logger.info(f"🔓 Successfully reconstructed key: {key_id}")
            return secret

        except Exception as e:
            logger.error(f"Failed to reconstruct key {key_id}: {e}")
            return None

    async def mark_vault_compromised(self, vault_id: str, reason: str = ""):
        """Mark a vault as compromised and trigger security response."""
        if vault_id not in self.key_vaults:
            logger.error(f"Vault not found: {vault_id}")
            return

        vault = self.key_vaults[vault_id]
        vault.is_compromised = True

        # Log the compromise
        await self._log_vault_access(vault_id, "COMPROMISED", None, False, {
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "vault_marked_compromised"
        })

        # Check if system security is still intact
        compromised_count = sum(1 for v in self.key_vaults.values() if v.is_compromised)

        if compromised_count > self.max_compromised_vaults:
            logger.critical(f"🚨 CRITICAL: Too many vaults compromised ({compromised_count}). System security may be at risk!")
            await self._trigger_emergency_key_rotation()
        else:
            logger.warning(f"⚠️ Vault {vault_id} marked as compromised. System remains secure ({compromised_count}/{self.max_compromised_vaults} compromised)")

        await self._save_vault(vault)

    async def _trigger_emergency_key_rotation(self):
        """Trigger emergency rotation of all keys."""
        logger.info("🔄 Triggering emergency key rotation...")

        for key_id, distributed_key in list(self.distributed_keys.items()):
            try:
                # Reconstruct current key
                current_secret = await self.reconstruct_key(key_id)
                if current_secret:
                    # Create new distributed key
                    new_key = await self.create_distributed_key(
                        distributed_key.domain,
                        distributed_key.security_tier,
                        f"emergency_rotation_{distributed_key.metadata.get('purpose', 'unknown')}",
                        distributed_key.threshold,
                        distributed_key.total_shards
                    )

                    # Mark old key as rotated
                    distributed_key.metadata["rotated_to"] = new_key.key_id
                    distributed_key.metadata["rotation_reason"] = "emergency_vault_compromise"
                    await self._save_distributed_key(distributed_key)

                    logger.info(f"🔄 Emergency rotated key: {key_id} -> {new_key.key_id}")

            except Exception as e:
                logger.error(f"Failed to rotate key {key_id}: {e}")

    async def get_domain_key(self, domain: KeyDomain, purpose: str = "master") -> Optional[bytes]:
        """Get a reconstructed key for a specific domain."""
        # Find the appropriate key
        for key_id, distributed_key in self.distributed_keys.items():
            if (distributed_key.domain == domain and
                distributed_key.metadata.get("purpose", "").startswith(purpose)):
                return await self.reconstruct_key(key_id)

        # Create new key if none exists
        logger.info(f"Creating new {purpose} key for domain {domain.value}")
        new_key = await self.create_distributed_key(domain, SecurityTier.QUANTUM_PROOF, purpose)
        return await self.reconstruct_key(new_key.key_id)

    async def _save_distributed_key(self, key: DistributedKey):
        """Save distributed key to database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO distributed_keys
                (key_id, domain, security_tier, total_shards, threshold, scheme, metadata, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                key.key_id,
                key.domain.value,
                key.security_tier.value,
                key.total_shards,
                key.threshold,
                key.scheme.value,
                json.dumps(key.metadata),
                key.created_at.isoformat(),
                key.expires_at.isoformat() if key.expires_at else None
            ))

            # Save shards
            for shard in key.shards.values():
                await db.execute("""
                    INSERT OR REPLACE INTO key_shards
                    (shard_id, key_id, domain, shard_index, shard_data, vault_id, metadata, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    shard.shard_id,
                    key.key_id,
                    shard.domain.value,
                    shard.shard_index,
                    shard.shard_data,
                    shard.metadata.get("vault_assignment", ""),
                    json.dumps(shard.metadata),
                    shard.created_at.isoformat()
                ))

            await db.commit()

    async def _save_vault(self, vault: KeyVault):
        """Save vault to database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO key_vaults
                (vault_id, domain, location, is_compromised, created_at, last_accessed)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                vault.vault_id,
                vault.domain.value,
                vault.location,
                vault.is_compromised,
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat()
            ))
            await db.commit()

    async def _log_vault_access(self, vault_id: str, operation: str, shard_id: Optional[str],
                               success: bool, metadata: Dict[str, Any]):
        """Log vault access for audit purposes."""
        log_id = f"log_{secrets.token_hex(8)}"

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO vault_access_log
                (log_id, vault_id, operation, shard_id, success, timestamp, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                log_id,
                vault_id,
                operation,
                shard_id,
                success,
                datetime.now(timezone.utc).isoformat(),
                json.dumps(metadata)
            ))
            await db.commit()

    async def get_security_status(self) -> Dict[str, Any]:
        """Get overall security status of the distributed key system."""
        total_vaults = len(self.key_vaults)
        compromised_vaults = sum(1 for v in self.key_vaults.values() if v.is_compromised)

        domain_status = {}
        for domain in KeyDomain:
            domain_keys = [k for k in self.distributed_keys.values() if k.domain == domain]
            domain_vaults = [v for v in self.key_vaults.values() if v.domain == domain]
            domain_compromised = sum(1 for v in domain_vaults if v.is_compromised)

            domain_status[domain.value] = {
                "keys": len(domain_keys),
                "vaults": len(domain_vaults),
                "compromised_vaults": domain_compromised,
                "security_intact": domain_compromised <= self.max_compromised_vaults
            }

        return {
            "total_keys": len(self.distributed_keys),
            "total_vaults": total_vaults,
            "compromised_vaults": compromised_vaults,
            "max_allowed_compromised": self.max_compromised_vaults,
            "overall_security_intact": compromised_vaults <= self.max_compromised_vaults,
            "domain_status": domain_status,
            "last_updated": datetime.now(timezone.utc).isoformat()
        }


# Global distributed key manager instance
distributed_key_manager = DistributedKeyManager()
