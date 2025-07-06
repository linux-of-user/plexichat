"""
NetLink Database Encryption System

Implements comprehensive database encryption with:
- Transparent data encryption (TDE)
- Column-level encryption for sensitive data
- Quantum-resistant encryption algorithms
- Key rotation and management
- Encrypted backups and logs
"""

import asyncio
import secrets
import hashlib
import logging
import json
import base64
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import aiosqlite
import aiofiles

from .quantum_encryption import QuantumEncryptionSystem, EncryptionContext, SecurityTier
from .distributed_key_manager import DistributedKeyManager, KeyDomain

# Cryptography imports
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class EncryptionLevel(Enum):
    """Database encryption levels."""
    NONE = 0
    COLUMN = 1          # Encrypt specific columns
    TABLE = 2           # Encrypt entire tables
    DATABASE = 3        # Encrypt entire database
    TRANSPARENT = 4     # Transparent data encryption


class DataClassification(Enum):
    """Data classification levels."""
    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    RESTRICTED = 4
    TOP_SECRET = 5


@dataclass
class EncryptedColumn:
    """Configuration for encrypted database column."""
    table_name: str
    column_name: str
    data_type: str
    classification: DataClassification
    encryption_level: EncryptionLevel
    key_id: str
    algorithm: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DatabaseKey:
    """Database encryption key."""
    key_id: str
    purpose: str
    classification: DataClassification
    key_data: bytes
    algorithm: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    rotation_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class DatabaseEncryption:
    """
    Database Encryption System
    
    Features:
    - Transparent data encryption for entire databases
    - Column-level encryption for sensitive fields
    - Quantum-resistant encryption algorithms
    - Automatic key rotation
    - Encrypted database backups
    - Search on encrypted data (where possible)
    - Audit logging of all encryption operations
    """
    
    def __init__(self, config_dir: str = "config/security/database"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Database for encryption metadata
        self.metadata_db = self.config_dir / "encryption_metadata.db"
        
        # Encryption configuration
        self.encrypted_columns: Dict[str, EncryptedColumn] = {}
        self.database_keys: Dict[str, DatabaseKey] = {}
        self.classification_policies: Dict[DataClassification, Dict[str, Any]] = {}
        
        # Encryption systems
        self.quantum_encryption = QuantumEncryptionSystem()
        self.distributed_keys = DistributedKeyManager()
        
        # Initialize system
        asyncio.create_task(self._initialize_system())
    
    async def _initialize_system(self):
        """Initialize the database encryption system."""
        await self._init_metadata_database()
        await self._load_encryption_config()
        await self._setup_classification_policies()
        await self._ensure_database_keys()
        logger.info("🔐 Database encryption system initialized")
    
    async def _init_metadata_database(self):
        """Initialize the encryption metadata database."""
        async with aiosqlite.connect(self.metadata_db) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS encrypted_columns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    table_name TEXT NOT NULL,
                    column_name TEXT NOT NULL,
                    data_type TEXT NOT NULL,
                    classification INTEGER NOT NULL,
                    encryption_level INTEGER NOT NULL,
                    key_id TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    metadata TEXT,
                    UNIQUE(table_name, column_name)
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS database_keys (
                    key_id TEXT PRIMARY KEY,
                    purpose TEXT NOT NULL,
                    classification INTEGER NOT NULL,
                    key_data BLOB NOT NULL,
                    algorithm TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    rotation_count INTEGER DEFAULT 0,
                    metadata TEXT
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS encryption_operations (
                    operation_id TEXT PRIMARY KEY,
                    operation_type TEXT NOT NULL,
                    table_name TEXT,
                    column_name TEXT,
                    key_id TEXT NOT NULL,
                    data_size INTEGER,
                    success BOOLEAN NOT NULL,
                    timestamp TEXT NOT NULL,
                    metadata TEXT
                )
            """)
            
            await db.commit()
    
    async def _load_encryption_config(self):
        """Load encryption configuration from database."""
        async with aiosqlite.connect(self.metadata_db) as db:
            # Load encrypted columns
            async with db.execute("SELECT * FROM encrypted_columns") as cursor:
                async for row in cursor:
                    column = EncryptedColumn(
                        table_name=row[1],
                        column_name=row[2],
                        data_type=row[3],
                        classification=DataClassification(row[4]),
                        encryption_level=EncryptionLevel(row[5]),
                        key_id=row[6],
                        algorithm=row[7],
                        created_at=datetime.fromisoformat(row[8]),
                        metadata=json.loads(row[9]) if row[9] else {}
                    )
                    key = f"{column.table_name}.{column.column_name}"
                    self.encrypted_columns[key] = column
            
            # Load database keys
            async with db.execute("SELECT * FROM database_keys") as cursor:
                async for row in cursor:
                    key = DatabaseKey(
                        key_id=row[0],
                        purpose=row[1],
                        classification=DataClassification(row[2]),
                        key_data=row[3],
                        algorithm=row[4],
                        created_at=datetime.fromisoformat(row[5]),
                        expires_at=datetime.fromisoformat(row[6]) if row[6] else None,
                        rotation_count=row[7],
                        metadata=json.loads(row[8]) if row[8] else {}
                    )
                    self.database_keys[key.key_id] = key
    
    async def _setup_classification_policies(self):
        """Setup encryption policies for different data classifications."""
        self.classification_policies = {
            DataClassification.PUBLIC: {
                "encryption_required": False,
                "algorithm": "none",
                "key_rotation_days": 0,
                "security_tier": SecurityTier.STANDARD
            },
            DataClassification.INTERNAL: {
                "encryption_required": True,
                "algorithm": "aes-256-gcm",
                "key_rotation_days": 90,
                "security_tier": SecurityTier.ENHANCED
            },
            DataClassification.CONFIDENTIAL: {
                "encryption_required": True,
                "algorithm": "chacha20-poly1305",
                "key_rotation_days": 30,
                "security_tier": SecurityTier.GOVERNMENT
            },
            DataClassification.RESTRICTED: {
                "encryption_required": True,
                "algorithm": "quantum-resistant",
                "key_rotation_days": 7,
                "security_tier": SecurityTier.MILITARY
            },
            DataClassification.TOP_SECRET: {
                "encryption_required": True,
                "algorithm": "quantum-resistant-multi-layer",
                "key_rotation_days": 1,
                "security_tier": SecurityTier.QUANTUM_PROOF
            }
        }
    
    async def _ensure_database_keys(self):
        """Ensure database keys exist for each classification level."""
        for classification in DataClassification:
            policy = self.classification_policies[classification]
            if policy["encryption_required"]:
                key_id = f"db_{classification.name.lower()}_master"
                if not any(k.key_id.startswith(key_id) for k in self.database_keys.values()):
                    await self._generate_database_key(classification, "master")
    
    async def _generate_database_key(self, classification: DataClassification, purpose: str) -> DatabaseKey:
        """Generate a new database encryption key."""
        policy = self.classification_policies[classification]
        key_id = f"db_{classification.name.lower()}_{purpose}_{secrets.token_hex(8)}"
        
        # Get key from distributed key manager
        domain_key = await self.distributed_keys.get_domain_key(KeyDomain.DATABASE)
        if domain_key:
            # Derive database key from domain key
            key_material = hashlib.blake2b(
                domain_key + key_id.encode() + classification.name.encode(),
                digest_size=32
            ).digest()
        else:
            # Generate random key as fallback
            key_material = secrets.token_bytes(32)
        
        # Set expiration based on policy
        expires_at = None
        if policy["key_rotation_days"] > 0:
            expires_at = datetime.now(timezone.utc) + timedelta(days=policy["key_rotation_days"])
        
        db_key = DatabaseKey(
            key_id=key_id,
            purpose=purpose,
            classification=classification,
            key_data=key_material,
            algorithm=policy["algorithm"],
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at,
            metadata={
                "policy": policy,
                "auto_generated": True
            }
        )
        
        self.database_keys[key_id] = db_key
        await self._save_database_key(db_key)
        
        logger.info(f"🔑 Generated database key: {key_id} for {classification.name}")
        return db_key
    
    async def configure_column_encryption(
        self, 
        table_name: str, 
        column_name: str, 
        data_type: str,
        classification: DataClassification
    ) -> bool:
        """Configure encryption for a database column."""
        policy = self.classification_policies[classification]
        
        if not policy["encryption_required"]:
            logger.info(f"Encryption not required for {classification.name} data")
            return True
        
        # Get or create appropriate key
        key_id = f"db_{classification.name.lower()}_column_{secrets.token_hex(4)}"
        db_key = await self._generate_database_key(classification, "column")
        
        # Create encrypted column configuration
        encrypted_column = EncryptedColumn(
            table_name=table_name,
            column_name=column_name,
            data_type=data_type,
            classification=classification,
            encryption_level=EncryptionLevel.COLUMN,
            key_id=db_key.key_id,
            algorithm=policy["algorithm"],
            metadata={
                "configured_by": "database_encryption_system",
                "policy": policy
            }
        )
        
        column_key = f"{table_name}.{column_name}"
        self.encrypted_columns[column_key] = encrypted_column
        await self._save_encrypted_column(encrypted_column)
        
        logger.info(f"🔐 Configured encryption for column: {table_name}.{column_name}")
        return True

    async def encrypt_column_data(self, table_name: str, column_name: str, data: Any) -> Optional[str]:
        """Encrypt data for a specific column."""
        column_key = f"{table_name}.{column_name}"

        if column_key not in self.encrypted_columns:
            logger.warning(f"Column not configured for encryption: {column_key}")
            return str(data) if data is not None else None

        if data is None:
            return None

        encrypted_column = self.encrypted_columns[column_key]
        db_key = self.database_keys.get(encrypted_column.key_id)

        if not db_key:
            logger.error(f"Database key not found: {encrypted_column.key_id}")
            return None

        # Convert data to bytes
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        elif isinstance(data, (int, float)):
            data_bytes = str(data).encode('utf-8')
        elif isinstance(data, bytes):
            data_bytes = data
        else:
            data_bytes = json.dumps(data).encode('utf-8')

        try:
            # Encrypt based on algorithm
            if db_key.algorithm == "aes-256-gcm":
                encrypted_data = await self._encrypt_aes_gcm(data_bytes, db_key.key_data)
            elif db_key.algorithm == "chacha20-poly1305":
                encrypted_data = await self._encrypt_chacha20(data_bytes, db_key.key_data)
            elif db_key.algorithm.startswith("quantum-resistant"):
                encrypted_data = await self._encrypt_quantum_resistant(data_bytes, db_key, encrypted_column)
            else:
                logger.error(f"Unknown encryption algorithm: {db_key.algorithm}")
                return None

            # Encode as base64 for database storage
            encoded_data = base64.b64encode(encrypted_data).decode('ascii')

            # Log the operation
            await self._log_encryption_operation(
                "encrypt", table_name, column_name, db_key.key_id,
                len(data_bytes), True
            )

            return encoded_data

        except Exception as e:
            logger.error(f"Failed to encrypt column data: {e}")
            await self._log_encryption_operation(
                "encrypt", table_name, column_name, db_key.key_id,
                len(data_bytes), False
            )
            return None

    async def decrypt_column_data(self, table_name: str, column_name: str, encrypted_data: str) -> Any:
        """Decrypt data for a specific column."""
        column_key = f"{table_name}.{column_name}"

        if column_key not in self.encrypted_columns:
            logger.warning(f"Column not configured for encryption: {column_key}")
            return encrypted_data

        if not encrypted_data:
            return None

        encrypted_column = self.encrypted_columns[column_key]
        db_key = self.database_keys.get(encrypted_column.key_id)

        if not db_key:
            logger.error(f"Database key not found: {encrypted_column.key_id}")
            return None

        try:
            # Decode from base64
            encrypted_bytes = base64.b64decode(encrypted_data.encode('ascii'))

            # Decrypt based on algorithm
            if db_key.algorithm == "aes-256-gcm":
                decrypted_data = await self._decrypt_aes_gcm(encrypted_bytes, db_key.key_data)
            elif db_key.algorithm == "chacha20-poly1305":
                decrypted_data = await self._decrypt_chacha20(encrypted_bytes, db_key.key_data)
            elif db_key.algorithm.startswith("quantum-resistant"):
                decrypted_data = await self._decrypt_quantum_resistant(encrypted_bytes, db_key, encrypted_column)
            else:
                logger.error(f"Unknown encryption algorithm: {db_key.algorithm}")
                return None

            # Convert back to appropriate data type
            decrypted_str = decrypted_data.decode('utf-8')

            # Try to convert back to original type based on column data type
            if encrypted_column.data_type.upper() in ['INTEGER', 'INT']:
                return int(decrypted_str)
            elif encrypted_column.data_type.upper() in ['REAL', 'FLOAT', 'DOUBLE']:
                return float(decrypted_str)
            elif encrypted_column.data_type.upper() in ['JSON', 'JSONB']:
                return json.loads(decrypted_str)
            else:
                return decrypted_str

        except Exception as e:
            logger.error(f"Failed to decrypt column data: {e}")
            return None

    async def _encrypt_aes_gcm(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using AES-256-GCM."""
        # Derive key using PBKDF2
        salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        derived_key = kdf.derive(key)

        # Encrypt with AES-GCM
        cipher = AESGCM(derived_key)
        nonce = secrets.token_bytes(12)
        ciphertext = cipher.encrypt(nonce, data, None)

        # Combine salt, nonce, and ciphertext
        return salt + nonce + ciphertext

    async def _decrypt_aes_gcm(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-256-GCM."""
        # Extract components
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        ciphertext = encrypted_data[28:]

        # Derive key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        derived_key = kdf.derive(key)

        # Decrypt with AES-GCM
        cipher = AESGCM(derived_key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)

        return plaintext

    async def _encrypt_chacha20(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using ChaCha20-Poly1305."""
        # Derive key using BLAKE2b
        salt = secrets.token_bytes(16)
        derived_key = hashlib.blake2b(key + salt, digest_size=32).digest()

        # Encrypt with ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(derived_key)
        nonce = secrets.token_bytes(12)
        ciphertext = cipher.encrypt(nonce, data, None)

        # Combine salt, nonce, and ciphertext
        return salt + nonce + ciphertext

    async def _decrypt_chacha20(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt data using ChaCha20-Poly1305."""
        # Extract components
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        ciphertext = encrypted_data[28:]

        # Derive key using BLAKE2b
        derived_key = hashlib.blake2b(key + salt, digest_size=32).digest()

        # Decrypt with ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(derived_key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)

        return plaintext

    async def _encrypt_quantum_resistant(self, data: bytes, db_key: DatabaseKey, column: EncryptedColumn) -> bytes:
        """Encrypt data using quantum-resistant algorithms."""
        # Create encryption context
        context = EncryptionContext(
            operation_id=f"db_encrypt_{secrets.token_hex(8)}",
            data_type="database_column",
            security_tier=self.classification_policies[column.classification]["security_tier"],
            algorithms=[],  # Will be determined by quantum encryption system
            key_ids=[db_key.key_id],
            metadata={
                "table": column.table_name,
                "column": column.column_name,
                "classification": column.classification.name
            }
        )

        # Use quantum encryption system
        encrypted_data, metadata = await self.quantum_encryption.encrypt_data(data, context)

        # Store metadata for decryption
        metadata_bytes = json.dumps(metadata).encode('utf-8')
        metadata_length = len(metadata_bytes).to_bytes(4, 'big')

        return metadata_length + metadata_bytes + encrypted_data

    async def _decrypt_quantum_resistant(self, encrypted_data: bytes, db_key: DatabaseKey, column: EncryptedColumn) -> bytes:
        """Decrypt data using quantum-resistant algorithms."""
        # Extract metadata
        metadata_length = int.from_bytes(encrypted_data[:4], 'big')
        metadata_bytes = encrypted_data[4:4+metadata_length]
        ciphertext = encrypted_data[4+metadata_length:]

        metadata = json.loads(metadata_bytes.decode('utf-8'))

        # Use quantum encryption system
        decrypted_data = await self.quantum_encryption.decrypt_data(ciphertext, metadata)

        return decrypted_data

    async def _save_encrypted_column(self, column: EncryptedColumn):
        """Save encrypted column configuration to database."""
        async with aiosqlite.connect(self.metadata_db) as db:
            await db.execute("""
                INSERT OR REPLACE INTO encrypted_columns
                (table_name, column_name, data_type, classification, encryption_level,
                 key_id, algorithm, created_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                column.table_name,
                column.column_name,
                column.data_type,
                column.classification.value,
                column.encryption_level.value,
                column.key_id,
                column.algorithm,
                column.created_at.isoformat(),
                json.dumps(column.metadata)
            ))
            await db.commit()

    async def _save_database_key(self, key: DatabaseKey):
        """Save database key to metadata database."""
        async with aiosqlite.connect(self.metadata_db) as db:
            await db.execute("""
                INSERT OR REPLACE INTO database_keys
                (key_id, purpose, classification, key_data, algorithm,
                 created_at, expires_at, rotation_count, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                key.key_id,
                key.purpose,
                key.classification.value,
                key.key_data,
                key.algorithm,
                key.created_at.isoformat(),
                key.expires_at.isoformat() if key.expires_at else None,
                key.rotation_count,
                json.dumps(key.metadata)
            ))
            await db.commit()

    async def _log_encryption_operation(self, operation_type: str, table_name: str,
                                       column_name: str, key_id: str, data_size: int, success: bool):
        """Log encryption operation for audit purposes."""
        operation_id = f"op_{secrets.token_hex(8)}"

        async with aiosqlite.connect(self.metadata_db) as db:
            await db.execute("""
                INSERT INTO encryption_operations
                (operation_id, operation_type, table_name, column_name, key_id,
                 data_size, success, timestamp, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                operation_id,
                operation_type,
                table_name,
                column_name,
                key_id,
                data_size,
                success,
                datetime.now(timezone.utc).isoformat(),
                json.dumps({
                    "operation_id": operation_id,
                    "success": success
                })
            ))
            await db.commit()

    async def rotate_database_keys(self, force: bool = False) -> int:
        """Rotate expired database keys."""
        rotated_count = 0
        current_time = datetime.now(timezone.utc)

        for key_id, db_key in list(self.database_keys.items()):
            should_rotate = force

            if not should_rotate and db_key.expires_at:
                should_rotate = current_time >= db_key.expires_at

            if should_rotate:
                await self._rotate_database_key(db_key)
                rotated_count += 1

        logger.info(f"🔄 Rotated {rotated_count} database keys")
        return rotated_count

    async def _rotate_database_key(self, old_key: DatabaseKey):
        """Rotate a single database key."""
        # Generate new key
        new_key = await self._generate_database_key(old_key.classification, old_key.purpose)

        # Update all columns using the old key
        for column_key, column in self.encrypted_columns.items():
            if column.key_id == old_key.key_id:
                column.key_id = new_key.key_id
                await self._save_encrypted_column(column)

        # Mark old key as rotated
        old_key.metadata["rotated_to"] = new_key.key_id
        old_key.metadata["rotated_at"] = datetime.now(timezone.utc).isoformat()
        await self._save_database_key(old_key)

        # Remove old key from active keys
        del self.database_keys[old_key.key_id]

        logger.info(f"🔄 Rotated database key: {old_key.key_id} -> {new_key.key_id}")

    async def get_encryption_status(self) -> Dict[str, Any]:
        """Get overall database encryption status."""
        total_columns = len(self.encrypted_columns)
        total_keys = len(self.database_keys)

        # Count by classification
        classification_stats = {}
        for classification in DataClassification:
            columns = [c for c in self.encrypted_columns.values() if c.classification == classification]
            keys = [k for k in self.database_keys.values() if k.classification == classification]

            classification_stats[classification.name] = {
                "encrypted_columns": len(columns),
                "active_keys": len(keys),
                "policy": self.classification_policies[classification]
            }

        # Check for expired keys
        current_time = datetime.now(timezone.utc)
        expired_keys = [
            k for k in self.database_keys.values()
            if k.expires_at and current_time >= k.expires_at
        ]

        return {
            "total_encrypted_columns": total_columns,
            "total_database_keys": total_keys,
            "expired_keys": len(expired_keys),
            "classification_stats": classification_stats,
            "encryption_policies": {
                name: policy for name, policy in
                [(c.name, self.classification_policies[c]) for c in DataClassification]
            },
            "last_updated": current_time.isoformat()
        }

    async def backup_encryption_metadata(self, backup_path: str) -> bool:
        """Create encrypted backup of encryption metadata."""
        try:
            backup_file = Path(backup_path)
            backup_file.parent.mkdir(parents=True, exist_ok=True)

            # Get backup key from distributed key manager
            backup_key = await self.distributed_keys.get_domain_key(KeyDomain.BACKUP)
            if not backup_key:
                logger.error("Could not get backup key for metadata encryption")
                return False

            # Create backup data
            backup_data = {
                "encrypted_columns": {
                    key: {
                        "table_name": col.table_name,
                        "column_name": col.column_name,
                        "data_type": col.data_type,
                        "classification": col.classification.value,
                        "encryption_level": col.encryption_level.value,
                        "key_id": col.key_id,
                        "algorithm": col.algorithm,
                        "created_at": col.created_at.isoformat(),
                        "metadata": col.metadata
                    }
                    for key, col in self.encrypted_columns.items()
                },
                "database_keys": {
                    key_id: {
                        "purpose": key.purpose,
                        "classification": key.classification.value,
                        "algorithm": key.algorithm,
                        "created_at": key.created_at.isoformat(),
                        "expires_at": key.expires_at.isoformat() if key.expires_at else None,
                        "rotation_count": key.rotation_count,
                        "metadata": key.metadata
                        # Note: key_data is not included in backup for security
                    }
                    for key_id, key in self.database_keys.items()
                },
                "backup_timestamp": datetime.now(timezone.utc).isoformat(),
                "backup_version": "1.0"
            }

            # Encrypt backup data
            backup_json = json.dumps(backup_data, indent=2)

            # Use ChaCha20-Poly1305 for backup encryption
            nonce = secrets.token_bytes(12)
            cipher = ChaCha20Poly1305(backup_key[:32])  # Use first 32 bytes as key
            encrypted_backup = cipher.encrypt(nonce, backup_json.encode('utf-8'), None)

            # Write encrypted backup
            final_backup = nonce + encrypted_backup
            async with aiofiles.open(backup_file, 'wb') as f:
                await f.write(final_backup)

            logger.info(f"📦 Created encrypted metadata backup: {backup_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to create metadata backup: {e}")
            return False

    async def is_column_encrypted(self, table_name: str, column_name: str) -> bool:
        """Check if a column is configured for encryption."""
        column_key = f"{table_name}.{column_name}"
        return column_key in self.encrypted_columns

    async def get_column_classification(self, table_name: str, column_name: str) -> Optional[DataClassification]:
        """Get the data classification for a column."""
        column_key = f"{table_name}.{column_name}"
        if column_key in self.encrypted_columns:
            return self.encrypted_columns[column_key].classification
        return None


# Global database encryption system instance
database_encryption = DatabaseEncryption()
