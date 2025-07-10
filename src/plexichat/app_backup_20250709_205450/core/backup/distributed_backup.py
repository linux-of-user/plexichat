"""
Intelligent Distributed Backup System
Encrypts and distributes database backups across users for redundancy and recovery.
"""

import asyncio
import hashlib
import secrets
import time
import json
import gzip
import base64
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
import uuid
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import aiofiles

from app.core.database.engines import db_cluster
from app.logger_config import logger
from app.core.config.settings import settings

@dataclass
class BackupShard:
    """Individual backup shard information."""
    shard_id: str
    backup_id: str
    shard_index: int
    total_shards: int
    encrypted_data: bytes
    checksum: str
    size: int
    created_at: datetime
    expires_at: datetime
    redundancy_level: int = 3  # Number of copies

@dataclass
class BackupMetadata:
    """Backup metadata and shard information."""
    backup_id: str
    created_at: datetime
    database_schema_version: str
    total_size: int
    shard_count: int
    encryption_key_hash: str
    shards: List[str] = field(default_factory=list)
    recovery_threshold: int = 0  # Minimum shards needed for recovery
    description: str = ""

@dataclass
class UserBackupStorage:
    """User's backup storage allocation."""
    user_id: int
    allocated_space: int  # bytes
    used_space: int
    stored_shards: List[str] = field(default_factory=list)
    last_cleanup: datetime = field(default_factory=datetime.utcnow)

class DistributedBackupSystem:
    """Intelligent distributed backup system."""
    
    def __init__(self):
        self.backup_dir = Path(getattr(settings, 'BACKUP_DIR', './backups'))
        self.backup_dir.mkdir(exist_ok=True)
        
        self.shard_registry: Dict[str, BackupShard] = {}
        self.backup_metadata: Dict[str, BackupMetadata] = {}
        self.user_storage: Dict[int, UserBackupStorage] = {}
        
        # Configuration
        self.max_backup_size = 40 * 1024 * 1024  # 40MB
        self.shard_size = 1024 * 1024  # 1MB per shard
        self.redundancy_factor = 3  # Each shard stored 3 times
        self.user_storage_limit = 100 * 1024 * 1024  # 100MB per user
        
        # Load existing data
        asyncio.create_task(self._load_backup_registry())
        asyncio.create_task(self._start_maintenance_tasks())
    
    async def _load_backup_registry(self):
        """Load backup registry from persistent storage."""
        try:
            registry_file = self.backup_dir / 'backup_registry.json'
            if registry_file.exists():
                async with aiofiles.open(registry_file, 'r') as f:
                    data = json.loads(await f.read())
                    
                    # Load backup metadata
                    for backup_data in data.get('backups', []):
                        metadata = BackupMetadata(**backup_data)
                        self.backup_metadata[metadata.backup_id] = metadata
                    
                    # Load shard registry
                    for shard_data in data.get('shards', []):
                        shard = BackupShard(**shard_data)
                        self.shard_registry[shard.shard_id] = shard
                    
                    # Load user storage
                    for user_data in data.get('user_storage', []):
                        storage = UserBackupStorage(**user_data)
                        self.user_storage[storage.user_id] = storage
                    
                    logger.info(f"Loaded {len(self.backup_metadata)} backups and {len(self.shard_registry)} shards")
        except Exception as e:
            logger.error(f"Failed to load backup registry: {e}")
    
    async def _save_backup_registry(self):
        """Save backup registry to persistent storage."""
        try:
            registry_file = self.backup_dir / 'backup_registry.json'
            
            data = {
                'backups': [
                    {
                        'backup_id': metadata.backup_id,
                        'created_at': metadata.created_at.isoformat(),
                        'database_schema_version': metadata.database_schema_version,
                        'total_size': metadata.total_size,
                        'shard_count': metadata.shard_count,
                        'encryption_key_hash': metadata.encryption_key_hash,
                        'shards': metadata.shards,
                        'recovery_threshold': metadata.recovery_threshold,
                        'description': metadata.description
                    }
                    for metadata in self.backup_metadata.values()
                ],
                'shards': [
                    {
                        'shard_id': shard.shard_id,
                        'backup_id': shard.backup_id,
                        'shard_index': shard.shard_index,
                        'total_shards': shard.total_shards,
                        'encrypted_data': base64.b64encode(shard.encrypted_data).decode(),
                        'checksum': shard.checksum,
                        'size': shard.size,
                        'created_at': shard.created_at.isoformat(),
                        'expires_at': shard.expires_at.isoformat(),
                        'redundancy_level': shard.redundancy_level
                    }
                    for shard in self.shard_registry.values()
                ],
                'user_storage': [
                    {
                        'user_id': storage.user_id,
                        'allocated_space': storage.allocated_space,
                        'used_space': storage.used_space,
                        'stored_shards': storage.stored_shards,
                        'last_cleanup': storage.last_cleanup.isoformat()
                    }
                    for storage in self.user_storage.values()
                ]
            }
            
            async with aiofiles.open(registry_file, 'w') as f:
                await f.write(json.dumps(data, indent=2))
                
        except Exception as e:
            logger.error(f"Failed to save backup registry: {e}")
    
    def _generate_encryption_key(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Generate encryption key from password."""
        if salt is None:
            salt = secrets.token_bytes(32)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def _encrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using Fernet encryption."""
        f = Fernet(key)
        return f.encrypt(data)
    
    def _decrypt_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt data using Fernet encryption."""
        f = Fernet(key)
        return f.decrypt(encrypted_data)
    
    def _calculate_checksum(self, data: bytes) -> str:
        """Calculate SHA-256 checksum of data."""
        return hashlib.sha256(data).hexdigest()
    
    async def _export_database_partial(self) -> bytes:
        """Export a partial database backup (critical data only)."""
        try:
            # This would export essential tables only to stay under size limit
            # For demonstration, we'll create a minimal backup
            
            async with db_cluster.get_session() as session:
                # Export critical tables (users, guilds, channels, recent messages)
                backup_data = {
                    'version': '2.0.0',
                    'timestamp': datetime.utcnow().isoformat(),
                    'schema_version': '1.0',
                    'tables': {}
                }
                
                # Export users (last 1000)
                # users_result = await session.execute("SELECT * FROM users ORDER BY created_at DESC LIMIT 1000")
                # backup_data['tables']['users'] = [dict(row) for row in users_result]
                
                # For now, create a sample backup
                backup_data['tables']['sample'] = {'data': 'sample_backup_data'}
                
                # Compress the data
                json_data = json.dumps(backup_data).encode()
                compressed_data = gzip.compress(json_data)
                
                logger.info(f"Created partial backup: {len(compressed_data)} bytes")
                return compressed_data
                
        except Exception as e:
            logger.error(f"Failed to export database: {e}")
            raise
    
    async def create_distributed_backup(self, description: str = "", password: str = None) -> str:
        """Create a new distributed backup."""
        try:
            # Generate backup ID
            backup_id = str(uuid.uuid4())
            
            # Export database
            backup_data = await self._export_database_partial()
            
            if len(backup_data) > self.max_backup_size:
                raise ValueError(f"Backup too large: {len(backup_data)} bytes > {self.max_backup_size}")
            
            # Generate encryption key
            if password is None:
                password = secrets.token_urlsafe(32)
            
            encryption_key, salt = self._generate_encryption_key(password)
            key_hash = hashlib.sha256(encryption_key).hexdigest()
            
            # Encrypt the backup
            encrypted_data = self._encrypt_data(backup_data, encryption_key)
            
            # Split into shards
            shards = await self._create_shards(backup_id, encrypted_data)
            
            # Create metadata
            metadata = BackupMetadata(
                backup_id=backup_id,
                created_at=datetime.utcnow(),
                database_schema_version='1.0',
                total_size=len(backup_data),
                shard_count=len(shards),
                encryption_key_hash=key_hash,
                shards=[shard.shard_id for shard in shards],
                recovery_threshold=len(shards) // 2 + 1,  # Need majority of shards
                description=description
            )
            
            self.backup_metadata[backup_id] = metadata
            
            # Distribute shards to users
            await self._distribute_shards(shards)
            
            # Save registry
            await self._save_backup_registry()
            
            logger.info(f"Created distributed backup {backup_id} with {len(shards)} shards")
            return backup_id
            
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            raise
    
    async def _create_shards(self, backup_id: str, encrypted_data: bytes) -> List[BackupShard]:
        """Split encrypted data into shards."""
        shards = []
        shard_count = (len(encrypted_data) + self.shard_size - 1) // self.shard_size
        
        for i in range(shard_count):
            start_pos = i * self.shard_size
            end_pos = min(start_pos + self.shard_size, len(encrypted_data))
            shard_data = encrypted_data[start_pos:end_pos]
            
            shard = BackupShard(
                shard_id=str(uuid.uuid4()),
                backup_id=backup_id,
                shard_index=i,
                total_shards=shard_count,
                encrypted_data=shard_data,
                checksum=self._calculate_checksum(shard_data),
                size=len(shard_data),
                created_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(days=30),
                redundancy_level=self.redundancy_factor
            )
            
            shards.append(shard)
            self.shard_registry[shard.shard_id] = shard
        
        return shards
    
    async def _distribute_shards(self, shards: List[BackupShard]):
        """Distribute shards across users intelligently."""
        try:
            # Get available users with storage space
            available_users = await self._get_available_users()
            
            if len(available_users) < self.redundancy_factor:
                logger.warning(f"Not enough users for redundancy: {len(available_users)} < {self.redundancy_factor}")
            
            # Distribute each shard to multiple users
            for shard in shards:
                assigned_users = []
                
                # Sort users by available space
                sorted_users = sorted(available_users, 
                                    key=lambda u: self.user_storage[u].allocated_space - self.user_storage[u].used_space,
                                    reverse=True)
                
                # Assign shard to users with most available space
                for user_id in sorted_users[:shard.redundancy_level]:
                    if self._can_store_shard(user_id, shard):
                        await self._assign_shard_to_user(user_id, shard)
                        assigned_users.append(user_id)
                
                if len(assigned_users) < shard.redundancy_level:
                    logger.warning(f"Shard {shard.shard_id} only assigned to {len(assigned_users)} users")
                
        except Exception as e:
            logger.error(f"Failed to distribute shards: {e}")
    
    async def _get_available_users(self) -> List[int]:
        """Get list of users available for backup storage."""
        try:
            async with db_cluster.get_session() as session:
                # Get active users (simplified query)
                # In real implementation, this would query the users table
                # For now, return some sample user IDs
                return [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
                
        except Exception as e:
            logger.error(f"Failed to get available users: {e}")
            return []
    
    def _can_store_shard(self, user_id: int, shard: BackupShard) -> bool:
        """Check if user can store the shard."""
        if user_id not in self.user_storage:
            # Initialize user storage
            self.user_storage[user_id] = UserBackupStorage(
                user_id=user_id,
                allocated_space=self.user_storage_limit,
                used_space=0
            )
        
        storage = self.user_storage[user_id]
        return storage.used_space + shard.size <= storage.allocated_space
    
    async def _assign_shard_to_user(self, user_id: int, shard: BackupShard):
        """Assign a shard to a user."""
        storage = self.user_storage[user_id]
        storage.stored_shards.append(shard.shard_id)
        storage.used_space += shard.size
        
        # In a real implementation, this would store the shard data
        # in the user's allocated space (could be in their browser's IndexedDB,
        # or a dedicated user storage area)
        
        logger.debug(f"Assigned shard {shard.shard_id} to user {user_id}")
    
    async def recover_backup(self, backup_id: str, password: str) -> bytes:
        """Recover a backup from distributed shards."""
        try:
            if backup_id not in self.backup_metadata:
                raise ValueError(f"Backup {backup_id} not found")
            
            metadata = self.backup_metadata[backup_id]
            
            # Collect available shards
            available_shards = []
            for shard_id in metadata.shards:
                if shard_id in self.shard_registry:
                    shard = self.shard_registry[shard_id]
                    if await self._verify_shard_integrity(shard):
                        available_shards.append(shard)
            
            if len(available_shards) < metadata.recovery_threshold:
                raise ValueError(f"Insufficient shards for recovery: {len(available_shards)} < {metadata.recovery_threshold}")
            
            # Sort shards by index
            available_shards.sort(key=lambda s: s.shard_index)
            
            # Reconstruct encrypted data
            encrypted_data = b''.join(shard.encrypted_data for shard in available_shards)
            
            # Decrypt data
            encryption_key, _ = self._generate_encryption_key(password)
            
            # Verify key
            key_hash = hashlib.sha256(encryption_key).hexdigest()
            if key_hash != metadata.encryption_key_hash:
                raise ValueError("Invalid password")
            
            decrypted_data = self._decrypt_data(encrypted_data, encryption_key)
            
            # Decompress
            backup_data = gzip.decompress(decrypted_data)
            
            logger.info(f"Successfully recovered backup {backup_id}")
            return backup_data
            
        except Exception as e:
            logger.error(f"Failed to recover backup {backup_id}: {e}")
            raise
    
    async def _verify_shard_integrity(self, shard: BackupShard) -> bool:
        """Verify shard data integrity."""
        try:
            calculated_checksum = self._calculate_checksum(shard.encrypted_data)
            return calculated_checksum == shard.checksum
        except Exception:
            return False
    
    async def get_backup_status(self) -> Dict[str, Any]:
        """Get overall backup system status."""
        total_backups = len(self.backup_metadata)
        total_shards = len(self.shard_registry)
        total_users = len(self.user_storage)
        
        # Calculate storage usage
        total_allocated = sum(storage.allocated_space for storage in self.user_storage.values())
        total_used = sum(storage.used_space for storage in self.user_storage.values())
        
        # Check backup health
        healthy_backups = 0
        for metadata in self.backup_metadata.values():
            available_shards = sum(1 for shard_id in metadata.shards 
                                 if shard_id in self.shard_registry)
            if available_shards >= metadata.recovery_threshold:
                healthy_backups += 1
        
        return {
            'total_backups': total_backups,
            'healthy_backups': healthy_backups,
            'total_shards': total_shards,
            'total_users': total_users,
            'storage': {
                'total_allocated': total_allocated,
                'total_used': total_used,
                'usage_percentage': (total_used / total_allocated * 100) if total_allocated > 0 else 0
            },
            'redundancy_factor': self.redundancy_factor,
            'max_backup_size': self.max_backup_size
        }
    
    async def list_backups(self) -> List[Dict[str, Any]]:
        """List all available backups."""
        backups = []
        
        for metadata in self.backup_metadata.values():
            # Check backup health
            available_shards = sum(1 for shard_id in metadata.shards 
                                 if shard_id in self.shard_registry)
            
            backup_info = {
                'backup_id': metadata.backup_id,
                'created_at': metadata.created_at.isoformat(),
                'description': metadata.description,
                'total_size': metadata.total_size,
                'shard_count': metadata.shard_count,
                'available_shards': available_shards,
                'recovery_threshold': metadata.recovery_threshold,
                'recoverable': available_shards >= metadata.recovery_threshold,
                'health_percentage': (available_shards / metadata.shard_count * 100)
            }
            
            backups.append(backup_info)
        
        return sorted(backups, key=lambda b: b['created_at'], reverse=True)
    
    async def cleanup_expired_shards(self):
        """Clean up expired shards."""
        now = datetime.utcnow()
        expired_shards = []
        
        for shard_id, shard in self.shard_registry.items():
            if shard.expires_at < now:
                expired_shards.append(shard_id)
        
        for shard_id in expired_shards:
            shard = self.shard_registry[shard_id]
            
            # Remove from user storage
            for storage in self.user_storage.values():
                if shard_id in storage.stored_shards:
                    storage.stored_shards.remove(shard_id)
                    storage.used_space -= shard.size
            
            # Remove from registry
            del self.shard_registry[shard_id]
        
        if expired_shards:
            logger.info(f"Cleaned up {len(expired_shards)} expired shards")
            await self._save_backup_registry()
    
    async def _start_maintenance_tasks(self):
        """Start background maintenance tasks."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                await self.cleanup_expired_shards()
                await self._save_backup_registry()

                # Auto-create backups if enabled
                if getattr(settings, 'BACKUP_AUTO_CREATE', True):
                    await self._auto_create_backup()

                # Auto-distribute pending shards
                await self._auto_distribute_pending_shards()

            except Exception as e:
                logger.error(f"Maintenance task error: {e}")

    async def _auto_create_backup(self):
        """Automatically create backups based on schedule."""
        try:
            # Check if it's time for a new backup
            last_backup_time = None
            if self.backup_metadata:
                last_backup_time = max(metadata.created_at for metadata in self.backup_metadata.values())

            backup_interval_hours = getattr(settings, 'BACKUP_INTERVAL_HOURS', 24)

            if (not last_backup_time or
                (datetime.utcnow() - last_backup_time).total_seconds() > backup_interval_hours * 3600):

                logger.info("Creating automatic backup...")
                backup_id = await self.create_distributed_backup(
                    description=f"Automatic backup - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
                )
                logger.info(f"Automatic backup created: {backup_id}")

        except Exception as e:
            logger.error(f"Auto backup creation failed: {e}")

    async def _auto_distribute_pending_shards(self):
        """Automatically distribute shards that need more redundancy."""
        try:
            for shard_id, shard in self.shard_registry.items():
                # Count current copies
                current_copies = sum(
                    1 for storage in self.user_storage.values()
                    if shard_id in storage.stored_shards
                )

                if current_copies < shard.redundancy_level:
                    logger.info(f"Redistributing shard {shard_id}: {current_copies}/{shard.redundancy_level} copies")
                    await self._redistribute_shard(shard)

        except Exception as e:
            logger.error(f"Auto shard distribution failed: {e}")

    async def _redistribute_shard(self, shard: BackupShard):
        """Redistribute a shard to maintain redundancy."""
        try:
            available_users = await self._get_available_users()

            # Find users who don't already have this shard
            users_without_shard = [
                user_id for user_id in available_users
                if user_id not in self.user_storage or
                shard.shard_id not in self.user_storage[user_id].stored_shards
            ]

            # Calculate how many more copies we need
            current_copies = sum(
                1 for storage in self.user_storage.values()
                if shard.shard_id in storage.stored_shards
            )
            needed_copies = shard.redundancy_level - current_copies

            # Distribute to users with most available space
            sorted_users = sorted(
                users_without_shard,
                key=lambda u: self.user_storage.get(u, UserBackupStorage(u, 0, 0)).allocated_space -
                             self.user_storage.get(u, UserBackupStorage(u, 0, 0)).used_space,
                reverse=True
            )

            for user_id in sorted_users[:needed_copies]:
                if self._can_store_shard(user_id, shard):
                    await self._assign_shard_to_user(user_id, shard)
                    logger.info(f"Redistributed shard {shard.shard_id} to user {user_id}")

        except Exception as e:
            logger.error(f"Shard redistribution failed: {e}")

    async def delete_backup(self, backup_id: str) -> bool:
        """Delete a backup and all its shards."""
        try:
            if backup_id not in self.backup_metadata:
                return False

            metadata = self.backup_metadata[backup_id]

            # Remove all shards
            for shard_id in metadata.shards:
                if shard_id in self.shard_registry:
                    shard = self.shard_registry[shard_id]

                    # Remove from user storage
                    for storage in self.user_storage.values():
                        if shard_id in storage.stored_shards:
                            storage.stored_shards.remove(shard_id)
                            storage.used_space -= shard.size

                    # Remove from registry
                    del self.shard_registry[shard_id]

            # Remove metadata
            del self.backup_metadata[backup_id]

            # Save registry
            await self._save_backup_registry()

            logger.info(f"Deleted backup {backup_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete backup {backup_id}: {e}")
            return False

    async def get_user_storage_info(self, user_id: int) -> Dict[str, Any]:
        """Get storage information for a specific user."""
        if user_id not in self.user_storage:
            return {
                'allocated_space': 0,
                'used_space': 0,
                'stored_shards': [],
                'usage_percentage': 0
            }

        storage = self.user_storage[user_id]
        return {
            'allocated_space': storage.allocated_space,
            'used_space': storage.used_space,
            'stored_shards': len(storage.stored_shards),
            'usage_percentage': (storage.used_space / storage.allocated_space * 100) if storage.allocated_space > 0 else 0,
            'last_cleanup': storage.last_cleanup.isoformat()
        }

    async def request_shard_for_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Request a shard for a user to store."""
        try:
            # Initialize user storage if not exists
            if user_id not in self.user_storage:
                self.user_storage[user_id] = UserBackupStorage(
                    user_id=user_id,
                    allocated_space=self.user_storage_limit,
                    used_space=0
                )

            storage = self.user_storage[user_id]

            # Find shards that need more redundancy and user doesn't have
            available_shards = []
            for shard_id, shard in self.shard_registry.items():
                # Skip if user already has this shard
                if shard_id in storage.stored_shards:
                    continue

                # Check if shard needs more copies
                current_copies = sum(
                    1 for s in self.user_storage.values()
                    if shard_id in s.stored_shards
                )

                if current_copies < shard.redundancy_level and self._can_store_shard(user_id, shard):
                    available_shards.append(shard)

            if not available_shards:
                return None

            # Select shard with lowest redundancy first
            selected_shard = min(available_shards, key=lambda s: sum(
                1 for storage in self.user_storage.values()
                if s.shard_id in storage.stored_shards
            ))

            # Assign shard to user
            await self._assign_shard_to_user(user_id, selected_shard)

            # Return shard info (encrypted data would be provided through secure channel)
            return {
                'shard_id': selected_shard.shard_id,
                'backup_id': selected_shard.backup_id,
                'shard_index': selected_shard.shard_index,
                'total_shards': selected_shard.total_shards,
                'size': selected_shard.size,
                'checksum': selected_shard.checksum,
                'expires_at': selected_shard.expires_at.isoformat(),
                'storage_reward': self._calculate_storage_reward(selected_shard)
            }

        except Exception as e:
            logger.error(f"Failed to request shard for user {user_id}: {e}")
            return None

    def _calculate_storage_reward(self, shard: BackupShard) -> Dict[str, Any]:
        """Calculate reward for storing a shard."""
        # This could be credits, points, or other incentives
        base_reward = shard.size / (1024 * 1024)  # 1 point per MB
        duration_bonus = (shard.expires_at - datetime.utcnow()).days * 0.1

        return {
            'points': round(base_reward + duration_bonus, 2),
            'storage_mb': round(shard.size / (1024 * 1024), 2),
            'duration_days': (shard.expires_at - datetime.utcnow()).days
        }

    async def verify_user_shard(self, user_id: int, shard_id: str, provided_checksum: str) -> bool:
        """Verify that a user has correctly stored a shard."""
        try:
            if user_id not in self.user_storage:
                return False

            storage = self.user_storage[user_id]
            if shard_id not in storage.stored_shards:
                return False

            if shard_id not in self.shard_registry:
                return False

            shard = self.shard_registry[shard_id]

            # Verify checksum
            if provided_checksum != shard.checksum:
                logger.warning(f"Checksum mismatch for shard {shard_id} from user {user_id}")
                return False

            logger.info(f"Shard {shard_id} verified for user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to verify shard for user {user_id}: {e}")
            return False

    async def get_user_shards(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all shards stored by a user."""
        try:
            if user_id not in self.user_storage:
                return []

            storage = self.user_storage[user_id]
            user_shards = []

            for shard_id in storage.stored_shards:
                if shard_id in self.shard_registry:
                    shard = self.shard_registry[shard_id]
                    user_shards.append({
                        'shard_id': shard_id,
                        'backup_id': shard.backup_id,
                        'size': shard.size,
                        'created_at': shard.created_at.isoformat(),
                        'expires_at': shard.expires_at.isoformat(),
                        'reward': self._calculate_storage_reward(shard)
                    })

            return user_shards

        except Exception as e:
            logger.error(f"Failed to get shards for user {user_id}: {e}")
            return []

    async def release_user_shard(self, user_id: int, shard_id: str) -> bool:
        """Release a shard from user storage."""
        try:
            if user_id not in self.user_storage:
                return False

            storage = self.user_storage[user_id]
            if shard_id not in storage.stored_shards:
                return False

            if shard_id in self.shard_registry:
                shard = self.shard_registry[shard_id]
                storage.used_space -= shard.size

            storage.stored_shards.remove(shard_id)

            # Try to redistribute the shard to maintain redundancy
            if shard_id in self.shard_registry:
                await self._redistribute_shard(self.shard_registry[shard_id])

            logger.info(f"Released shard {shard_id} from user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to release shard for user {user_id}: {e}")
            return False

# Global distributed backup system instance
distributed_backup = DistributedBackupSystem()
