import json
import logging
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.fernet import Fernet

from .config_manager import get_webui_config

"""
PlexiChat WebUI Distributed Authentication Storage

Advanced distributed authentication storage system with multiple backends,
automatic failover, data replication, and encryption.
"""

logger = logging.getLogger(__name__)

@dataclass
class AuthRecord:
    """Authentication record."""
    user_id: str
    username: str
    password_hash: str
    salt: str
    mfa_enabled: bool
    mfa_devices: List[str]
    session_data: Dict[str, Any]
    permissions: List[str]
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None
    login_attempts: int = 0
    locked_until: Optional[datetime] = None

class AuthStorageBackend(ABC):
    """Abstract base class for authentication storage backends."""
    
    @abstractmethod
    async def store_auth_record(self, record: AuthRecord) -> bool:
        """Store an authentication record."""
    
    @abstractmethod
    async def get_auth_record(self, user_id: str) -> Optional[AuthRecord]:
        """Get an authentication record."""
    
    @abstractmethod
    async def update_auth_record(self, record: AuthRecord) -> bool:
        """Update an authentication record."""
    
    @abstractmethod
    async def delete_auth_record(self, user_id: str) -> bool:
        """Delete an authentication record."""
    
    @abstractmethod
    async def list_auth_records(self) -> List[AuthRecord]:
        """List all authentication records."""
    
    @abstractmethod
    async def is_healthy(self) -> bool:
        """Check if the backend is healthy."""

class DatabaseAuthStorage(AuthStorageBackend):
    """Database-based authentication storage."""
    
    def __init__(self, db_path: str = "config/auth.db"):
        self.db_path = from pathlib import Path
Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True)
        self._init_database()
    
    def _init_database(self):
        """Initialize the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS auth_records (
                        user_id TEXT PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        mfa_enabled BOOLEAN DEFAULT FALSE,
                        mfa_devices TEXT DEFAULT '[]',
                        session_data TEXT DEFAULT '{}',
                        permissions TEXT DEFAULT '[]',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        last_login TEXT,
                        login_attempts INTEGER DEFAULT 0,
                        locked_until TEXT
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize auth database: {e}")
    
    async def store_auth_record(self, record: AuthRecord) -> bool:
        """Store an authentication record."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO auth_records 
                    (user_id, username, password_hash, salt, mfa_enabled, mfa_devices,
                     session_data, permissions, created_at, updated_at, last_login,
                     login_attempts, locked_until)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.user_id, record.username, record.password_hash, record.salt,
                    record.mfa_enabled, json.dumps(record.mfa_devices),
                    json.dumps(record.session_data), json.dumps(record.permissions),
                    record.created_at.isoformat(), record.updated_at.isoformat(),
                    record.last_login.isoformat() if record.last_login else None,
                    record.login_attempts,
                    record.locked_until.isoformat() if record.locked_until else None
                ))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to store auth record: {e}")
            return False
    
    async def get_auth_record(self, user_id: str) -> Optional[AuthRecord]:
        """Get an authentication record."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT * FROM auth_records WHERE user_id = ?", (user_id,)
                )
                row = cursor.fetchone()
                if row:
                    return self._row_to_record(row)
            return None
        except Exception as e:
            logger.error(f"Failed to get auth record: {e}")
            return None
    
    async def update_auth_record(self, record: AuthRecord) -> bool:
        """Update an authentication record."""
        record.updated_at = from datetime import datetime
datetime.utcnow()
        return await self.store_auth_record(record)
    
    async def delete_auth_record(self, user_id: str) -> bool:
        """Delete an authentication record."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM auth_records WHERE user_id = ?", (user_id,))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to delete auth record: {e}")
            return False
    
    async def list_auth_records(self) -> List[AuthRecord]:
        """List all authentication records."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT * FROM auth_records")
                rows = cursor.fetchall()
                return [self._row_to_record(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to list auth records: {e}")
            return []
    
    async def is_healthy(self) -> bool:
        """Check if the backend is healthy."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("SELECT 1")
            return True
        except Exception:
            return False
    
    def _row_to_record(self, row) -> AuthRecord:
        """Convert database row to AuthRecord."""
        return AuthRecord(
            user_id=row[0],
            username=row[1],
            password_hash=row[2],
            salt=row[3],
            mfa_enabled=bool(row[4]),
            mfa_devices=json.loads(row[5]),
            session_data=json.loads(row[6]),
            permissions=json.loads(row[7]),
            created_at=datetime.fromisoformat(row[8]),
            updated_at=datetime.fromisoformat(row[9]),
            last_login=datetime.fromisoformat(row[10]) if row[10] else None,
            login_attempts=row[11],
            locked_until=datetime.fromisoformat(row[12]) if row[12] else None
        )

class FileAuthStorage(AuthStorageBackend):
    """File-based authentication storage."""
    
    def __init__(self, storage_dir: str = "config/auth_storage"):
        self.storage_dir = from pathlib import Path
Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
        self.cipher = Fernet(Fernet.generate_key())  # In production, use proper key management
    
    async def store_auth_record(self, record: AuthRecord) -> bool:
        """Store an authentication record."""
        try:
            file_path = self.storage_dir / f"{record.user_id}.json"
            record_data = asdict(record)
            
            # Convert datetime objects to strings
            for key, value in record_data.items():
                if isinstance(value, datetime):
                    record_data[key] = value.isoformat()
            
            # Encrypt and store
            encrypted_data = self.cipher.encrypt(json.dumps(record_data).encode())
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            return True
        except Exception as e:
            logger.error(f"Failed to store auth record to file: {e}")
            return False
    
    async def get_auth_record(self, user_id: str) -> Optional[AuthRecord]:
        """Get an authentication record."""
        try:
            file_path = self.storage_dir / f"{user_id}.json"
            if not file_path.exists():
                return None
            
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.cipher.decrypt(encrypted_data)
            record_data = json.loads(decrypted_data.decode())
            
            # Convert datetime strings back to datetime objects
            for key in ['created_at', 'updated_at', 'last_login', 'locked_until']:
                if record_data.get(key):
                    record_data[key] = datetime.fromisoformat(record_data[key])
            
            return AuthRecord(**record_data)
        except Exception as e:
            logger.error(f"Failed to get auth record from file: {e}")
            return None
    
    async def update_auth_record(self, record: AuthRecord) -> bool:
        """Update an authentication record."""
        record.updated_at = from datetime import datetime
datetime.utcnow()
        return await self.store_auth_record(record)
    
    async def delete_auth_record(self, user_id: str) -> bool:
        """Delete an authentication record."""
        try:
            file_path = self.storage_dir / f"{user_id}.json"
            if file_path.exists():
                file_path.unlink()
            return True
        except Exception as e:
            logger.error(f"Failed to delete auth record file: {e}")
            return False
    
    async def list_auth_records(self) -> List[AuthRecord]:
        """List all authentication records."""
        records = []
        try:
            for file_path in self.storage_dir.glob("*.json"):
                user_id = file_path.stem
                record = await self.get_auth_record(user_id)
                if record:
                    records.append(record)
        except Exception as e:
            logger.error(f"Failed to list auth records from files: {e}")
        
        return records
    
    async def is_healthy(self) -> bool:
        """Check if the backend is healthy."""
        try:
            return self.storage_dir.exists() and self.storage_dir.is_dir()
        except Exception:
            return False

class DistributedAuthStorage:
    """Distributed authentication storage with multiple backends."""
    
    def __init__(self):
        self.config = get_webui_config()
        self.auth_config = self.config.get_auth_storage_config()
        
        # Initialize storage backends
        self.primary_backend = None
        self.backup_backends = []
        
        self._init_backends()
        
        # Encryption for sensitive data
        self.cipher = Fernet(self.config.encryption_key)
        
        logger.info("Distributed Authentication Storage initialized")
    
    def _init_backends(self):
        """Initialize storage backends."""
        try:
            # Initialize primary backend
            if self.auth_config.primary_storage == "database":
                self.primary_backend = DatabaseAuthStorage()
            elif self.auth_config.primary_storage == "file":
                self.primary_backend = FileAuthStorage()
            
            # Initialize backup backends
            for backend_type in self.auth_config.backup_storages:
                if backend_type == "database":
                    self.backup_backends.append(DatabaseAuthStorage("config/auth_backup.db"))
                elif backend_type == "file":
                    self.backup_backends.append(FileAuthStorage("config/auth_backup"))
            
            logger.info(f"Initialized {len(self.backup_backends) + 1} storage backends")
            
        except Exception as e:
            logger.error(f"Failed to initialize storage backends: {e}")
    
    async def store_auth_record(self, record: AuthRecord) -> bool:
        """Store authentication record across all backends."""
        success_count = 0
        
        # Store in primary backend
        if self.primary_backend:
            if await self.primary_backend.store_auth_record(record):
                success_count += 1
            else:
                logger.warning("Failed to store in primary backend")
        
        # Store in backup backends
        if self.auth_config.session_replication:
            for backend in self.backup_backends:
                try:
                    if await backend.store_auth_record(record):
                        success_count += 1
                except Exception as e:
                    logger.warning(f"Failed to store in backup backend: {e}")
        
        return success_count > 0
    
    async def get_auth_record(self, user_id: str) -> Optional[AuthRecord]:
        """Get authentication record with failover."""
        # Try primary backend first
        if self.primary_backend:
            try:
                record = await self.primary_backend.get_auth_record(user_id)
                if record:
                    return record
            except Exception as e:
                logger.warning(f"Primary backend failed: {e}")
        
        # Try backup backends if primary fails
        if self.auth_config.failover_enabled:
            for backend in self.backup_backends:
                try:
                    record = await backend.get_auth_record(user_id)
                    if record:
                        logger.info("Retrieved record from backup backend")
                        return record
                except Exception as e:
                    logger.warning(f"Backup backend failed: {e}")
        
        return None
    
    async def update_auth_record(self, record: AuthRecord) -> bool:
        """Update authentication record across all backends."""
        return await self.store_auth_record(record)
    
    async def delete_auth_record(self, user_id: str) -> bool:
        """Delete authentication record from all backends."""
        success_count = 0
        
        # Delete from primary backend
        if self.primary_backend:
            if await self.primary_backend.delete_auth_record(user_id):
                success_count += 1
        
        # Delete from backup backends
        for backend in self.backup_backends:
            try:
                if await backend.delete_auth_record(user_id):
                    success_count += 1
            except Exception as e:
                logger.warning(f"Failed to delete from backup backend: {e}")
        
        return success_count > 0
    
    async def sync_backends(self):
        """Synchronize data between backends."""
        if not self.auth_config.session_replication:
            return
        
        try:
            # Get all records from primary backend
            if self.primary_backend:
                primary_records = await self.primary_backend.list_auth_records()
                
                # Sync to backup backends
                for backend in self.backup_backends:
                    for record in primary_records:
                        await backend.store_auth_record(record)
                
                logger.info(f"Synced {len(primary_records)} records to backup backends")
        
        except Exception as e:
            logger.error(f"Failed to sync backends: {e}")
    
    async def health_check(self) -> Dict[str, bool]:
        """Check health of all backends."""
        health_status = {}
        
        if self.primary_backend:
            health_status['primary'] = await self.primary_backend.is_healthy()
        
        for i, backend in enumerate(self.backup_backends):
            health_status[f'backup_{i}'] = await backend.is_healthy()
        
        return health_status

# Global distributed auth storage instance
distributed_auth_storage = DistributedAuthStorage()

def get_auth_storage() -> DistributedAuthStorage:
    """Get the global distributed auth storage."""
    return distributed_auth_storage
