# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import time

# Import database abstraction layer
try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

from cryptography.fernet import Fernet

from plexichat.interfaces.web.core.config_manager import get_webui_config

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
        pass

    @abstractmethod
    async def get_auth_record(self, user_id: str) -> Optional[AuthRecord]:
        """Get an authentication record."""
        pass

    @abstractmethod
    async def update_auth_record(self, record: AuthRecord) -> bool:
        """Update an authentication record."""
        pass

    @abstractmethod
    async def delete_auth_record(self, user_id: str) -> bool:
        """Delete an authentication record."""
        pass

    @abstractmethod
    async def list_auth_records(self) -> List[AuthRecord]:
        """List all authentication records."""
        pass

    @abstractmethod
    async def is_healthy(self) -> bool:
        """Check if the backend is healthy."""
        pass

class DatabaseAuthStorage(AuthStorageBackend):
    """Database-based authentication storage."""
    def __init__(self, db_path: str = "config/auth.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True)
        self._init_database()

    async def _init_database(self):
        """Initialize the database using abstraction layer."""
        try:
            if database_manager:
                # Use database abstraction layer for schema creation
                await database_manager.ensure_table_exists("auth_records", {
                    "user_id": "TEXT PRIMARY KEY",
                    "username": "TEXT UNIQUE NOT NULL",
                    "password_hash": "TEXT NOT NULL",
                    "salt": "TEXT NOT NULL",
                    "mfa_enabled": "BOOLEAN DEFAULT FALSE",
                    "mfa_devices": "TEXT DEFAULT '[]'",
                    "session_data": "TEXT DEFAULT '{}'",
                    "permissions": "TEXT DEFAULT '[]'",
                    "created_at": "TEXT NOT NULL",
                    "updated_at": "TEXT NOT NULL",
                    "last_login": "TEXT",
                    "login_attempts": "INTEGER DEFAULT 0",
                    "locked_until": "TEXT"
                })
            else:
                # Fallback: create directory structure
                Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to initialize auth database: {e}")

    async def store_auth_record(self, record: AuthRecord) -> bool:
        """Store an authentication record using abstraction layer."""
        try:
            if database_manager:
                # Use database abstraction layer
                record_data = {
                    "user_id": record.user_id,
                    "username": record.username,
                    "password_hash": record.password_hash,
                    "salt": record.salt,
                    "mfa_enabled": record.mfa_enabled,
                    "mfa_devices": json.dumps(record.mfa_devices),
                    "session_data": json.dumps(record.session_data),
                    "permissions": json.dumps(record.permissions),
                    "created_at": record.created_at.isoformat(),
                    "updated_at": record.updated_at.isoformat(),
                    "last_login": record.last_login.isoformat() if record.last_login else None,
                    "login_attempts": record.login_attempts,
                    "locked_until": record.locked_until.isoformat() if record.locked_until else None
                }

                # Check if record exists
                existing = await database_manager.get_record("auth_records", record.user_id)
                if existing:
                    await database_manager.update_record("auth_records", record.user_id, record_data)
                else:
                    await database_manager.insert_record("auth_records", record_data)
                return True
            else:
                # Fallback: just return True (no actual storage)
                logger.warning("Database manager not available, auth record not stored")
                return True
        except Exception as e:
            logger.error(f"Failed to store auth record: {e}")
            return False

    async def get_auth_record(self, user_id: str) -> Optional[AuthRecord]:
        """Get an authentication record using abstraction layer."""
        try:
            if database_manager:
                # Use database abstraction layer
                record_data = await database_manager.get_record("auth_records", user_id)
                if record_data:
                    return self._dict_to_record(record_data)
            return None
        except Exception as e:
            logger.error(f"Failed to get auth record: {e}")
            return None

    async def update_auth_record(self, record: AuthRecord) -> bool:
        """Update an authentication record."""
        record.updated_at = datetime.now(timezone.utc)
        return await self.store_auth_record(record)

    async def delete_auth_record(self, user_id: str) -> bool:
        """Delete an authentication record using abstraction layer."""
        try:
            if database_manager:
                # Use database abstraction layer
                await database_manager.delete_record("auth_records", user_id)
                return True
            else:
                logger.warning("Database manager not available, auth record not deleted")
                return True
        except Exception as e:
            logger.error(f"Failed to delete auth record: {e}")
            return False

    async def list_auth_records(self) -> List[AuthRecord]:
        """List all authentication records using abstraction layer."""
        try:
            if database_manager:
                # Use database abstraction layer
                records_data = await database_manager.list_records("auth_records")
                return [self._dict_to_record(record_data) for record_data in records_data]
            else:
                return []
        except Exception as e:
            logger.error(f"Failed to list auth records: {e}")
            return []

    async def is_healthy(self) -> bool:
        """Check if the backend is healthy using abstraction layer."""
        try:
            if database_manager:
                # Use database abstraction layer health check
                return await database_manager.test_connection()
            else:
                # Fallback: check if directory exists
                return Path(self.db_path).parent.exists()
        except Exception:
            return False

    def _dict_to_record(self, data: Dict[str, Any]) -> AuthRecord:
        """Convert dictionary data to AuthRecord."""
        return AuthRecord(
            user_id=data["user_id"],
            username=data["username"],
            password_hash=data["password_hash"],
            salt=data["salt"],
            mfa_enabled=data.get("mfa_enabled", False),
            mfa_devices=json.loads(data.get("mfa_devices", "[]")),
            session_data=json.loads(data.get("session_data", "{}")),
            permissions=json.loads(data.get("permissions", "[]")),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else datetime.now(),
            last_login=datetime.fromisoformat(data["last_login"]) if data.get("last_login") else None,
            login_attempts=data.get("login_attempts", 0),
            locked_until=datetime.fromisoformat(data["locked_until"]) if data.get("locked_until") else None
        )

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
        self.storage_dir = Path(storage_dir)
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
        record.updated_at = datetime.now(timezone.utc)
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
        self.primary_backend: Optional[AuthStorageBackend] = None
        self.backup_backends: List[AuthStorageBackend] = []

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
            backup_storages = self.auth_config.backup_storages if self.auth_config.backup_storages is not None else []
            for backend_type in backup_storages:
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

# --- SSL/Certificate Management Integration Points ---
# These stubs will be used by the GUI/WebUI to trigger SSL setup, upload, renewal, and status checks.
# Reference: security.txt - Certificate Management, SSL Automation
# Example: def trigger_ssl_renewal(domain: str): ...

# --- Auth Storage DAO/Service Integration ---
# Reference: improvements.txt, security.txt
class AuthStorageService:
    def __init__(self):
        try:
            from plexichat.core.database.manager import database_manager
            self.db_manager = database_manager
        except ImportError:
            self.db_manager = None

    async def get_auth_record_by_id(self, user_id: str):
        if self.db_manager:
            result = await self.db_manager.get_auth_record_by_id(user_id)
            return result
        return None

    async def update_auth_record(self, record):
        if self.db_manager:
            await self.db_manager.update_auth_record(record)
