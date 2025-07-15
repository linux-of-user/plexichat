import asyncio
import hashlib
import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Optional

import aiosqlite


"""
Backup Node Authentication Manager

Manages authentication and authorization for backup nodes in the distributed system.
Implements secure API key management and node permission levels.
"""

logger = logging.getLogger(__name__)


class NodePermissionLevel(Enum):
    """Permission levels for backup nodes."""

    READ_ONLY = "read-only"
    WRITE_ONLY = "write-only"
    READ_WRITE = "read-write"
    ADMIN = "admin"
    SUPER_ADMIN = "super-admin"


class APIKeyStatus(Enum):
    """API key status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class BackupNodeCredentials:
    """Represents backup node credentials."""

    node_id: str
    api_key: str
    api_key_hash: str
    permission_level: NodePermissionLevel
    status: APIKeyStatus
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    usage_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class BackupNodeAuthManager:
    """
    Backup Node Authentication Manager

    Manages authentication and authorization for backup nodes:
    - Secure API key generation and management
    - Node permission levels and access control
    - Key rotation and expiration handling
    - Usage tracking and monitoring
    - Secure credential storage
    """

    def __init__(self, backup_manager):
        """Initialize the backup node auth manager."""
        self.backup_manager = backup_manager
        self.auth_dir = backup_manager.backup_dir / "auth"
        self.auth_dir.mkdir(parents=True, exist_ok=True)

        # Credentials registry
        self.node_credentials: Dict[str, BackupNodeCredentials] = {}

        # Configuration
        self.config = {
            "api_key_length": 64,
            "default_expiry_days": 365,
            "max_usage_per_key": 1000000,
            "key_rotation_days": 90,
            "require_key_rotation": True,
        }

        # Database
        self.auth_db_path = backup_manager.databases_dir / "node_auth.db"

        logger.info("Backup Node Auth Manager initialized")

    async def initialize(self):
        """Initialize the auth manager."""
        await self._initialize_database()
        await self._load_existing_credentials()

        # Start background tasks
        asyncio.create_task(self._key_expiry_monitoring_task())

        logger.info("Backup Node Auth Manager initialized successfully")

    async def _initialize_database(self):
        """Initialize the authentication database."""
        async with aiosqlite.connect(self.auth_db_path) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS node_credentials (
                    node_id TEXT PRIMARY KEY,
                    api_key_hash TEXT NOT NULL,
                    permission_level TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    last_used TEXT,
                    usage_count INTEGER DEFAULT 0,
                    metadata TEXT
                )
            """
            )

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_events (
                    event_id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    details TEXT
                )
            """
            )

            await db.commit()

    async def _load_existing_credentials(self):
        """Load existing credentials from database."""
        async with aiosqlite.connect(self.auth_db_path) as db:
            async with db.execute("SELECT * FROM node_credentials") as cursor:
                async for row in cursor:
                    # Note: We don't store the actual API key, only the hash
                    credentials = BackupNodeCredentials(
                        node_id=row[0],
                        api_key="",  # Not stored
                        api_key_hash=row[1],
                        permission_level=NodePermissionLevel(row[2]),
                        status=APIKeyStatus(row[3]),
                        created_at=datetime.fromisoformat(row[4]),
                        expires_at=datetime.fromisoformat(row[5]) if row[5] else None,
                        last_used=datetime.fromisoformat(row[6]) if row[6] else None,
                        usage_count=row[7],
                        metadata=json.loads(row[8]) if row[8] else {},
                    )
                    self.node_credentials[credentials.node_id] = credentials

    async def create_node_credentials(
        self,
        node_id: str,
        permission_level: NodePermissionLevel = NodePermissionLevel.READ_WRITE,
        expiry_days: Optional[int] = None,
    ) -> Tuple[str, str]:
        """Create new credentials for a backup node."""
        # Generate secure API key
        api_key = self._generate_api_key()
        api_key_hash = self._hash_api_key(api_key)

        # Calculate expiry
        expiry_days = expiry_days or self.config["default_expiry_days"]
        expires_at = datetime.now(timezone.utc) + timedelta(days=expiry_days)

        # Create credentials object
        credentials = BackupNodeCredentials(
            node_id=node_id,
            api_key=api_key,
            api_key_hash=api_key_hash,
            permission_level=permission_level,
            status=APIKeyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at,
        )

        # Store credentials
        self.node_credentials[node_id] = credentials
        await self._save_credentials_to_database(credentials)

        # Log event
        await self._log_auth_event(
            node_id,
            "credentials_created",
            {
                "permission_level": permission_level.value,
                "expires_at": expires_at.isoformat(),
            },
        )

        logger.info(
            f"Created credentials for node {node_id} with {permission_level.value} permissions"
        )
        return api_key, api_key_hash

    def _generate_api_key(self) -> str:
        """Generate a secure API key."""
        return secrets.token_urlsafe(self.config["api_key_length"])

    def _hash_api_key(self, api_key: str) -> str:
        """Hash an API key for secure storage."""
        return hashlib.sha256(api_key.encode()).hexdigest()

    async def authenticate_node(self, node_id: str, api_key: str) -> bool:
        """Authenticate a backup node."""
        if node_id not in self.node_credentials:
            await self._log_auth_event(
                node_id, "auth_failed", {"reason": "node_not_found"}
            )
            return False

        credentials = self.node_credentials[node_id]

        # Check if credentials are active
        if credentials.status != APIKeyStatus.ACTIVE:
            await self._log_auth_event(
                node_id, "auth_failed", {"reason": "inactive_credentials"}
            )
            return False

        # Check expiry
        if credentials.expires_at and credentials.expires_at <= datetime.now(
            timezone.utc
        ):
            credentials.status = APIKeyStatus.EXPIRED
            await self._save_credentials_to_database(credentials)
            await self._log_auth_event(
                node_id, "auth_failed", {"reason": "expired_credentials"}
            )
            return False

        # Verify API key
        api_key_hash = self._hash_api_key(api_key)
        if api_key_hash != credentials.api_key_hash:
            await self._log_auth_event(
                node_id, "auth_failed", {"reason": "invalid_key"}
            )
            return False

        # Update usage
        credentials.last_used = datetime.now(timezone.utc)
        credentials.usage_count += 1
        await self._save_credentials_to_database(credentials)

        await self._log_auth_event(node_id, "auth_success", {})
        return True

    async def authorize_operation(
        self, node_id: str, operation: str, resource: Optional[str] = None
    ) -> bool:
        """Authorize a node operation based on permissions."""
        if node_id not in self.node_credentials:
            return False

        credentials = self.node_credentials[node_id]
        permission_level = credentials.permission_level

        # Define operation permissions
        read_operations = ["get_backup", "list_backups", "get_shard", "verify_shard"]
        write_operations = ["create_backup", "store_shard", "delete_shard"]
        admin_operations = ["create_node", "delete_node", "manage_keys"]

        if operation in read_operations:
            return permission_level in [
                NodePermissionLevel.READ_ONLY,
                NodePermissionLevel.READ_WRITE,
                NodePermissionLevel.ADMIN,
                NodePermissionLevel.SUPER_ADMIN,
            ]
        elif operation in write_operations:
            return permission_level in [
                NodePermissionLevel.WRITE_ONLY,
                NodePermissionLevel.READ_WRITE,
                NodePermissionLevel.ADMIN,
                NodePermissionLevel.SUPER_ADMIN,
            ]
        elif operation in admin_operations:
            return permission_level in [
                NodePermissionLevel.ADMIN,
                NodePermissionLevel.SUPER_ADMIN,
            ]
        else:
            # Unknown operation, require super admin
            return permission_level == NodePermissionLevel.SUPER_ADMIN

    async def revoke_credentials(self, node_id: str):
        """Revoke credentials for a backup node."""
        if node_id in self.node_credentials:
            credentials = self.node_credentials[node_id]
            credentials.status = APIKeyStatus.REVOKED
            await self._save_credentials_to_database(credentials)

            await self._log_auth_event(node_id, "credentials_revoked", {})
            logger.info(f"Revoked credentials for node {node_id}")

    async def rotate_credentials(self, node_id: str) -> Tuple[str, str]:
        """Rotate credentials for a backup node."""
        if node_id not in self.node_credentials:
            raise ValueError(f"Node {node_id} not found")

        old_credentials = self.node_credentials[node_id]

        # Create new credentials with same permissions
        new_api_key, new_api_key_hash = await self.create_node_credentials(
            node_id, old_credentials.permission_level
        )

        # Revoke old credentials
        old_credentials.status = APIKeyStatus.REVOKED
        await self._save_credentials_to_database(old_credentials)

        await self._log_auth_event(node_id, "credentials_rotated", {})
        logger.info(f"Rotated credentials for node {node_id}")

        return new_api_key, new_api_key_hash

    async def _save_credentials_to_database(self, credentials: BackupNodeCredentials):
        """Save credentials to database."""
        async with aiosqlite.connect(self.auth_db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO node_credentials
                (node_id, api_key_hash, permission_level, status, created_at,
                 expires_at, last_used, usage_count, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    credentials.node_id,
                    credentials.api_key_hash,
                    credentials.permission_level.value,
                    credentials.status.value,
                    credentials.created_at.isoformat(),
                    (
                        credentials.expires_at.isoformat()
                        if credentials.expires_at
                        else None
                    ),
                    (
                        credentials.last_used.isoformat()
                        if credentials.last_used
                        else None
                    ),
                    credentials.usage_count,
                    json.dumps(credentials.metadata),
                ),
            )
            await db.commit()

    async def _log_auth_event(
        self, node_id: str, event_type: str, details: Dict[str, Any]
    ):
        """Log authentication event."""
        event_id = f"auth_{secrets.token_hex(8)}"

        async with aiosqlite.connect(self.auth_db_path) as db:
            await db.execute(
                """
                INSERT INTO auth_events (event_id, node_id, event_type, timestamp, details)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    event_id,
                    node_id,
                    event_type,
                    datetime.now(timezone.utc).isoformat(),
                    json.dumps(details),
                ),
            )
            await db.commit()

    async def _key_expiry_monitoring_task(self):
        """Background task for monitoring key expiry."""
        while True:
            try:
                await asyncio.sleep(3600)  # Check every hour
                await self._check_expiring_keys()
            except Exception as e:
                logger.error(f"Key expiry monitoring error: {e}")

    async def _check_expiring_keys(self):
        """Check for expiring keys and handle them."""
        now = datetime.now(timezone.utc)
        warning_threshold = now + timedelta(days=7)  # Warn 7 days before expiry

        for credentials in self.node_credentials.values():
            if credentials.expires_at:
                if credentials.expires_at <= now:
                    # Key expired
                    credentials.status = APIKeyStatus.EXPIRED
                    await self._save_credentials_to_database(credentials)
                    logger.warning(
                        f"API key for node {credentials.node_id} has expired"
                    )
                elif credentials.expires_at <= warning_threshold:
                    # Key expiring soon
                    logger.info(
                        f"API key for node {credentials.node_id} expires in {(credentials.expires_at - now).days} days"
                    )


# Global instance will be created by backup manager
backup_node_auth_manager = None
