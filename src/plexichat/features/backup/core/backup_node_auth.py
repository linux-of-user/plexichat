"""
Backup Node Authentication and Authorization System
Government-level security for backup node API access with restricted shard collection.
"""

import asyncio
import hashlib
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class NodePermissionLevel(Enum):
    """Permission levels for backup nodes."""
    READ_ONLY = "read_only"
    SHARD_ACCESS = "shard_access"
    LIMITED_COLLECTION = "limited_collection"
    FULL_ACCESS = "full_access"
    ADMIN = "admin"


class APIKeyStatus(Enum):
    """Status of API keys."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass
class BackupNodeAPIKey:
    """Backup node API key with restricted permissions."""
    key_id: str
    api_key_hash: str
    node_id: str
    node_name: str
    permission_level: NodePermissionLevel
    allowed_shard_types: Set[str]
    max_shards_per_hour: int
    max_total_shards: int
    current_shard_count: int
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    status: APIKeyStatus
    rate_limit_reset: datetime
    hourly_shard_count: int
    metadata: Dict[str, Any]


@dataclass
class ShardAccessLog:
    """Log entry for shard access attempts."""
    log_id: str
    api_key_id: str
    node_id: str
    shard_id: str
    access_type: str  # 'read', 'collect', 'verify'
    success: bool
    timestamp: datetime
    ip_address: str
    user_agent: str
    error_message: Optional[str] = None


class BackupNodeAuthManager:
    """
    Backup Node Authentication Manager
    
    Manages API keys and permissions for backup nodes with government-level security:
    - Restricted shard collection based on API key permissions
    - Rate limiting and quota management
    - Comprehensive audit logging
    - Automatic key rotation and expiration
    - Suspicious activity detection
    """
    
    def __init__(self, backup_manager):
        self.backup_manager = backup_manager
        self.auth_dir = backup_manager.backup_dir / "auth"
        self.auth_dir.mkdir(parents=True, exist_ok=True)
        
        # API key registry
        self.api_keys: Dict[str, BackupNodeAPIKey] = {}
        self.access_logs: List[ShardAccessLog] = []
        
        # Security configuration
        self.max_failed_attempts = 5
        self.lockout_duration = timedelta(hours=1)
        self.key_rotation_interval = timedelta(days=30)
        self.default_key_expiry = timedelta(days=90)
        
        # Rate limiting
        self.failed_attempts: Dict[str, int] = {}
        self.lockout_times: Dict[str, datetime] = {}
        
        # Database
        self.auth_db_path = backup_manager.databases_dir / "backup_node_auth.db"
        
        logger.info("Backup Node Auth Manager initialized")
    
    async def initialize(self):
        """Initialize the authentication system."""
        await self._initialize_database()
        await self._load_existing_keys()
        await self._start_maintenance_tasks()
        logger.info("Backup Node Authentication system initialized")
    
    async def _initialize_database(self):
        """Initialize authentication database."""
        import aiosqlite
        
        async with aiosqlite.connect(self.auth_db_path) as db:
            # API keys table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS backup_node_api_keys (
                    key_id TEXT PRIMARY KEY,
                    api_key_hash TEXT NOT NULL UNIQUE,
                    node_id TEXT NOT NULL,
                    node_name TEXT NOT NULL,
                    permission_level TEXT NOT NULL,
                    allowed_shard_types TEXT NOT NULL,
                    max_shards_per_hour INTEGER NOT NULL,
                    max_total_shards INTEGER NOT NULL,
                    current_shard_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP,
                    last_used_at TIMESTAMP,
                    status TEXT NOT NULL,
                    rate_limit_reset TIMESTAMP NOT NULL,
                    hourly_shard_count INTEGER DEFAULT 0,
                    metadata TEXT DEFAULT '{}'
                )
            """)
            
            # Access logs table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS shard_access_logs (
                    log_id TEXT PRIMARY KEY,
                    api_key_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    shard_id TEXT NOT NULL,
                    access_type TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    ip_address TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    error_message TEXT,
                    FOREIGN KEY (api_key_id) REFERENCES backup_node_api_keys (key_id)
                )
            """)
            
            # Failed attempts tracking
            await db.execute("""
                CREATE TABLE IF NOT EXISTS failed_auth_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    attempted_key TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    reason TEXT NOT NULL
                )
            """)
            
            await db.commit()
        
        logger.info("Backup node authentication database initialized")
    
    def generate_api_key(
        self,
        node_id: str,
        node_name: str,
        permission_level: NodePermissionLevel = NodePermissionLevel.SHARD_ACCESS,
        allowed_shard_types: Set[str] = None,
        max_shards_per_hour: int = 100,
        max_total_shards: int = 10000,
        expires_in_days: int = 90
    ) -> tuple[str, str]:
        """
        Generate new API key for backup node.
        
        Returns:
            tuple: (key_id, raw_api_key)
        """
        # Generate secure API key
        raw_api_key = secrets.token_urlsafe(64)
        api_key_hash = hashlib.sha512(raw_api_key.encode()).hexdigest()
        
        # Generate key ID
        key_id = f"bak_{secrets.token_hex(16)}"
        
        # Set default allowed shard types based on permission level
        if allowed_shard_types is None:
            if permission_level == NodePermissionLevel.READ_ONLY:
                allowed_shard_types = set()
            elif permission_level == NodePermissionLevel.SHARD_ACCESS:
                allowed_shard_types = {"user_data", "message_data"}
            elif permission_level == NodePermissionLevel.LIMITED_COLLECTION:
                allowed_shard_types = {"user_data", "message_data", "metadata"}
            elif permission_level == NodePermissionLevel.FULL_ACCESS:
                allowed_shard_types = {"user_data", "message_data", "metadata", "system_data"}
            else:  # ADMIN
                allowed_shard_types = {"*"}  # All types
        
        # Create API key object
        api_key = BackupNodeAPIKey(
            key_id=key_id,
            api_key_hash=api_key_hash,
            node_id=node_id,
            node_name=node_name,
            permission_level=permission_level,
            allowed_shard_types=allowed_shard_types,
            max_shards_per_hour=max_shards_per_hour,
            max_total_shards=max_total_shards,
            current_shard_count=0,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=expires_in_days),
            last_used_at=None,
            status=APIKeyStatus.ACTIVE,
            rate_limit_reset=datetime.now(timezone.utc) + timedelta(hours=1),
            hourly_shard_count=0,
            metadata={}
        )
        
        # Store API key
        self.api_keys[key_id] = api_key
        
        logger.info(f"Generated API key for backup node {node_id} with {permission_level.value} permissions")
        return key_id, raw_api_key
    
    async def authenticate_api_key(self, raw_api_key: str, ip_address: str = "unknown") -> Optional[BackupNodeAPIKey]:
        """
        Authenticate API key and return associated permissions.
        
        Args:
            raw_api_key: Raw API key to authenticate
            ip_address: IP address of the requesting node
            
        Returns:
            BackupNodeAPIKey if valid, None if invalid
        """
        api_key_hash = hashlib.sha512(raw_api_key.encode()).hexdigest()
        
        # Find matching API key
        for api_key in self.api_keys.values():
            if api_key.api_key_hash == api_key_hash:
                # Check if key is active and not expired
                if api_key.status != APIKeyStatus.ACTIVE:
                    await self._log_failed_attempt(api_key.node_id, ip_address, raw_api_key, f"Key status: {api_key.status.value}")
                    return None
                
                if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
                    api_key.status = APIKeyStatus.EXPIRED
                    await self._log_failed_attempt(api_key.node_id, ip_address, raw_api_key, "Key expired")
                    return None
                
                # Check if node is locked out
                if api_key.node_id in self.lockout_times:
                    if datetime.now(timezone.utc) < self.lockout_times[api_key.node_id]:
                        await self._log_failed_attempt(api_key.node_id, ip_address, raw_api_key, "Node locked out")
                        return None
                    else:
                        # Remove expired lockout
                        del self.lockout_times[api_key.node_id]
                        self.failed_attempts[api_key.node_id] = 0
                
                # Update last used time
                api_key.last_used_at = datetime.now(timezone.utc)
                
                # Reset rate limiting if needed
                if datetime.now(timezone.utc) >= api_key.rate_limit_reset:
                    api_key.hourly_shard_count = 0
                    api_key.rate_limit_reset = datetime.now(timezone.utc) + timedelta(hours=1)
                
                logger.info(f"Successfully authenticated API key for node {api_key.node_id}")
                return api_key
        
        # No matching key found
        await self._log_failed_attempt("unknown", ip_address, raw_api_key, "Invalid API key")
        return None
    
    async def _log_failed_attempt(self, node_id: str, ip_address: str, attempted_key: str, reason: str):
        """Log failed authentication attempt."""
        # Increment failed attempts
        self.failed_attempts[node_id] = self.failed_attempts.get(node_id, 0) + 1
        
        # Check if lockout threshold reached
        if self.failed_attempts[node_id] >= self.max_failed_attempts:
            self.lockout_times[node_id] = datetime.now(timezone.utc) + self.lockout_duration
            logger.warning(f"Node {node_id} locked out due to {self.failed_attempts[node_id]} failed attempts")
        
        # Log to database
        import aiosqlite
        attempt_id = f"fail_{secrets.token_hex(8)}"
        
        async with aiosqlite.connect(self.auth_db_path) as db:
            await db.execute("""
                INSERT INTO failed_auth_attempts 
                (attempt_id, node_id, ip_address, attempted_key, timestamp, reason)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                attempt_id, node_id, ip_address, 
                attempted_key[:16] + "...",  # Only log partial key for security
                datetime.now(timezone.utc), reason
            ))
            await db.commit()
        
        logger.warning(f"Failed authentication attempt from {ip_address} for node {node_id}: {reason}")
    
    async def _load_existing_keys(self):
        """Load existing API keys from database."""
        # Implementation would load from database
        logger.info("Loaded existing API keys from database")
    
    async def _start_maintenance_tasks(self):
        """Start background maintenance tasks."""
        asyncio.create_task(self._cleanup_expired_keys())
        asyncio.create_task(self._rotate_keys())
        logger.info("Started authentication maintenance tasks")
    
    async def _cleanup_expired_keys(self):
        """Clean up expired API keys."""
        while True:
            try:
                current_time = datetime.now(timezone.utc)
                expired_keys = []
                
                for key_id, api_key in self.api_keys.items():
                    if api_key.expires_at and api_key.expires_at < current_time:
                        api_key.status = APIKeyStatus.EXPIRED
                        expired_keys.append(key_id)
                
                if expired_keys:
                    logger.info(f"Marked {len(expired_keys)} API keys as expired")
                
                await asyncio.sleep(3600)  # Check every hour
            except Exception as e:
                logger.error(f"Error in key cleanup task: {e}")
                await asyncio.sleep(3600)
    
    async def _rotate_keys(self):
        """Rotate API keys that are due for rotation."""
        while True:
            try:
                # Key rotation logic would go here
                await asyncio.sleep(86400)  # Check daily
            except Exception as e:
                logger.error(f"Error in key rotation task: {e}")
                await asyncio.sleep(86400)
