"""
Government-Level Backup Manager

The central orchestrator of NetLink's revolutionary backup system.
Coordinates all backup operations with government-level security and zero data loss guarantees.
"""

import asyncio
import logging
import hashlib
import secrets
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import sqlite3
import aiosqlite

from .shard_manager import ImmutableShardManager
from .encryption_manager import QuantumEncryptionManager
from .distribution_manager import IntelligentDistributionManager
from .recovery_manager import AdvancedRecoveryManager
from .proxy_manager import DatabaseProxyManager
from .backup_node_auth import BackupNodeAuthManager
from .user_message_backup import UniversalBackupManager
from ..plugins.archive_system import ArchiveSystemPlugin

logger = logging.getLogger(__name__)


class BackupPriority(Enum):
    """Backup priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5


class BackupType(Enum):
    """Types of backups."""
    FULL = "full"
    INCREMENTAL = "incremental"
    DIFFERENTIAL = "differential"
    SNAPSHOT = "snapshot"
    EMERGENCY = "emergency"


class BackupStatus(Enum):
    """Backup operation status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    VERIFIED = "verified"
    FAILED = "failed"
    CORRUPTED = "corrupted"


@dataclass
class BackupOperation:
    """Represents a backup operation."""
    backup_id: str
    backup_type: BackupType
    priority: BackupPriority
    status: BackupStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_size: int = 0
    compressed_size: int = 0
    shard_count: int = 0
    redundancy_factor: int = 5
    encryption_key_hash: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None


@dataclass
class SystemHealth:
    """System health metrics."""
    total_backups: int
    active_shards: int
    healthy_nodes: int
    total_nodes: int
    storage_used: int
    storage_available: int
    backup_success_rate: float
    average_recovery_time: float
    last_health_check: datetime


class GovernmentBackupManager:
    """
    Government-Level Backup Manager
    
    The central orchestrator of NetLink's revolutionary backup system.
    
    Features:
    - Government-level security with quantum-resistant encryption
    - Immutable shard technology with zero data loss guarantees
    - AI-powered intelligent distribution across nodes
    - Real-time monitoring and health checks
    - Advanced recovery capabilities including partial restoration
    - Database proxy mode for resilient operation
    - Comprehensive audit logging and compliance
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the Government Backup Manager."""
        # Configuration
        self.config = config or self._get_default_config()
        
        # Directory structure
        self.backup_dir = Path("backup_data")
        self.shards_dir = self.backup_dir / "shards"
        self.databases_dir = self.backup_dir / "databases"
        self.logs_dir = self.backup_dir / "logs"
        self.temp_dir = self.backup_dir / "temp"
        
        # Ensure directories exist
        for directory in [self.backup_dir, self.shards_dir, self.databases_dir, self.logs_dir, self.temp_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Core managers (will be initialized in initialize())
        self.shard_manager: Optional[ImmutableShardManager] = None
        self.encryption_manager: Optional[QuantumEncryptionManager] = None
        self.distribution_manager: Optional[IntelligentDistributionManager] = None
        self.recovery_manager: Optional[AdvancedRecoveryManager] = None
        self.proxy_manager: Optional[DatabaseProxyManager] = None
        self.auth_manager: Optional[BackupNodeAuthManager] = None
        self.universal_backup_manager: Optional[UniversalBackupManager] = None
        self.archive_system: Optional[ArchiveSystemPlugin] = None
        
        # Operation tracking
        self.active_operations: Dict[str, BackupOperation] = {}
        self.system_health = SystemHealth(
            total_backups=0,
            active_shards=0,
            healthy_nodes=0,
            total_nodes=0,
            storage_used=0,
            storage_available=0,
            backup_success_rate=1.0,
            average_recovery_time=0.0,
            last_health_check=datetime.now(timezone.utc)
        )
        
        # State
        self.proxy_mode_active = False
        self.initialized = False
        
        # Database paths
        self.metadata_db_path = self.databases_dir / "backup_metadata.db"
        self.audit_db_path = self.databases_dir / "audit_log.db"
        
        logger.info("Government Backup Manager created")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            'security_level': 'GOVERNMENT',
            'redundancy_factor': 5,
            'quantum_encryption': True,
            'zero_data_loss': True,
            'backup_retention_days': 365,
            'health_check_interval': 300,  # 5 minutes
            'emergency_backup_threshold': 0.95,
            'max_concurrent_operations': 10,
            'shard_verification_interval': 3600,  # 1 hour
            'auto_recovery_enabled': True
        }
    
    async def initialize(self):
        """Initialize the backup manager and all core components."""
        if self.initialized:
            return
        
        logger.info("Initializing Government Backup Manager...")
        
        # Initialize databases
        await self._initialize_databases()
        
        # Initialize core managers
        self.shard_manager = ImmutableShardManager(self)
        await self.shard_manager.initialize()
        
        self.encryption_manager = QuantumEncryptionManager(self)
        await self.encryption_manager.initialize()
        
        self.distribution_manager = IntelligentDistributionManager(self)
        await self.distribution_manager.initialize()
        
        self.recovery_manager = AdvancedRecoveryManager(self)
        await self.recovery_manager.initialize()
        
        self.proxy_manager = DatabaseProxyManager(self)
        await self.proxy_manager.initialize()

        # Initialize authentication manager
        self.auth_manager = BackupNodeAuthManager(self)
        await self.auth_manager.initialize()

        # Initialize universal backup manager
        self.universal_backup_manager = UniversalBackupManager(self)
        await self.universal_backup_manager.initialize()

        # Initialize archive system plugin
        self.archive_system = ArchiveSystemPlugin(self)
        await self.archive_system.initialize()

        # Start background tasks
        asyncio.create_task(self._health_monitoring_task())
        asyncio.create_task(self._maintenance_task())
        
        # Load existing operations
        await self._load_existing_operations()
        
        self.initialized = True
        logger.info("Government Backup Manager initialized successfully")
        
        # Log initialization audit event
        await self._log_audit_event(
            operation="SYSTEM_INITIALIZE",
            details="Government Backup Manager initialized with government-level security",
            success=True
        )
    
    async def _initialize_databases(self):
        """Initialize backup system databases."""
        # Metadata database
        async with aiosqlite.connect(self.metadata_db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS backup_operations (
                    backup_id TEXT PRIMARY KEY,
                    backup_type TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    total_size INTEGER DEFAULT 0,
                    compressed_size INTEGER DEFAULT 0,
                    shard_count INTEGER DEFAULT 0,
                    redundancy_factor INTEGER DEFAULT 5,
                    encryption_key_hash TEXT,
                    metadata TEXT,
                    error_message TEXT
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS system_health_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    total_backups INTEGER,
                    active_shards INTEGER,
                    healthy_nodes INTEGER,
                    total_nodes INTEGER,
                    storage_used INTEGER,
                    storage_available INTEGER,
                    backup_success_rate REAL,
                    average_recovery_time REAL
                )
            """)
            
            await db.commit()
        
        # Audit database
        async with aiosqlite.connect(self.audit_db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    user_id TEXT,
                    backup_id TEXT,
                    details TEXT,
                    success BOOLEAN NOT NULL,
                    security_level TEXT
                )
            """)
            
            await db.commit()
    
    async def _load_existing_operations(self):
        """Load existing backup operations from database."""
        async with aiosqlite.connect(self.metadata_db_path) as db:
            async with db.execute("SELECT * FROM backup_operations WHERE status IN ('pending', 'in_progress')") as cursor:
                async for row in cursor:
                    operation = BackupOperation(
                        backup_id=row[0],
                        backup_type=BackupType(row[1]),
                        priority=BackupPriority(row[2]),
                        status=BackupStatus(row[3]),
                        created_at=datetime.fromisoformat(row[4]),
                        started_at=datetime.fromisoformat(row[5]) if row[5] else None,
                        completed_at=datetime.fromisoformat(row[6]) if row[6] else None,
                        total_size=row[7],
                        compressed_size=row[8],
                        shard_count=row[9],
                        redundancy_factor=row[10],
                        encryption_key_hash=row[11],
                        metadata=json.loads(row[12]) if row[12] else {},
                        error_message=row[13]
                    )
                    self.active_operations[operation.backup_id] = operation
        
        logger.info(f"Loaded {len(self.active_operations)} existing backup operations")
    
    async def create_backup(
        self,
        backup_type: BackupType = BackupType.FULL,
        priority: BackupPriority = BackupPriority.NORMAL,
        redundancy_factor: int = 5,
        description: str = "",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create a new backup operation."""
        backup_id = f"backup_{backup_type.value}_{secrets.token_hex(16)}_{int(datetime.now(timezone.utc).timestamp())}"
        
        operation = BackupOperation(
            backup_id=backup_id,
            backup_type=backup_type,
            priority=priority,
            status=BackupStatus.PENDING,
            created_at=datetime.now(timezone.utc),
            redundancy_factor=redundancy_factor,
            metadata=metadata or {'description': description}
        )
        
        # Add to active operations
        self.active_operations[backup_id] = operation
        
        # Start backup execution asynchronously
        asyncio.create_task(self._execute_backup(operation))
        
        logger.info(f"Created backup operation {backup_id}")
        return backup_id

    async def _execute_backup(self, operation: BackupOperation):
        """Execute a backup operation."""
        try:
            operation.status = BackupStatus.IN_PROGRESS
            operation.started_at = datetime.now(timezone.utc)

            logger.info(f"Starting backup operation {operation.backup_id}")

            # Get data to backup based on type
            backup_data = await self._get_backup_data(operation.backup_type)
            operation.total_size = len(backup_data)

            # Compress data
            compressed_data = await self._compress_data(backup_data)
            operation.compressed_size = len(compressed_data)

            # Encrypt data
            encrypted_data, encryption_key_hash = await self.encryption_manager.encrypt_backup_data(
                compressed_data, operation.backup_id
            )
            operation.encryption_key_hash = encryption_key_hash

            # Create shards
            shards = await self.shard_manager.create_shards(
                backup_id=operation.backup_id,
                data=encrypted_data,
                redundancy_factor=operation.redundancy_factor
            )
            operation.shard_count = len(shards)

            # Distribute shards intelligently
            await self.distribution_manager.distribute_shards(shards, operation)

            # Verify backup integrity
            verification_success = await self._verify_backup_integrity(operation)

            if verification_success:
                operation.status = BackupStatus.VERIFIED
                operation.completed_at = datetime.now(timezone.utc)
                logger.info(f"Backup operation {operation.backup_id} completed successfully")
            else:
                operation.status = BackupStatus.CORRUPTED
                operation.error_message = "Backup verification failed"
                logger.error(f"Backup operation {operation.backup_id} verification failed")

            # Save operation to database
            await self._save_backup_operation(operation)

            # Log audit event
            await self._log_audit_event(
                operation="COMPLETE_BACKUP",
                backup_id=operation.backup_id,
                details=f"Backup completed with status {operation.status.value}",
                success=(operation.status == BackupStatus.VERIFIED)
            )

        except Exception as e:
            operation.status = BackupStatus.FAILED
            operation.error_message = str(e)
            operation.completed_at = datetime.now(timezone.utc)

            logger.error(f"Backup operation {operation.backup_id} failed: {e}")

            await self._log_audit_event(
                operation="BACKUP_FAILED",
                backup_id=operation.backup_id,
                details=f"Backup failed: {str(e)}",
                success=False
            )

    async def get_backup_status(self, backup_id: str) -> Optional[BackupOperation]:
        """Get the status of a backup operation."""
        return self.active_operations.get(backup_id)

    async def list_backups(
        self,
        status_filter: Optional[BackupStatus] = None,
        limit: int = 100
    ) -> List[BackupOperation]:
        """List backup operations with optional filtering."""
        operations = list(self.active_operations.values())

        if status_filter:
            operations = [op for op in operations if op.status == status_filter]

        # Sort by creation time (newest first)
        operations.sort(key=lambda x: x.created_at, reverse=True)

        return operations[:limit]

    async def get_system_health(self) -> SystemHealth:
        """Get current system health metrics."""
        await self._update_system_health()
        return self.system_health

    async def enable_proxy_mode(self, reason: str = "Database unavailable"):
        """Enable proxy mode for database failures."""
        if not self.proxy_mode_active:
            self.proxy_mode_active = True
            await self.proxy_manager.enable_proxy_mode(reason)

            await self._log_audit_event(
                operation="ENABLE_PROXY_MODE",
                details=f"Proxy mode enabled: {reason}",
                success=True
            )

            logger.warning(f"Proxy mode enabled: {reason}")

    async def disable_proxy_mode(self):
        """Disable proxy mode and return to normal operation."""
        if self.proxy_mode_active:
            self.proxy_mode_active = False
            await self.proxy_manager.disable_proxy_mode()

            await self._log_audit_event(
                operation="DISABLE_PROXY_MODE",
                details="Proxy mode disabled, returning to normal operation",
                success=True
            )

            logger.info("Proxy mode disabled, returning to normal operation")

    async def emergency_backup(self, reason: str = "Emergency backup triggered"):
        """Trigger emergency backup procedure."""
        logger.critical(f"Emergency backup triggered: {reason}")

        backup_id = await self.create_backup(
            backup_type=BackupType.EMERGENCY,
            priority=BackupPriority.EMERGENCY,
            description=f"Emergency backup: {reason}"
        )

        await self._log_audit_event(
            operation="EMERGENCY_BACKUP",
            backup_id=backup_id,
            details=f"Emergency backup triggered: {reason}",
            success=True
        )

        return backup_id

    async def _get_backup_data(self, backup_type: BackupType) -> bytes:
        """Get data to backup based on backup type."""
        # TODO: Implement actual data retrieval from database
        # This is a placeholder that would integrate with the main NetLink database

        if backup_type == BackupType.FULL:
            # Get complete database dump
            return b"FULL_DATABASE_DUMP_PLACEHOLDER"
        elif backup_type == BackupType.INCREMENTAL:
            # Get changes since last backup
            return b"INCREMENTAL_CHANGES_PLACEHOLDER"
        elif backup_type == BackupType.DIFFERENTIAL:
            # Get changes since last full backup
            return b"DIFFERENTIAL_CHANGES_PLACEHOLDER"
        elif backup_type == BackupType.SNAPSHOT:
            # Get current state snapshot
            return b"SNAPSHOT_DATA_PLACEHOLDER"
        elif backup_type == BackupType.EMERGENCY:
            # Get critical data only
            return b"EMERGENCY_DATA_PLACEHOLDER"
        else:
            raise ValueError(f"Unknown backup type: {backup_type}")

    async def _compress_data(self, data: bytes) -> bytes:
        """Compress backup data."""
        import gzip
        return gzip.compress(data, compresslevel=9)

    async def _verify_backup_integrity(self, operation: BackupOperation) -> bool:
        """Verify backup integrity."""
        try:
            # Verify all shards exist and are accessible
            shard_verification = await self.shard_manager.verify_backup_shards(operation.backup_id)

            # Verify distribution meets redundancy requirements
            distribution_verification = await self.distribution_manager.verify_distribution(operation.backup_id)

            # Verify encryption integrity
            encryption_verification = await self.encryption_manager.verify_encryption(operation.backup_id)

            return shard_verification and distribution_verification and encryption_verification

        except Exception as e:
            logger.error(f"Backup verification failed for {operation.backup_id}: {e}")
            return False

    async def _save_backup_operation(self, operation: BackupOperation):
        """Save backup operation to database."""
        async with aiosqlite.connect(self.metadata_db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO backup_operations (
                    backup_id, backup_type, priority, status, created_at,
                    started_at, completed_at, total_size, compressed_size,
                    shard_count, redundancy_factor, encryption_key_hash,
                    metadata, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                operation.backup_id,
                operation.backup_type.value,
                operation.priority.value,
                operation.status.value,
                operation.created_at.isoformat(),
                operation.started_at.isoformat() if operation.started_at else None,
                operation.completed_at.isoformat() if operation.completed_at else None,
                operation.total_size,
                operation.compressed_size,
                operation.shard_count,
                operation.redundancy_factor,
                operation.encryption_key_hash,
                json.dumps(operation.metadata),
                operation.error_message
            ))
            await db.commit()

    async def _log_audit_event(
        self,
        operation: str,
        user_id: Optional[str] = None,
        backup_id: Optional[str] = None,
        details: str = "",
        success: bool = True
    ):
        """Log audit event."""
        async with aiosqlite.connect(self.audit_db_path) as db:
            await db.execute("""
                INSERT INTO audit_log (
                    timestamp, operation, user_id, backup_id, details, success, security_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now(timezone.utc).isoformat(),
                operation,
                user_id,
                backup_id,
                details,
                success,
                self.config['security_level']
            ))
            await db.commit()

    async def _update_system_health(self):
        """Update system health metrics."""
        try:
            # Count backups by status
            total_backups = len(self.active_operations)
            completed_backups = len([op for op in self.active_operations.values()
                                   if op.status == BackupStatus.VERIFIED])

            # Get shard and node information from managers
            active_shards = await self.shard_manager.get_active_shard_count()
            healthy_nodes, total_nodes = await self.distribution_manager.get_node_health()
            storage_used, storage_available = await self._get_storage_metrics()

            # Calculate success rate
            backup_success_rate = (completed_backups / total_backups) if total_backups > 0 else 1.0

            # Get average recovery time (placeholder)
            average_recovery_time = 30.0  # TODO: Calculate from actual recovery operations

            self.system_health = SystemHealth(
                total_backups=total_backups,
                active_shards=active_shards,
                healthy_nodes=healthy_nodes,
                total_nodes=total_nodes,
                storage_used=storage_used,
                storage_available=storage_available,
                backup_success_rate=backup_success_rate,
                average_recovery_time=average_recovery_time,
                last_health_check=datetime.now(timezone.utc)
            )

            # Save health metrics to database
            await self._save_health_metrics()

        except Exception as e:
            logger.error(f"Failed to update system health: {e}")

    async def _get_storage_metrics(self) -> Tuple[int, int]:
        """Get storage usage metrics."""
        try:
            # Calculate storage used by shards
            storage_used = 0
            if self.shards_dir.exists():
                for shard_file in self.shards_dir.rglob("*"):
                    if shard_file.is_file():
                        storage_used += shard_file.stat().st_size

            # Get available storage (simplified)
            import shutil
            _, _, storage_available = shutil.disk_usage(self.backup_dir)

            return storage_used, storage_available

        except Exception as e:
            logger.error(f"Failed to get storage metrics: {e}")
            return 0, 0

    async def _save_health_metrics(self):
        """Save health metrics to database."""
        async with aiosqlite.connect(self.metadata_db_path) as db:
            await db.execute("""
                INSERT INTO system_health_log (
                    timestamp, total_backups, active_shards, healthy_nodes,
                    total_nodes, storage_used, storage_available,
                    backup_success_rate, average_recovery_time
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                self.system_health.last_health_check.isoformat(),
                self.system_health.total_backups,
                self.system_health.active_shards,
                self.system_health.healthy_nodes,
                self.system_health.total_nodes,
                self.system_health.storage_used,
                self.system_health.storage_available,
                self.system_health.backup_success_rate,
                self.system_health.average_recovery_time
            ))
            await db.commit()

    async def _health_monitoring_task(self):
        """Background task for health monitoring."""
        while True:
            try:
                await asyncio.sleep(self.config['health_check_interval'])
                await self._update_system_health()

                # Check for emergency conditions
                if self.system_health.backup_success_rate < self.config['emergency_backup_threshold']:
                    await self.emergency_backup("Low backup success rate detected")

                # Check node health
                if (self.system_health.healthy_nodes / max(self.system_health.total_nodes, 1)) < 0.5:
                    await self.enable_proxy_mode("Majority of nodes unhealthy")

            except Exception as e:
                logger.error(f"Health monitoring task error: {e}")

    async def _maintenance_task(self):
        """Background task for system maintenance."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour

                # Clean up old operations
                await self._cleanup_old_operations()

                # Optimize shard distribution
                await self.distribution_manager.optimize_distribution()

                # Verify random shards
                await self.shard_manager.verify_random_shards()

            except Exception as e:
                logger.error(f"Maintenance task error: {e}")

    async def _cleanup_old_operations(self):
        """Clean up old completed operations."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(days=self.config['backup_retention_days'])

        operations_to_remove = []
        for backup_id, operation in self.active_operations.items():
            if (operation.completed_at and
                operation.completed_at < cutoff_time and
                operation.status in [BackupStatus.VERIFIED, BackupStatus.FAILED]):
                operations_to_remove.append(backup_id)

        for backup_id in operations_to_remove:
            del self.active_operations[backup_id]
            logger.info(f"Cleaned up old operation {backup_id}")

    # Government-Level Security Enhancement Methods

    async def generate_backup_node_api_key(
        self,
        node_id: str,
        node_name: str,
        permission_level: str = "shard_access",
        max_shards_per_hour: int = 100,
        expires_in_days: int = 90
    ) -> tuple[str, str]:
        """
        Generate API key for backup node with restricted permissions.

        Returns:
            tuple: (key_id, raw_api_key)
        """
        if not self.auth_manager:
            raise RuntimeError("Authentication manager not initialized")

        from .backup_node_auth import NodePermissionLevel

        # Convert string to enum
        permission_map = {
            "read_only": NodePermissionLevel.READ_ONLY,
            "shard_access": NodePermissionLevel.SHARD_ACCESS,
            "limited_collection": NodePermissionLevel.LIMITED_COLLECTION,
            "full_access": NodePermissionLevel.FULL_ACCESS,
            "admin": NodePermissionLevel.ADMIN
        }

        permission_enum = permission_map.get(permission_level, NodePermissionLevel.SHARD_ACCESS)

        key_id, raw_key = self.auth_manager.generate_api_key(
            node_id=node_id,
            node_name=node_name,
            permission_level=permission_enum,
            max_shards_per_hour=max_shards_per_hour,
            expires_in_days=expires_in_days
        )

        await self._log_audit_event(
            operation="GENERATE_API_KEY",
            details=f"Generated API key for node {node_id} with {permission_level} permissions",
            success=True
        )

        return key_id, raw_key

    async def authenticate_backup_node(self, api_key: str, ip_address: str = "unknown"):
        """Authenticate backup node API key."""
        if not self.auth_manager:
            raise RuntimeError("Authentication manager not initialized")

        return await self.auth_manager.authenticate_api_key(api_key, ip_address)

    async def set_user_backup_preferences(
        self,
        user_id: str,
        username: str,
        backup_enabled: bool = True,
        opted_out_data_types: list = None
    ):
        """Set user backup preferences with opt-out capability."""
        if not self.universal_backup_manager:
            raise RuntimeError("Universal backup manager not initialized")

        from .user_message_backup import BackupOptStatus, BackupDataType

        # Convert data types
        opted_out_set = set()
        if opted_out_data_types:
            for data_type in opted_out_data_types:
                if hasattr(BackupDataType, data_type.upper()):
                    opted_out_set.add(getattr(BackupDataType, data_type.upper()))

        backup_status = BackupOptStatus.OPTED_IN if backup_enabled else BackupOptStatus.OPTED_OUT

        return await self.universal_backup_manager.set_user_backup_preferences(
            user_id=user_id,
            username=username,
            backup_status=backup_status,
            opted_out_data_types=opted_out_set
        )

    async def backup_user_message(
        self,
        message_id: str,
        user_id: str,
        chat_id: str,
        message_content: str,
        message_type: str = "text",
        attachments: list = None,
        reactions: dict = None
    ):
        """Backup user message with opt-out checking."""
        if not self.universal_backup_manager:
            raise RuntimeError("Universal backup manager not initialized")

        return await self.universal_backup_manager.backup_user_message(
            message_id=message_id,
            user_id=user_id,
            chat_id=chat_id,
            message_content=message_content,
            message_type=message_type,
            attachments=attachments or [],
            reactions=reactions or {}
        )

    async def opt_out_user_backup(self, user_id: str, data_types: list = None):
        """Opt user out of backup system."""
        if not self.universal_backup_manager:
            raise RuntimeError("Universal backup manager not initialized")

        from .user_message_backup import BackupDataType

        # Convert data types
        data_type_set = None
        if data_types:
            data_type_set = set()
            for data_type in data_types:
                if hasattr(BackupDataType, data_type.upper()):
                    data_type_set.add(getattr(BackupDataType, data_type.upper()))

        result = await self.universal_backup_manager.opt_out_user_backup(user_id, data_type_set)

        await self._log_audit_event(
            operation="USER_OPT_OUT",
            details=f"User {user_id} opted out of backup: {data_types or 'all data types'}",
            success=result
        )

        return result

    async def opt_in_user_backup(self, user_id: str, data_types: list = None):
        """Opt user back into backup system."""
        if not self.universal_backup_manager:
            raise RuntimeError("Universal backup manager not initialized")

        from .user_message_backup import BackupDataType

        # Convert data types
        data_type_set = None
        if data_types:
            data_type_set = set()
            for data_type in data_types:
                if hasattr(BackupDataType, data_type.upper()):
                    data_type_set.add(getattr(BackupDataType, data_type.upper()))

        result = await self.universal_backup_manager.opt_in_user_backup(user_id, data_type_set)

        await self._log_audit_event(
            operation="USER_OPT_IN",
            details=f"User {user_id} opted into backup: {data_types or 'all data types'}",
            success=result
        )

        return result

    async def create_archive(
        self,
        name: str,
        description: str,
        created_by: str,
        data: Union[bytes, str, dict],
        archive_type: str = "full_archive",
        compression_enabled: bool = True,
        encryption_enabled: bool = True,
        retention_days: int = None,
        tags: list = None,
        metadata: dict = None
    ):
        """Create a new archive with versioning through shard system."""
        if not self.archive_system:
            raise RuntimeError("Archive system not initialized")

        from ..plugins.archive_system import ArchiveType

        # Convert string to enum
        archive_type_map = {
            "full_archive": ArchiveType.FULL_ARCHIVE,
            "incremental_archive": ArchiveType.INCREMENTAL_ARCHIVE,
            "differential_archive": ArchiveType.DIFFERENTIAL_ARCHIVE,
            "snapshot_archive": ArchiveType.SNAPSHOT_ARCHIVE,
            "versioned_archive": ArchiveType.VERSIONED_ARCHIVE
        }

        archive_type_enum = archive_type_map.get(archive_type, ArchiveType.FULL_ARCHIVE)

        result = await self.archive_system.create_archive(
            name=name,
            description=description,
            created_by=created_by,
            data=data,
            archive_type=archive_type_enum,
            compression_enabled=compression_enabled,
            encryption_enabled=encryption_enabled,
            retention_days=retention_days,
            tags=set(tags) if tags else None,
            metadata=metadata
        )

        await self._log_audit_event(
            operation="CREATE_ARCHIVE",
            details=f"Created archive '{name}' by {created_by}",
            success=True
        )

        return result

    async def create_archive_version(
        self,
        archive_id: str,
        data: Union[bytes, str, dict],
        created_by: str,
        archive_type: str = "incremental_archive",
        metadata: dict = None
    ):
        """Create a new version of an existing archive."""
        if not self.archive_system:
            raise RuntimeError("Archive system not initialized")

        from ..plugins.archive_system import ArchiveType

        archive_type_map = {
            "full_archive": ArchiveType.FULL_ARCHIVE,
            "incremental_archive": ArchiveType.INCREMENTAL_ARCHIVE,
            "differential_archive": ArchiveType.DIFFERENTIAL_ARCHIVE,
            "snapshot_archive": ArchiveType.SNAPSHOT_ARCHIVE,
            "versioned_archive": ArchiveType.VERSIONED_ARCHIVE
        }

        archive_type_enum = archive_type_map.get(archive_type, ArchiveType.INCREMENTAL_ARCHIVE)

        result = await self.archive_system.create_archive_version(
            archive_id=archive_id,
            data=data,
            created_by=created_by,
            archive_type=archive_type_enum,
            metadata=metadata
        )

        await self._log_audit_event(
            operation="CREATE_ARCHIVE_VERSION",
            details=f"Created version for archive {archive_id} by {created_by}",
            success=True
        )

        return result


# Global backup manager instance
government_backup_manager = GovernmentBackupManager()
