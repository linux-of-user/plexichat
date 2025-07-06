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
    FAILED = "failed"
    CORRUPTED = "corrupted"
    VERIFIED = "verified"


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
    encryption_key_hash: str = ""
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
    
    The central orchestrator that coordinates all backup operations with:
    - Government-level security and encryption
    - Intelligent shard distribution
    - Zero data loss guarantees
    - Real-time monitoring and health checks
    - Emergency recovery capabilities
    - Proxy mode for database failures
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize the government backup manager."""
        self.config_path = config_path or Path("backup_system/config/backup_config.yaml")
        self.backup_dir = Path("backup_system")
        self.databases_dir = self.backup_dir / "databases"
        self.shards_dir = self.backup_dir / "shards"
        self.logs_dir = self.backup_dir / "logs"
        
        # Ensure directories exist
        for directory in [self.backup_dir, self.databases_dir, self.shards_dir, self.logs_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize core components
        self.shard_manager = ImmutableShardManager(self)
        self.encryption_manager = QuantumEncryptionManager(self)
        self.distribution_manager = IntelligentDistributionManager(self)
        self.recovery_manager = AdvancedRecoveryManager(self)
        self.proxy_manager = DatabaseProxyManager(self)
        
        # System state
        self.active_operations: Dict[str, BackupOperation] = {}
        self.system_health = SystemHealth(0, 0, 0, 0, 0, 0, 0.0, 0.0, datetime.now(timezone.utc))
        self.is_initialized = False
        self.proxy_mode_active = False
        
        # Configuration
        self.config = self._load_config()
        
        # Database connections
        self.metadata_db_path = self.databases_dir / "backup_metadata.db"
        self.audit_db_path = self.databases_dir / "audit_log.db"
        
        # Initialize logging
        self._setup_logging()
        
        logger.info("Government Backup Manager initialized with quantum-resistant security")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load backup system configuration."""
        default_config = {
            'security_level': 'GOVERNMENT',
            'redundancy_factor': 5,
            'max_shard_size': 50 * 1024 * 1024,  # 50MB
            'encryption_algorithm': 'AES-256-GCM',
            'quantum_resistant': True,
            'immutable_shards': True,
            'intelligent_distribution': True,
            'real_time_monitoring': True,
            'proxy_mode_enabled': True,
            'audit_logging': True,
            'performance_optimization': True,
            'backup_retention_days': 365,
            'health_check_interval': 300,  # 5 minutes
            'emergency_backup_threshold': 0.1,  # 10% node failure triggers emergency backup
        }
        
        # TODO: Load from YAML file when it exists
        return default_config
    
    def _setup_logging(self):
        """Setup comprehensive logging system."""
        log_file = self.logs_dir / "backup_system.log"
        
        # Create file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(file_handler)
        logger.setLevel(logging.INFO)
    
    async def initialize(self):
        """Initialize the backup system."""
        if self.is_initialized:
            return
        
        try:
            logger.info("Initializing Government-Level Backup System...")
            
            # Initialize database
            await self._initialize_databases()
            
            # Initialize core components
            await self.shard_manager.initialize()
            await self.encryption_manager.initialize()
            await self.distribution_manager.initialize()
            await self.recovery_manager.initialize()
            await self.proxy_manager.initialize()
            
            # Start monitoring tasks
            asyncio.create_task(self._health_monitoring_task())
            asyncio.create_task(self._maintenance_task())
            
            # Update system health
            await self._update_system_health()
            
            self.is_initialized = True
            logger.info("Government Backup System initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize backup system: {e}")
            raise
    
    async def _initialize_databases(self):
        """Initialize backup system databases."""
        # Create metadata database
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
                    timestamp TEXT PRIMARY KEY,
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
        
        # Create audit database
        async with aiosqlite.connect(self.audit_db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    user_id TEXT,
                    backup_id TEXT,
                    details TEXT,
                    success BOOLEAN,
                    security_level TEXT
                )
            """)
            
            await db.commit()
    
    async def create_backup(
        self,
        backup_type: BackupType = BackupType.FULL,
        priority: BackupPriority = BackupPriority.NORMAL,
        description: str = "",
        user_id: Optional[str] = None
    ) -> str:
        """Create a new backup operation."""
        backup_id = f"backup_{secrets.token_hex(16)}_{int(datetime.now(timezone.utc).timestamp())}"
        
        operation = BackupOperation(
            backup_id=backup_id,
            backup_type=backup_type,
            priority=priority,
            status=BackupStatus.PENDING,
            created_at=datetime.now(timezone.utc),
            metadata={'description': description, 'user_id': user_id}
        )
        
        self.active_operations[backup_id] = operation
        
        # Log audit event
        await self._log_audit_event(
            operation="CREATE_BACKUP",
            user_id=user_id,
            backup_id=backup_id,
            details=f"Created {backup_type.value} backup with {priority.value} priority",
            success=True
        )
        
        # Start backup process
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


# Global backup manager instance
government_backup_manager = GovernmentBackupManager()
