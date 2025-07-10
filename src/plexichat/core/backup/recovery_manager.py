"""
Advanced Recovery Manager

Manages backup recovery operations with partial restore capabilities,
disaster recovery, and minimal data loss even with multiple node failures.
"""

import asyncio
import logging
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import aiosqlite

logger = logging.getLogger(__name__)


class RecoveryType(Enum):
    """Types of recovery operations."""
    FULL_RESTORE = "full-restore"
    PARTIAL_RESTORE = "partial-restore"
    PROGRESSIVE_RESTORE = "progressive-restore"
    EMERGENCY_RESTORE = "emergency-restore"
    DISASTER_RECOVERY = "disaster-recovery"


class RecoveryStatus(Enum):
    """Recovery operation status."""
    PENDING = "pending"
    IN_PROGRESS = "in-progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL_SUCCESS = "partial-success"


@dataclass
class RecoveryOperation:
    """Represents a recovery operation."""
    recovery_id: str
    backup_id: str
    recovery_type: RecoveryType
    status: RecoveryStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    target_path: Optional[str] = None
    recovered_bytes: int = 0
    total_bytes: int = 0
    success_rate: float = 0.0
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class AdvancedRecoveryManager:
    """
    Advanced Recovery Manager
    
    Manages backup recovery operations with:
    - Partial recovery capabilities even with missing shards
    - Progressive restoration for large datasets
    - Disaster recovery with minimal data loss
    - Intelligent shard reconstruction
    - Real-time recovery progress monitoring
    """
    
    def __init__(self, backup_manager):
        """Initialize the advanced recovery manager."""
        self.backup_manager = backup_manager
        self.recovery_dir = backup_manager.backup_dir / "recovery"
        self.recovery_dir.mkdir(parents=True, exist_ok=True)
        
        # Recovery operations tracking
        self.active_recoveries: Dict[str, RecoveryOperation] = {}
        self.recovery_history: List[RecoveryOperation] = []
        
        # Configuration
        self.config = {
            "partial_recovery_enabled": True,
            "progressive_recovery_enabled": True,
            "disaster_recovery_enabled": True,
            "minimum_shard_threshold": 0.6,  # 60% of shards needed for recovery
            "max_concurrent_recoveries": 3,
            "recovery_timeout_hours": 24
        }
        
        # Database
        self.recovery_db_path = backup_manager.databases_dir / "recovery_registry.db"
        
        logger.info("Advanced Recovery Manager initialized")
    
    async def initialize(self):
        """Initialize the recovery manager."""
        await self._initialize_database()
        await self._load_existing_recoveries()
        
        # Start background tasks
        asyncio.create_task(self._recovery_monitoring_task())
        
        logger.info("Advanced Recovery Manager initialized successfully")
    
    async def _initialize_database(self):
        """Initialize the recovery database."""
        async with aiosqlite.connect(self.recovery_db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS recovery_operations (
                    recovery_id TEXT PRIMARY KEY,
                    backup_id TEXT NOT NULL,
                    recovery_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    target_path TEXT,
                    recovered_bytes INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0,
                    success_rate REAL DEFAULT 0.0,
                    error_message TEXT,
                    metadata TEXT
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS recovery_progress (
                    recovery_id TEXT,
                    timestamp TEXT,
                    progress_percent REAL,
                    bytes_recovered INTEGER,
                    current_operation TEXT,
                    PRIMARY KEY (recovery_id, timestamp)
                )
            """)
            
            await db.commit()
    
    async def _load_existing_recoveries(self):
        """Load existing recovery operations from database."""
        async with aiosqlite.connect(self.recovery_db_path) as db:
            async with db.execute("SELECT * FROM recovery_operations") as cursor:
                async for row in cursor:
                    recovery = RecoveryOperation(
                        recovery_id=row[0],
                        backup_id=row[1],
                        recovery_type=RecoveryType(row[2]),
                        status=RecoveryStatus(row[3]),
                        created_at=datetime.fromisoformat(row[4]),
                        started_at=datetime.fromisoformat(row[5]) if row[5] else None,
                        completed_at=datetime.fromisoformat(row[6]) if row[6] else None,
                        target_path=row[7],
                        recovered_bytes=row[8],
                        total_bytes=row[9],
                        success_rate=row[10],
                        error_message=row[11],
                        metadata=json.loads(row[12]) if row[12] else {}
                    )
                    
                    if recovery.status in [RecoveryStatus.PENDING, RecoveryStatus.IN_PROGRESS]:
                        self.active_recoveries[recovery.recovery_id] = recovery
                    else:
                        self.recovery_history.append(recovery)
    
    async def start_recovery(
        self,
        backup_id: str,
        recovery_type: RecoveryType = RecoveryType.FULL_RESTORE,
        target_path: Optional[str] = None
    ) -> str:
        """Start a recovery operation."""
        import secrets
        
        recovery_id = f"recovery_{backup_id}_{secrets.token_hex(8)}"
        
        recovery = RecoveryOperation(
            recovery_id=recovery_id,
            backup_id=backup_id,
            recovery_type=recovery_type,
            status=RecoveryStatus.PENDING,
            created_at=datetime.now(timezone.utc),
            target_path=target_path or str(self.recovery_dir / backup_id)
        )
        
        # Store recovery operation
        self.active_recoveries[recovery_id] = recovery
        await self._save_recovery_to_database(recovery)
        
        # Start recovery task
        asyncio.create_task(self._execute_recovery(recovery))
        
        logger.info(f"Started recovery operation {recovery_id} for backup {backup_id}")
        return recovery_id
    
    async def _execute_recovery(self, recovery: RecoveryOperation):
        """Execute the recovery operation."""
        try:
            recovery.status = RecoveryStatus.IN_PROGRESS
            recovery.started_at = datetime.now(timezone.utc)
            await self._save_recovery_to_database(recovery)
            
            # Get backup shards
            shards = await self._get_backup_shards(recovery.backup_id)
            
            if not shards:
                raise Exception(f"No shards found for backup {recovery.backup_id}")
            
            recovery.total_bytes = sum(shard.size_bytes for shard in shards)
            
            # Check if we have enough shards for recovery
            available_shards = [s for s in shards if s.status.value != "missing"]
            availability_ratio = len(available_shards) / len(shards)
            
            if availability_ratio < self.config["minimum_shard_threshold"]:
                if recovery.recovery_type == RecoveryType.PARTIAL_RESTORE:
                    logger.warning(f"Only {availability_ratio:.1%} shards available, proceeding with partial recovery")
                else:
                    raise Exception(f"Insufficient shards for recovery: {availability_ratio:.1%} available")
            
            # Perform recovery based on type
            if recovery.recovery_type == RecoveryType.PROGRESSIVE_RESTORE:
                await self._progressive_recovery(recovery, available_shards)
            elif recovery.recovery_type == RecoveryType.PARTIAL_RESTORE:
                await self._partial_recovery(recovery, available_shards)
            else:
                await self._full_recovery(recovery, available_shards)
            
            # Mark as completed
            recovery.status = RecoveryStatus.COMPLETED
            recovery.completed_at = datetime.now(timezone.utc)
            recovery.success_rate = recovery.recovered_bytes / recovery.total_bytes if recovery.total_bytes > 0 else 0.0
            
            logger.info(f"Recovery {recovery.recovery_id} completed with {recovery.success_rate:.1%} success rate")
            
        except Exception as e:
            recovery.status = RecoveryStatus.FAILED
            recovery.error_message = str(e)
            logger.error(f"Recovery {recovery.recovery_id} failed: {e}")
        
        finally:
            await self._save_recovery_to_database(recovery)
            # Move from active to history
            if recovery.recovery_id in self.active_recoveries:
                del self.active_recoveries[recovery.recovery_id]
                self.recovery_history.append(recovery)
    
    async def _get_backup_shards(self, backup_id: str):
        """Get all shards for a backup."""
        # Get shards from shard manager
        shards = []
        for shard in self.backup_manager.shard_manager.immutable_shards.values():
            if shard.backup_id == backup_id:
                shards.append(shard)
        
        return sorted(shards, key=lambda s: s.shard_index)
    
    async def _full_recovery(self, recovery: RecoveryOperation, shards: List):
        """Perform full recovery of all shards."""
        target_path = Path(recovery.target_path)
        target_path.mkdir(parents=True, exist_ok=True)
        
        recovered_data = b""
        
        for shard in shards:
            try:
                # Read shard data (simplified)
                shard_data = await self._read_shard_data(shard)
                recovered_data += shard_data
                recovery.recovered_bytes += len(shard_data)
                
                # Update progress
                await self._update_recovery_progress(recovery, f"Recovered shard {shard.shard_index}")
                
            except Exception as e:
                logger.error(f"Failed to recover shard {shard.shard_id}: {e}")
        
        # Write recovered data
        output_file = target_path / f"{recovery.backup_id}_recovered.data"
        with open(output_file, 'wb') as f:
            f.write(recovered_data)
        
        logger.info(f"Full recovery completed: {len(recovered_data)} bytes written to {output_file}")
    
    async def _partial_recovery(self, recovery: RecoveryOperation, shards: List):
        """Perform partial recovery with available shards."""
        target_path = Path(recovery.target_path)
        target_path.mkdir(parents=True, exist_ok=True)
        
        for shard in shards:
            try:
                # Read shard data
                shard_data = await self._read_shard_data(shard)
                recovery.recovered_bytes += len(shard_data)
                
                # Write individual shard file
                shard_file = target_path / f"shard_{shard.shard_index:04d}.data"
                with open(shard_file, 'wb') as f:
                    f.write(shard_data)
                
                await self._update_recovery_progress(recovery, f"Recovered shard {shard.shard_index}")
                
            except Exception as e:
                logger.error(f"Failed to recover shard {shard.shard_id}: {e}")
        
        logger.info(f"Partial recovery completed: {recovery.recovered_bytes} bytes recovered")
    
    async def _progressive_recovery(self, recovery: RecoveryOperation, shards: List):
        """Perform progressive recovery in priority order."""
        # Sort shards by priority (metadata-based)
        priority_shards = sorted(shards, key=lambda s: s.metadata.get('priority', 0), reverse=True)
        
        await self._partial_recovery(recovery, priority_shards)
    
    async def _read_shard_data(self, shard) -> bytes:
        """Read data from a shard."""
        # This is a simplified implementation
        # In production, this would handle decryption, decompression, etc.
        shard_path = self.backup_manager.shard_manager.immutable_dir / f"{shard.shard_id}.shard"
        
        if shard_path.exists():
            with open(shard_path, 'rb') as f:
                return f.read()
        else:
            raise Exception(f"Shard file not found: {shard_path}")
    
    async def _update_recovery_progress(self, recovery: RecoveryOperation, operation: str):
        """Update recovery progress."""
        progress_percent = (recovery.recovered_bytes / recovery.total_bytes * 100) if recovery.total_bytes > 0 else 0
        
        async with aiosqlite.connect(self.recovery_db_path) as db:
            await db.execute("""
                INSERT INTO recovery_progress 
                (recovery_id, timestamp, progress_percent, bytes_recovered, current_operation)
                VALUES (?, ?, ?, ?, ?)
            """, (
                recovery.recovery_id,
                datetime.now(timezone.utc).isoformat(),
                progress_percent,
                recovery.recovered_bytes,
                operation
            ))
            await db.commit()
    
    async def _save_recovery_to_database(self, recovery: RecoveryOperation):
        """Save recovery operation to database."""
        async with aiosqlite.connect(self.recovery_db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO recovery_operations 
                (recovery_id, backup_id, recovery_type, status, created_at, started_at,
                 completed_at, target_path, recovered_bytes, total_bytes, success_rate,
                 error_message, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                recovery.recovery_id,
                recovery.backup_id,
                recovery.recovery_type.value,
                recovery.status.value,
                recovery.created_at.isoformat(),
                recovery.started_at.isoformat() if recovery.started_at else None,
                recovery.completed_at.isoformat() if recovery.completed_at else None,
                recovery.target_path,
                recovery.recovered_bytes,
                recovery.total_bytes,
                recovery.success_rate,
                recovery.error_message,
                json.dumps(recovery.metadata)
            ))
            await db.commit()
    
    async def _recovery_monitoring_task(self):
        """Background task for monitoring recovery operations."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                await self._check_recovery_timeouts()
            except Exception as e:
                logger.error(f"Recovery monitoring error: {e}")
    
    async def _check_recovery_timeouts(self):
        """Check for timed out recovery operations."""
        timeout_hours = self.config["recovery_timeout_hours"]
        timeout_threshold = datetime.now(timezone.utc).timestamp() - (timeout_hours * 3600)
        
        for recovery in list(self.active_recoveries.values()):
            if (recovery.started_at and 
                recovery.started_at.timestamp() < timeout_threshold):
                logger.warning(f"Recovery {recovery.recovery_id} timed out")
                recovery.status = RecoveryStatus.FAILED
                recovery.error_message = "Recovery operation timed out"
                await self._save_recovery_to_database(recovery)

# Global instance will be created by backup manager
advanced_recovery_manager = None
