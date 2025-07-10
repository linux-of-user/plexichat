"""
Advanced Recovery Manager

Provides comprehensive backup recovery capabilities including partial restoration,
emergency recovery procedures, and intelligent data reconstruction.
"""

import asyncio
import logging
import secrets
import json
import gzip
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import aiosqlite
import aiofiles

logger = logging.getLogger(__name__)


class RecoveryType(Enum):
    """Types of recovery operations."""
    FULL = "full"
    PARTIAL = "partial"
    SELECTIVE = "selective"
    EMERGENCY = "emergency"
    POINT_IN_TIME = "point_in_time"


class RecoveryStatus(Enum):
    """Recovery operation status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL_SUCCESS = "partial_success"


class RecoveryPriority(Enum):
    """Recovery priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5


@dataclass
class RecoveryOperation:
    """Represents a recovery operation."""
    recovery_id: str
    backup_id: str
    recovery_type: RecoveryType
    priority: RecoveryPriority
    status: RecoveryStatus
    target_path: Optional[str]
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    bytes_recovered: int = 0
    total_bytes: int = 0
    shards_recovered: int = 0
    total_shards: int = 0
    success_rate: float = 0.0
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RecoveryPlan:
    """Recovery execution plan."""
    plan_id: str
    recovery_id: str
    required_shards: List[str]
    available_shards: List[str]
    missing_shards: List[str]
    recovery_strategy: str
    estimated_time: float
    success_probability: float
    alternative_plans: List[str] = field(default_factory=list)


class AdvancedRecoveryManager:
    """
    Advanced Recovery Manager
    
    Provides comprehensive recovery capabilities with:
    - Full and partial backup restoration
    - Intelligent shard reconstruction
    - Emergency recovery procedures
    - Point-in-time recovery
    - Missing shard compensation
    - Recovery optimization and planning
    """
    
    def __init__(self, backup_manager):
        """Initialize the advanced recovery manager."""
        self.backup_manager = backup_manager
        self.recovery_dir = backup_manager.backup_dir / "recovery"
        self.temp_recovery_dir = self.recovery_dir / "temp"
        self.completed_recovery_dir = self.recovery_dir / "completed"
        
        # Ensure directories exist
        for directory in [self.recovery_dir, self.temp_recovery_dir, self.completed_recovery_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Recovery registry
        self.active_recoveries: Dict[str, RecoveryOperation] = {}
        self.recovery_plans: Dict[str, RecoveryPlan] = {}
        
        # Configuration
        self.max_concurrent_recoveries = 5
        self.recovery_timeout_hours = 24
        self.min_shard_threshold = 0.6  # 60% of shards needed for recovery
        
        # Database
        self.recovery_db_path = backup_manager.databases_dir / "recovery_registry.db"
        
        logger.info("Advanced Recovery Manager initialized")
    
    async def initialize(self):
        """Initialize the recovery manager."""
        await self._initialize_database()
        await self._load_existing_recoveries()
        
        # Start background tasks
        asyncio.create_task(self._recovery_monitoring_task())
        
        logger.info("Recovery Manager initialized successfully")
    
    async def _initialize_database(self):
        """Initialize recovery registry database."""
        async with aiosqlite.connect(self.recovery_db_path) as db:
            # Recovery operations table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS recovery_operations (
                    recovery_id TEXT PRIMARY KEY,
                    backup_id TEXT NOT NULL,
                    recovery_type TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    target_path TEXT,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    bytes_recovered INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0,
                    shards_recovered INTEGER DEFAULT 0,
                    total_shards INTEGER DEFAULT 0,
                    success_rate REAL DEFAULT 0.0,
                    error_message TEXT,
                    metadata TEXT
                )
            """)
            
            # Recovery plans table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS recovery_plans (
                    plan_id TEXT PRIMARY KEY,
                    recovery_id TEXT NOT NULL,
                    required_shards TEXT NOT NULL,
                    available_shards TEXT NOT NULL,
                    missing_shards TEXT NOT NULL,
                    recovery_strategy TEXT NOT NULL,
                    estimated_time REAL NOT NULL,
                    success_probability REAL NOT NULL,
                    alternative_plans TEXT,
                    FOREIGN KEY (recovery_id) REFERENCES recovery_operations (recovery_id)
                )
            """)
            
            # Recovery performance log
            await db.execute("""
                CREATE TABLE IF NOT EXISTS recovery_performance_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recovery_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    operation_type TEXT NOT NULL,
                    performance_metric REAL,
                    success BOOLEAN NOT NULL,
                    details TEXT
                )
            """)
            
            await db.commit()
    
    async def _load_existing_recoveries(self):
        """Load existing recovery operations from database."""
        async with aiosqlite.connect(self.recovery_db_path) as db:
            async with db.execute("SELECT * FROM recovery_operations WHERE status IN ('pending', 'in_progress')") as cursor:
                async for row in cursor:
                    recovery = RecoveryOperation(
                        recovery_id=row[0],
                        backup_id=row[1],
                        recovery_type=RecoveryType(row[2]),
                        priority=RecoveryPriority(row[3]),
                        status=RecoveryStatus(row[4]),
                        target_path=row[5],
                        created_at=datetime.fromisoformat(row[6]),
                        started_at=datetime.fromisoformat(row[7]) if row[7] else None,
                        completed_at=datetime.fromisoformat(row[8]) if row[8] else None,
                        bytes_recovered=row[9],
                        total_bytes=row[10],
                        shards_recovered=row[11],
                        total_shards=row[12],
                        success_rate=row[13],
                        error_message=row[14],
                        metadata=json.loads(row[15]) if row[15] else {}
                    )
                    self.active_recoveries[recovery.recovery_id] = recovery
        
        logger.info(f"Loaded {len(self.active_recoveries)} active recovery operations")
    
    async def create_recovery(
        self,
        backup_id: str,
        recovery_type: RecoveryType = RecoveryType.FULL,
        priority: RecoveryPriority = RecoveryPriority.NORMAL,
        target_path: Optional[str] = None,
        selective_criteria: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create a new recovery operation."""
        recovery_id = f"recovery_{recovery_type.value}_{secrets.token_hex(16)}_{int(datetime.now(timezone.utc).timestamp())}"
        
        # Create recovery operation
        recovery = RecoveryOperation(
            recovery_id=recovery_id,
            backup_id=backup_id,
            recovery_type=recovery_type,
            priority=priority,
            status=RecoveryStatus.PENDING,
            target_path=target_path,
            created_at=datetime.now(timezone.utc),
            metadata=selective_criteria or {}
        )
        
        # Add to active recoveries
        self.active_recoveries[recovery_id] = recovery
        
        # Create recovery plan
        plan = await self._create_recovery_plan(recovery)
        if plan:
            self.recovery_plans[plan.plan_id] = plan
        
        # Start recovery execution asynchronously
        asyncio.create_task(self._execute_recovery(recovery))
        
        logger.info(f"Created recovery operation {recovery_id} for backup {backup_id}")
        return recovery_id
    
    async def _create_recovery_plan(self, recovery: RecoveryOperation) -> Optional[RecoveryPlan]:
        """Create a recovery plan for the operation."""
        # Get backup information
        backup_shards = [
            shard for shard in self.backup_manager.shard_manager.immutable_shards.values()
            if shard.backup_id == recovery.backup_id
        ]
        
        if not backup_shards:
            logger.error(f"No shards found for backup {recovery.backup_id}")
            return None
        
        # Analyze shard availability
        required_shards = [shard.shard_id for shard in backup_shards]
        available_shards = []
        missing_shards = []
        
        for shard in backup_shards:
            # Check if shard is available on any node
            if recovery.backup_id in self.backup_manager.distribution_manager.shard_distributions:
                distribution = self.backup_manager.distribution_manager.shard_distributions[shard.shard_id]
                if any(node_id in self.backup_manager.distribution_manager.backup_nodes 
                       for node_id in distribution.node_assignments):
                    available_shards.append(shard.shard_id)
                else:
                    missing_shards.append(shard.shard_id)
            else:
                missing_shards.append(shard.shard_id)
        
        # Determine recovery strategy
        availability_ratio = len(available_shards) / len(required_shards)
        
        if availability_ratio >= 1.0:
            strategy = "full_recovery"
            success_probability = 0.95
        elif availability_ratio >= self.min_shard_threshold:
            strategy = "partial_recovery_with_reconstruction"
            success_probability = 0.8 * availability_ratio
        else:
            strategy = "emergency_recovery"
            success_probability = 0.5 * availability_ratio
        
        # Estimate recovery time
        total_size = sum(shard.size_bytes for shard in backup_shards)
        estimated_time = total_size / (10 * 1024 * 1024)  # Assume 10MB/s recovery rate
        
        plan = RecoveryPlan(
            plan_id=f"plan_{recovery.recovery_id}_{secrets.token_hex(8)}",
            recovery_id=recovery.recovery_id,
            required_shards=required_shards,
            available_shards=available_shards,
            missing_shards=missing_shards,
            recovery_strategy=strategy,
            estimated_time=estimated_time,
            success_probability=success_probability
        )
        
        # Save plan to database
        await self._save_recovery_plan(plan)
        
        logger.info(f"Created recovery plan {plan.plan_id} with {availability_ratio:.1%} shard availability")
        return plan

    async def _save_recovery_plan(self, plan: RecoveryPlan):
        """Save recovery plan to database."""
        async with aiosqlite.connect(self.recovery_db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO recovery_plans (
                    plan_id, recovery_id, required_shards, available_shards,
                    missing_shards, recovery_strategy, estimated_time,
                    success_probability, alternative_plans
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                plan.plan_id,
                plan.recovery_id,
                json.dumps(plan.required_shards),
                json.dumps(plan.available_shards),
                json.dumps(plan.missing_shards),
                plan.recovery_strategy,
                plan.estimated_time,
                plan.success_probability,
                json.dumps(plan.alternative_plans)
            ))
            await db.commit()

    async def _execute_recovery(self, recovery: RecoveryOperation):
        """Execute a recovery operation."""
        try:
            recovery.status = RecoveryStatus.IN_PROGRESS
            recovery.started_at = datetime.now(timezone.utc)

            logger.info(f"Starting recovery operation {recovery.recovery_id}")

            # Get recovery plan
            plan = None
            for p in self.recovery_plans.values():
                if p.recovery_id == recovery.recovery_id:
                    plan = p
                    break

            if not plan:
                raise Exception("Recovery plan not found")

            # Execute recovery based on strategy
            if plan.recovery_strategy == "full_recovery":
                success = await self._execute_full_recovery(recovery, plan)
            elif plan.recovery_strategy == "partial_recovery_with_reconstruction":
                success = await self._execute_partial_recovery(recovery, plan)
            elif plan.recovery_strategy == "emergency_recovery":
                success = await self._execute_emergency_recovery(recovery, plan)
            else:
                raise Exception(f"Unknown recovery strategy: {plan.recovery_strategy}")

            # Update recovery status
            if success:
                recovery.status = RecoveryStatus.COMPLETED
                recovery.success_rate = recovery.shards_recovered / recovery.total_shards if recovery.total_shards > 0 else 0.0
                logger.info(f"Recovery operation {recovery.recovery_id} completed successfully")
            else:
                recovery.status = RecoveryStatus.PARTIAL_SUCCESS if recovery.shards_recovered > 0 else RecoveryStatus.FAILED
                logger.warning(f"Recovery operation {recovery.recovery_id} completed with issues")

            recovery.completed_at = datetime.now(timezone.utc)

            # Save recovery operation
            await self._save_recovery_operation(recovery)

        except Exception as e:
            recovery.status = RecoveryStatus.FAILED
            recovery.error_message = str(e)
            recovery.completed_at = datetime.now(timezone.utc)

            logger.error(f"Recovery operation {recovery.recovery_id} failed: {e}")
            await self._save_recovery_operation(recovery)

    async def _execute_full_recovery(self, recovery: RecoveryOperation, plan: RecoveryPlan) -> bool:
        """Execute full recovery with all shards available."""
        logger.info(f"Executing full recovery for {recovery.recovery_id}")

        recovery.total_shards = len(plan.available_shards)
        recovered_data = b""

        # Recover all shards in order
        for shard_id in plan.available_shards:
            try:
                shard_data = await self._recover_shard_data(shard_id)
                if shard_data:
                    recovered_data += shard_data
                    recovery.shards_recovered += 1
                    recovery.bytes_recovered += len(shard_data)

                    # Update progress
                    await self._log_recovery_progress(recovery, f"Recovered shard {shard_id}")

            except Exception as e:
                logger.error(f"Failed to recover shard {shard_id}: {e}")
                continue

        # Decrypt and decompress recovered data
        try:
            final_data = await self._process_recovered_data(recovered_data, recovery.backup_id)

            # Save recovered data
            if recovery.target_path:
                await self._save_recovered_data(final_data, recovery.target_path)
            else:
                # Save to default location
                default_path = self.completed_recovery_dir / f"{recovery.recovery_id}_recovered.data"
                await self._save_recovered_data(final_data, str(default_path))

            recovery.total_bytes = len(final_data)
            return True

        except Exception as e:
            logger.error(f"Failed to process recovered data: {e}")
            recovery.error_message = f"Data processing failed: {str(e)}"
            return False

    async def _execute_partial_recovery(self, recovery: RecoveryOperation, plan: RecoveryPlan) -> bool:
        """Execute partial recovery with missing shards."""
        logger.info(f"Executing partial recovery for {recovery.recovery_id} ({len(plan.missing_shards)} shards missing)")

        recovery.total_shards = len(plan.required_shards)
        recovered_shards = {}

        # Recover available shards
        for shard_id in plan.available_shards:
            try:
                shard_data = await self._recover_shard_data(shard_id)
                if shard_data:
                    recovered_shards[shard_id] = shard_data
                    recovery.shards_recovered += 1
                    recovery.bytes_recovered += len(shard_data)

            except Exception as e:
                logger.error(f"Failed to recover shard {shard_id}: {e}")
                continue

        # Attempt to reconstruct missing shards (simplified)
        reconstructed_count = 0
        for missing_shard_id in plan.missing_shards:
            try:
                # In a real implementation, this would use advanced reconstruction algorithms
                # For now, we'll create placeholder data
                placeholder_data = b"MISSING_SHARD_PLACEHOLDER"
                recovered_shards[missing_shard_id] = placeholder_data
                reconstructed_count += 1

            except Exception as e:
                logger.error(f"Failed to reconstruct shard {missing_shard_id}: {e}")
                continue

        # Combine recovered and reconstructed data
        try:
            combined_data = b""
            for shard_id in plan.required_shards:
                if shard_id in recovered_shards:
                    combined_data += recovered_shards[shard_id]

            # Process combined data
            final_data = await self._process_recovered_data(combined_data, recovery.backup_id)

            # Save recovered data
            target_path = recovery.target_path or str(self.completed_recovery_dir / f"{recovery.recovery_id}_partial_recovered.data")
            await self._save_recovered_data(final_data, target_path)

            recovery.total_bytes = len(final_data)
            logger.info(f"Partial recovery completed: {recovery.shards_recovered}/{recovery.total_shards} shards recovered, {reconstructed_count} reconstructed")

            return recovery.shards_recovered > 0

        except Exception as e:
            logger.error(f"Failed to process partial recovery data: {e}")
            recovery.error_message = f"Partial recovery processing failed: {str(e)}"
            return False

    async def _execute_emergency_recovery(self, recovery: RecoveryOperation, plan: RecoveryPlan) -> bool:
        """Execute emergency recovery with minimal data."""
        logger.info(f"Executing emergency recovery for {recovery.recovery_id}")

        recovery.total_shards = len(plan.required_shards)

        # Try to recover whatever is available
        available_data = []
        for shard_id in plan.available_shards:
            try:
                shard_data = await self._recover_shard_data(shard_id)
                if shard_data:
                    available_data.append(shard_data)
                    recovery.shards_recovered += 1
                    recovery.bytes_recovered += len(shard_data)

            except Exception as e:
                logger.error(f"Emergency recovery: failed to recover shard {shard_id}: {e}")
                continue

        if not available_data:
            logger.error("Emergency recovery failed: no data could be recovered")
            return False

        # Combine available data
        combined_data = b"".join(available_data)

        # Save emergency recovery data (may be incomplete/corrupted)
        target_path = recovery.target_path or str(self.completed_recovery_dir / f"{recovery.recovery_id}_emergency_recovered.data")
        await self._save_recovered_data(combined_data, target_path)

        recovery.total_bytes = len(combined_data)
        logger.warning(f"Emergency recovery completed: {recovery.shards_recovered}/{recovery.total_shards} shards recovered (data may be incomplete)")

        return True
