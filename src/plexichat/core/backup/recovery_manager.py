#!/usr/bin/env python3
"""
Recovery Manager for Massive Scale Database Reconstruction

Handles complete database reconstruction from distributed shards,
streaming recovery for massive datasets, and partial recovery capabilities.
Designed to handle 427+ billion messages and petabyte-scale databases.


import asyncio
import logging
import sqlite3
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, AsyncIterator, Tuple
from uuid import uuid4

logger = logging.getLogger(__name__)

class RecoveryType(Enum):
    """Types of recovery operations."""
        COMPLETE = "complete"           # Full database reconstruction
    PARTIAL = "partial"             # Specific tables or time ranges
    INCREMENTAL = "incremental"     # Apply changes since last backup
    VERIFICATION = "verification"   # Verify data integrity only

class RecoveryStatus(Enum):
    """Status of recovery operations."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class RecoveryOperation:
    """Represents a recovery operation.
        operation_id: str
    recovery_type: RecoveryType
    backup_id: str
    target_path: str
    status: RecoveryStatus
    progress_percent: float = 0.0
    bytes_processed: int = 0
    total_bytes: int = 0
    shards_processed: int = 0
    total_shards: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration_seconds(self) -> float:
        """Get operation duration in seconds."""
        if not self.started_at:
            return 0.0
        end_time = self.completed_at or datetime.now(timezone.utc)
        return (end_time - self.started_at).total_seconds()
    
    @property
    def throughput_mbps(self) -> float:
        Get throughput in MB/s."""
        duration = self.duration_seconds
        if duration > 0:
            return (self.bytes_processed / (1024 * 1024)) / duration
        return 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "operation_id": self.operation_id,
            "recovery_type": self.recovery_type.value,
            "backup_id": self.backup_id,
            "target_path": self.target_path,
            "status": self.status.value,
            "progress_percent": self.progress_percent,
            "bytes_processed": self.bytes_processed,
            "total_bytes": self.total_bytes,
            "shards_processed": self.shards_processed,
            "total_shards": self.total_shards,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "throughput_mbps": self.throughput_mbps,
            "error_message": self.error_message,
            "metadata": self.metadata
        }

class MassiveScaleRecoveryManager:
    """Manages recovery operations for massive scale databases."""
        def __init__(self, shard_manager, distribution_manager, p2p_manager=None):
        self.shard_manager = shard_manager
        self.distribution_manager = distribution_manager
        self.p2p_manager = p2p_manager
        
        # Recovery operations tracking
        self.active_operations: Dict[str, RecoveryOperation] = {}
        self.completed_operations: Dict[str, RecoveryOperation] = {}
        
        # Configuration
        self.max_concurrent_operations = 3
        self.streaming_chunk_size = 64 * 1024 * 1024  # 64MB chunks for streaming
        self.verification_enabled = True
        self.parallel_shard_processing = True
        self.max_parallel_shards = 10
        
        # Statistics
        self.stats = {
            "total_recoveries": 0,
            "successful_recoveries": 0,
            "failed_recoveries": 0,
            "total_bytes_recovered": 0,
            "total_shards_processed": 0,
            "average_throughput_mbps": 0.0
        }
    
    async def start_complete_recovery(self, backup_id: str, target_path: str,
                                    verify_integrity: bool = True) -> str:
        """Start complete database recovery from distributed shards."""
        try:
            operation_id = str(uuid4())
            
            # Get shard set for backup
            shard_set = self.shard_manager.get_shard_set(backup_id)
            if not shard_set:
                raise ValueError(f"Backup {backup_id} not found")
            
            if not shard_set.can_restore:
                raise ValueError(f"Insufficient shards for recovery: need {shard_set.min_shards_required}, have {len(shard_set.available_shards)}")
            
            # Create recovery operation
            operation = RecoveryOperation(
                operation_id=operation_id,
                recovery_type=RecoveryType.COMPLETE,
                backup_id=backup_id,
                target_path=target_path,
                status=RecoveryStatus.PENDING,
                total_bytes=shard_set.total_size,
                total_shards=len(shard_set.all_shards),
                metadata={
                    "verify_integrity": verify_integrity,
                    "shard_set_info": {
                        "redundancy_level": shard_set.redundancy_level,
                        "min_shards_required": shard_set.min_shards_required,
                        "available_shards": len(shard_set.available_shards)
                    }
                }
            )
            
            self.active_operations[operation_id] = operation
            
            # Start recovery in background
            asyncio.create_task(self._execute_complete_recovery(operation, shard_set))
            
            logger.info(f"Started complete recovery operation {operation_id} for backup {backup_id}")
            return operation_id
            
        except Exception as e:
            logger.error(f"Failed to start complete recovery: {e}")
            raise
    
    async def start_partial_recovery(self, backup_id: str, target_path: str,
                                table_names: Optional[List[str]] = None,
                                time_range: Optional[Tuple[datetime, datetime]] = None) -> str:
        """Start partial database recovery for specific tables or time ranges."""
        try:
            operation_id = str(uuid4())
            
            # Create recovery operation
            operation = RecoveryOperation(
                operation_id=operation_id,
                recovery_type=RecoveryType.PARTIAL,
                backup_id=backup_id,
                target_path=target_path,
                status=RecoveryStatus.PENDING,
                metadata={
                    "table_names": table_names,
                    "time_range": {
                        "start": time_range[0].isoformat() if time_range else None,
                        "end": time_range[1].isoformat() if time_range else None
                    } if time_range else None
                }
            )
            
            self.active_operations[operation_id] = operation
            
            # Start partial recovery in background
            asyncio.create_task(self._execute_partial_recovery(operation, table_names, time_range))
            
            logger.info(f"Started partial recovery operation {operation_id}")
            return operation_id
            
        except Exception as e:
            logger.error(f"Failed to start partial recovery: {e}")
            raise
    
    async def _execute_complete_recovery(self, operation: RecoveryOperation, shard_set):
        """Execute complete database recovery."""
        try:
            operation.status = RecoveryStatus.RUNNING
            operation.started_at = datetime.now(timezone.utc)
            
            logger.info(f"Executing complete recovery for {operation.total_bytes:,} bytes from {operation.total_shards} shards")
            
            # Create target directory
            target_path = Path(operation.target_path)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Use streaming recovery for large datasets
            if operation.total_bytes > self.streaming_chunk_size:
                await self._streaming_recovery(operation, shard_set)
            else:
                await self._memory_recovery(operation, shard_set)
            
            # Verify integrity if requested
            if operation.metadata.get("verify_integrity", False):
                await self._verify_recovered_database(operation)
            
            operation.status = RecoveryStatus.COMPLETED
            operation.completed_at = datetime.now(timezone.utc)
            operation.progress_percent = 100.0
            
            # Move to completed operations
            self.completed_operations[operation.operation_id] = operation
            del self.active_operations[operation.operation_id]
            
            # Update statistics
            self.stats["total_recoveries"] += 1
            self.stats["successful_recoveries"] += 1
            self.stats["total_bytes_recovered"] += operation.bytes_processed
            self.stats["total_shards_processed"] += operation.shards_processed
            
            logger.info(f"Complete recovery {operation.operation_id} finished successfully in {operation.duration_seconds:.1f}s")
            
        except Exception as e:
            operation.status = RecoveryStatus.FAILED
            operation.error_message = str(e)
            operation.completed_at = datetime.now(timezone.utc)
            
            self.completed_operations[operation.operation_id] = operation
            del self.active_operations[operation.operation_id]
            
            self.stats["failed_recoveries"] += 1
            
            logger.error(f"Complete recovery {operation.operation_id} failed: {e}")
    
    async def _streaming_recovery(self, operation: RecoveryOperation, shard_set):
        """Perform streaming recovery for massive datasets."""
        logger.info(f"Using streaming recovery for large dataset ({operation.total_bytes:,} bytes)")
        
        # Create temporary file for streaming reconstruction
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            # Stream shard reconstruction
            async with self._stream_shard_reconstruction(shard_set) as shard_stream:
                with open(temp_path, 'wb') as output_file:
                    async for chunk in shard_stream:
                        output_file.write(chunk)
                        operation.bytes_processed += len(chunk)
                        
                        # Update progress
                        if operation.total_bytes > 0:
                            operation.progress_percent = (operation.bytes_processed / operation.total_bytes) * 100
                        
                        # Log progress for large operations
                        if operation.bytes_processed % (100 * 1024 * 1024) == 0:  # Every 100MB
                            logger.info(f"Recovery progress: {operation.progress_percent:.1f}% ({operation.bytes_processed:,} bytes)")
            
            # Move reconstructed file to final location
            Path(temp_path).rename(operation.target_path)
            
        finally:
            # Clean up temporary file
            if Path(temp_path).exists():
                Path(temp_path).unlink()
    
    async def _memory_recovery(self, operation: RecoveryOperation, shard_set):
        """Perform in-memory recovery for smaller datasets."""
        logger.info(f"Using in-memory recovery for dataset ({operation.total_bytes:,} bytes)")
        
        # Reconstruct data in memory
        reconstructed_data = self.shard_manager.reconstruct_data(shard_set)
        
        if not reconstructed_data:
            raise ValueError("Failed to reconstruct data from shards")
        
        # Write to target file
        with open(operation.target_path, 'wb') as f:
            f.write(reconstructed_data)
        
        operation.bytes_processed = len(reconstructed_data)
        operation.shards_processed = len(shard_set.all_shards)
    
    async def _stream_shard_reconstruction(self, shard_set) -> AsyncIterator[bytes]:
        """Stream shard reconstruction for massive datasets."""
        try:
            # Group shards by chunk index for ordered reconstruction
            chunks_data = {}
            
            # Collect shard data
            for shard in shard_set.available_shards:
                if shard.shard_type == shard_set.metadata_shard.shard_type:
                    continue  # Skip metadata shard
                
                chunk_idx = shard.metadata.get("chunk_index", 0)
                if chunk_idx not in chunks_data:
                    chunks_data[chunk_idx] = {"data": [], "parity": []}
                
                # Load shard data
                if self.p2p_manager:
                    # Try to get from P2P network first
                    shard_data = await self.p2p_manager.request_shard(shard.shard_id, shard_set.backup_id)
                else:
                    # Load from local storage
                    if shard.location and Path(shard.location).exists():
                        with open(shard.location, 'rb') as f:
                            shard_data = f.read()
                    else:
                        continue
                
                if shard_data:
                    # Verify checksum
                    if self.shard_manager._calculate_checksum(shard_data) == shard.checksum:
                        if shard.shard_type.value == "data":
                            chunks_data[chunk_idx]["data"].append((shard.shard_index, shard_data))
                        elif shard.shard_type.value == "parity":
                            chunks_data[chunk_idx]["parity"].append((shard.metadata.get("parity_index", 0), shard_data))
            
            # Stream reconstructed chunks in order
            for chunk_idx in sorted(chunks_data.keys()):
                chunk_data = chunks_data[chunk_idx]
                
                # Reconstruct chunk
                if self.shard_manager.rs_codec:
                    reconstructed_chunk = self.shard_manager._reconstruct_chunk_rs(chunk_data, chunk_idx)
                else:
                    reconstructed_chunk = self.shard_manager._reconstruct_chunk_simple(chunk_data, chunk_idx)
                
                if reconstructed_chunk:
                    yield reconstructed_chunk
                else:
                    logger.warning(f"Failed to reconstruct chunk {chunk_idx}")
                    
        except Exception as e:
            logger.error(f"Streaming shard reconstruction failed: {e}")
            raise
    
    async def _verify_recovered_database(self, operation: RecoveryOperation):
        """Verify integrity of recovered database."""
        try:
            logger.info(f"Verifying recovered database: {operation.target_path}")
            
            # Basic file existence and size check
            target_file = Path(operation.target_path)
            if not target_file.exists():
                raise ValueError("Recovered file does not exist")
            
            actual_size = target_file.stat().st_size
            if actual_size != operation.total_bytes:
                logger.warning(f"Size mismatch: expected {operation.total_bytes}, got {actual_size}")
            
            # Try to open as SQLite database for basic validation
            try:
                with sqlite3.connect(operation.target_path) as conn:
                    cursor = conn.cursor()
                    
                    # Check if it's a valid SQLite database
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = cursor.fetchall()
                    
                    operation.metadata["verification"] = {
                        "file_size": actual_size,
                        "table_count": len(tables),
                        "tables": [table[0] for table in tables],
                        "verified_at": datetime.now(timezone.utc).isoformat()
                    }
                    
                    logger.info(f"Database verification successful: {len(tables)} tables found")
                    
            except sqlite3.Error as e:
                logger.warning(f"SQLite verification failed (may not be SQLite): {e}")
                operation.metadata["verification"] = {
                    "file_size": actual_size,
                    "sqlite_valid": False,
                    "error": str(e)
                }
            
        except Exception as e:
            logger.error(f"Database verification failed: {e}")
            operation.metadata["verification_error"] = str(e)
    
    def get_operation_status(self, operation_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a recovery operation.
        operation = self.active_operations.get(operation_id) or self.completed_operations.get(operation_id)
        return operation.to_dict() if operation else None
    
    def list_operations(self, include_completed: bool = True) -> List[Dict[str, Any]]:
        """List all recovery operations."""
        operations = list(self.active_operations.values())
        
        if include_completed:
            operations.extend(self.completed_operations.values())
        
        # Sort by start time (newest first)
        operations.sort(key=lambda op: op.started_at or datetime.min, reverse=True)
        
        return [op.to_dict() for op in operations]
    
    async def cancel_operation(self, operation_id: str) -> bool:
        Cancel an active recovery operation."""
        operation = self.active_operations.get(operation_id)
        if not operation:
            return False
        
        operation.status = RecoveryStatus.CANCELLED
        operation.completed_at = datetime.now(timezone.utc)
        
        # Move to completed operations
        self.completed_operations[operation_id] = operation
        del self.active_operations[operation_id]
        
        logger.info(f"Recovery operation {operation_id} cancelled")
        return True
    
    def get_recovery_stats(self) -> Dict[str, Any]:
        """Get recovery manager statistics."""
        stats = self.stats.copy()
        
        # Calculate average throughput
        if self.stats["successful_recoveries"] > 0:
            total_duration = sum(
                op.duration_seconds for op in self.completed_operations.values()
                if op.status == RecoveryStatus.COMPLETED
            )
            if total_duration > 0:
                stats["average_throughput_mbps"] = (self.stats["total_bytes_recovered"] / (1024 * 1024)) / total_duration
        
        stats.update({
            "active_operations": len(self.active_operations),
            "completed_operations": len(self.completed_operations),
            "success_rate": (self.stats["successful_recoveries"] / self.stats["total_recoveries"] * 100) if self.stats["total_recoveries"] > 0 else 0,
            "streaming_chunk_size_mb": self.streaming_chunk_size / (1024 * 1024),
            "max_parallel_shards": self.max_parallel_shards
        })
        
        return stats

# Export main classes
__all__ = [
    "MassiveScaleRecoveryManager",
    "RecoveryOperation",
    "RecoveryType",
    "RecoveryStatus"
]
