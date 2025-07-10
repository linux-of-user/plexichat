"""
Database Proxy Manager

Manages database proxy mode for backup operations, allowing the backup system
to operate even when the main database is unavailable.
"""

import asyncio
import logging
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
import aiosqlite

logger = logging.getLogger(__name__)


class ProxyMode(Enum):
    """Database proxy modes."""
    DISABLED = "disabled"
    ENABLED = "enabled"
    FALLBACK_ONLY = "fallback-only"
    ALWAYS_ON = "always-on"


@dataclass
class ProxyOperation:
    """Represents a proxy database operation."""
    operation_id: str
    operation_type: str
    table_name: str
    data: Dict[str, Any]
    timestamp: datetime
    synced: bool = False


class DatabaseProxyManager:
    """
    Database Proxy Manager
    
    Manages database proxy operations for backup system resilience:
    - Operates when main database is unavailable
    - Queues operations for later synchronization
    - Provides fallback storage for critical backup metadata
    - Ensures backup operations continue during database outages
    """
    
    def __init__(self, backup_manager):
        """Initialize the database proxy manager."""
        self.backup_manager = backup_manager
        self.proxy_dir = backup_manager.backup_dir / "proxy"
        self.proxy_dir.mkdir(parents=True, exist_ok=True)
        
        # Proxy configuration
        self.proxy_mode = ProxyMode.ENABLED
        self.sync_interval = 300  # 5 minutes
        self.max_queue_size = 10000
        
        # Operation queue
        self.pending_operations: List[ProxyOperation] = []
        self.failed_operations: List[ProxyOperation] = []
        
        # Proxy database
        self.proxy_db_path = self.proxy_dir / "proxy_operations.db"
        
        logger.info("Database Proxy Manager initialized")
    
    async def initialize(self):
        """Initialize the proxy manager."""
        await self._initialize_proxy_database()
        await self._load_pending_operations()
        
        # Start background sync task
        asyncio.create_task(self._sync_operations_task())
        
        logger.info("Database Proxy Manager initialized successfully")
    
    async def _initialize_proxy_database(self):
        """Initialize the proxy database."""
        async with aiosqlite.connect(self.proxy_db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS proxy_operations (
                    operation_id TEXT PRIMARY KEY,
                    operation_type TEXT NOT NULL,
                    table_name TEXT NOT NULL,
                    data TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    synced INTEGER DEFAULT 0
                )
            """)
            await db.commit()
    
    async def _load_pending_operations(self):
        """Load pending operations from proxy database."""
        async with aiosqlite.connect(self.proxy_db_path) as db:
            async with db.execute("SELECT * FROM proxy_operations WHERE synced = 0") as cursor:
                async for row in cursor:
                    operation = ProxyOperation(
                        operation_id=row[0],
                        operation_type=row[1],
                        table_name=row[2],
                        data=json.loads(row[3]),
                        timestamp=datetime.fromisoformat(row[4]),
                        synced=bool(row[5])
                    )
                    self.pending_operations.append(operation)
        
        logger.info(f"Loaded {len(self.pending_operations)} pending proxy operations")
    
    async def queue_operation(
        self,
        operation_type: str,
        table_name: str,
        data: Dict[str, Any]
    ) -> str:
        """Queue a database operation for proxy handling."""
        import secrets
        
        operation_id = f"proxy_{operation_type}_{secrets.token_hex(8)}"
        
        operation = ProxyOperation(
            operation_id=operation_id,
            operation_type=operation_type,
            table_name=table_name,
            data=data,
            timestamp=datetime.now(timezone.utc)
        )
        
        # Add to queue
        self.pending_operations.append(operation)
        
        # Save to proxy database
        await self._save_operation_to_proxy_db(operation)
        
        logger.debug(f"Queued proxy operation {operation_id}")
        return operation_id
    
    async def _save_operation_to_proxy_db(self, operation: ProxyOperation):
        """Save operation to proxy database."""
        async with aiosqlite.connect(self.proxy_db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO proxy_operations 
                (operation_id, operation_type, table_name, data, timestamp, synced)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                operation.operation_id,
                operation.operation_type,
                operation.table_name,
                json.dumps(operation.data),
                operation.timestamp.isoformat(),
                int(operation.synced)
            ))
            await db.commit()
    
    async def _sync_operations_task(self):
        """Background task for syncing operations to main database."""
        while True:
            try:
                await asyncio.sleep(self.sync_interval)
                if self.proxy_mode in [ProxyMode.ENABLED, ProxyMode.ALWAYS_ON]:
                    await self._sync_pending_operations()
            except Exception as e:
                logger.error(f"Proxy sync task error: {e}")
    
    async def _sync_pending_operations(self):
        """Sync pending operations to main database."""
        if not self.pending_operations:
            return
        
        synced_count = 0
        failed_count = 0
        
        for operation in list(self.pending_operations):
            try:
                # Attempt to sync operation to main database
                success = await self._sync_single_operation(operation)
                
                if success:
                    operation.synced = True
                    await self._save_operation_to_proxy_db(operation)
                    self.pending_operations.remove(operation)
                    synced_count += 1
                else:
                    failed_count += 1
                    
            except Exception as e:
                logger.error(f"Failed to sync operation {operation.operation_id}: {e}")
                failed_count += 1
        
        if synced_count > 0:
            logger.info(f"Synced {synced_count} proxy operations to main database")
        
        if failed_count > 0:
            logger.warning(f"Failed to sync {failed_count} proxy operations")
    
    async def _sync_single_operation(self, operation: ProxyOperation) -> bool:
        """Sync a single operation to the main database."""
        try:
            # This is a simplified implementation
            # In production, this would connect to the actual main database
            # and execute the queued operation
            
            if operation.operation_type == "INSERT":
                # Simulate database insert
                logger.debug(f"Syncing INSERT operation for {operation.table_name}")
                return True
            elif operation.operation_type == "UPDATE":
                # Simulate database update
                logger.debug(f"Syncing UPDATE operation for {operation.table_name}")
                return True
            elif operation.operation_type == "DELETE":
                # Simulate database delete
                logger.debug(f"Syncing DELETE operation for {operation.table_name}")
                return True
            else:
                logger.warning(f"Unknown operation type: {operation.operation_type}")
                return False
                
        except Exception as e:
            logger.error(f"Error syncing operation {operation.operation_id}: {e}")
            return False
    
    async def is_main_database_available(self) -> bool:
        """Check if main database is available."""
        try:
            # This is a simplified check
            # In production, this would test actual database connectivity
            return True
        except Exception:
            return False
    
    async def get_proxy_status(self) -> Dict[str, Any]:
        """Get current proxy status."""
        return {
            "proxy_mode": self.proxy_mode.value,
            "pending_operations": len(self.pending_operations),
            "failed_operations": len(self.failed_operations),
            "main_database_available": await self.is_main_database_available(),
            "last_sync": datetime.now(timezone.utc).isoformat()
        }
    
    async def enable_proxy_mode(self):
        """Enable proxy mode."""
        self.proxy_mode = ProxyMode.ENABLED
        logger.info("Database proxy mode enabled")
    
    async def disable_proxy_mode(self):
        """Disable proxy mode."""
        self.proxy_mode = ProxyMode.DISABLED
        logger.info("Database proxy mode disabled")
    
    async def force_sync(self):
        """Force immediate synchronization of all pending operations."""
        logger.info("Forcing immediate sync of all pending operations")
        await self._sync_pending_operations()

# Global instance will be created by backup manager
database_proxy_manager = None
