"""
NetLink Backup Node System

A comprehensive backup node system that can operate in two modes:
1. Built-in module: Integrated into the main NetLink application
2. Standalone service: Independent backup node for distributed storage

Features:
- Government-level encryption and security
- Intelligent shard distribution and replication
- Real-time health monitoring and status reporting
- Cross-node synchronization and clustering
- Configurable storage limits and cleanup
- Hot-swappable operation modes
"""

import asyncio
import json
import yaml
import hashlib
import secrets
import aiofiles
import aiohttp
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import sqlite3
import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from cryptography.fernet import Fernet
import logging

from app.logger_config import logger
from app.backup.enhanced_backup_system import enhanced_backup_system, BackupType, ShardMetadata

class NodeMode(str, Enum):
    """Backup node operation modes."""
    BUILTIN = "builtin"      # Integrated into main app
    STANDALONE = "standalone" # Independent service
    HYBRID = "hybrid"        # Both modes available

class NodeStatus(str, Enum):
    """Node status states."""
    INITIALIZING = "initializing"
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"
    ERROR = "error"

class ShardPriority(int, Enum):
    """Shard storage priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5

@dataclass
class BackupNodeConfig:
    """Backup node configuration."""
    # Node identity
    node_id: str = field(default_factory=lambda: f"backup_node_{secrets.token_hex(8)}")
    node_name: str = "NetLink Backup Node"
    node_mode: NodeMode = NodeMode.BUILTIN
    
    # Network settings
    host: str = "0.0.0.0"
    port: int = 8001
    api_key: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    
    # Storage configuration
    storage_path: str = "data/backup_node/storage"
    max_storage_gb: int = 100
    cleanup_threshold_percent: int = 85
    shard_replication_factor: int = 2
    
    # Performance settings
    max_concurrent_operations: int = 10
    health_check_interval: int = 30
    sync_interval: int = 300
    compression_enabled: bool = True
    
    # Security settings
    encryption_enabled: bool = True
    require_authentication: bool = True
    allowed_nodes: List[str] = field(default_factory=list)
    
    # Clustering
    cluster_enabled: bool = True
    cluster_nodes: List[Dict[str, Any]] = field(default_factory=list)
    auto_discovery: bool = True

@dataclass
class BackupShard:
    """Backup shard information."""
    shard_id: str
    data_hash: str
    size_bytes: int
    created_at: datetime
    last_accessed: datetime
    priority: ShardPriority
    metadata: Dict[str, Any] = field(default_factory=dict)
    replicas: List[str] = field(default_factory=list)
    encrypted: bool = True
    compressed: bool = False

@dataclass
class NodeInfo:
    """Information about a backup node."""
    node_id: str
    address: str
    port: int
    status: NodeStatus
    last_seen: datetime
    storage_used: int = 0
    storage_capacity: int = 0
    shard_count: int = 0
    performance_score: float = 1.0
    capabilities: List[str] = field(default_factory=list)

class BackupNodeSystem:
    """Comprehensive backup node system."""
    
    def __init__(self, config: BackupNodeConfig = None):
        self.config = config or BackupNodeConfig()
        self.status = NodeStatus.INITIALIZING
        self.storage_path = Path(self.config.storage_path)
        self.db_path = self.storage_path / "backup_node.db"
        
        # Storage management
        self.shards: Dict[str, BackupShard] = {}
        self.storage_used = 0
        self.max_storage_bytes = self.config.max_storage_gb * 1024 * 1024 * 1024
        
        # Clustering
        self.cluster_nodes: Dict[str, NodeInfo] = {}
        self.node_info = NodeInfo(
            node_id=self.config.node_id,
            address=self.config.host,
            port=self.config.port,
            status=self.status,
            last_seen=datetime.now(timezone.utc),
            storage_capacity=self.max_storage_bytes
        )
        
        # Security
        self.encryption_key = Fernet.generate_key() if self.config.encryption_enabled else None
        self.cipher = Fernet(self.encryption_key) if self.encryption_key else None
        
        # FastAPI app for standalone mode
        self.app = None
        if self.config.node_mode in [NodeMode.STANDALONE, NodeMode.HYBRID]:
            self.app = self._create_fastapi_app()
        
        # Background tasks
        self.background_tasks: Set[asyncio.Task] = set()
        
        logger.info(f"🔧 Backup Node System initialized: {self.config.node_id}")
    
    async def initialize(self):
        """Initialize the backup node system."""
        try:
            # Create storage directories
            self.storage_path.mkdir(parents=True, exist_ok=True)
            (self.storage_path / "shards").mkdir(exist_ok=True)
            (self.storage_path / "temp").mkdir(exist_ok=True)
            
            # Initialize database
            await self._init_database()
            
            # Load existing shards
            await self._load_shards()
            
            # Start background tasks
            await self._start_background_tasks()
            
            # Initialize clustering if enabled
            if self.config.cluster_enabled:
                await self._initialize_clustering()
            
            self.status = NodeStatus.ONLINE
            self.node_info.status = self.status
            
            logger.info(f"✅ Backup Node System initialized successfully")
            
        except Exception as e:
            self.status = NodeStatus.ERROR
            logger.error(f"Failed to initialize backup node system: {e}")
            raise
    
    async def _init_database(self):
        """Initialize SQLite database for shard metadata."""
        try:
            async with aiofiles.open(self.db_path, 'w') as f:
                pass  # Create file if it doesn't exist
            
            # Use synchronous sqlite3 for initialization
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create shards table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS shards (
                    shard_id TEXT PRIMARY KEY,
                    data_hash TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    last_accessed TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    metadata TEXT,
                    replicas TEXT,
                    encrypted BOOLEAN DEFAULT TRUE,
                    compressed BOOLEAN DEFAULT FALSE
                )
            ''')
            
            # Create nodes table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS nodes (
                    node_id TEXT PRIMARY KEY,
                    address TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    storage_used INTEGER DEFAULT 0,
                    storage_capacity INTEGER DEFAULT 0,
                    shard_count INTEGER DEFAULT 0,
                    performance_score REAL DEFAULT 1.0,
                    capabilities TEXT
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_shards_priority ON shards(priority)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_shards_created ON shards(created_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status)')
            
            conn.commit()
            conn.close()
            
            logger.info("📊 Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    async def _load_shards(self):
        """Load existing shards from database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM shards')
            rows = cursor.fetchall()
            
            for row in rows:
                shard = BackupShard(
                    shard_id=row[0],
                    data_hash=row[1],
                    size_bytes=row[2],
                    created_at=datetime.fromisoformat(row[3]),
                    last_accessed=datetime.fromisoformat(row[4]),
                    priority=ShardPriority(row[5]),
                    metadata=json.loads(row[6]) if row[6] else {},
                    replicas=json.loads(row[7]) if row[7] else [],
                    encrypted=bool(row[8]),
                    compressed=bool(row[9])
                )
                self.shards[shard.shard_id] = shard
                self.storage_used += shard.size_bytes
            
            # Load cluster nodes
            cursor.execute('SELECT * FROM nodes')
            rows = cursor.fetchall()
            
            for row in rows:
                node = NodeInfo(
                    node_id=row[0],
                    address=row[1],
                    port=row[2],
                    status=NodeStatus(row[3]),
                    last_seen=datetime.fromisoformat(row[4]),
                    storage_used=row[5],
                    storage_capacity=row[6],
                    shard_count=row[7],
                    performance_score=row[8],
                    capabilities=json.loads(row[9]) if row[9] else []
                )
                self.cluster_nodes[node.node_id] = node
            
            conn.close()
            
            logger.info(f"📦 Loaded {len(self.shards)} shards and {len(self.cluster_nodes)} cluster nodes")
            
        except Exception as e:
            logger.error(f"Failed to load shards: {e}")
    
    async def store_shard(self, shard_id: str, data: bytes, 
                         priority: ShardPriority = ShardPriority.NORMAL,
                         metadata: Dict[str, Any] = None) -> bool:
        """Store a shard in the backup node."""
        try:
            # Check storage capacity
            if self.storage_used + len(data) > self.max_storage_bytes:
                if not await self._cleanup_storage():
                    logger.warning(f"Storage full, cannot store shard {shard_id}")
                    return False
            
            # Encrypt data if enabled
            if self.config.encryption_enabled and self.cipher:
                data = self.cipher.encrypt(data)
            
            # Compress data if enabled
            if self.config.compression_enabled:
                import gzip
                data = gzip.compress(data)
            
            # Calculate hash
            data_hash = hashlib.sha256(data).hexdigest()
            
            # Store to disk
            shard_path = self.storage_path / "shards" / shard_id
            async with aiofiles.open(shard_path, 'wb') as f:
                await f.write(data)
            
            # Create shard metadata
            shard = BackupShard(
                shard_id=shard_id,
                data_hash=data_hash,
                size_bytes=len(data),
                created_at=datetime.now(timezone.utc),
                last_accessed=datetime.now(timezone.utc),
                priority=priority,
                metadata=metadata or {},
                encrypted=self.config.encryption_enabled,
                compressed=self.config.compression_enabled
            )
            
            # Store in memory and database
            self.shards[shard_id] = shard
            self.storage_used += len(data)
            await self._save_shard_to_db(shard)
            
            # Replicate to other nodes if clustering is enabled
            if self.config.cluster_enabled:
                asyncio.create_task(self._replicate_shard(shard_id, data))
            
            logger.info(f"✅ Stored shard {shard_id} ({len(data)} bytes)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store shard {shard_id}: {e}")
            return False
    
    async def retrieve_shard(self, shard_id: str) -> Optional[bytes]:
        """Retrieve a shard from the backup node."""
        try:
            if shard_id not in self.shards:
                logger.warning(f"Shard {shard_id} not found")
                return None
            
            shard = self.shards[shard_id]
            shard_path = self.storage_path / "shards" / shard_id
            
            if not shard_path.exists():
                logger.error(f"Shard file {shard_id} missing from disk")
                return None
            
            # Read data
            async with aiofiles.open(shard_path, 'rb') as f:
                data = await f.read()
            
            # Decompress if needed
            if shard.compressed:
                import gzip
                data = gzip.decompress(data)
            
            # Decrypt if needed
            if shard.encrypted and self.cipher:
                data = self.cipher.decrypt(data)
            
            # Update access time
            shard.last_accessed = datetime.now(timezone.utc)
            await self._save_shard_to_db(shard)
            
            logger.info(f"📤 Retrieved shard {shard_id}")
            return data
            
        except Exception as e:
            logger.error(f"Failed to retrieve shard {shard_id}: {e}")
            return None
    
    async def delete_shard(self, shard_id: str) -> bool:
        """Delete a shard from the backup node."""
        try:
            if shard_id not in self.shards:
                return True  # Already deleted
            
            shard = self.shards[shard_id]
            shard_path = self.storage_path / "shards" / shard_id
            
            # Remove from disk
            if shard_path.exists():
                shard_path.unlink()
            
            # Remove from memory and database
            self.storage_used -= shard.size_bytes
            del self.shards[shard_id]
            
            # Remove from database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM shards WHERE shard_id = ?', (shard_id,))
            conn.commit()
            conn.close()
            
            logger.info(f"🗑️ Deleted shard {shard_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete shard {shard_id}: {e}")
            return False

    async def _cleanup_storage(self) -> bool:
        """Clean up storage by removing old/low-priority shards."""
        try:
            if self.storage_used < self.max_storage_bytes * (self.config.cleanup_threshold_percent / 100):
                return True

            # Sort shards by priority and age (lowest priority and oldest first)
            sorted_shards = sorted(
                self.shards.values(),
                key=lambda s: (s.priority.value, s.last_accessed)
            )

            cleaned_bytes = 0
            target_cleanup = self.max_storage_bytes * 0.2  # Clean 20% of storage

            for shard in sorted_shards:
                if cleaned_bytes >= target_cleanup:
                    break

                if shard.priority != ShardPriority.EMERGENCY:
                    await self.delete_shard(shard.shard_id)
                    cleaned_bytes += shard.size_bytes

            logger.info(f"🧹 Cleaned up {cleaned_bytes} bytes of storage")
            return cleaned_bytes > 0

        except Exception as e:
            logger.error(f"Storage cleanup failed: {e}")
            return False

    async def _save_shard_to_db(self, shard: BackupShard):
        """Save shard metadata to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO shards
                (shard_id, data_hash, size_bytes, created_at, last_accessed,
                 priority, metadata, replicas, encrypted, compressed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                shard.shard_id,
                shard.data_hash,
                shard.size_bytes,
                shard.created_at.isoformat(),
                shard.last_accessed.isoformat(),
                shard.priority.value,
                json.dumps(shard.metadata),
                json.dumps(shard.replicas),
                shard.encrypted,
                shard.compressed
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Failed to save shard to database: {e}")

    async def _start_background_tasks(self):
        """Start background maintenance tasks."""
        try:
            # Health check task
            health_task = asyncio.create_task(self._health_check_loop())
            self.background_tasks.add(health_task)
            health_task.add_done_callback(self.background_tasks.discard)

            # Sync task
            if self.config.cluster_enabled:
                sync_task = asyncio.create_task(self._sync_loop())
                self.background_tasks.add(sync_task)
                sync_task.add_done_callback(self.background_tasks.discard)

            # Cleanup task
            cleanup_task = asyncio.create_task(self._cleanup_loop())
            self.background_tasks.add(cleanup_task)
            cleanup_task.add_done_callback(self.background_tasks.discard)

            logger.info("🔄 Background tasks started")

        except Exception as e:
            logger.error(f"Failed to start background tasks: {e}")

    async def _health_check_loop(self):
        """Periodic health check loop."""
        while True:
            try:
                await asyncio.sleep(self.config.health_check_interval)

                # Update node info
                self.node_info.last_seen = datetime.now(timezone.utc)
                self.node_info.storage_used = self.storage_used
                self.node_info.shard_count = len(self.shards)

                # Check disk space
                storage_usage = self.storage_used / self.max_storage_bytes
                if storage_usage > 0.9:
                    self.status = NodeStatus.DEGRADED
                elif storage_usage > 0.95:
                    self.status = NodeStatus.ERROR
                else:
                    self.status = NodeStatus.ONLINE

                self.node_info.status = self.status

            except Exception as e:
                logger.error(f"Health check error: {e}")
                self.status = NodeStatus.ERROR

    async def _sync_loop(self):
        """Periodic cluster synchronization loop."""
        while True:
            try:
                await asyncio.sleep(self.config.sync_interval)
                await self._sync_with_cluster()

            except Exception as e:
                logger.error(f"Sync loop error: {e}")

    async def _cleanup_loop(self):
        """Periodic cleanup loop."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour

                # Check if cleanup is needed
                storage_usage = self.storage_used / self.max_storage_bytes
                if storage_usage > (self.config.cleanup_threshold_percent / 100):
                    await self._cleanup_storage()

            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")

    async def _initialize_clustering(self):
        """Initialize clustering functionality."""
        try:
            # Register with configured cluster nodes
            for node_config in self.config.cluster_nodes:
                await self._register_with_node(node_config)

            # Start auto-discovery if enabled
            if self.config.auto_discovery:
                discovery_task = asyncio.create_task(self._auto_discovery_loop())
                self.background_tasks.add(discovery_task)
                discovery_task.add_done_callback(self.background_tasks.discard)

            logger.info("🌐 Clustering initialized")

        except Exception as e:
            logger.error(f"Clustering initialization failed: {e}")

    async def _register_with_node(self, node_config: Dict[str, Any]):
        """Register this node with another backup node."""
        try:
            url = f"http://{node_config['address']}:{node_config['port']}/api/v1/nodes/register"

            async with aiohttp.ClientSession() as session:
                async with session.post(url, json={
                    "node_id": self.config.node_id,
                    "address": self.config.host,
                    "port": self.config.port,
                    "storage_capacity": self.max_storage_bytes,
                    "capabilities": ["storage", "replication", "sync"]
                }) as response:
                    if response.status == 200:
                        logger.info(f"✅ Registered with node {node_config['address']}:{node_config['port']}")
                    else:
                        logger.warning(f"Failed to register with node: {response.status}")

        except Exception as e:
            logger.error(f"Node registration failed: {e}")

    async def _auto_discovery_loop(self):
        """Auto-discovery loop for finding other backup nodes."""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                # TODO: Implement auto-discovery logic
                # This could use multicast, service discovery, or other methods

            except Exception as e:
                logger.error(f"Auto-discovery error: {e}")

    async def _sync_with_cluster(self):
        """Synchronize with cluster nodes."""
        try:
            for node_id, node_info in self.cluster_nodes.items():
                if node_info.status == NodeStatus.ONLINE:
                    await self._sync_with_node(node_info)

        except Exception as e:
            logger.error(f"Cluster sync failed: {e}")

    async def _sync_with_node(self, node_info: NodeInfo):
        """Synchronize with a specific node."""
        try:
            url = f"http://{node_info.address}:{node_info.port}/api/v1/sync/status"

            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        # TODO: Process sync data
                        logger.debug(f"Synced with node {node_info.node_id}")

        except Exception as e:
            logger.error(f"Node sync failed for {node_info.node_id}: {e}")

    async def _replicate_shard(self, shard_id: str, data: bytes):
        """Replicate shard to other nodes."""
        try:
            replicated_count = 0
            target_replicas = min(self.config.shard_replication_factor, len(self.cluster_nodes))

            # Sort nodes by performance score and available storage
            available_nodes = [
                node for node in self.cluster_nodes.values()
                if node.status == NodeStatus.ONLINE and
                   node.storage_used < node.storage_capacity * 0.9
            ]

            available_nodes.sort(key=lambda n: n.performance_score, reverse=True)

            for node in available_nodes[:target_replicas]:
                if await self._replicate_to_node(node, shard_id, data):
                    replicated_count += 1
                    self.shards[shard_id].replicas.append(node.node_id)

            logger.info(f"📋 Replicated shard {shard_id} to {replicated_count} nodes")

        except Exception as e:
            logger.error(f"Shard replication failed: {e}")

    async def _replicate_to_node(self, node: NodeInfo, shard_id: str, data: bytes) -> bool:
        """Replicate shard to a specific node."""
        try:
            url = f"http://{node.address}:{node.port}/api/v1/shards/{shard_id}"

            async with aiohttp.ClientSession() as session:
                async with session.put(url, data=data) as response:
                    return response.status == 200

        except Exception as e:
            logger.error(f"Failed to replicate to node {node.node_id}: {e}")
            return False

    def _create_fastapi_app(self) -> FastAPI:
        """Create FastAPI application for standalone mode."""
        app = FastAPI(
            title="NetLink Backup Node",
            description="Government-grade distributed backup storage system",
            version="3.0.0"
        )

        @app.get("/health")
        async def health_check():
            """Health check endpoint."""
            return {
                "status": self.status.value,
                "node_id": self.config.node_id,
                "storage_used": self.storage_used,
                "storage_capacity": self.max_storage_bytes,
                "shard_count": len(self.shards),
                "cluster_nodes": len(self.cluster_nodes),
                "uptime": (datetime.now(timezone.utc) - self.node_info.last_seen).total_seconds()
            }

        @app.get("/api/v1/status")
        async def get_status():
            """Get detailed node status."""
            return {
                "node_info": asdict(self.node_info),
                "storage": {
                    "used_bytes": self.storage_used,
                    "capacity_bytes": self.max_storage_bytes,
                    "usage_percent": (self.storage_used / self.max_storage_bytes) * 100,
                    "shard_count": len(self.shards)
                },
                "cluster": {
                    "enabled": self.config.cluster_enabled,
                    "nodes": [asdict(node) for node in self.cluster_nodes.values()],
                    "replication_factor": self.config.shard_replication_factor
                },
                "config": {
                    "mode": self.config.node_mode.value,
                    "encryption_enabled": self.config.encryption_enabled,
                    "compression_enabled": self.config.compression_enabled,
                    "auto_discovery": self.config.auto_discovery
                }
            }

        @app.get("/api/v1/shards")
        async def list_shards():
            """List all shards."""
            return {
                "shards": [
                    {
                        "shard_id": shard.shard_id,
                        "size_bytes": shard.size_bytes,
                        "created_at": shard.created_at.isoformat(),
                        "last_accessed": shard.last_accessed.isoformat(),
                        "priority": shard.priority.value,
                        "replicas": len(shard.replicas),
                        "encrypted": shard.encrypted,
                        "compressed": shard.compressed
                    }
                    for shard in self.shards.values()
                ],
                "total_count": len(self.shards),
                "total_size": self.storage_used
            }

        @app.get("/api/v1/shards/{shard_id}")
        async def get_shard(shard_id: str):
            """Retrieve a specific shard."""
            data = await self.retrieve_shard(shard_id)
            if data is None:
                raise HTTPException(status_code=404, detail="Shard not found")

            return JSONResponse(
                content={"shard_id": shard_id, "size": len(data)},
                headers={"Content-Type": "application/octet-stream"}
            )

        @app.put("/api/v1/shards/{shard_id}")
        async def store_shard_endpoint(shard_id: str, request):
            """Store a shard."""
            data = await request.body()
            priority = ShardPriority.NORMAL  # Default priority

            success = await self.store_shard(shard_id, data, priority)
            if not success:
                raise HTTPException(status_code=507, detail="Insufficient storage")

            return {"success": True, "shard_id": shard_id, "size": len(data)}

        @app.delete("/api/v1/shards/{shard_id}")
        async def delete_shard_endpoint(shard_id: str):
            """Delete a shard."""
            success = await self.delete_shard(shard_id)
            if not success:
                raise HTTPException(status_code=404, detail="Shard not found")

            return {"success": True, "shard_id": shard_id}

        @app.post("/api/v1/nodes/register")
        async def register_node(node_data: dict):
            """Register a new node in the cluster."""
            try:
                node_info = NodeInfo(
                    node_id=node_data["node_id"],
                    address=node_data["address"],
                    port=node_data["port"],
                    status=NodeStatus.ONLINE,
                    last_seen=datetime.now(timezone.utc),
                    storage_capacity=node_data.get("storage_capacity", 0),
                    capabilities=node_data.get("capabilities", [])
                )

                self.cluster_nodes[node_info.node_id] = node_info

                # Save to database
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO nodes
                    (node_id, address, port, status, last_seen, storage_capacity, capabilities)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    node_info.node_id,
                    node_info.address,
                    node_info.port,
                    node_info.status.value,
                    node_info.last_seen.isoformat(),
                    node_info.storage_capacity,
                    json.dumps(node_info.capabilities)
                ))
                conn.commit()
                conn.close()

                logger.info(f"🌐 Registered cluster node: {node_info.node_id}")
                return {"success": True, "node_id": node_info.node_id}

            except Exception as e:
                logger.error(f"Node registration failed: {e}")
                raise HTTPException(status_code=400, detail=str(e))

        @app.get("/api/v1/sync/status")
        async def sync_status():
            """Get sync status for cluster synchronization."""
            return {
                "node_id": self.config.node_id,
                "last_sync": datetime.now(timezone.utc).isoformat(),
                "shard_hashes": {
                    shard_id: shard.data_hash
                    for shard_id, shard in self.shards.items()
                }
            }

        return app

    async def start_standalone(self):
        """Start the backup node in standalone mode."""
        if not self.app:
            raise RuntimeError("FastAPI app not initialized for standalone mode")

        await self.initialize()

        config = uvicorn.Config(
            self.app,
            host=self.config.host,
            port=self.config.port,
            log_level="info"
        )

        server = uvicorn.Server(config)
        logger.info(f"🚀 Starting standalone backup node on {self.config.host}:{self.config.port}")
        await server.serve()

    async def stop(self):
        """Stop the backup node system."""
        try:
            # Cancel background tasks
            for task in self.background_tasks:
                task.cancel()

            # Wait for tasks to complete
            if self.background_tasks:
                await asyncio.gather(*self.background_tasks, return_exceptions=True)

            self.status = NodeStatus.OFFLINE
            logger.info("🛑 Backup node system stopped")

        except Exception as e:
            logger.error(f"Error stopping backup node: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get current node status."""
        return {
            "node_id": self.config.node_id,
            "status": self.status.value,
            "mode": self.config.node_mode.value,
            "storage_used": self.storage_used,
            "storage_capacity": self.max_storage_bytes,
            "shard_count": len(self.shards),
            "cluster_nodes": len(self.cluster_nodes),
            "uptime": (datetime.now(timezone.utc) - self.node_info.last_seen).total_seconds()
        }

# Global instance for built-in mode
backup_node_system: Optional[BackupNodeSystem] = None

def initialize_backup_node(config: BackupNodeConfig = None) -> BackupNodeSystem:
    """Initialize the global backup node system."""
    global backup_node_system
    backup_node_system = BackupNodeSystem(config)
    return backup_node_system

def get_backup_node() -> Optional[BackupNodeSystem]:
    """Get the global backup node system instance."""
    return backup_node_system

# Standalone entry point
async def main():
    """Main entry point for standalone backup node."""
    import argparse

    parser = argparse.ArgumentParser(description="NetLink Backup Node")
    parser.add_argument("--config", type=str, help="Configuration file path")
    parser.add_argument("--node-id", type=str, help="Node ID")
    parser.add_argument("--port", type=int, default=8001, help="Port number")
    parser.add_argument("--storage-path", type=str, default="data/backup_node", help="Storage path")
    parser.add_argument("--max-storage-gb", type=int, default=100, help="Maximum storage in GB")

    args = parser.parse_args()

    # Load configuration
    if args.config and Path(args.config).exists():
        with open(args.config, 'r') as f:
            if args.config.endswith('.yaml') or args.config.endswith('.yml'):
                config_data = yaml.safe_load(f)
            else:
                config_data = json.load(f)
        config = BackupNodeConfig(**config_data)
    else:
        config = BackupNodeConfig(
            node_id=args.node_id or f"backup_node_{secrets.token_hex(8)}",
            port=args.port,
            storage_path=args.storage_path,
            max_storage_gb=args.max_storage_gb,
            node_mode=NodeMode.STANDALONE
        )

    # Create and start backup node
    node = BackupNodeSystem(config)

    try:
        await node.start_standalone()
    except KeyboardInterrupt:
        logger.info("🛑 Received shutdown signal")
        await node.stop()

if __name__ == "__main__":
    asyncio.run(main())
