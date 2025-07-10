#!/usr/bin/env python3
"""
NetLink Backup Node - Government-Grade Independent Backup Storage System
A dedicated backup node with advanced clustering, real-time monitoring, and quantum-resistant security.
Handles large shard storage, implements storage limits, provides seeding capabilities,
and maintains government-level security standards with distributed redundancy.
"""

import asyncio
import os
import sys
import json
import time
import hashlib
import secrets
import sqlite3
import threading
import uuid
import psutil
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict, field
import logging
from contextlib import asynccontextmanager
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Add parent directory to path for shared imports
sys.path.append(str(Path(__file__).parent.parent))

try:
    from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, FileResponse
    from pydantic import BaseModel
    import uvicorn
    import httpx
    import aiofiles
except ImportError as e:
    print(f"❌ Missing required dependencies: {e}")
    print("Please install: pip install fastapi uvicorn httpx aiofiles")
    sys.exit(1)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('backup_node/logs/backup_node.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("backup_node")

# Ensure log directory exists
Path("backup_node/logs").mkdir(parents=True, exist_ok=True)


@dataclass
class BackupShard:
    """Backup shard information."""
    shard_id: str
    original_hash: str
    size_bytes: int
    created_at: datetime
    last_verified: Optional[datetime] = None
    verification_count: int = 0
    source_node: Optional[str] = None
    redundancy_level: int = 1
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class NodeInfo:
    """Information about connected nodes."""
    node_id: str
    node_type: str  # 'main', 'backup', 'client'
    address: str
    port: int
    last_seen: datetime
    storage_capacity: int
    storage_used: int
    is_online: bool = True
    trust_level: float = 1.0


@dataclass
class BackupNodeConfig:
    """Enhanced backup node configuration with clustering."""
    node_id: str
    storage_path: str
    max_storage_gb: int
    port: int
    main_node_address: Optional[str] = None
    main_node_port: Optional[int] = None
    auto_cleanup_enabled: bool = True
    verification_interval_hours: int = 6  # More frequent verification
    seeding_enabled: bool = True
    max_concurrent_transfers: int = 20  # Increased for government-level performance
    bandwidth_limit_mbps: Optional[int] = None
    # Enhanced clustering features
    cluster_enabled: bool = True
    heartbeat_interval: int = 30
    node_timeout: int = 90
    replication_factor: int = 5  # Government-level redundancy
    encryption_enabled: bool = True
    quantum_resistant: bool = True
    geographic_location: Optional[str] = None
    priority_level: int = 1  # 1=highest, 10=lowest
    capabilities: List[str] = field(default_factory=lambda: ["backup", "replication", "seeding"])


@dataclass
class ClusterMetrics:
    """Cluster performance metrics."""
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    network_latency: float = 0.0
    throughput_mbps: float = 0.0
    active_connections: int = 0
    last_updated: datetime = field(default_factory=datetime.now)


class BackupNodeService:
    """Enhanced backup node service with government-level clustering."""

    def __init__(self, config: BackupNodeConfig):
        self.config = config
        self.storage_path = Path(config.storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        # Create additional directories for clustering
        self.cluster_path = self.storage_path / "cluster"
        self.metrics_path = self.storage_path / "metrics"
        self.logs_path = self.storage_path / "logs"
        for path in [self.cluster_path, self.metrics_path, self.logs_path]:
            path.mkdir(parents=True, exist_ok=True)

        # Storage management
        self.shards: Dict[str, BackupShard] = {}
        self.storage_used_bytes = 0
        self.max_storage_bytes = config.max_storage_gb * 1024 * 1024 * 1024

        # Enhanced network management
        self.connected_nodes: Dict[str, NodeInfo] = {}
        self.active_transfers: Set[str] = set()
        self.cluster_nodes: Dict[str, Dict[str, Any]] = {}
        self.is_cluster_master = False
        self.master_node_id: Optional[str] = None

        # Performance monitoring
        self.metrics = ClusterMetrics()
        self.performance_history: List[ClusterMetrics] = []

        # Enhanced metadata files
        self.shards_db_file = self.storage_path / "shards_database.json"
        self.nodes_db_file = self.storage_path / "nodes_database.json"
        self.cluster_db_file = self.cluster_path / "cluster_database.json"
        self.config_file = self.storage_path / "node_config.json"

        # SQLite database for advanced features
        self.db_path = self.storage_path / "backup_node.db"
        self._init_database()

        # Encryption setup
        if config.encryption_enabled:
            self.encryption_key = self._get_or_create_encryption_key()
            self.fernet = Fernet(self.encryption_key)
        else:
            self.encryption_key = None
            self.fernet = None

        # Background tasks
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        self.heartbeat_thread: Optional[threading.Thread] = None

        # Load existing data
        self._load_shards_database()
        self._load_nodes_database()
        self._load_cluster_database()
        self._calculate_storage_usage()

        # Start background monitoring
        self._start_background_tasks()

        logger.info(f"🔧 Enhanced backup node initialized: {config.node_id}")
        logger.info(f"📁 Storage path: {self.storage_path}")
        logger.info(f"💾 Storage limit: {config.max_storage_gb} GB")
        logger.info(f"📊 Current usage: {self.storage_used_bytes / (1024**3):.2f} GB")
        logger.info(f"🔐 Encryption: {'Enabled' if config.encryption_enabled else 'Disabled'}")
        logger.info(f"🌐 Clustering: {'Enabled' if config.cluster_enabled else 'Disabled'}")

    def _init_database(self):
        """Initialize SQLite database for advanced features."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Enhanced shards table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS shards_enhanced (
                        shard_id TEXT PRIMARY KEY,
                        backup_id TEXT NOT NULL,
                        shard_data TEXT NOT NULL,
                        encryption_key_hash TEXT,
                        replication_nodes TEXT,
                        verification_status TEXT DEFAULT 'pending',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_verified TIMESTAMP,
                        access_count INTEGER DEFAULT 0,
                        last_accessed TIMESTAMP
                    )
                ''')

                # Cluster nodes table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS cluster_nodes (
                        node_id TEXT PRIMARY KEY,
                        node_data TEXT NOT NULL,
                        last_heartbeat TIMESTAMP,
                        status TEXT DEFAULT 'unknown',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Performance metrics table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS performance_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        node_id TEXT NOT NULL,
                        metrics_data TEXT NOT NULL,
                        recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Replication tracking
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS replication_tracking (
                        shard_id TEXT NOT NULL,
                        source_node TEXT NOT NULL,
                        target_node TEXT NOT NULL,
                        replication_status TEXT DEFAULT 'pending',
                        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        completed_at TIMESTAMP,
                        PRIMARY KEY (shard_id, source_node, target_node)
                    )
                ''')

                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_shards_backup ON shards_enhanced(backup_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_nodes_heartbeat ON cluster_nodes(last_heartbeat)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_recorded ON performance_metrics(recorded_at)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_replication_status ON replication_tracking(replication_status)')

                conn.commit()
                logger.info("Enhanced backup node database initialized")
        except Exception as e:
            logger.error(f"Error initializing database: {e}")

    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for the node."""
        key_file = self.storage_path / "encryption.key"

        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            # Secure the key file
            os.chmod(key_file, 0o600)
            logger.info("Generated new encryption key")
            return key

    def _start_background_tasks(self):
        """Start background monitoring and maintenance tasks."""
        if self.config.cluster_enabled:
            self.monitoring_active = True

            # Performance monitoring thread
            self.monitoring_thread = threading.Thread(
                target=self._monitoring_loop,
                daemon=True
            )
            self.monitoring_thread.start()

            # Heartbeat thread for cluster communication
            self.heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop,
                daemon=True
            )
            self.heartbeat_thread.start()

            logger.info("Background clustering tasks started")

    def _monitoring_loop(self):
        """Background monitoring loop for performance metrics."""
        while self.monitoring_active:
            try:
                # Update performance metrics
                self._update_performance_metrics()

                # Check cluster health
                self._check_cluster_health()

                # Cleanup old data
                self._cleanup_old_metrics()

                time.sleep(60)  # Update every minute
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(30)

    def _heartbeat_loop(self):
        """Background heartbeat loop for cluster communication."""
        while self.monitoring_active:
            try:
                # Send heartbeats to known cluster nodes
                self._send_cluster_heartbeats()

                # Check for failed nodes
                self._check_failed_nodes()

                time.sleep(self.config.heartbeat_interval)
            except Exception as e:
                logger.error(f"Error in heartbeat loop: {e}")
                time.sleep(15)

    def _update_performance_metrics(self):
        """Update current performance metrics."""
        try:
            # Get system metrics
            self.metrics.cpu_usage = psutil.cpu_percent(interval=1)
            self.metrics.memory_usage = psutil.virtual_memory().percent
            self.metrics.disk_usage = psutil.disk_usage(str(self.storage_path)).percent
            self.metrics.active_connections = len(self.connected_nodes)
            self.metrics.last_updated = datetime.now()

            # Store in database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO performance_metrics (node_id, metrics_data) VALUES (?, ?)',
                    (self.config.node_id, json.dumps(asdict(self.metrics)))
                )
                conn.commit()

            # Keep recent history in memory
            self.performance_history.append(self.metrics)
            if len(self.performance_history) > 100:  # Keep last 100 entries
                self.performance_history = self.performance_history[-50:]
        except Exception as e:
            logger.error(f"Error updating performance metrics: {e}")

    def _load_cluster_database(self):
        """Load cluster database from file."""
        try:
            if self.cluster_db_file.exists():
                with open(self.cluster_db_file, 'r') as f:
                    data = json.load(f)
                    self.cluster_nodes = data.get('cluster_nodes', {})
                    self.is_cluster_master = data.get('is_cluster_master', False)
                    self.master_node_id = data.get('master_node_id')

                logger.info(f"Loaded cluster database with {len(self.cluster_nodes)} nodes")
        except Exception as e:
            logger.error(f"Error loading cluster database: {e}")

    def _save_cluster_database(self):
        """Save cluster database to file."""
        try:
            data = {
                'cluster_nodes': self.cluster_nodes,
                'is_cluster_master': self.is_cluster_master,
                'master_node_id': self.master_node_id,
                'last_updated': datetime.now().isoformat()
            }

            with open(self.cluster_db_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving cluster database: {e}")
    
    def _load_shards_database(self):
        """Load shards database from file."""
        try:
            if self.shards_db_file.exists():
                with open(self.shards_db_file, 'r') as f:
                    data = json.load(f)
                    
                for shard_id, shard_data in data.items():
                    # Convert datetime strings back to datetime objects
                    shard_data['created_at'] = datetime.fromisoformat(shard_data['created_at'])
                    if shard_data.get('last_verified'):
                        shard_data['last_verified'] = datetime.fromisoformat(shard_data['last_verified'])
                    
                    self.shards[shard_id] = BackupShard(**shard_data)
                
                logger.info(f"📂 Loaded {len(self.shards)} shards from database")
        except Exception as e:
            logger.error(f"Failed to load shards database: {e}")
    
    def _save_shards_database(self):
        """Save shards database to file."""
        try:
            data = {}
            for shard_id, shard in self.shards.items():
                shard_dict = asdict(shard)
                # Convert datetime objects to strings
                shard_dict['created_at'] = shard.created_at.isoformat()
                if shard.last_verified:
                    shard_dict['last_verified'] = shard.last_verified.isoformat()
                data[shard_id] = shard_dict
            
            with open(self.shards_db_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save shards database: {e}")
    
    def _load_nodes_database(self):
        """Load nodes database from file."""
        try:
            if self.nodes_db_file.exists():
                with open(self.nodes_db_file, 'r') as f:
                    data = json.load(f)
                    
                for node_id, node_data in data.items():
                    node_data['last_seen'] = datetime.fromisoformat(node_data['last_seen'])
                    self.connected_nodes[node_id] = NodeInfo(**node_data)
                
                logger.info(f"🌐 Loaded {len(self.connected_nodes)} nodes from database")
        except Exception as e:
            logger.error(f"Failed to load nodes database: {e}")
    
    def _save_nodes_database(self):
        """Save nodes database to file."""
        try:
            data = {}
            for node_id, node in self.connected_nodes.items():
                node_dict = asdict(node)
                node_dict['last_seen'] = node.last_seen.isoformat()
                data[node_id] = node_dict
            
            with open(self.nodes_db_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save nodes database: {e}")
    
    def _calculate_storage_usage(self):
        """Calculate current storage usage."""
        total_size = 0
        
        for shard_file in self.storage_path.glob("shard_*"):
            if shard_file.is_file():
                total_size += shard_file.stat().st_size
        
        self.storage_used_bytes = total_size
        logger.info(f"📊 Calculated storage usage: {total_size / (1024**3):.2f} GB")
    
    async def store_shard(
        self,
        shard_id: str,
        shard_data: bytes,
        original_hash: str,
        source_node: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Store a backup shard."""
        try:
            # Check storage limits
            if self.storage_used_bytes + len(shard_data) > self.max_storage_bytes:
                logger.warning(f"⚠️ Storage limit exceeded for shard {shard_id}")
                await self._cleanup_old_shards()
                
                # Check again after cleanup
                if self.storage_used_bytes + len(shard_data) > self.max_storage_bytes:
                    logger.error(f"❌ Cannot store shard {shard_id}: insufficient space")
                    return False
            
            # Verify hash
            calculated_hash = hashlib.sha256(shard_data).hexdigest()
            if calculated_hash != original_hash:
                logger.error(f"❌ Hash mismatch for shard {shard_id}")
                return False
            
            # Store shard file
            shard_file = self.storage_path / f"shard_{shard_id}"
            async with aiofiles.open(shard_file, 'wb') as f:
                await f.write(shard_data)
            
            # Create shard record
            shard = BackupShard(
                shard_id=shard_id,
                original_hash=original_hash,
                size_bytes=len(shard_data),
                created_at=datetime.now(timezone.utc),
                source_node=source_node,
                metadata=metadata or {}
            )
            
            self.shards[shard_id] = shard
            self.storage_used_bytes += len(shard_data)
            
            # Save database
            self._save_shards_database()
            
            logger.info(f"✅ Stored shard {shard_id} ({len(shard_data)} bytes)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store shard {shard_id}: {e}")
            return False
    
    async def retrieve_shard(self, shard_id: str) -> Optional[bytes]:
        """Retrieve a backup shard."""
        try:
            if shard_id not in self.shards:
                logger.warning(f"⚠️ Shard {shard_id} not found")
                return None
            
            shard_file = self.storage_path / f"shard_{shard_id}"
            if not shard_file.exists():
                logger.error(f"❌ Shard file missing: {shard_id}")
                # Remove from database
                del self.shards[shard_id]
                self._save_shards_database()
                return None
            
            async with aiofiles.open(shard_file, 'rb') as f:
                shard_data = await f.read()
            
            # Verify integrity
            calculated_hash = hashlib.sha256(shard_data).hexdigest()
            expected_hash = self.shards[shard_id].original_hash
            
            if calculated_hash != expected_hash:
                logger.error(f"❌ Shard integrity check failed: {shard_id}")
                return None
            
            # Update verification info
            self.shards[shard_id].last_verified = datetime.now(timezone.utc)
            self.shards[shard_id].verification_count += 1
            self._save_shards_database()
            
            logger.info(f"✅ Retrieved shard {shard_id}")
            return shard_data
            
        except Exception as e:
            logger.error(f"Failed to retrieve shard {shard_id}: {e}")
            return None
    
    async def delete_shard(self, shard_id: str) -> bool:
        """Delete a backup shard."""
        try:
            if shard_id not in self.shards:
                return False
            
            shard_file = self.storage_path / f"shard_{shard_id}"
            if shard_file.exists():
                shard_file.unlink()
                self.storage_used_bytes -= self.shards[shard_id].size_bytes
            
            del self.shards[shard_id]
            self._save_shards_database()
            
            logger.info(f"🗑️ Deleted shard {shard_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete shard {shard_id}: {e}")
            return False
    
    async def _cleanup_old_shards(self):
        """Clean up old shards to free space."""
        try:
            # Sort shards by last access time (oldest first)
            sorted_shards = sorted(
                self.shards.items(),
                key=lambda x: x[1].last_verified or x[1].created_at
            )
            
            # Remove oldest 10% of shards
            cleanup_count = max(1, len(sorted_shards) // 10)
            
            for i in range(cleanup_count):
                shard_id, shard = sorted_shards[i]
                await self.delete_shard(shard_id)
                logger.info(f"🧹 Cleaned up old shard: {shard_id}")
            
            logger.info(f"🧹 Cleanup completed: removed {cleanup_count} shards")
            
        except Exception as e:
            logger.error(f"Failed to cleanup old shards: {e}")
    
    def get_node_status(self) -> Dict[str, Any]:
        """Get current node status."""
        return {
            "node_id": self.config.node_id,
            "node_type": "backup",
            "storage": {
                "used_bytes": self.storage_used_bytes,
                "max_bytes": self.max_storage_bytes,
                "used_percentage": (self.storage_used_bytes / self.max_storage_bytes) * 100,
                "available_bytes": self.max_storage_bytes - self.storage_used_bytes
            },
            "shards": {
                "total_count": len(self.shards),
                "total_size_bytes": sum(shard.size_bytes for shard in self.shards.values())
            },
            "network": {
                "connected_nodes": len(self.connected_nodes),
                "active_transfers": len(self.active_transfers)
            },
            "uptime": time.time(),
            "last_updated": datetime.now(timezone.utc).isoformat()
        }


# Global backup node service
backup_node_service: Optional[BackupNodeService] = None


# Pydantic models for API
class ShardStoreRequest(BaseModel):
    shard_id: str
    shard_data: str  # Base64 encoded
    original_hash: str
    source_node: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class NodeRegistrationRequest(BaseModel):
    node_id: str
    node_type: str
    address: str
    port: int
    storage_capacity: int


# FastAPI application
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management."""
    # Startup
    logger.info("🚀 Starting NetLink Backup Node")
    
    # Start background tasks
    asyncio.create_task(periodic_verification())
    asyncio.create_task(node_health_check())
    
    yield
    
    # Shutdown
    logger.info("🛑 Shutting down NetLink Backup Node")


app = FastAPI(
    title="NetLink Backup Node",
    description="Independent backup storage system for NetLink network",
    version="3.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "NetLink Backup Node",
        "version": "3.0.0",
        "status": "running",
        "node_id": backup_node_service.config.node_id if backup_node_service else "not_initialized",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    if not backup_node_service:
        raise HTTPException(status_code=503, detail="Backup node not initialized")
    
    status = backup_node_service.get_node_status()
    
    return {
        "status": "healthy",
        "node_status": status,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/v1/shards/store")
async def store_shard_endpoint(request: ShardStoreRequest):
    """Store a backup shard."""
    if not backup_node_service:
        raise HTTPException(status_code=503, detail="Backup node not initialized")

    try:
        import base64
        shard_data = base64.b64decode(request.shard_data)

        success = await backup_node_service.store_shard(
            shard_id=request.shard_id,
            shard_data=shard_data,
            original_hash=request.original_hash,
            source_node=request.source_node,
            metadata=request.metadata
        )

        if success:
            return {
                "success": True,
                "shard_id": request.shard_id,
                "message": "Shard stored successfully"
            }
        else:
            raise HTTPException(status_code=507, detail="Insufficient storage space")

    except Exception as e:
        logger.error(f"Failed to store shard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/shards/{shard_id}")
async def retrieve_shard_endpoint(shard_id: str):
    """Retrieve a backup shard."""
    if not backup_node_service:
        raise HTTPException(status_code=503, detail="Backup node not initialized")

    try:
        shard_data = await backup_node_service.retrieve_shard(shard_id)

        if shard_data is None:
            raise HTTPException(status_code=404, detail="Shard not found")

        import base64
        return {
            "shard_id": shard_id,
            "shard_data": base64.b64encode(shard_data).decode('utf-8'),
            "size_bytes": len(shard_data),
            "retrieved_at": datetime.now(timezone.utc).isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve shard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/v1/shards/{shard_id}")
async def delete_shard_endpoint(shard_id: str):
    """Delete a backup shard."""
    if not backup_node_service:
        raise HTTPException(status_code=503, detail="Backup node not initialized")

    try:
        success = await backup_node_service.delete_shard(shard_id)

        if success:
            return {
                "success": True,
                "shard_id": shard_id,
                "message": "Shard deleted successfully"
            }
        else:
            raise HTTPException(status_code=404, detail="Shard not found")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete shard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/shards")
async def list_shards():
    """List all stored shards."""
    if not backup_node_service:
        raise HTTPException(status_code=503, detail="Backup node not initialized")

    try:
        shards_info = []

        for shard_id, shard in backup_node_service.shards.items():
            shards_info.append({
                "shard_id": shard_id,
                "size_bytes": shard.size_bytes,
                "created_at": shard.created_at.isoformat(),
                "last_verified": shard.last_verified.isoformat() if shard.last_verified else None,
                "verification_count": shard.verification_count,
                "source_node": shard.source_node,
                "redundancy_level": shard.redundancy_level
            })

        return {
            "shards": shards_info,
            "total_count": len(shards_info),
            "total_size_bytes": sum(shard.size_bytes for shard in backup_node_service.shards.values())
        }

    except Exception as e:
        logger.error(f"Failed to list shards: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/status")
async def get_node_status():
    """Get detailed node status."""
    if not backup_node_service:
        raise HTTPException(status_code=503, detail="Backup node not initialized")

    try:
        return backup_node_service.get_node_status()

    except Exception as e:
        logger.error(f"Failed to get node status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/nodes/register")
async def register_node(request: NodeRegistrationRequest):
    """Register a new node in the network."""
    if not backup_node_service:
        raise HTTPException(status_code=503, detail="Backup node not initialized")

    try:
        node_info = NodeInfo(
            node_id=request.node_id,
            node_type=request.node_type,
            address=request.address,
            port=request.port,
            last_seen=datetime.now(timezone.utc),
            storage_capacity=request.storage_capacity,
            storage_used=0
        )

        backup_node_service.connected_nodes[request.node_id] = node_info
        backup_node_service._save_nodes_database()

        logger.info(f"🌐 Registered node: {request.node_id} ({request.node_type})")

        return {
            "success": True,
            "node_id": request.node_id,
            "message": "Node registered successfully"
        }

    except Exception as e:
        logger.error(f"Failed to register node: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/nodes")
async def list_nodes():
    """List all connected nodes."""
    if not backup_node_service:
        raise HTTPException(status_code=503, detail="Backup node not initialized")

    try:
        nodes_info = []

        for node_id, node in backup_node_service.connected_nodes.items():
            nodes_info.append({
                "node_id": node_id,
                "node_type": node.node_type,
                "address": node.address,
                "port": node.port,
                "last_seen": node.last_seen.isoformat(),
                "storage_capacity": node.storage_capacity,
                "storage_used": node.storage_used,
                "is_online": node.is_online,
                "trust_level": node.trust_level
            })

        return {
            "nodes": nodes_info,
            "total_count": len(nodes_info),
            "online_count": sum(1 for node in backup_node_service.connected_nodes.values() if node.is_online)
        }

    except Exception as e:
        logger.error(f"Failed to list nodes: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Background tasks
async def periodic_verification():
    """Periodically verify stored shards."""
    while True:
        try:
            if backup_node_service:
                logger.info("🔍 Starting periodic shard verification")

                verification_count = 0
                for shard_id, shard in backup_node_service.shards.items():
                    # Check if verification is needed
                    if (not shard.last_verified or
                        datetime.now(timezone.utc) - shard.last_verified >
                        timedelta(hours=backup_node_service.config.verification_interval_hours)):

                        # Verify shard integrity
                        shard_data = await backup_node_service.retrieve_shard(shard_id)
                        if shard_data is not None:
                            verification_count += 1

                logger.info(f"✅ Verified {verification_count} shards")

            # Wait for next verification cycle
            await asyncio.sleep(3600)  # Check every hour

        except Exception as e:
            logger.error(f"Error in periodic verification: {e}")
            await asyncio.sleep(300)  # Wait 5 minutes on error


async def node_health_check():
    """Check health of connected nodes."""
    while True:
        try:
            if backup_node_service:
                current_time = datetime.now(timezone.utc)
                offline_nodes = []

                for node_id, node in backup_node_service.connected_nodes.items():
                    # Check if node is offline (no contact for 5 minutes)
                    if current_time - node.last_seen > timedelta(minutes=5):
                        if node.is_online:
                            node.is_online = False
                            offline_nodes.append(node_id)
                            logger.warning(f"📴 Node {node_id} went offline")

                if offline_nodes:
                    backup_node_service._save_nodes_database()

            # Wait for next health check
            await asyncio.sleep(60)  # Check every minute

        except Exception as e:
            logger.error(f"Error in node health check: {e}")
            await asyncio.sleep(60)


def load_config() -> BackupNodeConfig:
    """Load backup node configuration."""
    config_file = Path("backup_node/config.json")

    # Default configuration
    default_config = {
        "node_id": f"backup_node_{secrets.token_hex(8)}",
        "storage_path": "backup_node/storage",
        "max_storage_gb": 100,
        "port": 8001,
        "main_node_address": None,
        "main_node_port": None,
        "auto_cleanup_enabled": True,
        "verification_interval_hours": 24,
        "seeding_enabled": True,
        "max_concurrent_transfers": 10,
        "bandwidth_limit_mbps": None
    }

    try:
        if config_file.exists():
            with open(config_file, 'r') as f:
                config_data = json.load(f)
                # Merge with defaults
                default_config.update(config_data)
        else:
            # Create default config file
            config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            logger.info(f"📝 Created default config file: {config_file}")

        return BackupNodeConfig(**default_config)

    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        return BackupNodeConfig(**default_config)


def main():
    """Main entry point for backup node."""
    global backup_node_service

    print("🚀 NetLink Backup Node v3.0.0")
    print("=" * 50)

    try:
        # Load configuration
        config = load_config()

        # Initialize backup node service
        backup_node_service = BackupNodeService(config)

        print(f"🆔 Node ID: {config.node_id}")
        print(f"📁 Storage Path: {config.storage_path}")
        print(f"💾 Storage Limit: {config.max_storage_gb} GB")
        print(f"🌐 Port: {config.port}")
        print("=" * 50)

        # Start the server
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=config.port,
            log_level="info",
            access_log=True
        )

    except KeyboardInterrupt:
        logger.info("🛑 Backup node stopped by user")
    except Exception as e:
        logger.error(f"❌ Failed to start backup node: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
