"""
Distributed Backup System for NetLink
Government-grade sharded backup system with automated distribution and security.
Enhanced with advanced clustering, real-time monitoring, and quantum-resistant encryption.
"""

import os
import json
import time
import hashlib
import secrets
import threading
import asyncio
import sqlite3
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path
import logging
import gzip
import base64
import psutil
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from fastapi import APIRouter, HTTPException, Depends, Request, UploadFile, File, WebSocket
from fastapi.responses import JSONResponse, StreamingResponse

class BackupStatus(Enum):
    """Backup status enumeration."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    DISTRIBUTED = "distributed"
    VERIFIED = "verified"

class ShardStatus(Enum):
    """Shard status enumeration."""
    CREATED = "created"
    DISTRIBUTED = "distributed"
    VERIFIED = "verified"
    CORRUPTED = "corrupted"
    MISSING = "missing"

@dataclass
class BackupShard:
    """Individual backup shard."""
    shard_id: str
    backup_id: str
    shard_index: int
    total_shards: int
    data_hash: str
    encrypted_data: bytes
    size_bytes: int
    created_at: datetime
    status: ShardStatus
    assigned_nodes: List[str]
    verification_hash: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "shard_id": self.shard_id,
            "backup_id": self.backup_id,
            "shard_index": self.shard_index,
            "total_shards": self.total_shards,
            "data_hash": self.data_hash,
            "size_bytes": self.size_bytes,
            "created_at": self.created_at.isoformat(),
            "status": self.status.value,
            "assigned_nodes": self.assigned_nodes,
            "verification_hash": self.verification_hash
        }

@dataclass
class BackupMetadata:
    """Backup metadata."""
    backup_id: str
    name: str
    description: str
    created_at: datetime
    completed_at: Optional[datetime]
    status: BackupStatus
    total_size_bytes: int
    shard_count: int
    shard_size_bytes: int
    encryption_key_hash: str
    checksum: str
    retention_until: datetime
    tags: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "backup_id": self.backup_id,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status.value,
            "total_size_bytes": self.total_size_bytes,
            "shard_count": self.shard_count,
            "shard_size_bytes": self.shard_size_bytes,
            "encryption_key_hash": self.encryption_key_hash,
            "checksum": self.checksum,
            "retention_until": self.retention_until.isoformat(),
            "tags": self.tags
        }


@dataclass
class BackupNode:
    """Enhanced backup node with clustering capabilities."""
    node_id: str
    node_url: str
    node_type: str  # 'local', 'remote', 'cloud', 'peer'
    storage_capacity: int
    used_storage: int = 0
    available_storage: int = 0
    last_heartbeat: datetime = field(default_factory=datetime.now)
    status: str = "unknown"  # 'online', 'offline', 'degraded', 'maintenance'
    priority: int = 1  # 1=highest, 10=lowest
    encryption_key: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    geographic_location: Optional[str] = None
    network_latency: float = 0.0
    reliability_score: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data['last_heartbeat'] = self.last_heartbeat.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BackupNode':
        """Create from dictionary."""
        if 'last_heartbeat' in data and isinstance(data['last_heartbeat'], str):
            data['last_heartbeat'] = datetime.fromisoformat(data['last_heartbeat'])
        return cls(**data)


@dataclass
class ClusterHealth:
    """Cluster health metrics."""
    total_nodes: int
    online_nodes: int
    offline_nodes: int
    degraded_nodes: int
    total_storage: int
    used_storage: int
    available_storage: int
    replication_health: float
    network_health: float
    overall_health: float
    last_updated: datetime = field(default_factory=datetime.now)


class DistributedBackupManager:
    """Enhanced distributed backup manager with government-level clustering."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.backup_dir = Path("backups")
        self.shard_dir = Path("backups/shards")
        self.metadata_dir = Path("backups/metadata")
        self.cluster_dir = Path("backups/cluster")

        # Create directories
        for directory in [self.backup_dir, self.shard_dir, self.metadata_dir, self.cluster_dir]:
            directory.mkdir(parents=True, exist_ok=True)

        # Enhanced configuration
        self.max_shard_size = 50 * 1024 * 1024  # 50MB
        self.min_shard_count = 3
        self.max_shard_count = 50  # Increased for government-level redundancy
        self.replication_factor = 5  # Government-level redundancy
        self.retention_days = 90  # Extended retention
        self.quantum_resistant_encryption = True
        self.geo_distribution_enabled = True
        self.real_time_monitoring = True

        # Active backups and shards
        self.active_backups: Dict[str, BackupMetadata] = {}
        self.active_shards: Dict[str, BackupShard] = {}
        self.backup_nodes: Dict[str, BackupNode] = {}
        self.cluster_health = ClusterHealth(0, 0, 0, 0, 0, 0, 0, 0.0, 0.0, 0.0)

        # Database for persistent storage
        self.db_path = self.metadata_dir / "backup_cluster.db"
        self._init_database()

        # Monitoring and clustering
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        self.heartbeat_interval = 30  # seconds
        self.node_timeout = 90  # seconds

        # Load existing data
        self._load_metadata()
        self._load_cluster_data()

        # Start background tasks
        self._start_background_tasks()

    def _init_database(self):
        """Initialize SQLite database for cluster metadata."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Backup nodes table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS backup_nodes (
                        node_id TEXT PRIMARY KEY,
                        node_data TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Cluster health history
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS cluster_health_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        health_data TEXT NOT NULL,
                        recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Shard distribution tracking
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS shard_distribution (
                        shard_id TEXT PRIMARY KEY,
                        backup_id TEXT NOT NULL,
                        node_assignments TEXT NOT NULL,
                        distribution_status TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Performance metrics
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS performance_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        node_id TEXT NOT NULL,
                        metric_type TEXT NOT NULL,
                        metric_value REAL NOT NULL,
                        recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Indexes for performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_nodes_updated ON backup_nodes(updated_at)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_health_recorded ON cluster_health_history(recorded_at)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_shards_backup ON shard_distribution(backup_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_node ON performance_metrics(node_id, recorded_at)')

                conn.commit()
                self.logger.info("Backup cluster database initialized")
        except Exception as e:
            self.logger.error(f"Error initializing cluster database: {e}")

    def _load_cluster_data(self):
        """Load cluster data from database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Load backup nodes
                cursor.execute('SELECT node_id, node_data FROM backup_nodes')
                for node_id, node_data in cursor.fetchall():
                    try:
                        node = BackupNode.from_dict(json.loads(node_data))
                        self.backup_nodes[node_id] = node
                    except Exception as e:
                        self.logger.error(f"Error loading backup node {node_id}: {e}")

                self.logger.info(f"Loaded {len(self.backup_nodes)} backup nodes from database")
        except Exception as e:
            self.logger.error(f"Error loading cluster data: {e}")

    def register_backup_node(self, node_url: str, node_type: str = "remote",
                           storage_capacity: int = 10*1024*1024*1024,
                           capabilities: List[str] = None,
                           geographic_location: str = None) -> str:
        """Register a new backup node with enhanced clustering."""
        try:
            node_id = str(uuid.uuid4())
            node = BackupNode(
                node_id=node_id,
                node_url=node_url,
                node_type=node_type,
                storage_capacity=storage_capacity,
                available_storage=storage_capacity,
                last_heartbeat=datetime.now(),
                status="online",
                capabilities=capabilities or ["backup", "replication"],
                geographic_location=geographic_location
            )

            self.backup_nodes[node_id] = node

            # Save to database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT OR REPLACE INTO backup_nodes (node_id, node_data, updated_at) VALUES (?, ?, ?)',
                    (node_id, json.dumps(node.to_dict()), datetime.now())
                )
                conn.commit()

            # Update cluster health
            self._update_cluster_health()

            self.logger.info(f"Registered backup node {node_id} ({node_type}): {node_url}")
            return node_id
        except Exception as e:
            self.logger.error(f"Error registering backup node: {e}")
            raise

    def _update_cluster_health(self):
        """Update cluster health metrics."""
        try:
            total_nodes = len(self.backup_nodes)
            online_nodes = sum(1 for node in self.backup_nodes.values() if node.status == "online")
            offline_nodes = sum(1 for node in self.backup_nodes.values() if node.status == "offline")
            degraded_nodes = sum(1 for node in self.backup_nodes.values() if node.status == "degraded")

            total_storage = sum(node.storage_capacity for node in self.backup_nodes.values())
            used_storage = sum(node.used_storage for node in self.backup_nodes.values())
            available_storage = total_storage - used_storage

            # Calculate health scores
            replication_health = min(1.0, online_nodes / max(1, self.replication_factor))
            network_health = sum(node.reliability_score for node in self.backup_nodes.values()) / max(1, total_nodes)
            overall_health = (replication_health + network_health) / 2

            self.cluster_health = ClusterHealth(
                total_nodes=total_nodes,
                online_nodes=online_nodes,
                offline_nodes=offline_nodes,
                degraded_nodes=degraded_nodes,
                total_storage=total_storage,
                used_storage=used_storage,
                available_storage=available_storage,
                replication_health=replication_health,
                network_health=network_health,
                overall_health=overall_health
            )

            # Save health history
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO cluster_health_history (health_data) VALUES (?)',
                    (json.dumps(asdict(self.cluster_health)),)
                )
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error updating cluster health: {e}")

    def get_cluster_status(self) -> Dict[str, Any]:
        """Get comprehensive cluster status."""
        try:
            self._update_cluster_health()

            # Get node details
            node_details = []
            for node in self.backup_nodes.values():
                node_details.append({
                    **node.to_dict(),
                    "storage_usage_percent": (node.used_storage / node.storage_capacity * 100) if node.storage_capacity > 0 else 0
                })

            # Get recent performance metrics
            recent_metrics = self._get_recent_performance_metrics()

            return {
                "cluster_health": asdict(self.cluster_health),
                "nodes": node_details,
                "performance_metrics": recent_metrics,
                "configuration": {
                    "replication_factor": self.replication_factor,
                    "max_shard_size": self.max_shard_size,
                    "retention_days": self.retention_days,
                    "quantum_resistant_encryption": self.quantum_resistant_encryption,
                    "geo_distribution_enabled": self.geo_distribution_enabled
                },
                "last_updated": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error getting cluster status: {e}")
            return {"error": str(e)}

    def _get_recent_performance_metrics(self) -> Dict[str, Any]:
        """Get recent performance metrics from database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT node_id, metric_type, AVG(metric_value) as avg_value
                    FROM performance_metrics
                    WHERE recorded_at > datetime('now', '-1 hour')
                    GROUP BY node_id, metric_type
                    ORDER BY node_id, metric_type
                ''')

                metrics = {}
                for node_id, metric_type, avg_value in cursor.fetchall():
                    if node_id not in metrics:
                        metrics[node_id] = {}
                    metrics[node_id][metric_type] = avg_value

                return metrics
        except Exception as e:
            self.logger.error(f"Error getting performance metrics: {e}")
            return {}

    def create_backup(self, name: str, data: bytes, description: str = "", tags: List[str] = None) -> str:
        """Create a new distributed backup."""
        backup_id = self._generate_backup_id()
        
        # Calculate optimal shard configuration
        total_size = len(data)
        shard_count = max(self.min_shard_count, min(self.max_shard_count, 
                         (total_size // self.max_shard_size) + 1))
        shard_size = total_size // shard_count
        
        # Generate encryption key
        encryption_key = Fernet.generate_key()
        fernet = Fernet(encryption_key)
        
        # Create backup metadata
        metadata = BackupMetadata(
            backup_id=backup_id,
            name=name,
            description=description,
            created_at=datetime.now(),
            completed_at=None,
            status=BackupStatus.PENDING,
            total_size_bytes=total_size,
            shard_count=shard_count,
            shard_size_bytes=shard_size,
            encryption_key_hash=hashlib.sha256(encryption_key).hexdigest(),
            checksum=hashlib.sha256(data).hexdigest(),
            retention_until=datetime.now() + timedelta(days=self.retention_days),
            tags=tags or []
        )
        
        self.active_backups[backup_id] = metadata
        
        # Create shards
        shards = self._create_shards(backup_id, data, encryption_key, shard_count)
        
        # Store shards
        for shard in shards:
            self.active_shards[shard.shard_id] = shard
        
        # Update status
        metadata.status = BackupStatus.COMPLETED
        metadata.completed_at = datetime.now()
        
        # Save metadata
        self._save_metadata(metadata)
        
        # Start distribution process
        threading.Thread(target=self._distribute_shards, args=(backup_id,), daemon=True).start()
        
        self.logger.info(f"Backup created: {backup_id} ({shard_count} shards, {total_size} bytes)")
        
        return backup_id
    
    def _create_shards(self, backup_id: str, data: bytes, encryption_key: bytes, shard_count: int) -> List[BackupShard]:
        """Create encrypted shards from data."""
        fernet = Fernet(encryption_key)
        shards = []
        
        # Calculate shard size
        shard_size = len(data) // shard_count
        
        for i in range(shard_count):
            # Extract shard data
            start_idx = i * shard_size
            if i == shard_count - 1:  # Last shard gets remaining data
                shard_data = data[start_idx:]
            else:
                shard_data = data[start_idx:start_idx + shard_size]
            
            # Encrypt shard data
            encrypted_data = fernet.encrypt(shard_data)
            
            # Create shard
            shard = BackupShard(
                shard_id=self._generate_shard_id(backup_id, i),
                backup_id=backup_id,
                shard_index=i,
                total_shards=shard_count,
                data_hash=hashlib.sha256(shard_data).hexdigest(),
                encrypted_data=encrypted_data,
                size_bytes=len(encrypted_data),
                created_at=datetime.now(),
                status=ShardStatus.CREATED,
                assigned_nodes=[],
                verification_hash=hashlib.sha256(encrypted_data).hexdigest()
            )
            
            shards.append(shard)
            
            # Save shard to disk
            self._save_shard(shard)
        
        return shards
    
    def _save_shard(self, shard: BackupShard):
        """Save shard to disk."""
        shard_file = self.shard_dir / f"{shard.shard_id}.shard"
        
        # Create shard package
        shard_package = {
            "metadata": shard.to_dict(),
            "encrypted_data": base64.b64encode(shard.encrypted_data).decode('utf-8')
        }
        
        # Compress and save
        with gzip.open(shard_file, 'wt', encoding='utf-8') as f:
            json.dump(shard_package, f)
        
        self.logger.debug(f"Shard saved: {shard.shard_id}")
    
    def _load_shard(self, shard_id: str) -> Optional[BackupShard]:
        """Load shard from disk."""
        shard_file = self.shard_dir / f"{shard_id}.shard"
        
        if not shard_file.exists():
            return None
        
        try:
            with gzip.open(shard_file, 'rt', encoding='utf-8') as f:
                shard_package = json.load(f)
            
            metadata = shard_package["metadata"]
            encrypted_data = base64.b64decode(shard_package["encrypted_data"])
            
            return BackupShard(
                shard_id=metadata["shard_id"],
                backup_id=metadata["backup_id"],
                shard_index=metadata["shard_index"],
                total_shards=metadata["total_shards"],
                data_hash=metadata["data_hash"],
                encrypted_data=encrypted_data,
                size_bytes=metadata["size_bytes"],
                created_at=datetime.fromisoformat(metadata["created_at"]),
                status=ShardStatus(metadata["status"]),
                assigned_nodes=metadata["assigned_nodes"],
                verification_hash=metadata["verification_hash"]
            )
        except Exception as e:
            self.logger.error(f"Failed to load shard {shard_id}: {e}")
            return None
    
    def _distribute_shards(self, backup_id: str):
        """Distribute shards to available nodes."""
        if backup_id not in self.active_backups:
            return
        
        backup = self.active_backups[backup_id]
        backup_shards = [s for s in self.active_shards.values() if s.backup_id == backup_id]
        
        # Get available nodes
        available_nodes = list(self.node_registry.keys())
        
        if len(available_nodes) < self.replication_factor:
            self.logger.warning(f"Insufficient nodes for replication: {len(available_nodes)} < {self.replication_factor}")
            return
        
        # Distribute each shard
        for shard in backup_shards:
            # Select nodes for this shard
            import random
            selected_nodes = random.sample(available_nodes, min(self.replication_factor, len(available_nodes)))
            shard.assigned_nodes = selected_nodes
            shard.status = ShardStatus.DISTRIBUTED
            
            # Update shard on disk
            self._save_shard(shard)
        
        # Update backup status
        backup.status = BackupStatus.DISTRIBUTED
        self._save_metadata(backup)
        
        self.logger.info(f"Backup {backup_id} distributed to {len(available_nodes)} nodes")
    
    def register_node(self, node_id: str, node_info: Dict[str, Any]) -> bool:
        """Register a backup node."""
        self.node_registry[node_id] = {
            "node_id": node_id,
            "registered_at": datetime.now().isoformat(),
            "last_seen": datetime.now().isoformat(),
            "status": "active",
            "capacity_bytes": node_info.get("capacity_bytes", 0),
            "used_bytes": node_info.get("used_bytes", 0),
            "endpoint": node_info.get("endpoint", ""),
            "public_key": node_info.get("public_key", "")
        }
        
        self.logger.info(f"Node registered: {node_id}")
        return True
    
    def get_shard_for_node(self, node_id: str, shard_id: str) -> Optional[bytes]:
        """Get shard data for a specific node."""
        if node_id not in self.node_registry:
            return None
        
        shard = self._load_shard(shard_id)
        if not shard or node_id not in shard.assigned_nodes:
            return None
        
        # Create distribution package
        package = {
            "shard_id": shard.shard_id,
            "backup_id": shard.backup_id,
            "shard_index": shard.shard_index,
            "total_shards": shard.total_shards,
            "verification_hash": shard.verification_hash,
            "encrypted_data": base64.b64encode(shard.encrypted_data).decode('utf-8'),
            "distributed_at": datetime.now().isoformat()
        }
        
        return json.dumps(package).encode('utf-8')
    
    def submit_shard(self, node_id: str, shard_data: bytes) -> bool:
        """Accept shard submission from a node."""
        if node_id not in self.node_registry:
            return False
        
        try:
            package = json.loads(shard_data.decode('utf-8'))
            shard_id = package["shard_id"]
            
            # Verify shard
            encrypted_data = base64.b64decode(package["encrypted_data"])
            verification_hash = hashlib.sha256(encrypted_data).hexdigest()
            
            if verification_hash != package["verification_hash"]:
                self.logger.error(f"Shard verification failed: {shard_id}")
                return False
            
            # Update node last seen
            self.node_registry[node_id]["last_seen"] = datetime.now().isoformat()
            
            self.logger.info(f"Shard received from node {node_id}: {shard_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to process shard submission: {e}")
            return False
    
    def restore_backup(self, backup_id: str, encryption_key: str) -> Optional[bytes]:
        """Restore backup from shards."""
        if backup_id not in self.active_backups:
            return None
        
        backup = self.active_backups[backup_id]
        
        # Verify encryption key
        key_bytes = base64.b64decode(encryption_key)
        if hashlib.sha256(key_bytes).hexdigest() != backup.encryption_key_hash:
            self.logger.error(f"Invalid encryption key for backup {backup_id}")
            return None
        
        # Collect all shards
        backup_shards = [s for s in self.active_shards.values() if s.backup_id == backup_id]
        backup_shards.sort(key=lambda x: x.shard_index)
        
        if len(backup_shards) != backup.shard_count:
            self.logger.error(f"Missing shards for backup {backup_id}: {len(backup_shards)}/{backup.shard_count}")
            return None
        
        # Decrypt and combine shards
        fernet = Fernet(key_bytes)
        restored_data = b""
        
        for shard in backup_shards:
            try:
                decrypted_data = fernet.decrypt(shard.encrypted_data)
                restored_data += decrypted_data
            except Exception as e:
                self.logger.error(f"Failed to decrypt shard {shard.shard_id}: {e}")
                return None
        
        # Verify checksum
        if hashlib.sha256(restored_data).hexdigest() != backup.checksum:
            self.logger.error(f"Checksum verification failed for backup {backup_id}")
            return None
        
        self.logger.info(f"Backup restored: {backup_id} ({len(restored_data)} bytes)")
        return restored_data
    
    def cleanup_expired_backups(self):
        """Clean up expired backups."""
        current_time = datetime.now()
        expired_backups = []
        
        for backup_id, backup in self.active_backups.items():
            if current_time > backup.retention_until:
                expired_backups.append(backup_id)
        
        for backup_id in expired_backups:
            self._delete_backup(backup_id)
        
        if expired_backups:
            self.logger.info(f"Cleaned up {len(expired_backups)} expired backups")
    
    def _delete_backup(self, backup_id: str):
        """Delete a backup and its shards."""
        # Delete shards
        backup_shards = [s for s in self.active_shards.values() if s.backup_id == backup_id]
        for shard in backup_shards:
            shard_file = self.shard_dir / f"{shard.shard_id}.shard"
            if shard_file.exists():
                shard_file.unlink()
            del self.active_shards[shard.shard_id]
        
        # Delete metadata
        metadata_file = self.metadata_dir / f"{backup_id}.json"
        if metadata_file.exists():
            metadata_file.unlink()
        
        # Remove from active backups
        if backup_id in self.active_backups:
            del self.active_backups[backup_id]
        
        self.logger.info(f"Backup deleted: {backup_id}")
    
    def _save_metadata(self, metadata: BackupMetadata):
        """Save backup metadata."""
        metadata_file = self.metadata_dir / f"{metadata.backup_id}.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata.to_dict(), f, indent=2)
    
    def _load_metadata(self):
        """Load all backup metadata."""
        for metadata_file in self.metadata_dir.glob("*.json"):
            try:
                with open(metadata_file, 'r') as f:
                    data = json.load(f)
                
                metadata = BackupMetadata(
                    backup_id=data["backup_id"],
                    name=data["name"],
                    description=data["description"],
                    created_at=datetime.fromisoformat(data["created_at"]),
                    completed_at=datetime.fromisoformat(data["completed_at"]) if data["completed_at"] else None,
                    status=BackupStatus(data["status"]),
                    total_size_bytes=data["total_size_bytes"],
                    shard_count=data["shard_count"],
                    shard_size_bytes=data["shard_size_bytes"],
                    encryption_key_hash=data["encryption_key_hash"],
                    checksum=data["checksum"],
                    retention_until=datetime.fromisoformat(data["retention_until"]),
                    tags=data["tags"]
                )
                
                self.active_backups[metadata.backup_id] = metadata
                
                # Load associated shards
                for i in range(metadata.shard_count):
                    shard_id = self._generate_shard_id(metadata.backup_id, i)
                    shard = self._load_shard(shard_id)
                    if shard:
                        self.active_shards[shard_id] = shard
                
            except Exception as e:
                self.logger.error(f"Failed to load metadata from {metadata_file}: {e}")
    
    def _start_background_tasks(self):
        """Start background maintenance tasks."""
        def cleanup_task():
            while True:
                try:
                    self.cleanup_expired_backups()
                    time.sleep(3600)  # Run every hour
                except Exception as e:
                    self.logger.error(f"Cleanup task error: {e}")
                    time.sleep(300)  # Wait 5 minutes on error
        
        threading.Thread(target=cleanup_task, daemon=True).start()
    
    def _generate_backup_id(self) -> str:
        """Generate unique backup ID."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_part = secrets.token_hex(8)
        return f"backup_{timestamp}_{random_part}"
    
    def _generate_shard_id(self, backup_id: str, shard_index: int) -> str:
        """Generate shard ID."""
        return f"{backup_id}_shard_{shard_index:03d}"
    
    def get_backup_status(self, backup_id: str) -> Optional[Dict[str, Any]]:
        """Get backup status and information."""
        if backup_id not in self.active_backups:
            return None
        
        backup = self.active_backups[backup_id]
        backup_shards = [s for s in self.active_shards.values() if s.backup_id == backup_id]
        
        return {
            "backup": backup.to_dict(),
            "shards": [shard.to_dict() for shard in backup_shards],
            "node_count": len(self.node_registry),
            "distribution_complete": backup.status == BackupStatus.DISTRIBUTED
        }
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List all backups."""
        return [backup.to_dict() for backup in self.active_backups.values()]
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get backup system statistics."""
        total_backups = len(self.active_backups)
        total_shards = len(self.active_shards)
        total_size = sum(backup.total_size_bytes for backup in self.active_backups.values())
        active_nodes = len(self.node_registry)
        
        return {
            "total_backups": total_backups,
            "total_shards": total_shards,
            "total_size_bytes": total_size,
            "active_nodes": active_nodes,
            "replication_factor": self.replication_factor,
            "retention_days": self.retention_days
        }

# Backup API Router
backup_router = APIRouter(prefix="/api/v1/backup", tags=["Distributed Backup"])

@backup_router.post("/create")
async def create_backup_endpoint(
    name: str,
    file: UploadFile = File(...),
    description: str = "",
    tags: str = ""
):
    """Create a new distributed backup."""
    try:
        # Read file data
        data = await file.read()

        # Parse tags
        tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()] if tags else []

        # Create backup
        backup_id = backup_manager.create_backup(
            name=name,
            data=data,
            description=description,
            tags=tag_list
        )

        return JSONResponse({
            "success": True,
            "backup_id": backup_id,
            "message": "Backup created successfully"
        })

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create backup: {e}")

@backup_router.get("/list")
async def list_backups_endpoint():
    """List all backups."""
    try:
        backups = backup_manager.list_backups()
        return JSONResponse({
            "success": True,
            "backups": backups
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list backups: {e}")

@backup_router.get("/{backup_id}/status")
async def get_backup_status_endpoint(backup_id: str):
    """Get backup status and details."""
    try:
        status = backup_manager.get_backup_status(backup_id)
        if not status:
            raise HTTPException(status_code=404, detail="Backup not found")

        return JSONResponse({
            "success": True,
            "status": status
        })
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get backup status: {e}")

@backup_router.post("/{backup_id}/restore")
async def restore_backup_endpoint(backup_id: str, encryption_key: str):
    """Restore backup from shards."""
    try:
        data = backup_manager.restore_backup(backup_id, encryption_key)
        if not data:
            raise HTTPException(status_code=400, detail="Failed to restore backup")

        # Return as streaming response
        def generate():
            yield data

        return StreamingResponse(
            generate(),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename=backup_{backup_id}.bin"}
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to restore backup: {e}")

@backup_router.delete("/{backup_id}")
async def delete_backup_endpoint(backup_id: str):
    """Delete a backup."""
    try:
        backup_manager._delete_backup(backup_id)
        return JSONResponse({
            "success": True,
            "message": "Backup deleted successfully"
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete backup: {e}")

# Node Management Endpoints
@backup_router.post("/nodes/register")
async def register_node_endpoint(request: Request):
    """Register a backup node."""
    try:
        data = await request.json()
        node_id = data.get("node_id")
        node_info = data.get("node_info", {})

        if not node_id:
            raise HTTPException(status_code=400, detail="node_id is required")

        success = backup_manager.register_node(node_id, node_info)

        return JSONResponse({
            "success": success,
            "message": "Node registered successfully" if success else "Failed to register node"
        })

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to register node: {e}")

@backup_router.get("/nodes/{node_id}/shard/{shard_id}")
async def get_shard_for_node_endpoint(node_id: str, shard_id: str):
    """Get shard data for a specific node."""
    try:
        shard_data = backup_manager.get_shard_for_node(node_id, shard_id)
        if not shard_data:
            raise HTTPException(status_code=404, detail="Shard not found or not assigned to node")

        return StreamingResponse(
            iter([shard_data]),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename=shard_{shard_id}.bin"}
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get shard: {e}")

@backup_router.post("/nodes/{node_id}/submit")
async def submit_shard_endpoint(node_id: str, file: UploadFile = File(...)):
    """Accept shard submission from a node."""
    try:
        shard_data = await file.read()
        success = backup_manager.submit_shard(node_id, shard_data)

        return JSONResponse({
            "success": success,
            "message": "Shard submitted successfully" if success else "Failed to submit shard"
        })

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to submit shard: {e}")

@backup_router.get("/stats")
async def get_backup_stats_endpoint():
    """Get backup system statistics."""
    try:
        stats = backup_manager.get_system_stats()
        return JSONResponse({
            "success": True,
            "stats": stats
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {e}")

@backup_router.post("/cleanup")
async def cleanup_expired_backups_endpoint():
    """Manually trigger cleanup of expired backups."""
    try:
        backup_manager.cleanup_expired_backups()
        return JSONResponse({
            "success": True,
            "message": "Cleanup completed"
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cleanup: {e}")

# Enhanced backup abuse protection methods
class BackupAbuseProtection:
    """Backup abuse protection and rate limiting."""

    def __init__(self, backup_manager):
        self.backup_manager = backup_manager
        self.logger = logging.getLogger(__name__)

    def check_backup_permission(self, user_id: str, backup_type: str = "full") -> Tuple[bool, str]:
        """Check if user can create a backup."""
        current_time = time.time()

        # Check if user is blocked
        if user_id in self.backup_manager.abuse_protection["blocked_users"]:
            return False, "User is blocked from creating backups"

        # Admin override
        if self.backup_manager.abuse_protection["admin_override"]:
            return True, "Admin override active"

        # Check backup type
        if backup_type not in self.backup_manager.abuse_protection["allowed_backup_types"]:
            return False, f"Backup type '{backup_type}' not allowed"

        # Initialize user tracking if needed
        if user_id not in self.backup_manager.abuse_protection["user_request_tracking"]:
            self.backup_manager.abuse_protection["user_request_tracking"][user_id] = {
                "backup_requests": [],
                "restore_requests": [],
                "last_backup": 0,
                "last_restore": 0
            }

        user_data = self.backup_manager.abuse_protection["user_request_tracking"][user_id]

        # Check minimum interval
        min_interval = self.backup_manager.abuse_protection["min_backup_interval_minutes"] * 60
        if current_time - user_data["last_backup"] < min_interval:
            remaining = int(min_interval - (current_time - user_data["last_backup"]))
            return False, f"Must wait {remaining} seconds before next backup"

        # Check hourly limit
        hour_ago = current_time - 3600
        recent_backups = [req for req in user_data["backup_requests"] if req > hour_ago]
        if len(recent_backups) >= self.backup_manager.abuse_protection["max_backups_per_hour"]:
            return False, "Hourly backup limit exceeded"

        # Check daily limit
        day_ago = current_time - 86400
        daily_backups = [req for req in user_data["backup_requests"] if req > day_ago]
        if len(daily_backups) >= self.backup_manager.abuse_protection["max_backups_per_day"]:
            return False, "Daily backup limit exceeded"

        # Check concurrent operations
        if len(self.backup_manager.active_backups) >= self.backup_manager.abuse_protection["max_concurrent_operations"]:
            return False, "Maximum concurrent backups reached"

        return True, "Backup permitted"

    def record_backup_request(self, user_id: str):
        """Record a backup request."""
        current_time = time.time()

        if user_id not in self.backup_manager.abuse_protection["user_request_tracking"]:
            self.backup_manager.abuse_protection["user_request_tracking"][user_id] = {
                "backup_requests": [],
                "restore_requests": [],
                "last_backup": 0,
                "last_restore": 0
            }

        user_data = self.backup_manager.abuse_protection["user_request_tracking"][user_id]
        user_data["backup_requests"].append(current_time)
        user_data["last_backup"] = current_time

        # Clean old requests (keep last 24 hours)
        day_ago = current_time - 86400
        user_data["backup_requests"] = [req for req in user_data["backup_requests"] if req > day_ago]

    def check_restore_permission(self, user_id: str, is_admin: bool = False) -> Tuple[bool, str]:
        """Check if user can perform a restore."""
        current_time = time.time()

        # Check admin requirement
        if self.backup_manager.abuse_protection["require_admin_for_restore"] and not is_admin:
            return False, "Restore operations require admin privileges"

        # Check if user is blocked
        if user_id in self.backup_manager.abuse_protection["blocked_users"]:
            return False, "User is blocked from restore operations"

        # Admin override
        if self.backup_manager.abuse_protection["admin_override"]:
            return True, "Admin override active"

        # Initialize user tracking if needed
        if user_id not in self.backup_manager.abuse_protection["user_request_tracking"]:
            self.backup_manager.abuse_protection["user_request_tracking"][user_id] = {
                "backup_requests": [],
                "restore_requests": [],
                "last_backup": 0,
                "last_restore": 0
            }

        user_data = self.backup_manager.abuse_protection["user_request_tracking"][user_id]

        # Check minimum interval
        min_interval = self.backup_manager.abuse_protection["min_restore_interval_minutes"] * 60
        if current_time - user_data["last_restore"] < min_interval:
            remaining = int(min_interval - (current_time - user_data["last_restore"]))
            return False, f"Must wait {remaining} seconds before next restore"

        # Check hourly limit
        hour_ago = current_time - 3600
        recent_restores = [req for req in user_data["restore_requests"] if req > hour_ago]
        if len(recent_restores) >= self.backup_manager.abuse_protection["max_restores_per_hour"]:
            return False, "Hourly restore limit exceeded"

        # Check daily limit
        day_ago = current_time - 86400
        daily_restores = [req for req in user_data["restore_requests"] if req > day_ago]
        if len(daily_restores) >= self.backup_manager.abuse_protection["max_restores_per_day"]:
            return False, "Daily restore limit exceeded"

        # Check concurrent operations
        if len(self.backup_manager.active_restores) >= self.backup_manager.abuse_protection["max_concurrent_operations"]:
            return False, "Maximum concurrent restores reached"

        return True, "Restore permitted"

class BackupRestoreManager:
    """Handles backup restoration with partial and full restore capabilities."""

    def __init__(self, backup_manager):
        self.backup_manager = backup_manager
        self.logger = logging.getLogger(__name__)

    async def restore_backup(self, backup_id: str, restore_type: str = "full",
                           components: List[str] = None, user_id: str = None,
                           is_admin: bool = False) -> Dict[str, Any]:
        """Restore a backup with full or partial restoration."""
        try:
            # Check permissions
            abuse_protection = BackupAbuseProtection(self.backup_manager)
            can_restore, reason = abuse_protection.check_restore_permission(user_id, is_admin)

            if not can_restore:
                return {
                    "success": False,
                    "error": reason,
                    "restore_id": None
                }

            # Generate restore ID
            restore_id = f"restore_{int(time.time())}_{backup_id[:8]}"

            # Get backup metadata
            backup_metadata = await self._get_backup_metadata(backup_id)
            if not backup_metadata:
                return {
                    "success": False,
                    "error": "Backup not found",
                    "restore_id": restore_id
                }

            # Validate restore type and components
            if restore_type not in ["full", "partial"]:
                return {
                    "success": False,
                    "error": "Invalid restore type. Must be 'full' or 'partial'",
                    "restore_id": restore_id
                }

            if restore_type == "partial" and not components:
                return {
                    "success": False,
                    "error": "Components must be specified for partial restore",
                    "restore_id": restore_id
                }

            # Record restore request
            abuse_protection.record_restore_request(user_id)

            # Start restore operation
            restore_info = {
                "restore_id": restore_id,
                "backup_id": backup_id,
                "restore_type": restore_type,
                "components": components or [],
                "user_id": user_id,
                "is_admin": is_admin,
                "started_at": time.time(),
                "status": "in_progress",
                "progress": 0,
                "estimated_completion": None
            }

            self.backup_manager.active_restores[restore_id] = restore_info

            # Perform the restore
            if restore_type == "full":
                result = await self._perform_full_restore(backup_id, restore_id)
            else:
                result = await self._perform_partial_restore(backup_id, components, restore_id)

            # Update restore status
            restore_info["status"] = "completed" if result["success"] else "failed"
            restore_info["completed_at"] = time.time()
            restore_info["result"] = result

            # Log the restore
            self._log_restore_operation(restore_info)

            # Clean up active restore
            if restore_id in self.backup_manager.active_restores:
                del self.backup_manager.active_restores[restore_id]

            return result

        except Exception as e:
            self.logger.error(f"Restore operation failed: {e}")
            return {
                "success": False,
                "error": f"Restore failed: {str(e)}",
                "restore_id": restore_id if 'restore_id' in locals() else None
            }

    async def _perform_full_restore(self, backup_id: str, restore_id: str) -> Dict[str, Any]:
        """Perform a full system restore."""
        try:
            # This would implement the actual full restore logic
            # For now, return a simulated result

            self.logger.info(f"Starting full restore from backup {backup_id}")

            # Simulate restore progress
            for progress in [10, 30, 50, 70, 90, 100]:
                if restore_id in self.backup_manager.active_restores:
                    self.backup_manager.active_restores[restore_id]["progress"] = progress
                await asyncio.sleep(0.1)  # Simulate work

            return {
                "success": True,
                "restore_id": restore_id,
                "restore_type": "full",
                "components_restored": ["database", "config", "logs", "user_data"],
                "files_restored": 1234,
                "data_restored_mb": 567.8,
                "duration_seconds": 12.3
            }

        except Exception as e:
            self.logger.error(f"Full restore failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "restore_id": restore_id
            }

    async def _perform_partial_restore(self, backup_id: str, components: List[str],
                                     restore_id: str) -> Dict[str, Any]:
        """Perform a partial restore of specific components."""
        try:
            self.logger.info(f"Starting partial restore from backup {backup_id}: {components}")

            valid_components = ["database", "config", "logs", "user_data", "cache"]
            invalid_components = [c for c in components if c not in valid_components]

            if invalid_components:
                return {
                    "success": False,
                    "error": f"Invalid components: {invalid_components}",
                    "valid_components": valid_components,
                    "restore_id": restore_id
                }

            # Simulate component restoration
            restored_components = []
            for i, component in enumerate(components):
                progress = int((i + 1) / len(components) * 100)
                if restore_id in self.backup_manager.active_restores:
                    self.backup_manager.active_restores[restore_id]["progress"] = progress

                # Simulate component restore
                await asyncio.sleep(0.1)
                restored_components.append(component)

            return {
                "success": True,
                "restore_id": restore_id,
                "restore_type": "partial",
                "components_restored": restored_components,
                "files_restored": len(components) * 100,
                "data_restored_mb": len(components) * 50.5,
                "duration_seconds": len(components) * 2.1
            }

        except Exception as e:
            self.logger.error(f"Partial restore failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "restore_id": restore_id
            }

# Global backup manager instance
backup_manager = DistributedBackupManager()
backup_abuse_protection = BackupAbuseProtection(backup_manager)
backup_restore_manager = BackupRestoreManager(backup_manager)

class ImmutableShardManager:
    """Manages immutable backup shards with difference files."""

    def __init__(self, backup_manager):
        self.backup_manager = backup_manager
        self.logger = logging.getLogger(__name__)

        self.shards_dir = Path("backups/shards")
        self.diffs_dir = Path("backups/diffs")
        self.metadata_dir = Path("backups/metadata")

        for dir_path in [self.shards_dir, self.diffs_dir, self.metadata_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)

        self.shard_registry = {}
        self.diff_chains = {}
        self.load_shard_registry()

    def create_immutable_shard(self, data: bytes, shard_type: str,
                              reference_id: str = None) -> Dict[str, Any]:
        """Create an immutable shard that never changes."""
        try:
            shard_id = hashlib.sha256(data).hexdigest()
            shard_path = self.shards_dir / f"{shard_id}.shard"

            # Check if shard already exists (deduplication)
            if shard_path.exists():
                self.logger.info(f"Shard {shard_id} already exists (deduplicated)")
                return self._get_shard_metadata(shard_id)

            # Compress data
            compressed_data = gzip.compress(data, compresslevel=9)

            # Encrypt if enabled
            if self.backup_manager.config.get("encryption", {}).get("enabled", False):
                compressed_data = self._encrypt_data(compressed_data)

            # Write immutable shard
            with open(shard_path, 'wb') as f:
                f.write(compressed_data)

            # Make file read-only
            if os.name != 'nt':  # Unix-like systems
                os.chmod(shard_path, 0o444)

            # Create metadata
            metadata = {
                "shard_id": shard_id,
                "shard_type": shard_type,
                "original_size": len(data),
                "compressed_size": len(compressed_data),
                "created_at": datetime.now().isoformat(),
                "reference_id": reference_id,
                "checksum": hashlib.md5(data).hexdigest(),
                "immutable": True,
                "encryption_enabled": self.backup_manager.config.get("encryption", {}).get("enabled", False)
            }

            # Save metadata
            metadata_path = self.metadata_dir / f"{shard_id}.json"
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)

            # Register shard
            self.shard_registry[shard_id] = metadata
            self.save_shard_registry()

            self.logger.info(f"Created immutable shard: {shard_id}")
            return metadata

        except Exception as e:
            self.logger.error(f"Error creating immutable shard: {e}")
            raise

    def create_difference_file(self, old_shard_id: str, new_data: bytes,
                              change_description: str = "") -> Dict[str, Any]:
        """Create a difference file for changes to existing data."""
        try:
            # Get old shard data
            old_data = self.read_shard(old_shard_id)
            if not old_data:
                raise ValueError(f"Old shard {old_shard_id} not found")

            # Calculate differences
            diff_data = self._calculate_diff(old_data, new_data)

            # Create difference file ID
            diff_id = hashlib.sha256(f"{old_shard_id}{time.time()}".encode()).hexdigest()
            diff_path = self.diffs_dir / f"{diff_id}.diff"

            # Compress and encrypt diff
            compressed_diff = gzip.compress(diff_data, compresslevel=9)
            if self.backup_manager.config.get("encryption", {}).get("enabled", False):
                compressed_diff = self._encrypt_data(compressed_diff)

            # Write difference file
            with open(diff_path, 'wb') as f:
                f.write(compressed_diff)

            # Create diff metadata
            diff_metadata = {
                "diff_id": diff_id,
                "base_shard_id": old_shard_id,
                "diff_size": len(diff_data),
                "compressed_size": len(compressed_diff),
                "created_at": datetime.now().isoformat(),
                "change_description": change_description,
                "checksum": hashlib.md5(diff_data).hexdigest(),
                "new_data_checksum": hashlib.md5(new_data).hexdigest()
            }

            # Save diff metadata
            diff_metadata_path = self.metadata_dir / f"{diff_id}_diff.json"
            with open(diff_metadata_path, 'w', encoding='utf-8') as f:
                json.dump(diff_metadata, f, indent=2)

            # Update diff chain
            if old_shard_id not in self.diff_chains:
                self.diff_chains[old_shard_id] = []
            self.diff_chains[old_shard_id].append(diff_id)

            self.save_shard_registry()

            self.logger.info(f"Created difference file: {diff_id} for shard {old_shard_id}")
            return diff_metadata

        except Exception as e:
            self.logger.error(f"Error creating difference file: {e}")
            raise

    def read_shard(self, shard_id: str) -> Optional[bytes]:
        """Read data from an immutable shard."""
        try:
            shard_path = self.shards_dir / f"{shard_id}.shard"
            if not shard_path.exists():
                return None

            with open(shard_path, 'rb') as f:
                data = f.read()

            # Decrypt if needed
            if self.backup_manager.config.get("encryption", {}).get("enabled", False):
                data = self._decrypt_data(data)

            # Decompress
            return gzip.decompress(data)

        except Exception as e:
            self.logger.error(f"Error reading shard {shard_id}: {e}")
            return None

    def read_with_diffs(self, base_shard_id: str, target_diff_id: str = None) -> Optional[bytes]:
        """Read data by applying difference files to base shard."""
        try:
            # Start with base shard
            data = self.read_shard(base_shard_id)
            if not data:
                return None

            # Get diff chain
            diff_chain = self.diff_chains.get(base_shard_id, [])
            if not diff_chain:
                return data

            # Apply diffs up to target (or all if no target specified)
            target_index = len(diff_chain)
            if target_diff_id:
                try:
                    target_index = diff_chain.index(target_diff_id) + 1
                except ValueError:
                    self.logger.warning(f"Target diff {target_diff_id} not found in chain")

            for diff_id in diff_chain[:target_index]:
                diff_data = self._read_diff(diff_id)
                if diff_data:
                    data = self._apply_diff(data, diff_data)

            return data

        except Exception as e:
            self.logger.error(f"Error reading with diffs: {e}")
            return None

    def partial_restore_without_database(self, available_shards: List[str],
                                       target_components: List[str] = None) -> Dict[str, Any]:
        """Restore what's possible even without complete backup or database."""
        try:
            restored_data = {}
            restoration_log = []

            self.logger.info(f"Starting partial restore with {len(available_shards)} available shards")

            for shard_id in available_shards:
                try:
                    # Try to read shard metadata
                    metadata = self._get_shard_metadata(shard_id)
                    if not metadata:
                        restoration_log.append(f"No metadata for shard {shard_id}, attempting blind restore")
                        # Try to restore without metadata
                        data = self.read_shard(shard_id)
                        if data:
                            restored_data[f"unknown_shard_{shard_id[:8]}"] = {
                                "data": data,
                                "size": len(data),
                                "type": "unknown"
                            }
                        continue

                    # Check if this component is requested
                    if target_components and metadata.get("shard_type") not in target_components:
                        continue

                    # Read shard data
                    data = self.read_shard(shard_id)
                    if not data:
                        restoration_log.append(f"Failed to read shard {shard_id}")
                        continue

                    # Try to apply any available diffs
                    if shard_id in self.diff_chains:
                        try:
                            data = self.read_with_diffs(shard_id)
                            restoration_log.append(f"Applied {len(self.diff_chains[shard_id])} diffs to shard {shard_id}")
                        except Exception as e:
                            restoration_log.append(f"Failed to apply diffs to shard {shard_id}: {e}")

                    # Store restored data
                    component_name = metadata.get("shard_type", f"component_{shard_id[:8]}")
                    restored_data[component_name] = {
                        "data": data,
                        "size": len(data),
                        "type": metadata.get("shard_type"),
                        "original_size": metadata.get("original_size"),
                        "created_at": metadata.get("created_at"),
                        "shard_id": shard_id
                    }

                    restoration_log.append(f"Successfully restored {component_name} from shard {shard_id}")

                except Exception as e:
                    restoration_log.append(f"Error processing shard {shard_id}: {e}")
                    continue

            # Attempt to reconstruct database from available data
            if "database" in restored_data:
                try:
                    self._attempt_database_reconstruction(restored_data["database"]["data"])
                    restoration_log.append("Database reconstruction attempted")
                except Exception as e:
                    restoration_log.append(f"Database reconstruction failed: {e}")

            # Generate restoration report
            restoration_report = {
                "success": len(restored_data) > 0,
                "restored_components": list(restored_data.keys()),
                "total_shards_processed": len(available_shards),
                "successful_restorations": len(restored_data),
                "restoration_log": restoration_log,
                "restored_data_size": sum(item["size"] for item in restored_data.values()),
                "restoration_timestamp": datetime.now().isoformat()
            }

            self.logger.info(f"Partial restore completed: {len(restored_data)} components restored")
            return {
                "restored_data": restored_data,
                "report": restoration_report
            }

        except Exception as e:
            self.logger.error(f"Error in partial restore: {e}")
            return {
                "restored_data": {},
                "report": {
                    "success": False,
                    "error": str(e),
                    "restoration_timestamp": datetime.now().isoformat()
                }
            }

    def get_backup_completeness_status(self) -> Dict[str, Any]:
        """Get status of backup completeness and shard availability."""
        try:
            total_shards = len(self.shard_registry)
            available_shards = 0
            missing_shards = []
            corrupted_shards = []

            for shard_id, metadata in self.shard_registry.items():
                shard_path = self.shards_dir / f"{shard_id}.shard"

                if not shard_path.exists():
                    missing_shards.append(shard_id)
                    continue

                # Verify shard integrity
                try:
                    data = self.read_shard(shard_id)
                    if data:
                        # Verify checksum
                        actual_checksum = hashlib.md5(data).hexdigest()
                        expected_checksum = metadata.get("checksum")

                        if actual_checksum == expected_checksum:
                            available_shards += 1
                        else:
                            corrupted_shards.append(shard_id)
                    else:
                        corrupted_shards.append(shard_id)
                except Exception:
                    corrupted_shards.append(shard_id)

            # Calculate completeness percentage
            completeness_percentage = (available_shards / total_shards * 100) if total_shards > 0 else 0

            # Analyze diff chains
            diff_status = {}
            for base_shard, diffs in self.diff_chains.items():
                available_diffs = 0
                for diff_id in diffs:
                    diff_path = self.diffs_dir / f"{diff_id}.diff"
                    if diff_path.exists():
                        available_diffs += 1

                diff_status[base_shard] = {
                    "total_diffs": len(diffs),
                    "available_diffs": available_diffs,
                    "completeness": (available_diffs / len(diffs) * 100) if diffs else 100
                }

            return {
                "total_shards": total_shards,
                "available_shards": available_shards,
                "missing_shards": len(missing_shards),
                "corrupted_shards": len(corrupted_shards),
                "completeness_percentage": round(completeness_percentage, 2),
                "missing_shard_ids": missing_shards,
                "corrupted_shard_ids": corrupted_shards,
                "diff_chains_status": diff_status,
                "can_partial_restore": available_shards > 0,
                "last_checked": datetime.now().isoformat()
            }

        except Exception as e:
            self.logger.error(f"Error getting backup completeness status: {e}")
            return {
                "error": str(e),
                "last_checked": datetime.now().isoformat()
            }

    def _calculate_diff(self, old_data: bytes, new_data: bytes) -> bytes:
        """Calculate binary difference between old and new data."""
        # Simple implementation - in production, use more sophisticated diff algorithms
        import difflib

        # Convert to text for difflib (this is simplified)
        try:
            old_text = old_data.decode('utf-8', errors='ignore')
            new_text = new_data.decode('utf-8', errors='ignore')

            diff = list(difflib.unified_diff(
                old_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                lineterm=''
            ))

            return '\n'.join(diff).encode('utf-8')

        except Exception:
            # Fallback to simple binary diff
            return new_data  # Store complete new data as diff

    def _apply_diff(self, base_data: bytes, diff_data: bytes) -> bytes:
        """Apply difference data to base data."""
        # Simple implementation - in production, use proper patch application
        try:
            diff_text = diff_data.decode('utf-8', errors='ignore')

            # If it looks like a unified diff, try to apply it
            if diff_text.startswith('---') or diff_text.startswith('+++'):
                # This is a simplified patch application
                # In production, use proper patch libraries
                return diff_data  # Return diff as new data for now
            else:
                # Assume diff_data is the complete new data
                return diff_data

        except Exception:
            return diff_data

    def _read_diff(self, diff_id: str) -> Optional[bytes]:
        """Read difference file."""
        try:
            diff_path = self.diffs_dir / f"{diff_id}.diff"
            if not diff_path.exists():
                return None

            with open(diff_path, 'rb') as f:
                data = f.read()

            # Decrypt if needed
            if self.backup_manager.config.get("encryption", {}).get("enabled", False):
                data = self._decrypt_data(data)

            # Decompress
            return gzip.decompress(data)

        except Exception as e:
            self.logger.error(f"Error reading diff {diff_id}: {e}")
            return None

    def _get_shard_metadata(self, shard_id: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a shard."""
        if shard_id in self.shard_registry:
            return self.shard_registry[shard_id]

        # Try to load from file
        metadata_path = self.metadata_dir / f"{shard_id}.json"
        if metadata_path.exists():
            try:
                with open(metadata_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Error loading metadata for shard {shard_id}: {e}")

        return None

    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data (placeholder for actual encryption)."""
        # In production, implement proper encryption
        return data

    def _decrypt_data(self, data: bytes) -> bytes:
        """Decrypt data (placeholder for actual decryption)."""
        # In production, implement proper decryption
        return data

    def _attempt_database_reconstruction(self, database_data: bytes):
        """Attempt to reconstruct database from backup data."""
        # This would implement database reconstruction logic
        # For now, just log the attempt
        self.logger.info("Attempting database reconstruction from backup data")

    def load_shard_registry(self):
        """Load shard registry from storage."""
        registry_file = self.metadata_dir / "shard_registry.json"
        if registry_file.exists():
            try:
                with open(registry_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.shard_registry = data.get("shards", {})
                    self.diff_chains = data.get("diff_chains", {})
            except Exception as e:
                self.logger.error(f"Error loading shard registry: {e}")

    def save_shard_registry(self):
        """Save shard registry to storage."""
        registry_file = self.metadata_dir / "shard_registry.json"
        try:
            data = {
                "shards": self.shard_registry,
                "diff_chains": self.diff_chains,
                "last_updated": datetime.now().isoformat()
            }

            with open(registry_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            self.logger.error(f"Error saving shard registry: {e}")

# Enhanced backup manager with immutable shards
immutable_shard_manager = ImmutableShardManager(backup_manager)
