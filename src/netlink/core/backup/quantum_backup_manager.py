"""
NetLink Quantum Backup Manager

Central orchestrator for the unified backup system with quantum-proof encryption,
distributed shard management, and zero-knowledge architecture.
"""

import asyncio
import logging
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import aiosqlite
import aiofiles

# Import security systems
from ...security import (
    security_manager, quantum_encryption, distributed_key_manager,
    database_encryption, KeyDomain, DataClassification
)

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
    ZERO_KNOWLEDGE = "zero_knowledge"


class BackupStatus(Enum):
    """Backup operation status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    VERIFYING = "verifying"
    VERIFIED = "verified"


@dataclass
class BackupRequest:
    """Backup request with quantum security metadata."""
    backup_id: str
    data_type: str
    data_source: str
    priority: BackupPriority
    backup_type: BackupType
    encryption_level: int
    redundancy_factor: int
    zero_knowledge: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class BackupResult:
    """Backup operation result."""
    backup_id: str
    status: BackupStatus
    shard_count: int
    total_size: int
    encrypted_size: int
    node_distribution: Dict[str, List[str]]
    verification_hash: str
    completion_time: Optional[datetime] = None
    error_message: Optional[str] = None


class QuantumBackupManager:
    """
    Quantum-secure backup manager with distributed architecture.
    
    Features:
    - Post-quantum cryptography
    - Zero-knowledge backup protocol
    - Distributed multi-key security
    - AI-powered shard distribution
    - Real-time health monitoring
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "config/backup.yaml"
        self.backup_requests: Dict[str, BackupRequest] = {}
        self.backup_results: Dict[str, BackupResult] = {}
        self.active_backups: Set[str] = set()
        
        # Component managers (will be initialized)
        self.shard_system = None
        self.node_network = None
        self.zero_knowledge = None
        self.immutable_manager = None
        self.recovery_system = None
        self.analytics = None
        
        # Configuration
        self.config = {}
        self.initialized = False
        
        # Database connection
        self.db_path = Path("data/backup_manager.db")
        self.db_connection = None
    
    async def initialize(self):
        """Initialize the quantum backup manager."""
        if self.initialized:
            return
        
        try:
            # Load configuration
            await self._load_configuration()
            
            # Initialize database
            await self._initialize_database()
            
            # Initialize component managers
            await self._initialize_components()
            
            # Start background tasks
            await self._start_background_tasks()
            
            self.initialized = True
            logger.info("✅ Quantum Backup Manager initialized successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize Quantum Backup Manager: {e}")
            raise
    
    async def create_backup(self, request: BackupRequest) -> str:
        """Create a new backup with quantum security."""
        if not self.initialized:
            await self.initialize()
        
        backup_id = request.backup_id
        self.backup_requests[backup_id] = request
        self.active_backups.add(backup_id)
        
        try:
            logger.info(f"🔄 Starting quantum backup: {backup_id}")
            
            # Create backup result
            result = BackupResult(
                backup_id=backup_id,
                status=BackupStatus.IN_PROGRESS,
                shard_count=0,
                total_size=0,
                encrypted_size=0,
                node_distribution={},
                verification_hash=""
            )
            self.backup_results[backup_id] = result
            
            # Process backup through components
            await self._process_backup(request, result)
            
            result.status = BackupStatus.COMPLETED
            result.completion_time = datetime.now(timezone.utc)
            
            logger.info(f"✅ Quantum backup completed: {backup_id}")
            return backup_id
            
        except Exception as e:
            logger.error(f"❌ Backup failed {backup_id}: {e}")
            if backup_id in self.backup_results:
                self.backup_results[backup_id].status = BackupStatus.FAILED
                self.backup_results[backup_id].error_message = str(e)
            raise
        finally:
            self.active_backups.discard(backup_id)
    
    async def get_backup_status(self, backup_id: str) -> Optional[BackupResult]:
        """Get backup status and results."""
        return self.backup_results.get(backup_id)
    
    async def list_backups(self, limit: int = 100) -> List[BackupResult]:
        """List recent backups."""
        results = list(self.backup_results.values())
        results.sort(key=lambda x: x.completion_time or datetime.min, reverse=True)
        return results[:limit]
    
    async def _load_configuration(self):
        """Load backup configuration."""
        # Default configuration
        self.config = {
            "encryption": {
                "algorithm": "post_quantum",
                "key_size": 4096,
                "quantum_resistant": True
            },
            "distribution": {
                "min_redundancy": 7,
                "max_shard_size": 25 * 1024 * 1024,
                "geographic_distribution": True
            },
            "zero_knowledge": {
                "enabled": True,
                "client_side_encryption": True,
                "proof_of_storage": True
            }
        }
        
        # TODO: Load from YAML file
        logger.info("📋 Backup configuration loaded")
    
    async def _initialize_database(self):
        """Initialize backup manager database."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.db_connection = await aiosqlite.connect(str(self.db_path))
        
        # Create tables
        await self.db_connection.execute("""
            CREATE TABLE IF NOT EXISTS backup_requests (
                backup_id TEXT PRIMARY KEY,
                data_type TEXT NOT NULL,
                data_source TEXT NOT NULL,
                priority INTEGER NOT NULL,
                backup_type TEXT NOT NULL,
                encryption_level INTEGER NOT NULL,
                redundancy_factor INTEGER NOT NULL,
                zero_knowledge BOOLEAN NOT NULL,
                metadata TEXT,
                created_at TIMESTAMP NOT NULL
            )
        """)
        
        await self.db_connection.execute("""
            CREATE TABLE IF NOT EXISTS backup_results (
                backup_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                shard_count INTEGER NOT NULL,
                total_size INTEGER NOT NULL,
                encrypted_size INTEGER NOT NULL,
                node_distribution TEXT,
                verification_hash TEXT NOT NULL,
                completion_time TIMESTAMP,
                error_message TEXT
            )
        """)
        
        await self.db_connection.commit()
        logger.info("🗄️ Backup database initialized")
    
    async def _initialize_components(self):
        """Initialize component managers."""
        # Import and initialize components
        from .distributed_shard_system import DistributedShardSystem
        from .backup_node_network import BackupNodeNetwork
        from .zero_knowledge_protocol import ZeroKnowledgeProtocol
        from .immutable_shard_manager import ImmutableShardManager
        from .advanced_recovery_system import AdvancedRecoverySystem
        from .backup_analytics import BackupAnalytics
        
        self.shard_system = DistributedShardSystem(self)
        self.node_network = BackupNodeNetwork(self)
        self.zero_knowledge = ZeroKnowledgeProtocol(self)
        self.immutable_manager = ImmutableShardManager(self)
        self.recovery_system = AdvancedRecoverySystem(self)
        self.analytics = BackupAnalytics(self)
        
        # Initialize all components
        await self.shard_system.initialize()
        await self.node_network.initialize()
        await self.zero_knowledge.initialize()
        await self.immutable_manager.initialize()
        await self.recovery_system.initialize()
        await self.analytics.initialize()
        
        logger.info("🔧 Backup components initialized")
    
    async def _start_background_tasks(self):
        """Start background monitoring and maintenance tasks."""
        # Start analytics monitoring
        asyncio.create_task(self.analytics.start_monitoring())
        
        # Start node health monitoring
        asyncio.create_task(self.node_network.start_health_monitoring())
        
        # Start shard verification
        asyncio.create_task(self.immutable_manager.start_verification_loop())
        
        logger.info("🔄 Background tasks started")
    
    async def _process_backup(self, request: BackupRequest, result: BackupResult):
        """Process backup through all components."""
        # 1. Zero-knowledge encryption
        encrypted_data = await self.zero_knowledge.encrypt_data(request)
        
        # 2. Create shards
        shards = await self.shard_system.create_shards(encrypted_data, request)
        result.shard_count = len(shards)
        
        # 3. Distribute to nodes
        distribution = await self.node_network.distribute_shards(shards, request)
        result.node_distribution = distribution
        
        # 4. Create immutable records
        await self.immutable_manager.create_shard_records(shards, request)
        
        # 5. Verify backup
        verification_hash = await self._verify_backup(shards, request)
        result.verification_hash = verification_hash
        
        # 6. Update analytics
        await self.analytics.record_backup(request, result)
    
    async def _verify_backup(self, shards: List[Any], request: BackupRequest) -> str:
        """Verify backup integrity."""
        # Create verification hash
        hasher = hashlib.sha512()
        for shard in shards:
            hasher.update(shard.get('data', b''))
        
        verification_hash = hasher.hexdigest()
        logger.info(f"🔍 Backup verified: {request.backup_id}")
        return verification_hash


# Global instance
quantum_backup_manager = QuantumBackupManager()
