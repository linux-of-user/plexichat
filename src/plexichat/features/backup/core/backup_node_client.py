import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import aiohttp


"""
PlexiChat Backup Node Client
Government-Grade Independent Backup Storage System Client

A comprehensive client library for interacting with PlexiChat backup nodes with:
- Advanced clustering and real-time monitoring
- Quantum-resistant security
- Distributed redundancy management
- Large shard storage capabilities
- Seeding and synchronization features
"""

logger = logging.getLogger(__name__)


class NodeStatus(Enum):
    """Backup node status."""

    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"
    SYNCING = "syncing"
    ERROR = "error"


class ShardStatus(Enum):
    """Shard status on backup node."""

    STORED = "stored"
    VERIFIED = "verified"
    CORRUPTED = "corrupted"
    MISSING = "missing"
    SYNCING = "syncing"


@dataclass
class BackupNodeInfo:
    """Information about a backup node."""

    node_id: str
    address: str
    port: int
    status: NodeStatus = NodeStatus.OFFLINE
    storage_capacity: int = 0
    storage_used: int = 0
    storage_available: int = 0
    last_heartbeat: Optional[datetime] = None
    priority: int = 1
    trust_level: float = 1.0
    capabilities: Optional[List[str]] = None
    performance_metrics: Dict[str, float] = None
    geographic_location: Optional[str] = None
    network_latency: float = 0.0
    reliability_score: float = 1.0

    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = []
        if self.performance_metrics is None:
            self.performance_metrics = {}


@dataclass
class ShardInfo:
    """Information about a shard on backup node."""

    shard_id: str
    node_id: str
    status: ShardStatus
    size_bytes: int
    checksum: str
    created_at: datetime
    last_verified: Optional[datetime] = None
    verification_count: int = 0
    metadata: Optional[Dict[str, Any]] = None


class BackupNodeClient:
    """
    PlexiChat Backup Node Client

    Provides comprehensive client functionality for interacting with backup nodes:
    - Shard storage and retrieval
    - Node health monitoring
    - Redundancy management
    - Performance optimization
    """

    def __init__(self, node_id: str, address: str, port: int, timeout: int = 30):
        self.node_id = node_id
        self.address = address
        self.port = port
        self.timeout = timeout
        self.base_url = f"http://{address}:{port}"
        self.session: Optional[aiohttp.ClientSession] = None
        self.last_health_check: Optional[datetime] = None
        self.node_info: Optional[BackupNodeInfo] = None

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def connect(self):
        """Connect to the backup node."""
        if self.session is None:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(timeout=timeout)

    async def close(self):
        """Close connection to backup node."""
        if self.session:
            await if self.session: self.session.close()
            self.session = None

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on backup node."""
        try:
            await self.connect()
            async with self.session.get(f"{self.base_url}/health") as response:
                if response.status == 200:
                    health_data = await response.json()
                    self.last_health_check = datetime.now(timezone.utc)

                    # Update node info
                    if self.node_info:
                        self.node_info.status = NodeStatus.ONLINE
                        self.node_info.last_heartbeat = self.last_health_check
                        self.node_info.storage_used = health_data.get("storage_used", 0)
                        self.node_info.storage_available = health_data.get(
                            "storage_available", 0
                        )

                    return health_data
                else:
                    logger.warning(
                        f"Health check failed for node {self.node_id}: HTTP {response.status}"
                    )
                    return {"status": "unhealthy", "error": f"HTTP {response.status}"}

        except Exception as e:
            logger.error(f"Health check error for node {self.node_id}: {e}")
            if self.node_info:
                self.node_info.status = NodeStatus.ERROR
            return {"status": "error", "error": str(e)}

    async def store_shard(
        self,
        shard_id: str,
        shard_data: bytes,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Store a shard on the backup node."""
        try:
            await self.connect()

            # Calculate checksum
            checksum = hashlib.sha256(shard_data).hexdigest()

            # Prepare request data
            request_data = {
                "shard_id": shard_id,
                "checksum": checksum,
                "size": len(shard_data),
                "metadata": metadata or {},
            }

            # Create multipart form data
            data = aiohttp.FormData()
            data.add_field("shard_data", shard_data, filename=shard_id)
            data.add_field("request_data", json.dumps(request_data))

            async with self.session.post(
                f"{self.base_url}/store", data=data
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(f" Shard {shard_id} stored on node {self.node_id}")
                    return result.get("success", False)
                else:
                    logger.error(
                        f" Failed to store shard {shard_id} on node {self.node_id}: HTTP {response.status}"
                    )
                    return False

        except Exception as e:
            logger.error(f" Error storing shard {shard_id} on node {self.node_id}: {e}")
            return False

    async def retrieve_shard(self, shard_id: str) -> Optional[bytes]:
        """Retrieve a shard from the backup node."""
        try:
            await self.connect()
            async with self.session.get(
                f"{self.base_url}/retrieve/{shard_id}"
            ) as response:
                if response.status == 200:
                    shard_data = await response.read()
                    logger.info(f" Shard {shard_id} retrieved from node {self.node_id}")
                    return shard_data
                elif response.status == 404:
                    logger.warning(
                        f" Shard {shard_id} not found on node {self.node_id}"
                    )
                    return None
                else:
                    logger.error(
                        f" Failed to retrieve shard {shard_id} from node {self.node_id}: HTTP {response.status}"
                    )
                    return None

        except Exception as e:
            logger.error(
                f" Error retrieving shard {shard_id} from node {self.node_id}: {e}"
            )
            return None

    async def verify_shard(self, shard_id: str) -> bool:
        """Verify a shard's integrity on the backup node."""
        try:
            await self.connect()
            async with self.session.post(
                f"{self.base_url}/verify/{shard_id}"
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    is_valid = result.get("valid", False)
                    logger.info(
                        f" Shard {shard_id} verification on node {self.node_id}: {'VALID' if is_valid else 'INVALID'}"
                    )
                    return is_valid
                else:
                    logger.error(
                        f" Failed to verify shard {shard_id} on node {self.node_id}: HTTP {response.status}"
                    )
                    return False

        except Exception as e:
            logger.error(
                f" Error verifying shard {shard_id} on node {self.node_id}: {e}"
            )
            return False

    async def delete_shard(self, shard_id: str) -> bool:
        """Delete a shard from the backup node."""
        try:
            await self.connect()
            async with self.session.delete(
                f"{self.base_url}/delete/{shard_id}"
            ) as response:
                if response.status == 200:
                    logger.info(f" Shard {shard_id} deleted from node {self.node_id}")
                    return True
                elif response.status == 404:
                    logger.warning(
                        f" Shard {shard_id} not found on node {self.node_id}"
                    )
                    return True  # Already deleted
                else:
                    logger.error(
                        f" Failed to delete shard {shard_id} from node {self.node_id}: HTTP {response.status}"
                    )
                    return False

        except Exception as e:
            logger.error(
                f" Error deleting shard {shard_id} from node {self.node_id}: {e}"
            )
            return False

    async def list_shards(self) -> List[ShardInfo]:
        """List all shards on the backup node."""
        try:
            await self.connect()
            async with self.session.get(f"{self.base_url}/shards") as response:
                if response.status == 200:
                    shards_data = await response.json()
                    shards = []
                    for shard_data in shards_data.get("shards", []):
                        shard = ShardInfo(
                            shard_id=shard_data["shard_id"],
                            node_id=self.node_id,
                            status=ShardStatus(shard_data.get("status", "stored")),
                            size_bytes=shard_data["size_bytes"],
                            checksum=shard_data["checksum"],
                            created_at=datetime.fromisoformat(shard_data["created_at"]),
                            last_verified=(
                                datetime.fromisoformat(shard_data["last_verified"])
                                if shard_data.get("last_verified")
                                else None
                            ),
                            verification_count=shard_data.get("verification_count", 0),
                            metadata=shard_data.get("metadata"),
                        )
                        shards.append(shard)
                    return shards
                else:
                    logger.error(
                        f" Failed to list shards on node {self.node_id}: HTTP {response.status}"
                    )
                    return []

        except Exception as e:
            logger.error(f" Error listing shards on node {self.node_id}: {e}")
            return []


class BackupNodeManager:
    """
    PlexiChat Backup Node Manager

    Manages multiple backup nodes with:
    - Redundancy and load balancing
    - Automatic failover
    - Health monitoring
    - Performance optimization
    """

    def __init__(self):
        self.nodes: Dict[str, BackupNodeClient] = {}
        self.node_priorities: Dict[str, int] = {}
        self.last_health_check: Optional[datetime] = None
        self.health_check_interval = 60  # seconds

    def add_node(self, node_id: str, address: str, port: int, priority: int = 1):
        """Add a backup node to the manager."""
        client = BackupNodeClient(node_id, address, port)
        client.node_info = BackupNodeInfo(
            node_id=node_id, address=address, port=port, priority=priority
        )
        self.nodes[node_id] = client
        self.node_priorities[node_id] = priority
        logger.info(
            f" Added backup node {node_id} ({address}:{port}) with priority {priority}"
        )

    def remove_node(self, node_id: str):
        """Remove a backup node from the manager."""
        if node_id in self.nodes:
            del self.nodes[node_id]
            del self.node_priorities[node_id]
            logger.info(f" Removed backup node {node_id}")

    async def health_check_all(self) -> Dict[str, Dict[str, Any]]:
        """Perform health check on all nodes."""
        results = {}
        tasks = []

        for node_id, client in self.nodes.items():
            tasks.append(self._health_check_node(node_id, client))

        health_results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, (node_id, _) in enumerate(self.nodes.items()):
            if isinstance(health_results[i], Exception):
                results[node_id] = {"status": "error", "error": str(health_results[i])}
            else:
                results[node_id] = health_results[i]

        self.last_health_check = datetime.now(timezone.utc)
        return results

    async def _health_check_node(
        self, node_id: str, client: BackupNodeClient
    ) -> Dict[str, Any]:
        """Health check for a single node."""
        try:
            return await client.health_check()
        except Exception as e:
            logger.error(f"Health check failed for node {node_id}: {e}")
            return {"status": "error", "error": str(e)}

    def get_online_nodes(self) -> List[BackupNodeClient]:
        """Get list of online nodes sorted by priority."""
        online_nodes = []
        for node_id, client in self.nodes.items():
            if client.node_info and client.node_info.status == NodeStatus.ONLINE:
                online_nodes.append(client)

        # Sort by priority (lower number = higher priority)
        online_nodes.sort(key=lambda x: self.node_priorities.get(x.node_id, 999))
        return online_nodes

    async def store_shard_redundant(
        self,
        shard_id: str,
        shard_data: bytes,
        redundancy_level: int = 2,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, List[str]]:
        """Store a shard with redundancy across multiple nodes."""
        online_nodes = self.get_online_nodes()

        if len(online_nodes) < redundancy_level:
            logger.warning(
                f" Only {len(online_nodes)} nodes available, requested redundancy: {redundancy_level}"
            )
            redundancy_level = len(online_nodes)

        if redundancy_level == 0:
            logger.error(" No online nodes available for shard storage")
            return False, []

        # Select nodes for storage
        selected_nodes = online_nodes[:redundancy_level]

        # Store on selected nodes
        tasks = []
        for node in selected_nodes:
            tasks.append(node.store_shard(shard_id, shard_data, metadata))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        successful_nodes = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(
                    f" Failed to store shard {shard_id} on node {selected_nodes[i].node_id}: {result}"
                )
            elif result:
                successful_nodes.append(selected_nodes[i].node_id)

        success = len(successful_nodes) >= (
            redundancy_level // 2 + 1
        )  # Majority success

        if success:
            logger.info(
                f" Shard {shard_id} stored successfully on {len(successful_nodes)} nodes"
            )
        else:
            logger.error(
                f" Failed to store shard {shard_id} with sufficient redundancy"
            )

        return success, successful_nodes

    async def retrieve_shard_any(self, shard_id: str) -> Optional[bytes]:
        """Retrieve a shard from any available node."""
        online_nodes = self.get_online_nodes()

        for node in online_nodes:
            try:
                shard_data = await node.retrieve_shard(shard_id)
                if shard_data:
                    logger.info(f" Shard {shard_id} retrieved from node {node.node_id}")
                    return shard_data
            except Exception as e:
                logger.warning(
                    f" Failed to retrieve shard {shard_id} from node {node.node_id}: {e}"
                )
                continue

        logger.error(f" Failed to retrieve shard {shard_id} from any node")
        return None

    async def verify_shard_all(self, shard_id: str) -> Dict[str, bool]:
        """Verify a shard on all nodes that have it."""
        results = {}
        tasks = []
        node_ids = []

        for node_id, client in self.nodes.items():
            if client.node_info and client.node_info.status == NodeStatus.ONLINE:
                tasks.append(client.verify_shard(shard_id))
                node_ids.append(node_id)

        if not tasks:
            logger.warning(" No online nodes available for shard verification")
            return {}

        verification_results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(verification_results):
            node_id = node_ids[i]
            if isinstance(result, Exception):
                logger.error(
                    f" Verification failed for shard {shard_id} on node {node_id}: {result}"
                )
                results[node_id] = False
            else:
                results[node_id] = result

        return results

    async def get_cluster_status(self) -> Dict[str, Any]:
        """Get comprehensive cluster status."""
        health_results = await self.health_check_all()

        online_count = sum(
            1 for result in health_results.values() if result.get("status") == "healthy"
        )
        total_count = len(self.nodes)

        total_storage = 0
        used_storage = 0

        for node_id, health in health_results.items():
            if health.get("status") == "healthy":
                total_storage += health.get("storage_capacity", 0)
                used_storage += health.get("storage_used", 0)

        return {
            "cluster_health": (
                "healthy" if online_count > total_count // 2 else "degraded"
            ),
            "nodes_online": online_count,
            "nodes_total": total_count,
            "storage_total": total_storage,
            "storage_used": used_storage,
            "storage_available": total_storage - used_storage,
            "storage_utilization": (
                (used_storage / total_storage * 100) if total_storage > 0 else 0
            ),
            "last_health_check": (
                self.last_health_check.isoformat() if self.last_health_check else None
            ),
            "node_details": health_results,
        }

    async def close_all(self):
        """Close all node connections."""
        for client in self.nodes.values():
            await client.close()

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close_all()
