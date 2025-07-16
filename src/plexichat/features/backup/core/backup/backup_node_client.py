# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

import aiohttp


"""
Backup Node Client

Client for communicating with backup nodes in the distributed system.
Handles node discovery, communication, and shard operations.
"""

logger = logging.getLogger(__name__)


class NodeStatus(Enum):
    """Backup node status."""

    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"


class ShardStatus(Enum):
    """Shard status on node."""

    AVAILABLE = "available"
    MISSING = "missing"
    CORRUPTED = "corrupted"
    SYNCING = "syncing"


@dataclass
class BackupNodeInfo:
    """Information about a backup node."""

    node_id: str
    hostname: str
    ip_address: str
    port: int
    status: NodeStatus
    capacity_bytes: int
    used_bytes: int
    shard_count: int
    last_seen: datetime


@dataclass
class ShardInfo:
    """Information about a shard on a node."""

    shard_id: str
    node_id: str
    status: ShardStatus
    size_bytes: int
    checksum: str
    last_verified: datetime


class BackupNodeClient:
    """
    Backup Node Client

    Handles communication with individual backup nodes:
    - Node health checking
    - Shard upload/download
    - Node status monitoring
    - Secure API communication
    """

    def __init__(self, node_info: BackupNodeInfo, api_key: Optional[str] = None):
        """Initialize backup node client."""
        self.node_info = node_info
        self.api_key = api_key
        self.base_url = f"http://{node_info.ip_address}:{node_info.port}"
        self.session: Optional[aiohttp.ClientSession] = None

        logger.info(f"Initialized client for node {node_info.node_id}")

    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={"Authorization": f"Bearer {self.api_key}"} if self.api_key else {},
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await if self.session: self.session.close()

    async def check_health(self) -> bool:
        """Check if the backup node is healthy."""
        try:
            async with self.session.get(f"{self.base_url}/health") as response:
                if response.status == 200:
                    data = await response.json()
                    self.node_info.status = NodeStatus(data.get("status", "offline"))
                    self.node_info.last_seen = datetime.now(timezone.utc)
                    return True
                else:
                    self.node_info.status = NodeStatus.OFFLINE
                    return False
        except Exception as e:
            logger.error(f"Health check failed for node {self.node_info.node_id}: {e}")
            self.node_info.status = NodeStatus.OFFLINE
            return False

    async def upload_shard(self, shard_id: str, shard_data: bytes) -> bool:
        """Upload a shard to the backup node."""
        try:
            data = aiohttp.FormData()
            data.add_field("shard_id", shard_id)
            data.add_field(
                "shard_data", shard_data, content_type="application/octet-stream"
            )

            async with self.session.post(
                f"{self.base_url}/shards", data=data
            ) as response:
                if response.status == 201:
                    logger.info(
                        f"Successfully uploaded shard {shard_id} to node {self.node_info.node_id}"
                    )
                    return True
                else:
                    logger.error(
                        f"Failed to upload shard {shard_id}: HTTP {response.status}"
                    )
                    return False
        except Exception as e:
            logger.error(
                f"Error uploading shard {shard_id} to node {self.node_info.node_id}: {e}"
            )
            return False

    async def download_shard(self, shard_id: str) -> Optional[bytes]:
        """Download a shard from the backup node."""
        try:
            async with self.session.get(
                f"{self.base_url}/shards/{shard_id}"
            ) as response:
                if response.status == 200:
                    shard_data = await response.read()
                    logger.info(
                        f"Successfully downloaded shard {shard_id} from node {self.node_info.node_id}"
                    )
                    return shard_data
                else:
                    logger.error(
                        f"Failed to download shard {shard_id}: HTTP {response.status}"
                    )
                    return None
        except Exception as e:
            logger.error(
                f"Error downloading shard {shard_id} from node {self.node_info.node_id}: {e}"
            )
            return None

    async def verify_shard(self, shard_id: str, expected_checksum: str) -> bool:
        """Verify a shard on the backup node."""
        try:
            async with self.session.get(
                f"{self.base_url}/shards/{shard_id}/verify"
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    actual_checksum = data.get("checksum")
                    return actual_checksum == expected_checksum
                else:
                    return False
        except Exception as e:
            logger.error(
                f"Error verifying shard {shard_id} on node {self.node_info.node_id}: {e}"
            )
            return False

    async def list_shards(self) -> List[ShardInfo]:
        """List all shards on the backup node."""
        try:
            async with self.session.get(f"{self.base_url}/shards") as response:
                if response.status == 200:
                    data = await response.json()
                    shards = []
                    for shard_data in data.get("shards", []):
                        shard = ShardInfo(
                            shard_id=shard_data["shard_id"],
                            node_id=self.node_info.node_id,
                            status=ShardStatus(shard_data.get("status", "available")),
                            size_bytes=shard_data.get("size_bytes", 0),
                            checksum=shard_data.get("checksum", ""),
                            last_verified=datetime.fromisoformat(
                                shard_data["last_verified"]
                            ),
                        )
                        shards.append(shard)
                    return shards
                else:
                    return []
        except Exception as e:
            logger.error(f"Error listing shards on node {self.node_info.node_id}: {e}")
            return []

    async def delete_shard(self, shard_id: str) -> bool:
        """Delete a shard from the backup node."""
        try:
            async with self.session.delete(
                f"{self.base_url}/shards/{shard_id}"
            ) as response:
                if response.status == 204:
                    logger.info(
                        f"Successfully deleted shard {shard_id} from node {self.node_info.node_id}"
                    )
                    return True
                else:
                    logger.error(
                        f"Failed to delete shard {shard_id}: HTTP {response.status}"
                    )
                    return False
        except Exception as e:
            logger.error(
                f"Error deleting shard {shard_id} from node {self.node_info.node_id}: {e}"
            )
            return False


class BackupNodeManager:
    """
    Backup Node Manager

    Manages multiple backup node clients:
    - Node discovery and registration
    - Load balancing across nodes
    - Health monitoring
    - Failover handling
    """

    def __init__(self, backup_manager):
        """Initialize backup node manager."""
        self.backup_manager = backup_manager
        self.nodes: Dict[str, BackupNodeInfo] = {}
        self.clients: Dict[str, BackupNodeClient] = {}

        logger.info("Backup Node Manager initialized")

    async def initialize(self):
        """Initialize the node manager."""
        await self._discover_nodes()

        # Start background tasks
        asyncio.create_task(self._health_monitoring_task())

        logger.info("Backup Node Manager initialized successfully")

    async def _discover_nodes(self):
        """Discover available backup nodes."""
        # Add localhost as default node
        localhost_node = BackupNodeInfo(
            node_id="localhost",
            hostname="localhost",
            ip_address="127.0.0.1",
            port=8080,
            status=NodeStatus.ONLINE,
            capacity_bytes=100 * 1024 * 1024 * 1024,  # 100GB
            used_bytes=0,
            shard_count=0,
            last_seen=datetime.now(timezone.utc),
        )

        await self.register_node(localhost_node)

    async def register_node(self, node_info: BackupNodeInfo, api_key: Optional[str] = None):
        """Register a new backup node."""
        self.nodes[node_info.node_id] = node_info
        self.clients[node_info.node_id] = BackupNodeClient(node_info, api_key)

        logger.info(
            f"Registered backup node {node_info.node_id} at {node_info.ip_address}:{node_info.port}"
        )

    async def get_healthy_nodes(self) -> List[BackupNodeInfo]:
        """Get list of healthy backup nodes."""
        healthy_nodes = []
        for node in self.nodes.values():
            if node.status == NodeStatus.ONLINE:
                healthy_nodes.append(node)
        return healthy_nodes

    async def select_nodes_for_shard(self, redundancy_factor: int) -> List[str]:
        """Select optimal nodes for shard storage."""
        healthy_nodes = await self.get_healthy_nodes()

        if len(healthy_nodes) < redundancy_factor:
            logger.warning(
                f"Only {len(healthy_nodes)} healthy nodes available, need {redundancy_factor}"
            )
            redundancy_factor = len(healthy_nodes)

        # Simple selection based on capacity
        selected_nodes = sorted(
            healthy_nodes, key=lambda n: n.used_bytes / n.capacity_bytes
        )[:redundancy_factor]

        return [node.node_id for node in selected_nodes]

    async def upload_shard_to_nodes(
        self, shard_id: str, shard_data: bytes, node_ids: List[str]
    ) -> List[str]:
        """Upload shard to multiple nodes."""
        successful_uploads = []

        for node_id in node_ids:
            if node_id in self.clients:
                client = self.clients[node_id]
                async with client:
                    success = await client.upload_shard(shard_id, shard_data)
                    if success:
                        successful_uploads.append(node_id)
                        # Update node usage
                        self.nodes[node_id].used_bytes += len(shard_data)
                        self.nodes[node_id].shard_count += 1

        logger.info(
            f"Uploaded shard {shard_id} to {len(successful_uploads)}/{len(node_ids)} nodes"
        )
        return successful_uploads

    async def download_shard_from_nodes(
        self, shard_id: str, node_ids: List[str]
    ) -> Optional[bytes]:
        """Download shard from any available node."""
        for node_id in node_ids:
            if (
                node_id in self.clients
                and self.nodes[node_id].status == NodeStatus.ONLINE
            ):
                client = self.clients[node_id]
                async with client:
                    shard_data = await client.download_shard(shard_id)
                    if shard_data:
                        logger.info(
                            f"Successfully downloaded shard {shard_id} from node {node_id}"
                        )
                        return shard_data

        logger.error(f"Failed to download shard {shard_id} from any node")
        return None

    async def _health_monitoring_task(self):
        """Background task for monitoring node health."""
        while True:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes
                await self._check_all_nodes_health()
            except Exception as e:
                logger.error(f"Health monitoring task error: {e}")

    async def _check_all_nodes_health(self):
        """Check health of all registered nodes."""
        for node_id, client in self.clients.items():
            try:
                async with client:
                    await client.check_health()
            except Exception as e:
                logger.error(f"Health check failed for node {node_id}: {e}")
                self.nodes[node_id].status = NodeStatus.OFFLINE


# Global instances will be created by backup manager
backup_node_client = None
backup_node_manager = None
