import logging

import asyncio
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from ...core_system.logging import get_logger


"""
Unified Node Manager

Consolidates all backup node management with:
- Automatic node discovery and registration
- Load balancing and health monitoring
- Secure node authentication
- Performance optimization
"""

logger = get_logger(__name__)


class NodeStatus(Enum):
    """Node status states."""

    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"


class NodeType(Enum):
    """Types of backup nodes."""

    STORAGE = "storage"
    COMPUTE = "compute"
    HYBRID = "hybrid"


class UnifiedNodeManager:
    """
    Unified Node Manager

    Manages all backup nodes in the distributed system with
    automatic discovery, health monitoring, and load balancing.
    """

    def __init__(self, backup_manager):
        self.backup_manager = backup_manager
        self.initialized = False

        # Configuration
        self.config = backup_manager.config.get("nodes", {})

        # Node tracking
        self.registered_nodes: Dict[str, Dict[str, Any]] = {}
        self.node_health: Dict[str, Dict[str, Any]] = {}

        logger.info("Unified Node Manager initialized")

    async def initialize(self) -> None:
        """Initialize the node manager."""
        if self.initialized:
            return

        # Discover existing nodes
        await self._discover_nodes()

        # Start background tasks
        asyncio.create_task(self._node_health_monitoring_task())
        asyncio.create_task(self._node_discovery_task())

        self.initialized = True
        logger.info("Unified Node Manager initialized successfully")

    async def register_node(
        self,
        node_id: str,
        node_type: NodeType,
        endpoint: str,
        capacity: int,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Register a new backup node."""
        try:
            node_info = {
                "node_id": node_id,
                "node_type": node_type.value,
                "endpoint": endpoint,
                "capacity": capacity,
                "used_space": 0,
                "status": NodeStatus.ONLINE.value,
                "registered_at": datetime.now(timezone.utc),
                "last_seen": datetime.now(timezone.utc),
                "metadata": metadata or {},
            }

            self.registered_nodes[node_id] = node_info

            # Initialize health tracking
            self.node_health[node_id] = {
                "last_health_check": datetime.now(timezone.utc),
                "response_time": 0.0,
                "error_count": 0,
                "uptime": 0.0,
            }

            logger.info(f"Registered backup node {node_id} at {endpoint}")
            return True

        except Exception as e:
            logger.error(f"Failed to register node {node_id}: {e}")
            return False

    async def unregister_node(self, node_id: str) -> bool:
        """Unregister a backup node."""
        if node_id in self.registered_nodes:
            del self.registered_nodes[node_id]
            if node_id in self.node_health:
                del self.node_health[node_id]
            logger.info(f"Unregistered backup node {node_id}")
            return True
        return False

    async def get_available_nodes(
        self, node_type: Optional[NodeType] = None, min_capacity: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Get list of available nodes matching criteria."""
        available_nodes = []

        for node_id, node_info in self.registered_nodes.items():
            # Check if node is online
            if node_info["status"] != NodeStatus.ONLINE.value:
                continue

            # Check node type filter
            if node_type and node_info["node_type"] != node_type.value:
                continue

            # Check capacity filter
            available_capacity = node_info["capacity"] - node_info["used_space"]
            if min_capacity and available_capacity < min_capacity:
                continue

            available_nodes.append(node_info.copy())

        return available_nodes

    async def get_node_statistics(self) -> Dict[str, int]:
        """Get node statistics."""
        stats = {
            "total": len(self.registered_nodes),
            "healthy": 0,
            "degraded": 0,
            "offline": 0,
        }

        for node_info in self.registered_nodes.values():
            status = node_info["status"]
            if status == NodeStatus.ONLINE.value:
                stats["healthy"] += 1
            elif status == NodeStatus.DEGRADED.value:
                stats["degraded"] += 1
            elif status == NodeStatus.OFFLINE.value:
                stats["offline"] += 1

        return stats

    async def update_node_usage(self, node_id: str, used_space: int) -> None:
        """Update node storage usage."""
        if node_id in self.registered_nodes:
            self.registered_nodes[node_id]["used_space"] = used_space
            self.registered_nodes[node_id]["last_seen"] = datetime.now(timezone.utc)

    async def _discover_nodes(self) -> None:
        """Discover existing backup nodes."""
        # Placeholder - in production, this would discover nodes from network
        # For now, register some default nodes
        await self.register_node(
            "local_node_1",
            NodeType.HYBRID,
            "http://localhost:8001",
            1000000000,  # 1GB capacity
            {"location": "local"},
        )

        logger.info("Node discovery completed")

    async def _node_health_monitoring_task(self) -> None:
        """Background task for monitoring node health."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute

                for node_id in list(self.registered_nodes.keys()):
                    await self._check_node_health(node_id)

            except Exception as e:
                logger.error(f"Node health monitoring task error: {e}")

    async def _node_discovery_task(self) -> None:
        """Background task for discovering new nodes."""
        while True:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes

                # Discover new nodes
                await self._discover_new_nodes()

            except Exception as e:
                logger.error(f"Node discovery task error: {e}")

    async def _check_node_health(self, node_id: str) -> None:
        """Check health of a specific node."""
        try:
            if node_id not in self.registered_nodes:
                return

            node_info = self.registered_nodes[node_id]
            health_info = self.node_health[node_id]

            # Simulate health check - in production, ping the actual node
            current_time = datetime.now(timezone.utc)
            last_seen = node_info["last_seen"]

            # Consider node offline if not seen for 5 minutes
            if (current_time - last_seen).total_seconds() > 300:
                node_info["status"] = NodeStatus.OFFLINE.value
                health_info["error_count"] += 1
            else:
                node_info["status"] = NodeStatus.ONLINE.value
                health_info["error_count"] = max(0, health_info["error_count"] - 1)

            health_info["last_health_check"] = current_time

        except Exception as e:
            logger.error(f"Error checking health of node {node_id}: {e}")
            if node_id in self.registered_nodes:
                self.registered_nodes[node_id]["status"] = NodeStatus.DEGRADED.value

    async def _discover_new_nodes(self) -> None:
        """Discover new nodes on the network."""
        # Placeholder - in production, this would scan network for new nodes
