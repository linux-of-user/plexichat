#!/usr/bin/env python3
"""
P2P Network Manager for Distributed Backup System

Handles peer-to-peer networking for shard distribution, node discovery,
bandwidth management, and incentive mechanisms for storage providers.


import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Any, Tuple
from uuid import uuid4

# Network imports
try:
    import aiohttp
    import aiofiles
    NETWORK_AVAILABLE = True
except ImportError:
    NETWORK_AVAILABLE = False

logger = logging.getLogger(__name__)

class NodeRole(Enum):
    """Roles a node can have in the P2P network."""
        STORAGE = "storage"          # Stores shards
    RELAY = "relay"             # Relays requests
    BOOTSTRAP = "bootstrap"      # Bootstrap node for discovery
    HYBRID = "hybrid"           # Multiple roles

class RequestType(Enum):
    """Types of P2P requests."""
    SHARD_REQUEST = "shard_request"
    SHARD_OFFER = "shard_offer"
    NODE_DISCOVERY = "node_discovery"
    HEALTH_CHECK = "health_check"
    BANDWIDTH_TEST = "bandwidth_test"

class RequestPriority(Enum):
    """Priority levels for requests.
        CRITICAL = 1    # Emergency recovery
    HIGH = 2        # Important operations
    NORMAL = 3      # Regular operations
    LOW = 4         # Background tasks

@dataclass
class NetworkNode:
    """Represents a node in the P2P network."""
    node_id: str
    endpoint: str
    roles: List[NodeRole]
    location: Optional[str] = None
    bandwidth_mbps: float = 0.0
    storage_capacity_gb: float = 0.0
    storage_used_gb: float = 0.0
    reputation_score: float = 100.0
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    response_time_ms: float = 0.0
    uptime_percentage: float = 100.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def storage_available_gb(self) -> float:
        Get available storage in GB."""
        return max(0.0, self.storage_capacity_gb - self.storage_used_gb)
    
    @property
    def storage_usage_percent(self) -> float:
        """Get storage usage percentage.
        return (self.storage_used_gb / self.storage_capacity_gb * 100) if self.storage_capacity_gb > 0 else 100.0
    
    @property
    def is_reliable(self) -> bool:
        """Check if node is considered reliable."""
        return (self.reputation_score >= 80.0 and 
                self.uptime_percentage >= 95.0 and
                self.response_time_ms < 1000.0)
    
    def to_dict(self) -> Dict[str, Any]:
        Convert to dictionary."""
        return {
            "node_id": self.node_id,
            "endpoint": self.endpoint,
            "roles": [role.value for role in self.roles],
            "location": self.location,
            "bandwidth_mbps": self.bandwidth_mbps,
            "storage_capacity_gb": self.storage_capacity_gb,
            "storage_used_gb": self.storage_used_gb,
            "storage_available_gb": self.storage_available_gb,
            "reputation_score": self.reputation_score,
            "last_seen": self.last_seen.isoformat(),
            "response_time_ms": self.response_time_ms,
            "uptime_percentage": self.uptime_percentage,
            "is_reliable": self.is_reliable,
            "metadata": self.metadata
        }

@dataclass
class P2PRequest:
    """Represents a P2P network request.
        request_id: str
    request_type: RequestType
    priority: RequestPriority
    source_node: str
    target_node: Optional[str]
    payload: Dict[str, Any]
    created_at: datetime
    expires_at: Optional[datetime] = None
    retry_count: int = 0
    max_retries: int = 3
    
    @property
    def is_expired(self) -> bool:
        """Check if request has expired."""
        return self.expires_at and datetime.now(timezone.utc) > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        Convert to dictionary."""
        return {
            "request_id": self.request_id,
            "request_type": self.request_type.value,
            "priority": self.priority.value,
            "source_node": self.source_node,
            "target_node": self.target_node,
            "payload": self.payload,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries
        }

class P2PNetworkManager:
    """Manages P2P networking for distributed backup system."""
        def __init__(self, node_id: str, listen_port: int = 8080, 
                max_connections: int = 100, bandwidth_limit_mbps: float = 10.0):
        self.node_id = node_id
        self.listen_port = listen_port
        self.max_connections = max_connections
        self.bandwidth_limit_mbps = bandwidth_limit_mbps
        
        # Network state
        self.known_nodes: Dict[str, NetworkNode] = {}
        self.active_connections: Dict[str, Any] = {}
        self.pending_requests: Dict[str, P2PRequest] = {}
        self.request_queue: List[P2PRequest] = []
        
        # Bootstrap nodes for initial discovery
        self.bootstrap_nodes: List[str] = []
        
        # Bandwidth management
        self.bandwidth_usage = {
            "upload_mbps": 0.0,
            "download_mbps": 0.0,
            "total_uploaded_gb": 0.0,
            "total_downloaded_gb": 0.0
        }
        
        # Statistics
        self.stats = {
            "requests_sent": 0,
            "requests_received": 0,
            "successful_transfers": 0,
            "failed_transfers": 0,
            "nodes_discovered": 0,
            "uptime_start": datetime.now(timezone.utc)
        }
        
        # Running state
        self.is_running = False
        self.server_task = None
        
        if not NETWORK_AVAILABLE:
            logger.warning("Network libraries not available, P2P functionality limited")
    
    async def start(self):
        """Start the P2P network manager."""
        try:
            self.is_running = True
            
            # Start HTTP server for incoming requests
            if NETWORK_AVAILABLE:
                self.server_task = asyncio.create_task(self._start_http_server())
            
            # Start background tasks
            asyncio.create_task(self._process_request_queue())
            asyncio.create_task(self._monitor_nodes())
            asyncio.create_task(self._cleanup_expired_requests())
            
            # Discover initial nodes
            await self._discover_bootstrap_nodes()
            
            logger.info(f"P2P network manager started on port {self.listen_port}")
            
        except Exception as e:
            logger.error(f"Failed to start P2P network manager: {e}")
            self.is_running = False
    
    async def stop(self):
        """Stop the P2P network manager."""
        self.is_running = False
        
        if self.server_task:
            self.server_task.cancel()
            try:
                await self.server_task
            except asyncio.CancelledError:
                pass
        
        # Close active connections
        for connection in self.active_connections.values():
            if hasattr(connection, 'close'):
                await connection.close()
        
        logger.info("P2P network manager stopped")
    
    async def register_node(self, node: NetworkNode):
        """Register a new node in the network."""
        self.known_nodes[node.node_id] = node
        self.stats["nodes_discovered"] += 1
        
        logger.info(f"Registered node {node.node_id} at {node.endpoint}")
        
        # Perform initial health check
        await self._health_check_node(node.node_id)
    
    async def request_shard(self, shard_id: str, backup_id: str, 
                        preferred_nodes: Optional[List[str]] = None,
                        priority: RequestPriority = RequestPriority.NORMAL) -> Optional[bytes]:
        """Request a shard from the P2P network."""
        try:
            # Find nodes that might have the shard
            candidate_nodes = await self._find_shard_candidates(shard_id, preferred_nodes)
            
            if not candidate_nodes:
                logger.warning(f"No candidate nodes found for shard {shard_id}")
                return None
            
            # Sort by reliability and proximity
            candidate_nodes.sort(key=lambda n: (n.reputation_score, -n.response_time_ms), reverse=True)
            
            # Try requesting from each candidate
            for node in candidate_nodes[:3]:  # Try top 3 candidates
                try:
                    shard_data = await self._request_shard_from_node(
                        node.node_id, shard_id, backup_id, priority
                    )
                    
                    if shard_data:
                        # Update node reputation
                        node.reputation_score = min(100.0, node.reputation_score + 1.0)
                        self.stats["successful_transfers"] += 1
                        
                        logger.info(f"Successfully retrieved shard {shard_id} from node {node.node_id}")
                        return shard_data
                        
                except Exception as e:
                    logger.warning(f"Failed to retrieve shard from node {node.node_id}: {e}")
                    # Decrease reputation
                    node.reputation_score = max(0.0, node.reputation_score - 5.0)
                    continue
            
            self.stats["failed_transfers"] += 1
            logger.error(f"Failed to retrieve shard {shard_id} from any node")
            return None
            
        except Exception as e:
            logger.error(f"Shard request failed: {e}")
            return None
    
    async def offer_shard(self, shard_id: str, backup_id: str, shard_data: bytes,
                        target_nodes: Optional[List[str]] = None,
                        redundancy_copies: int = 3) -> Dict[str, bool]:
        """Offer a shard to nodes in the network."""
        try:
            # Find suitable nodes for storage
            if target_nodes:
                candidate_nodes = [self.known_nodes[nid] for nid in target_nodes 
                                if nid in self.known_nodes]
            else:
                candidate_nodes = await self._find_storage_candidates(
                    len(shard_data), redundancy_copies
                )
            
            if len(candidate_nodes) < redundancy_copies:
                logger.warning(f"Insufficient storage nodes available: need {redundancy_copies}, found {len(candidate_nodes)}")
            
            # Offer shard to selected nodes
            offer_results = {}
            successful_offers = 0
            
            for node in candidate_nodes[:redundancy_copies]:
                try:
                    success = await self._offer_shard_to_node(
                        node.node_id, shard_id, backup_id, shard_data
                    )
                    
                    offer_results[node.node_id] = success
                    
                    if success:
                        successful_offers += 1
                        node.storage_used_gb += len(shard_data) / (1024**3)
                        node.reputation_score = min(100.0, node.reputation_score + 0.5)
                        logger.info(f"Successfully offered shard {shard_id} to node {node.node_id}")
                    else:
                        node.reputation_score = max(0.0, node.reputation_score - 2.0)
                        
                except Exception as e:
                    logger.warning(f"Failed to offer shard to node {node.node_id}: {e}")
                    offer_results[node.node_id] = False
            
            logger.info(f"Shard offer completed: {successful_offers}/{len(candidate_nodes)} successful")
            return offer_results
            
        except Exception as e:
            logger.error(f"Shard offer failed: {e}")
            return {
    
    async def discover_nodes(self, max_nodes: int = 50) -> List[NetworkNode]:
        """Discover new nodes in the network."""
        try:
            discovered_nodes = []
            
            # Query known nodes for their peers
            for node in list(self.known_nodes.values())[:10]:  # Query top 10 nodes
                try:
                    peers = await self._request_node_peers(node.node_id)
                    
                    for peer_info in peers:
                        if peer_info["node_id"] not in self.known_nodes:
                            peer_node = NetworkNode(
                                node_id=peer_info["node_id"],
                                endpoint=peer_info["endpoint"],
                                roles=[NodeRole(role) for role in peer_info.get("roles", ["storage"])],
                                location=peer_info.get("location"),
                                bandwidth_mbps=peer_info.get("bandwidth_mbps", 0.0),
                                storage_capacity_gb=peer_info.get("storage_capacity_gb", 0.0),
                                reputation_score=peer_info.get("reputation_score", 50.0)
                            )
                            
                            await self.register_node(peer_node)
                            discovered_nodes.append(peer_node)
                            
                            if len(discovered_nodes) >= max_nodes:
                                break
                                
                except Exception as e:
                    logger.warning(f"Failed to discover peers from node {node.node_id}}: {e}")
                    continue
                
                if len(discovered_nodes) >= max_nodes:
                    break
            
            logger.info(f"Discovered {len(discovered_nodes)} new nodes")
            return discovered_nodes
            
        except Exception as e:
            logger.error(f"Node discovery failed: {e}")
            return []
    
    async def _find_shard_candidates(self, shard_id: str, 
                                preferred_nodes: Optional[List[str]] = None) -> List[NetworkNode]:
        """Find nodes that might have a specific shard.
        candidates = []
        
        # Check preferred nodes first
        if preferred_nodes:
            for node_id in preferred_nodes:
                if node_id in self.known_nodes:
                    node = self.known_nodes[node_id]
                    if node.is_reliable:
                        candidates.append(node)
        
        # Add other reliable storage nodes
        for node in self.known_nodes.values():
            if (NodeRole.STORAGE in node.roles and 
                node.is_reliable and 
                node not in candidates):
                candidates.append(node)
        
        return candidates
    
    async def _find_storage_candidates(self, shard_size_bytes: int, 
                                    count: int) -> List[NetworkNode]:
        """Find suitable nodes for storing a shard."""
        shard_size_gb = shard_size_bytes / (1024**3)
        
        # Filter nodes with sufficient storage and good reputation
        candidates = [
            node for node in self.known_nodes.values()
            if (NodeRole.STORAGE in node.roles and
                node.storage_available_gb >= shard_size_gb and
                node.reputation_score >= 70.0 and
                node.uptime_percentage >= 90.0)
        ]
        
        # Sort by reputation, available storage, and response time
        candidates.sort(
            key=lambda n: (n.reputation_score, n.storage_available_gb, -n.response_time_ms),
            reverse=True
        )
        
        return candidates[:count * 2]  # Return more candidates than needed
    
    async def _request_shard_from_node(self, node_id: str, shard_id: str, 
                                    backup_id: str, priority: RequestPriority) -> Optional[bytes]:
        Request a specific shard from a node."""
        if not NETWORK_AVAILABLE:
            return None
        
        try:
            node = self.known_nodes.get(node_id)
            if not node:
                return None
            
            # Create request
            request = P2PRequest(
                request_id=str(uuid4()),
                request_type=RequestType.SHARD_REQUEST,
                priority=priority,
                source_node=self.node_id,
                target_node=node_id,
                payload={
                    "shard_id": shard_id,
                    "backup_id": backup_id,
                    "priority": priority.value
                },
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)
            )
            
            # Send HTTP request
            async with aiohttp.ClientSession() as session:
                start_time = time.time()
                
                async with session.post(
                    f"{node.endpoint}/api/p2p/shard/request",
                    json=request.to_dict(),
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    
                    response_time = (time.time() - start_time) * 1000
                    node.response_time_ms = response_time
                    
                    if response.status == 200:
                        shard_data = await response.read()
                        self.stats["requests_sent"] += 1
                        return shard_data
                    else:
                        logger.warning(f"Shard request failed with status {response.status}")
                        return None
                        
        except Exception as e:
            logger.error(f"Failed to request shard from node {node_id}: {e}")
            return None
    
    async def _offer_shard_to_node(self, node_id: str, shard_id: str, 
                                backup_id: str, shard_data: bytes) -> bool:
        """Offer a shard to a specific node."""
        if not NETWORK_AVAILABLE:
            return False
        
        try:
            node = self.known_nodes.get(node_id)
            if not node:
                return False
            
            # Create offer request
            request = P2PRequest(
                request_id=str(uuid4()),
                request_type=RequestType.SHARD_OFFER,
                priority=RequestPriority.NORMAL,
                source_node=self.node_id,
                target_node=node_id,
                payload={
                    "shard_id": shard_id,
                    "backup_id": backup_id,
                    "shard_size": len(shard_data)
                },
                created_at=datetime.now(timezone.utc)
            )
            
            # Send HTTP request with shard data
            async with aiohttp.ClientSession() as session:
                data = aiohttp.FormData()
                data.add_field('request', json.dumps(request.to_dict()))
                data.add_field('shard_data', shard_data, filename=f"{shard_id}.shard")
                
                async with session.post(
                    f"{node.endpoint}/api/p2p/shard/offer",
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    
                    if response.status == 200:
                        result = await response.json()
                        return result.get("accepted", False)
                    else:
                        return False
                        
        except Exception as e:
            logger.error(f"Failed to offer shard to node {node_id}: {e}")
            return False
    
    def get_network_stats(self) -> Dict[str, Any]:
        """Get P2P network statistics."""
        uptime = datetime.now(timezone.utc) - self.stats["uptime_start"]
        
        stats = self.stats.copy()
        stats.update({
            "node_id": self.node_id,
            "known_nodes": len(self.known_nodes),
            "active_connections": len(self.active_connections),
            "pending_requests": len(self.pending_requests),
            "bandwidth_usage": self.bandwidth_usage,
            "uptime_hours": uptime.total_seconds() / 3600,
            "network_available": NETWORK_AVAILABLE
        })
        
        return stats

# Export main classes
__all__ = [
    "P2PNetworkManager",
    "NetworkNode",
    "P2PRequest",
    "NodeRole",
    "RequestType",
    "RequestPriority"
]
