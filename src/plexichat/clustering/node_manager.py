"""
Multi-Node Clustering System for NetLink
Distributed architecture with load balancing and intelligent request routing.
"""

import asyncio
import json
import time
import uuid
import hashlib
import socket
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from pathlib import Path
import threading
import aiohttp
import psutil

from fastapi import HTTPException, Request, BackgroundTasks
from fastapi.responses import JSONResponse
import redis
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Boolean, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

class NodeRole(Enum):
    """Node roles in the cluster."""
    MASTER = "master"
    WORKER = "worker"
    BACKUP = "backup"
    LOAD_BALANCER = "load_balancer"

class NodeStatus(Enum):
    """Node status states."""
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"
    JOINING = "joining"
    LEAVING = "leaving"

class LoadBalanceStrategy(Enum):
    """Load balancing strategies."""
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    RESOURCE_BASED = "resource_based"
    GEOGRAPHIC = "geographic"

@dataclass
class NodeInfo:
    """Information about a cluster node."""
    node_id: str
    hostname: str
    ip_address: str
    port: int
    role: NodeRole
    status: NodeStatus
    version: str
    capabilities: List[str]
    load_score: float
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_latency: float
    active_connections: int
    last_heartbeat: datetime
    joined_at: datetime
    metadata: Dict[str, Any]

@dataclass
class ClusterConfig:
    """Cluster configuration."""
    cluster_id: str
    cluster_name: str
    master_nodes: List[str]
    total_nodes: int
    replication_factor: int
    heartbeat_interval: int
    failure_timeout: int
    load_balance_strategy: LoadBalanceStrategy
    auto_scaling: bool
    max_nodes: int
    min_nodes: int

class NodeManager:
    """Manages cluster nodes and load balancing."""
    
    def __init__(self, node_id: str = None, role: NodeRole = NodeRole.WORKER):
        self.logger = logging.getLogger(__name__)
        
        # Node identity
        self.node_id = node_id or self._generate_node_id()
        self.role = role
        self.status = NodeStatus.JOINING
        self.version = "2.0.0"
        self.capabilities = ["api", "storage", "compute", "backup"]
        
        # Cluster state
        self.cluster_nodes: Dict[str, NodeInfo] = {}
        self.master_nodes: Set[str] = set()
        self.is_master = role == NodeRole.MASTER
        
        # Load balancing
        self.load_balance_strategy = LoadBalanceStrategy.RESOURCE_BASED
        self.connection_counts: Dict[str, int] = {}
        self.request_counts: Dict[str, int] = {}
        self.response_times: Dict[str, List[float]] = {}
        
        # Configuration
        self.config = self._load_cluster_config()
        
        # Storage
        self.redis_client = None
        self.db_session = None
        self._init_storage()
        
        # Network
        self.session = None
        self.server_info = self._get_server_info()
        
        # Start background tasks
        self._start_background_tasks()
    
    def _generate_node_id(self) -> str:
        """Generate unique node ID."""
        hostname = socket.gethostname()
        timestamp = str(int(time.time()))
        random_part = str(uuid.uuid4())[:8]
        return f"node_{hostname}_{timestamp}_{random_part}"
    
    def _get_server_info(self) -> Dict[str, Any]:
        """Get current server information."""
        try:
            return {
                "hostname": socket.gethostname(),
                "ip_address": socket.gethostbyname(socket.gethostname()),
                "port": 8000,  # Default port
                "cpu_count": psutil.cpu_count(),
                "memory_total": psutil.virtual_memory().total,
                "disk_total": psutil.disk_usage('/').total,
                "platform": psutil.LINUX if hasattr(psutil, 'LINUX') else "unknown"
            }
        except Exception as e:
            self.logger.error(f"Failed to get server info: {e}")
            return {
                "hostname": "unknown",
                "ip_address": "127.0.0.1",
                "port": 8000,
                "cpu_count": 1,
                "memory_total": 1024*1024*1024,
                "disk_total": 10*1024*1024*1024,
                "platform": "unknown"
            }
    
    def _load_cluster_config(self) -> ClusterConfig:
        """Load cluster configuration."""
        config_file = Path("config/cluster.json")
        
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    data = json.load(f)
                
                return ClusterConfig(
                    cluster_id=data.get("cluster_id", "netlink_cluster"),
                    cluster_name=data.get("cluster_name", "NetLink Cluster"),
                    master_nodes=data.get("master_nodes", []),
                    total_nodes=data.get("total_nodes", 1),
                    replication_factor=data.get("replication_factor", 2),
                    heartbeat_interval=data.get("heartbeat_interval", 30),
                    failure_timeout=data.get("failure_timeout", 120),
                    load_balance_strategy=LoadBalanceStrategy(data.get("load_balance_strategy", "resource_based")),
                    auto_scaling=data.get("auto_scaling", False),
                    max_nodes=data.get("max_nodes", 10),
                    min_nodes=data.get("min_nodes", 1)
                )
            except Exception as e:
                self.logger.error(f"Failed to load cluster config: {e}")
        
        # Default configuration
        return ClusterConfig(
            cluster_id="netlink_cluster",
            cluster_name="NetLink Cluster",
            master_nodes=[self.node_id] if self.is_master else [],
            total_nodes=1,
            replication_factor=1,
            heartbeat_interval=30,
            failure_timeout=120,
            load_balance_strategy=LoadBalanceStrategy.RESOURCE_BASED,
            auto_scaling=False,
            max_nodes=10,
            min_nodes=1
        )
    
    def _init_storage(self):
        """Initialize storage for cluster state."""
        try:
            # Redis for cluster coordination
            import redis
            self.redis_client = redis.Redis(host='localhost', port=6379, db=2, decode_responses=True)
            self.redis_client.ping()
            self.logger.info("Redis connected for cluster coordination")
        except Exception as e:
            self.logger.warning(f"Redis not available for clustering: {e}")
        
        # Database for persistent cluster state
        try:
            from sqlalchemy import create_engine
            self.engine = create_engine('sqlite:///cluster.db')
            self._create_cluster_tables()
            Session = sessionmaker(bind=self.engine)
            self.db_session = Session()
            self.logger.info("Database initialized for cluster state")
        except Exception as e:
            self.logger.error(f"Failed to initialize cluster database: {e}")
    
    def _create_cluster_tables(self):
        """Create database tables for cluster management."""
        Base = declarative_base()
        
        class ClusterNode(Base):
            __tablename__ = 'cluster_nodes'
            
            node_id = Column(String, primary_key=True)
            hostname = Column(String, nullable=False)
            ip_address = Column(String, nullable=False)
            port = Column(Integer, nullable=False)
            role = Column(String, nullable=False)
            status = Column(String, nullable=False)
            version = Column(String, nullable=False)
            capabilities = Column(JSON)
            load_score = Column(Float, default=0.0)
            cpu_usage = Column(Float, default=0.0)
            memory_usage = Column(Float, default=0.0)
            disk_usage = Column(Float, default=0.0)
            network_latency = Column(Float, default=0.0)
            active_connections = Column(Integer, default=0)
            last_heartbeat = Column(DateTime, nullable=False)
            joined_at = Column(DateTime, default=datetime.utcnow)
            metadata = Column(JSON)
        
        class ClusterState(Base):
            __tablename__ = 'cluster_state'
            
            cluster_id = Column(String, primary_key=True)
            cluster_name = Column(String, nullable=False)
            master_nodes = Column(JSON)
            total_nodes = Column(Integer, default=0)
            active_nodes = Column(Integer, default=0)
            last_updated = Column(DateTime, default=datetime.utcnow)
            configuration = Column(JSON)
        
        Base.metadata.create_all(self.engine)
        self.ClusterNode = ClusterNode
        self.ClusterState = ClusterState
    
    async def join_cluster(self, master_endpoints: List[str] = None) -> bool:
        """Join the cluster."""
        try:
            self.status = NodeStatus.JOINING
            
            # Create node info
            node_info = NodeInfo(
                node_id=self.node_id,
                hostname=self.server_info["hostname"],
                ip_address=self.server_info["ip_address"],
                port=self.server_info["port"],
                role=self.role,
                status=self.status,
                version=self.version,
                capabilities=self.capabilities,
                load_score=0.0,
                cpu_usage=0.0,
                memory_usage=0.0,
                disk_usage=0.0,
                network_latency=0.0,
                active_connections=0,
                last_heartbeat=datetime.now(),
                joined_at=datetime.now(),
                metadata={}
            )
            
            # If this is the first node or master node
            if not master_endpoints or self.is_master:
                await self._bootstrap_cluster(node_info)
            else:
                await self._join_existing_cluster(node_info, master_endpoints)
            
            self.status = NodeStatus.ONLINE
            self.cluster_nodes[self.node_id] = node_info
            
            # Start heartbeat
            asyncio.create_task(self._heartbeat_loop())
            
            self.logger.info(f"Node {self.node_id} joined cluster successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to join cluster: {e}")
            self.status = NodeStatus.OFFLINE
            return False
    
    async def _bootstrap_cluster(self, node_info: NodeInfo):
        """Bootstrap a new cluster."""
        self.is_master = True
        self.role = NodeRole.MASTER
        self.master_nodes.add(self.node_id)
        
        # Save cluster state
        if self.redis_client:
            cluster_data = {
                "cluster_id": self.config.cluster_id,
                "master_nodes": list(self.master_nodes),
                "nodes": {self.node_id: asdict(node_info)}
            }
            self.redis_client.set("cluster:state", json.dumps(cluster_data))
        
        self.logger.info(f"Bootstrapped new cluster: {self.config.cluster_id}")
    
    async def _join_existing_cluster(self, node_info: NodeInfo, master_endpoints: List[str]):
        """Join an existing cluster."""
        for endpoint in master_endpoints:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"http://{endpoint}/api/v1/cluster/join",
                        json=asdict(node_info)
                    ) as response:
                        if response.status == 200:
                            cluster_data = await response.json()
                            await self._update_cluster_state(cluster_data)
                            self.logger.info(f"Joined cluster via {endpoint}")
                            return
            except Exception as e:
                self.logger.warning(f"Failed to join via {endpoint}: {e}")
        
        raise Exception("Failed to join cluster via any master endpoint")
    
    async def _update_cluster_state(self, cluster_data: Dict[str, Any]):
        """Update local cluster state."""
        self.master_nodes = set(cluster_data.get("master_nodes", []))
        
        # Update node information
        nodes_data = cluster_data.get("nodes", {})
        for node_id, node_data in nodes_data.items():
            self.cluster_nodes[node_id] = NodeInfo(**node_data)
    
    async def select_target_node(self, request: Request = None, 
                               service_type: str = "api") -> Optional[NodeInfo]:
        """Select the best target node for a request."""
        available_nodes = [
            node for node in self.cluster_nodes.values()
            if node.status == NodeStatus.ONLINE and service_type in node.capabilities
        ]
        
        if not available_nodes:
            return None
        
        if self.load_balance_strategy == LoadBalanceStrategy.ROUND_ROBIN:
            return self._round_robin_selection(available_nodes)
        elif self.load_balance_strategy == LoadBalanceStrategy.LEAST_CONNECTIONS:
            return self._least_connections_selection(available_nodes)
        elif self.load_balance_strategy == LoadBalanceStrategy.RESOURCE_BASED:
            return self._resource_based_selection(available_nodes)
        elif self.load_balance_strategy == LoadBalanceStrategy.WEIGHTED_ROUND_ROBIN:
            return self._weighted_round_robin_selection(available_nodes)
        else:
            return available_nodes[0]  # Fallback
    
    def _round_robin_selection(self, nodes: List[NodeInfo]) -> NodeInfo:
        """Round-robin node selection."""
        if not hasattr(self, '_round_robin_index'):
            self._round_robin_index = 0
        
        node = nodes[self._round_robin_index % len(nodes)]
        self._round_robin_index += 1
        return node
    
    def _least_connections_selection(self, nodes: List[NodeInfo]) -> NodeInfo:
        """Select node with least active connections."""
        return min(nodes, key=lambda n: n.active_connections)
    
    def _resource_based_selection(self, nodes: List[NodeInfo]) -> NodeInfo:
        """Select node based on resource utilization."""
        def calculate_load_score(node: NodeInfo) -> float:
            # Lower score is better
            cpu_weight = 0.4
            memory_weight = 0.3
            connections_weight = 0.2
            latency_weight = 0.1
            
            # Normalize metrics (0-1 scale)
            cpu_score = node.cpu_usage / 100.0
            memory_score = node.memory_usage / 100.0
            connection_score = min(node.active_connections / 1000.0, 1.0)
            latency_score = min(node.network_latency / 1000.0, 1.0)
            
            return (cpu_score * cpu_weight + 
                   memory_score * memory_weight + 
                   connection_score * connections_weight + 
                   latency_score * latency_weight)
        
        return min(nodes, key=calculate_load_score)
    
    def _weighted_round_robin_selection(self, nodes: List[NodeInfo]) -> NodeInfo:
        """Weighted round-robin based on node capacity."""
        # Simple implementation - could be more sophisticated
        weights = []
        for node in nodes:
            # Higher capacity = higher weight
            weight = max(1, int((100 - node.cpu_usage) * (100 - node.memory_usage) / 1000))
            weights.append(weight)
        
        if not hasattr(self, '_weighted_counters'):
            self._weighted_counters = [0] * len(nodes)
        
        # Find node with lowest counter relative to weight
        best_index = 0
        best_ratio = float('inf')
        
        for i, (counter, weight) in enumerate(zip(self._weighted_counters, weights)):
            ratio = counter / weight if weight > 0 else float('inf')
            if ratio < best_ratio:
                best_ratio = ratio
                best_index = i
        
        self._weighted_counters[best_index] += 1
        return nodes[best_index]
    
    async def forward_request(self, target_node: NodeInfo, request: Request, 
                            path: str, method: str = "GET") -> Dict[str, Any]:
        """Forward request to target node."""
        try:
            url = f"http://{target_node.ip_address}:{target_node.port}{path}"
            
            # Prepare request data
            headers = dict(request.headers)
            headers.pop('host', None)  # Remove host header
            headers['X-Forwarded-For'] = request.client.host if request.client else 'unknown'
            headers['X-Forwarded-By'] = self.node_id
            
            # Get request body if present
            body = None
            if method.upper() in ['POST', 'PUT', 'PATCH']:
                body = await request.body()
            
            # Make request
            async with aiohttp.ClientSession() as session:
                start_time = time.time()
                
                async with session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body,
                    params=dict(request.query_params)
                ) as response:
                    response_time = time.time() - start_time
                    
                    # Update metrics
                    self._update_node_metrics(target_node.node_id, response_time)
                    
                    # Get response data
                    response_data = await response.text()
                    
                    return {
                        "status_code": response.status,
                        "headers": dict(response.headers),
                        "body": response_data,
                        "response_time": response_time
                    }
        
        except Exception as e:
            self.logger.error(f"Failed to forward request to {target_node.node_id}: {e}")
            raise HTTPException(status_code=502, detail=f"Failed to forward request: {e}")
    
    def _update_node_metrics(self, node_id: str, response_time: float):
        """Update node performance metrics."""
        if node_id not in self.response_times:
            self.response_times[node_id] = deque(maxlen=100)
        
        self.response_times[node_id].append(response_time)
        
        # Update connection count
        self.connection_counts[node_id] = self.connection_counts.get(node_id, 0) + 1
        
        # Update request count
        self.request_counts[node_id] = self.request_counts.get(node_id, 0) + 1
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeats."""
        while self.status in [NodeStatus.ONLINE, NodeStatus.DEGRADED]:
            try:
                await self._send_heartbeat()
                await asyncio.sleep(self.config.heartbeat_interval)
            except Exception as e:
                self.logger.error(f"Heartbeat error: {e}")
                await asyncio.sleep(5)
    
    async def _send_heartbeat(self):
        """Send heartbeat to cluster."""
        try:
            # Update node metrics
            node_info = self.cluster_nodes.get(self.node_id)
            if node_info:
                node_info.cpu_usage = psutil.cpu_percent()
                node_info.memory_usage = psutil.virtual_memory().percent
                node_info.disk_usage = psutil.disk_usage('/').percent
                node_info.last_heartbeat = datetime.now()
                node_info.active_connections = len(self.connection_counts)
            
            # Update cluster state
            if self.redis_client:
                heartbeat_data = {
                    "node_id": self.node_id,
                    "timestamp": datetime.now().isoformat(),
                    "status": self.status.value,
                    "metrics": {
                        "cpu_usage": psutil.cpu_percent(),
                        "memory_usage": psutil.virtual_memory().percent,
                        "disk_usage": psutil.disk_usage('/').percent,
                        "active_connections": len(self.connection_counts)
                    }
                }
                
                self.redis_client.setex(
                    f"heartbeat:{self.node_id}",
                    self.config.heartbeat_interval * 2,
                    json.dumps(heartbeat_data)
                )
            
        except Exception as e:
            self.logger.error(f"Failed to send heartbeat: {e}")
    
    def _start_background_tasks(self):
        """Start background maintenance tasks."""
        def monitor_cluster():
            while True:
                try:
                    self._check_node_health()
                    self._cleanup_metrics()
                    time.sleep(60)  # Check every minute
                except Exception as e:
                    self.logger.error(f"Cluster monitoring error: {e}")
                    time.sleep(30)
        
        threading.Thread(target=monitor_cluster, daemon=True).start()
    
    def _check_node_health(self):
        """Check health of cluster nodes."""
        if not self.redis_client:
            return
        
        current_time = datetime.now()
        timeout_threshold = timedelta(seconds=self.config.failure_timeout)
        
        for node_id in list(self.cluster_nodes.keys()):
            try:
                heartbeat_data = self.redis_client.get(f"heartbeat:{node_id}")
                if heartbeat_data:
                    heartbeat = json.loads(heartbeat_data)
                    last_seen = datetime.fromisoformat(heartbeat["timestamp"])
                    
                    if current_time - last_seen > timeout_threshold:
                        # Node is unresponsive
                        if node_id in self.cluster_nodes:
                            self.cluster_nodes[node_id].status = NodeStatus.OFFLINE
                            self.logger.warning(f"Node {node_id} marked as offline")
                else:
                    # No heartbeat found
                    if node_id in self.cluster_nodes:
                        self.cluster_nodes[node_id].status = NodeStatus.OFFLINE
                        
            except Exception as e:
                self.logger.error(f"Failed to check health of node {node_id}: {e}")
    
    def _cleanup_metrics(self):
        """Clean up old metrics data."""
        # Clean up old response times
        for node_id in list(self.response_times.keys()):
            if len(self.response_times[node_id]) == 0:
                del self.response_times[node_id]
        
        # Reset connection counts periodically
        if len(self.connection_counts) > 1000:
            self.connection_counts.clear()
    
    def get_cluster_status(self) -> Dict[str, Any]:
        """Get comprehensive cluster status."""
        online_nodes = sum(1 for node in self.cluster_nodes.values() if node.status == NodeStatus.ONLINE)
        
        return {
            "cluster_id": self.config.cluster_id,
            "cluster_name": self.config.cluster_name,
            "current_node": self.node_id,
            "node_role": self.role.value,
            "node_status": self.status.value,
            "total_nodes": len(self.cluster_nodes),
            "online_nodes": online_nodes,
            "master_nodes": list(self.master_nodes),
            "load_balance_strategy": self.load_balance_strategy.value,
            "nodes": {
                node_id: {
                    "hostname": node.hostname,
                    "ip_address": node.ip_address,
                    "port": node.port,
                    "role": node.role.value,
                    "status": node.status.value,
                    "cpu_usage": node.cpu_usage,
                    "memory_usage": node.memory_usage,
                    "active_connections": node.active_connections,
                    "last_heartbeat": node.last_heartbeat.isoformat()
                }
                for node_id, node in self.cluster_nodes.items()
            }
        }

# Global node manager instance
node_manager = NodeManager()

# FastAPI dependencies
async def get_node_manager():
    return node_manager

# Clustering API Router
from fastapi import APIRouter, Depends, BackgroundTasks
from fastapi.responses import JSONResponse

cluster_router = APIRouter(prefix="/api/v1/cluster", tags=["Cluster Management"])

@cluster_router.post("/join")
async def join_cluster_endpoint(node_data: dict, node_mgr: NodeManager = Depends(get_node_manager)):
    """Accept a new node joining the cluster."""
    try:
        node_info = NodeInfo(**node_data)

        # Add node to cluster
        node_mgr.cluster_nodes[node_info.node_id] = node_info

        # Update cluster state
        if node_mgr.redis_client:
            cluster_data = {
                "cluster_id": node_mgr.config.cluster_id,
                "master_nodes": list(node_mgr.master_nodes),
                "nodes": {node_id: asdict(node) for node_id, node in node_mgr.cluster_nodes.items()}
            }
            node_mgr.redis_client.set("cluster:state", json.dumps(cluster_data))

        node_mgr.logger.info(f"Node {node_info.node_id} joined cluster")

        return JSONResponse({
            "success": True,
            "message": "Node joined cluster successfully",
            "cluster_data": {
                "cluster_id": node_mgr.config.cluster_id,
                "master_nodes": list(node_mgr.master_nodes),
                "nodes": {node_id: asdict(node) for node_id, node in node_mgr.cluster_nodes.items()}
            }
        })

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to join cluster: {e}")

@cluster_router.get("/status")
async def get_cluster_status(node_mgr: NodeManager = Depends(get_node_manager)):
    """Get cluster status."""
    try:
        status = node_mgr.get_cluster_status()
        return JSONResponse({
            "success": True,
            "cluster_status": status
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get cluster status: {e}")

@cluster_router.get("/nodes")
async def list_cluster_nodes(node_mgr: NodeManager = Depends(get_node_manager)):
    """List all cluster nodes."""
    try:
        nodes = []
        for node_id, node in node_mgr.cluster_nodes.items():
            nodes.append({
                "node_id": node_id,
                "hostname": node.hostname,
                "ip_address": node.ip_address,
                "port": node.port,
                "role": node.role.value,
                "status": node.status.value,
                "version": node.version,
                "capabilities": node.capabilities,
                "load_score": node.load_score,
                "cpu_usage": node.cpu_usage,
                "memory_usage": node.memory_usage,
                "disk_usage": node.disk_usage,
                "active_connections": node.active_connections,
                "last_heartbeat": node.last_heartbeat.isoformat(),
                "joined_at": node.joined_at.isoformat()
            })

        return JSONResponse({
            "success": True,
            "nodes": nodes,
            "total_nodes": len(nodes)
        })

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list nodes: {e}")

@cluster_router.post("/nodes/{node_id}/remove")
async def remove_node(node_id: str, node_mgr: NodeManager = Depends(get_node_manager)):
    """Remove a node from the cluster."""
    try:
        if node_id not in node_mgr.cluster_nodes:
            raise HTTPException(status_code=404, detail="Node not found")

        # Mark node as leaving
        node_mgr.cluster_nodes[node_id].status = NodeStatus.LEAVING

        # Remove from cluster after grace period
        async def remove_after_grace_period():
            await asyncio.sleep(30)  # 30 second grace period
            if node_id in node_mgr.cluster_nodes:
                del node_mgr.cluster_nodes[node_id]
                node_mgr.logger.info(f"Node {node_id} removed from cluster")

        asyncio.create_task(remove_after_grace_period())

        return JSONResponse({
            "success": True,
            "message": f"Node {node_id} marked for removal"
        })

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to remove node: {e}")

@cluster_router.post("/load-balance/strategy")
async def set_load_balance_strategy(strategy: str, node_mgr: NodeManager = Depends(get_node_manager)):
    """Set load balancing strategy."""
    try:
        strategy_enum = LoadBalanceStrategy(strategy)
        node_mgr.load_balance_strategy = strategy_enum

        return JSONResponse({
            "success": True,
            "message": f"Load balance strategy set to {strategy}",
            "current_strategy": strategy
        })

    except ValueError:
        valid_strategies = [s.value for s in LoadBalanceStrategy]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid strategy. Valid options: {valid_strategies}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to set strategy: {e}")

@cluster_router.get("/metrics")
async def get_cluster_metrics(node_mgr: NodeManager = Depends(get_node_manager)):
    """Get cluster performance metrics."""
    try:
        metrics = {
            "cluster_id": node_mgr.config.cluster_id,
            "total_requests": sum(node_mgr.request_counts.values()),
            "total_connections": sum(node_mgr.connection_counts.values()),
            "average_response_times": {},
            "node_metrics": {}
        }

        # Calculate average response times
        for node_id, times in node_mgr.response_times.items():
            if times:
                metrics["average_response_times"][node_id] = sum(times) / len(times)

        # Node-specific metrics
        for node_id, node in node_mgr.cluster_nodes.items():
            metrics["node_metrics"][node_id] = {
                "cpu_usage": node.cpu_usage,
                "memory_usage": node.memory_usage,
                "disk_usage": node.disk_usage,
                "active_connections": node.active_connections,
                "request_count": node_mgr.request_counts.get(node_id, 0),
                "average_response_time": metrics["average_response_times"].get(node_id, 0)
            }

        return JSONResponse({
            "success": True,
            "metrics": metrics
        })

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get metrics: {e}")

@cluster_router.post("/proxy/{path:path}")
async def proxy_request(path: str, request: Request, node_mgr: NodeManager = Depends(get_node_manager)):
    """Proxy request to appropriate cluster node."""
    try:
        # Select target node
        target_node = await node_mgr.select_target_node(request, "api")
        if not target_node:
            raise HTTPException(status_code=503, detail="No available nodes")

        # Don't proxy to self
        if target_node.node_id == node_mgr.node_id:
            raise HTTPException(status_code=400, detail="Cannot proxy to self")

        # Forward request
        result = await node_mgr.forward_request(target_node, request, f"/{path}", request.method)

        return JSONResponse(
            content=json.loads(result["body"]) if result["body"] else {},
            status_code=result["status_code"],
            headers=dict(result["headers"])
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Proxy error: {e}")

# Load balancing middleware
class LoadBalancingMiddleware:
    """Middleware for automatic load balancing."""

    def __init__(self, app, node_manager: NodeManager):
        self.app = app
        self.node_manager = node_manager

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)

        # Skip load balancing for cluster management endpoints
        if request.url.path.startswith("/api/v1/cluster"):
            await self.app(scope, receive, send)
            return

        # Skip if this is the only node
        if len(self.node_manager.cluster_nodes) <= 1:
            await self.app(scope, receive, send)
            return

        # Check if we should proxy this request
        if self._should_proxy_request(request):
            try:
                target_node = await self.node_manager.select_target_node(request, "api")
                if target_node and target_node.node_id != self.node_manager.node_id:
                    # Proxy the request
                    result = await self.node_manager.forward_request(
                        target_node, request, request.url.path, request.method
                    )

                    # Send proxied response
                    await send({
                        "type": "http.response.start",
                        "status": result["status_code"],
                        "headers": [[k.encode(), v.encode()] for k, v in result["headers"].items()],
                    })

                    await send({
                        "type": "http.response.body",
                        "body": result["body"].encode() if isinstance(result["body"], str) else result["body"],
                    })
                    return
            except Exception as e:
                # Fall back to local processing
                logging.getLogger(__name__).warning(f"Load balancing failed, processing locally: {e}")

        # Process locally
        await self.app(scope, receive, send)

    def _should_proxy_request(self, request: Request) -> bool:
        """Determine if request should be proxied."""
        # Don't proxy static files
        if request.url.path.startswith("/static"):
            return False

        # Don't proxy health checks
        if request.url.path in ["/health", "/heartbeat"]:
            return False

        # Proxy API requests if cluster has multiple nodes
        if request.url.path.startswith("/api"):
            return len(self.node_manager.cluster_nodes) > 1

        return False


