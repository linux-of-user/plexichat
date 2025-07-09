"""
NetLink Cluster Manager
Handles multi-server coordination and clustering.
"""

import os
import json
import time
import asyncio
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
import socket

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    aiohttp = None

class ClusterNode:
    """Represents a node in the NetLink cluster."""
    
    def __init__(self, node_id: str, host: str, port: int, version: str = "1.0.0"):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.version = version
        self.last_seen = datetime.utcnow()
        self.status = "unknown"
        self.load = 0.0
        self.connections = 0
        self.is_leader = False
        self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary."""
        return {
            "node_id": self.node_id,
            "host": self.host,
            "port": self.port,
            "version": self.version,
            "last_seen": self.last_seen.isoformat(),
            "status": self.status,
            "load": self.load,
            "connections": self.connections,
            "is_leader": self.is_leader,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ClusterNode':
        """Create node from dictionary."""
        node = cls(
            data["node_id"],
            data["host"],
            data["port"],
            data.get("version", "1.0.0")
        )
        node.last_seen = datetime.fromisoformat(data["last_seen"])
        node.status = data.get("status", "unknown")
        node.load = data.get("load", 0.0)
        node.connections = data.get("connections", 0)
        node.is_leader = data.get("is_leader", False)
        node.metadata = data.get("metadata", {})
        return node
    
    @property
    def url(self) -> str:
        """Get node URL."""
        return f"http://{self.host}:{self.port}"
    
    def is_alive(self, timeout_seconds: int = 30) -> bool:
        """Check if node is considered alive."""
        return (datetime.utcnow() - self.last_seen).total_seconds() < timeout_seconds

class ClusterManager:
    """Manages NetLink cluster coordination."""
    
    def __init__(self):
        self.node_id = self.generate_node_id()
        self.nodes: Dict[str, ClusterNode] = {}
        self.current_node: Optional[ClusterNode] = None
        self.is_leader = False
        self.leader_node_id: Optional[str] = None
        self.cluster_file = Path("data/cluster.json")
        self.heartbeat_interval = 10  # seconds
        self.node_timeout = 30  # seconds
        self.discovery_ports = [8000, 8001, 8002, 8003, 8004]  # Common ports to scan
        self.running = False
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Ensure data directory exists
        self.cluster_file.parent.mkdir(exist_ok=True)
        
        # Load existing cluster state
        self.load_cluster_state()
    
    def generate_node_id(self) -> str:
        """Generate unique node ID."""
        hostname = socket.gethostname()
        timestamp = str(int(time.time()))
        unique_string = f"{hostname}-{timestamp}-{os.getpid()}"
        return hashlib.md5(unique_string.encode()).hexdigest()[:12]
    
    def get_current_config(self) -> Dict[str, Any]:
        """Get current node configuration."""
        try:
            from app.logger_config import settings
            return {
                "host": getattr(settings, 'HOST', '0.0.0.0'),
                "port": getattr(settings, 'PORT', 8000),
                "version": getattr(settings, 'APP_VERSION', '1.0.0')
            }
        except ImportError:
            return {
                "host": os.getenv('HOST', '0.0.0.0'),
                "port": int(os.getenv('PORT', 8000)),
                "version": '1.0.0'
            }
    
    def initialize_current_node(self):
        """Initialize current node."""
        config = self.get_current_config()
        
        self.current_node = ClusterNode(
            self.node_id,
            config["host"],
            config["port"],
            config["version"]
        )
        self.current_node.status = "active"
        self.nodes[self.node_id] = self.current_node
    
    def load_cluster_state(self):
        """Load cluster state from file."""
        try:
            if self.cluster_file.exists():
                with open(self.cluster_file, 'r') as f:
                    data = json.load(f)
                
                # Load nodes
                for node_data in data.get("nodes", []):
                    node = ClusterNode.from_dict(node_data)
                    self.nodes[node.node_id] = node
                
                # Load leader info
                self.leader_node_id = data.get("leader_node_id")
                
        except Exception as e:
            print(f"Failed to load cluster state: {e}")
    
    def save_cluster_state(self):
        """Save cluster state to file."""
        try:
            data = {
                "nodes": [node.to_dict() for node in self.nodes.values()],
                "leader_node_id": self.leader_node_id,
                "last_updated": datetime.utcnow().isoformat()
            }
            
            with open(self.cluster_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            print(f"Failed to save cluster state: {e}")
    
    async def start_cluster_services(self):
        """Start cluster coordination services."""
        if self.running:
            return
        
        self.running = True
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5))
        
        # Initialize current node
        self.initialize_current_node()
        
        # Start background tasks
        asyncio.create_task(self.heartbeat_loop())
        asyncio.create_task(self.discovery_loop())
        asyncio.create_task(self.leader_election_loop())
        asyncio.create_task(self.cleanup_loop())
        
        print(f"Cluster services started for node {self.node_id}")
    
    async def stop_cluster_services(self):
        """Stop cluster coordination services."""
        self.running = False
        
        if self.session:
            await self.session.close()
            self.session = None
        
        # Save final state
        self.save_cluster_state()
        
        print(f"Cluster services stopped for node {self.node_id}")
    
    async def heartbeat_loop(self):
        """Send periodic heartbeats to other nodes."""
        while self.running:
            try:
                await self.send_heartbeats()
                await asyncio.sleep(self.heartbeat_interval)
            except Exception as e:
                print(f"Heartbeat error: {e}")
                await asyncio.sleep(self.heartbeat_interval)
    
    async def discovery_loop(self):
        """Discover other nodes in the network."""
        while self.running:
            try:
                await self.discover_nodes()
                await asyncio.sleep(30)  # Discovery every 30 seconds
            except Exception as e:
                print(f"Discovery error: {e}")
                await asyncio.sleep(30)
    
    async def leader_election_loop(self):
        """Handle leader election."""
        while self.running:
            try:
                await self.handle_leader_election()
                await asyncio.sleep(15)  # Check leadership every 15 seconds
            except Exception as e:
                print(f"Leader election error: {e}")
                await asyncio.sleep(15)
    
    async def cleanup_loop(self):
        """Clean up dead nodes."""
        while self.running:
            try:
                self.cleanup_dead_nodes()
                await asyncio.sleep(60)  # Cleanup every minute
            except Exception as e:
                print(f"Cleanup error: {e}")
                await asyncio.sleep(60)
    
    async def send_heartbeats(self):
        """Send heartbeats to all known nodes."""
        if not self.current_node or not self.session:
            return
        
        # Update current node status
        self.current_node.last_seen = datetime.utcnow()
        self.current_node.load = await self.get_current_load()
        self.current_node.connections = await self.get_current_connections()
        
        heartbeat_data = {
            "node": self.current_node.to_dict(),
            "timestamp": datetime.utcnow().isoformat(),
            "cluster_size": len(self.nodes)
        }
        
        # Send to all other nodes
        for node in self.nodes.values():
            if node.node_id != self.node_id:
                try:
                    async with self.session.post(
                        f"{node.url}/api/cluster/heartbeat",
                        json=heartbeat_data
                    ) as response:
                        if response.status == 200:
                            node.status = "active"
                            node.last_seen = datetime.utcnow()
                except Exception:
                    node.status = "unreachable"
    
    async def discover_nodes(self):
        """Discover nodes on the local network."""
        if not self.session:
            return
        
        # Get local network range
        local_ip = self.get_local_ip()
        if not local_ip:
            return
        
        # Scan common ports on local network
        network_base = '.'.join(local_ip.split('.')[:-1])
        
        for i in range(1, 255):  # Scan .1 to .254
            for port in self.discovery_ports:
                try:
                    target_ip = f"{network_base}.{i}"
                    if target_ip == local_ip and port == self.current_node.port:
                        continue  # Skip self
                    
                    async with self.session.get(
                        f"http://{target_ip}:{port}/api/cluster/info",
                        timeout=aiohttp.ClientTimeout(total=2)
                    ) as response:
                        if response.status == 200:
                            node_info = await response.json()
                            await self.add_discovered_node(node_info, target_ip, port)
                            
                except Exception:
                    continue  # Node not reachable
    
    async def add_discovered_node(self, node_info: Dict[str, Any], host: str, port: int):
        """Add a discovered node to the cluster."""
        node_id = node_info.get("node_id")
        if not node_id or node_id == self.node_id:
            return
        
        if node_id not in self.nodes:
            node = ClusterNode(
                node_id,
                host,
                port,
                node_info.get("version", "1.0.0")
            )
            node.status = "discovered"
            self.nodes[node_id] = node
            
            print(f"Discovered new node: {node_id} at {host}:{port}")
            self.save_cluster_state()
    
    async def handle_leader_election(self):
        """Handle leader election process."""
        alive_nodes = [node for node in self.nodes.values() if node.is_alive()]
        
        if not alive_nodes:
            return
        
        # Check if current leader is still alive
        if self.leader_node_id:
            leader_node = self.nodes.get(self.leader_node_id)
            if leader_node and leader_node.is_alive():
                return  # Current leader is still active
        
        # Elect new leader (node with lowest ID among alive nodes)
        candidate_nodes = sorted(alive_nodes, key=lambda n: n.node_id)
        new_leader = candidate_nodes[0]
        
        if new_leader.node_id != self.leader_node_id:
            self.leader_node_id = new_leader.node_id
            
            # Update leader status
            for node in self.nodes.values():
                node.is_leader = (node.node_id == self.leader_node_id)
            
            self.is_leader = (self.leader_node_id == self.node_id)
            
            if self.is_leader:
                print(f"Elected as cluster leader: {self.node_id}")
            else:
                print(f"New cluster leader elected: {self.leader_node_id}")
            
            self.save_cluster_state()
    
    def cleanup_dead_nodes(self):
        """Remove dead nodes from cluster."""
        dead_nodes = []
        
        for node_id, node in self.nodes.items():
            if node_id != self.node_id and not node.is_alive(self.node_timeout):
                dead_nodes.append(node_id)
        
        for node_id in dead_nodes:
            print(f"Removing dead node: {node_id}")
            del self.nodes[node_id]
            
            if self.leader_node_id == node_id:
                self.leader_node_id = None  # Trigger new election
        
        if dead_nodes:
            self.save_cluster_state()
    
    def get_local_ip(self) -> Optional[str]:
        """Get local IP address."""
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return None
    
    async def get_current_load(self) -> float:
        """Get current system load."""
        try:
            import psutil
            return psutil.cpu_percent(interval=1)
        except ImportError:
            return 0.0
    
    async def get_current_connections(self) -> int:
        """Get current connection count."""
        # This would be implemented based on your web server metrics
        return 0
    
    def get_cluster_status(self) -> Dict[str, Any]:
        """Get current cluster status."""
        alive_nodes = [node for node in self.nodes.values() if node.is_alive()]
        
        return {
            "node_id": self.node_id,
            "is_leader": self.is_leader,
            "leader_node_id": self.leader_node_id,
            "total_nodes": len(self.nodes),
            "alive_nodes": len(alive_nodes),
            "cluster_health": "healthy" if len(alive_nodes) > 0 else "degraded",
            "nodes": [node.to_dict() for node in self.nodes.values()],
            "last_updated": datetime.utcnow().isoformat()
        }
    
    async def broadcast_message(self, message: Dict[str, Any]) -> List[str]:
        """Broadcast message to all nodes."""
        if not self.session:
            return []
        
        successful_nodes = []
        
        for node in self.nodes.values():
            if node.node_id != self.node_id and node.is_alive():
                try:
                    async with self.session.post(
                        f"{node.url}/api/cluster/message",
                        json=message
                    ) as response:
                        if response.status == 200:
                            successful_nodes.append(node.node_id)
                except Exception:
                    continue
        
        return successful_nodes
    
    def get_load_balanced_node(self) -> Optional[ClusterNode]:
        """Get node with lowest load for load balancing."""
        alive_nodes = [node for node in self.nodes.values() if node.is_alive() and node.status == "active"]
        
        if not alive_nodes:
            return None
        
        # Return node with lowest load
        return min(alive_nodes, key=lambda n: n.load)

# Global cluster manager
cluster_manager = ClusterManager()
