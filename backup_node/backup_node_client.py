"""
NetLink Backup Node Client
Client library for interacting with backup nodes.
"""

import asyncio
import base64
import hashlib
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import logging

try:
    import httpx
except ImportError:
    print("❌ Missing httpx dependency. Install with: pip install httpx")
    raise

logger = logging.getLogger(__name__)


class BackupNodeClient:
    """Client for interacting with backup nodes."""
    
    def __init__(self, node_address: str, node_port: int, timeout: int = 30):
        self.base_url = f"http://{node_address}:{node_port}"
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout)
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
    
    async def health_check(self) -> Dict[str, Any]:
        """Check if the backup node is healthy."""
        try:
            response = await self.client.get(f"{self.base_url}/health")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            raise
    
    async def get_node_status(self) -> Dict[str, Any]:
        """Get detailed node status."""
        try:
            response = await self.client.get(f"{self.base_url}/api/v1/status")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get node status: {e}")
            raise
    
    async def store_shard(
        self,
        shard_id: str,
        shard_data: bytes,
        source_node: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Store a shard on the backup node."""
        try:
            # Calculate hash
            original_hash = hashlib.sha256(shard_data).hexdigest()
            
            # Encode data
            encoded_data = base64.b64encode(shard_data).decode('utf-8')
            
            # Prepare request
            request_data = {
                "shard_id": shard_id,
                "shard_data": encoded_data,
                "original_hash": original_hash,
                "source_node": source_node,
                "metadata": metadata
            }
            
            response = await self.client.post(
                f"{self.base_url}/api/v1/shards/store",
                json=request_data
            )
            response.raise_for_status()
            
            result = response.json()
            return result.get("success", False)
            
        except Exception as e:
            logger.error(f"Failed to store shard {shard_id}: {e}")
            return False
    
    async def retrieve_shard(self, shard_id: str) -> Optional[bytes]:
        """Retrieve a shard from the backup node."""
        try:
            response = await self.client.get(f"{self.base_url}/api/v1/shards/{shard_id}")
            
            if response.status_code == 404:
                return None
            
            response.raise_for_status()
            result = response.json()
            
            # Decode data
            encoded_data = result.get("shard_data")
            if not encoded_data:
                return None
            
            shard_data = base64.b64decode(encoded_data)
            return shard_data
            
        except Exception as e:
            logger.error(f"Failed to retrieve shard {shard_id}: {e}")
            return None
    
    async def delete_shard(self, shard_id: str) -> bool:
        """Delete a shard from the backup node."""
        try:
            response = await self.client.delete(f"{self.base_url}/api/v1/shards/{shard_id}")
            
            if response.status_code == 404:
                return False
            
            response.raise_for_status()
            result = response.json()
            return result.get("success", False)
            
        except Exception as e:
            logger.error(f"Failed to delete shard {shard_id}: {e}")
            return False
    
    async def list_shards(self) -> List[Dict[str, Any]]:
        """List all shards on the backup node."""
        try:
            response = await self.client.get(f"{self.base_url}/api/v1/shards")
            response.raise_for_status()
            
            result = response.json()
            return result.get("shards", [])
            
        except Exception as e:
            logger.error(f"Failed to list shards: {e}")
            return []
    
    async def register_node(
        self,
        node_id: str,
        node_type: str,
        address: str,
        port: int,
        storage_capacity: int
    ) -> bool:
        """Register this node with the backup node."""
        try:
            request_data = {
                "node_id": node_id,
                "node_type": node_type,
                "address": address,
                "port": port,
                "storage_capacity": storage_capacity
            }
            
            response = await self.client.post(
                f"{self.base_url}/api/v1/nodes/register",
                json=request_data
            )
            response.raise_for_status()
            
            result = response.json()
            return result.get("success", False)
            
        except Exception as e:
            logger.error(f"Failed to register node: {e}")
            return False
    
    async def list_nodes(self) -> List[Dict[str, Any]]:
        """List all nodes connected to the backup node."""
        try:
            response = await self.client.get(f"{self.base_url}/api/v1/nodes")
            response.raise_for_status()
            
            result = response.json()
            return result.get("nodes", [])
            
        except Exception as e:
            logger.error(f"Failed to list nodes: {e}")
            return []


class BackupNodeManager:
    """Manager for multiple backup nodes."""
    
    def __init__(self):
        self.nodes: Dict[str, BackupNodeClient] = {}
        self.node_configs: Dict[str, Dict[str, Any]] = {}
    
    def add_node(
        self,
        node_id: str,
        address: str,
        port: int,
        priority: int = 1,
        timeout: int = 30
    ):
        """Add a backup node to the manager."""
        self.nodes[node_id] = BackupNodeClient(address, port, timeout)
        self.node_configs[node_id] = {
            "address": address,
            "port": port,
            "priority": priority,
            "timeout": timeout,
            "last_health_check": None,
            "is_healthy": False
        }
        
        logger.info(f"Added backup node: {node_id} ({address}:{port})")
    
    def remove_node(self, node_id: str):
        """Remove a backup node from the manager."""
        if node_id in self.nodes:
            del self.nodes[node_id]
            del self.node_configs[node_id]
            logger.info(f"Removed backup node: {node_id}")
    
    async def health_check_all(self) -> Dict[str, bool]:
        """Check health of all backup nodes."""
        results = {}
        
        for node_id, client in self.nodes.items():
            try:
                await client.health_check()
                results[node_id] = True
                self.node_configs[node_id]["is_healthy"] = True
                self.node_configs[node_id]["last_health_check"] = datetime.now().isoformat()
            except Exception as e:
                logger.warning(f"Health check failed for node {node_id}: {e}")
                results[node_id] = False
                self.node_configs[node_id]["is_healthy"] = False
        
        return results
    
    async def store_shard_redundant(
        self,
        shard_id: str,
        shard_data: bytes,
        redundancy_level: int = 2,
        source_node: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, List[str]]:
        """Store a shard with redundancy across multiple nodes."""
        successful_nodes = []
        
        # Sort nodes by priority and health
        available_nodes = [
            (node_id, client) for node_id, client in self.nodes.items()
            if self.node_configs[node_id]["is_healthy"]
        ]
        
        available_nodes.sort(key=lambda x: self.node_configs[x[0]]["priority"])
        
        # Store on multiple nodes
        for node_id, client in available_nodes[:redundancy_level]:
            try:
                success = await client.store_shard(shard_id, shard_data, source_node, metadata)
                if success:
                    successful_nodes.append(node_id)
                    logger.info(f"Stored shard {shard_id} on node {node_id}")
            except Exception as e:
                logger.error(f"Failed to store shard {shard_id} on node {node_id}: {e}")
        
        success = len(successful_nodes) >= min(redundancy_level, len(available_nodes))
        return success, successful_nodes
    
    async def retrieve_shard_any(self, shard_id: str) -> Optional[bytes]:
        """Retrieve a shard from any available node."""
        # Try nodes in priority order
        sorted_nodes = sorted(
            [(node_id, client) for node_id, client in self.nodes.items()
             if self.node_configs[node_id]["is_healthy"]],
            key=lambda x: self.node_configs[x[0]]["priority"]
        )
        
        for node_id, client in sorted_nodes:
            try:
                shard_data = await client.retrieve_shard(shard_id)
                if shard_data is not None:
                    logger.info(f"Retrieved shard {shard_id} from node {node_id}")
                    return shard_data
            except Exception as e:
                logger.warning(f"Failed to retrieve shard {shard_id} from node {node_id}: {e}")
        
        logger.error(f"Failed to retrieve shard {shard_id} from any node")
        return None
    
    async def delete_shard_all(self, shard_id: str) -> Dict[str, bool]:
        """Delete a shard from all nodes."""
        results = {}
        
        for node_id, client in self.nodes.items():
            try:
                success = await client.delete_shard(shard_id)
                results[node_id] = success
                if success:
                    logger.info(f"Deleted shard {shard_id} from node {node_id}")
            except Exception as e:
                logger.error(f"Failed to delete shard {shard_id} from node {node_id}: {e}")
                results[node_id] = False
        
        return results
    
    async def get_cluster_status(self) -> Dict[str, Any]:
        """Get status of the entire backup cluster."""
        cluster_status = {
            "total_nodes": len(self.nodes),
            "healthy_nodes": 0,
            "total_storage_bytes": 0,
            "used_storage_bytes": 0,
            "total_shards": 0,
            "nodes": {}
        }
        
        for node_id, client in self.nodes.items():
            try:
                status = await client.get_node_status()
                cluster_status["nodes"][node_id] = status
                
                if self.node_configs[node_id]["is_healthy"]:
                    cluster_status["healthy_nodes"] += 1
                
                storage = status.get("storage", {})
                cluster_status["total_storage_bytes"] += storage.get("max_bytes", 0)
                cluster_status["used_storage_bytes"] += storage.get("used_bytes", 0)
                
                shards = status.get("shards", {})
                cluster_status["total_shards"] += shards.get("total_count", 0)
                
            except Exception as e:
                logger.error(f"Failed to get status from node {node_id}: {e}")
                cluster_status["nodes"][node_id] = {"error": str(e)}
        
        return cluster_status
    
    async def close_all(self):
        """Close all client connections."""
        for client in self.nodes.values():
            await client.client.aclose()


# Example usage
async def example_usage():
    """Example of how to use the backup node client."""
    
    # Single node client
    async with BackupNodeClient("localhost", 8001) as client:
        # Check health
        health = await client.health_check()
        print(f"Node health: {health}")
        
        # Store a shard
        test_data = b"Hello, backup world!"
        success = await client.store_shard("test_shard_1", test_data)
        print(f"Store success: {success}")
        
        # Retrieve the shard
        retrieved_data = await client.retrieve_shard("test_shard_1")
        print(f"Retrieved data: {retrieved_data}")
        
        # List shards
        shards = await client.list_shards()
        print(f"Shards: {len(shards)}")
    
    # Multiple nodes manager
    manager = BackupNodeManager()
    manager.add_node("node1", "localhost", 8001, priority=1)
    manager.add_node("node2", "localhost", 8002, priority=2)
    
    # Health check all nodes
    health_results = await manager.health_check_all()
    print(f"Health results: {health_results}")
    
    # Store with redundancy
    test_data = b"Redundant backup data"
    success, nodes = await manager.store_shard_redundant("redundant_shard", test_data, redundancy_level=2)
    print(f"Redundant store success: {success}, nodes: {nodes}")
    
    # Get cluster status
    cluster_status = await manager.get_cluster_status()
    print(f"Cluster status: {cluster_status}")
    
    await manager.close_all()


if __name__ == "__main__":
    asyncio.run(example_usage())
