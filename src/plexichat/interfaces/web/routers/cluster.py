from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from plexichat.core.cluster_manager import ClusterNode, cluster_manager

"""
PlexiChat Cluster Router
Handles cluster coordination API endpoints.
"""

# Import cluster manager
try:
except ImportError:
    cluster_manager = None

router = APIRouter(prefix="/api/cluster", tags=["cluster"])

# Pydantic models
class HeartbeatRequest(BaseModel):
    node: Dict[str, Any]
    timestamp: str
    cluster_size: int

class ClusterMessage(BaseModel):
    message_type: str
    data: Dict[str, Any]
    sender_node_id: str
    timestamp: str

class NodeInfo(BaseModel):
    node_id: str
    host: str
    port: int
    version: str
    status: str
    load: float
    connections: int
    is_leader: bool
    last_seen: str

class ClusterStatus(BaseModel):
    node_id: str
    is_leader: bool
    leader_node_id: Optional[str]
    total_nodes: int
    alive_nodes: int
    cluster_health: str
    nodes: List[NodeInfo]
    last_updated: str

@router.get("/info")
async def get_cluster_info():
    """Get basic cluster node information."""
    if not cluster_manager:
        raise HTTPException(status_code=500, detail="Cluster manager not available")
    
    if not cluster_manager.current_node:
        cluster_manager.initialize_current_node()
    
    return {
        "node_id": cluster_manager.node_id,
        "version": cluster_manager.current_node.version if cluster_manager.current_node else "1.0.0",
        "status": "active",
        "cluster_enabled": True
    }

@router.get("/status", response_model=ClusterStatus)
async def get_cluster_status():
    """Get comprehensive cluster status."""
    if not cluster_manager:
        raise HTTPException(status_code=500, detail="Cluster manager not available")
    
    status = cluster_manager.get_cluster_status()
    
    # Convert nodes to NodeInfo models
    nodes = []
    for node_data in status["nodes"]:
        nodes.append(NodeInfo(**node_data))
    
    return ClusterStatus(
        node_id=status["node_id"],
        is_leader=status["is_leader"],
        leader_node_id=status["leader_node_id"],
        total_nodes=status["total_nodes"],
        alive_nodes=status["alive_nodes"],
        cluster_health=status["cluster_health"],
        nodes=nodes,
        last_updated=status["last_updated"]
    )

@router.post("/heartbeat")
async def receive_heartbeat(heartbeat: HeartbeatRequest):
    """Receive heartbeat from another node."""
    if not cluster_manager:
        raise HTTPException(status_code=500, detail="Cluster manager not available")
    
    try:
        # Update node information
        node_data = heartbeat.node
        node_id = node_data["node_id"]
        
        if node_id not in cluster_manager.nodes:
            # Add new node
            node = ClusterNode.from_dict(node_data)
            cluster_manager.nodes[node_id] = node
            print(f"Added new node from heartbeat: {node_id}")
        else:
            # Update existing node
            node = cluster_manager.nodes[node_id]
            node.last_seen = datetime.fromisoformat(node_data["last_seen"])
            node.status = node_data.get("status", "active")
            node.load = node_data.get("load", 0.0)
            node.connections = node_data.get("connections", 0)
            node.metadata = node_data.get("metadata", {})
        
        # Save cluster state
        cluster_manager.save_cluster_state()
        
        return {
            "status": "ok",
            "node_id": cluster_manager.node_id,
            "timestamp": from datetime import datetime
datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid heartbeat: {e}")

@router.post("/message")
async def receive_cluster_message(message: ClusterMessage):
    """Receive message from another cluster node."""
    if not cluster_manager:
        raise HTTPException(status_code=500, detail="Cluster manager not available")
    
    try:
        # Process cluster message based on type
        if message.message_type == "leader_election":
            # Handle leader election message
            pass
        elif message.message_type == "data_sync":
            # Handle data synchronization
            pass
        elif message.message_type == "health_check":
            # Handle health check
            pass
        else:
            print(f"Unknown cluster message type: {message.message_type}")
        
        return {
            "status": "received",
            "node_id": cluster_manager.node_id,
            "timestamp": from datetime import datetime
datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Message processing failed: {e}")

@router.post("/broadcast")
async def broadcast_message(message: Dict[str, Any]):
    """Broadcast message to all cluster nodes."""
    if not cluster_manager:
        raise HTTPException(status_code=500, detail="Cluster manager not available")
    
    try:
        cluster_message = {
            "message_type": message.get("type", "general"),
            "data": message.get("data", {}),
            "sender_node_id": cluster_manager.node_id,
            "timestamp": from datetime import datetime
datetime.utcnow().isoformat()
        }
        
        successful_nodes = await cluster_manager.broadcast_message(cluster_message)
        
        return {
            "status": "broadcasted",
            "successful_nodes": successful_nodes,
            "total_nodes": len(cluster_manager.nodes) - 1,  # Exclude self
            "timestamp": from datetime import datetime
datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Broadcast failed: {e}")

@router.get("/nodes")
async def list_cluster_nodes():
    """List all cluster nodes."""
    if not cluster_manager:
        raise HTTPException(status_code=500, detail="Cluster manager not available")
    
    nodes = []
    for node in cluster_manager.nodes.values():
        nodes.append({
            "node_id": node.node_id,
            "host": node.host,
            "port": node.port,
            "version": node.version,
            "status": node.status,
            "load": node.load,
            "connections": node.connections,
            "is_leader": node.is_leader,
            "is_alive": node.is_alive(),
            "last_seen": node.last_seen.isoformat(),
            "url": node.url
        })
    
    return {
        "nodes": nodes,
        "total_count": len(nodes),
        "alive_count": len([n for n in cluster_manager.nodes.values() if n.is_alive()])
    }

@router.get("/leader")
async def get_cluster_leader():
    """Get current cluster leader information."""
    if not cluster_manager:
        raise HTTPException(status_code=500, detail="Cluster manager not available")
    
    if not cluster_manager.leader_node_id:
        return {
            "leader": None,
            "message": "No leader elected"
        }
    
    leader_node = cluster_manager.nodes.get(cluster_manager.leader_node_id)
    if not leader_node:
        return {
            "leader": None,
            "message": "Leader node not found"
        }
    
    return {
        "leader": {
            "node_id": leader_node.node_id,
            "host": leader_node.host,
            "port": leader_node.port,
            "version": leader_node.version,
            "status": leader_node.status,
            "load": leader_node.load,
            "is_alive": leader_node.is_alive(),
            "url": leader_node.url
        },
        "is_current_node": cluster_manager.leader_node_id == cluster_manager.node_id
    }

@router.get("/load-balance")
async def get_load_balanced_node():
    """Get node with lowest load for load balancing."""
    if not cluster_manager:
        raise HTTPException(status_code=500, detail="Cluster manager not available")
    
    node = cluster_manager.get_load_balanced_node()
    
    if not node:
        return {
            "node": None,
            "message": "No available nodes for load balancing"
        }
    
    return {
        "node": {
            "node_id": node.node_id,
            "host": node.host,
            "port": node.port,
            "load": node.load,
            "connections": node.connections,
            "url": node.url
        },
        "recommended_url": node.url
    }

@router.post("/join")
async def join_cluster(node_info: Dict[str, Any]):
    """Manually join a node to the cluster."""
    if not cluster_manager:
        raise HTTPException(status_code=500, detail="Cluster manager not available")
    
    try:
        required_fields = ["node_id", "host", "port"]
        for field in required_fields:
            if field not in node_info:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        node_id = node_info["node_id"]
        
        if node_id == cluster_manager.node_id:
            raise HTTPException(status_code=400, detail="Cannot join self to cluster")
        
        if node_id in cluster_manager.nodes:
            raise HTTPException(status_code=409, detail="Node already in cluster")
        
        # Create and add node
        node = ClusterNode(
            node_id,
            node_info["host"],
            node_info["port"],
            node_info.get("version", "1.0.0")
        )
        node.status = "joined"
        
        cluster_manager.nodes[node_id] = node
        cluster_manager.save_cluster_state()
        
        return {
            "status": "joined",
            "node_id": node_id,
            "message": f"Node {node_id} joined cluster successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Join failed: {e}")

@router.delete("/leave/{node_id}")
async def leave_cluster(node_id: str):
    """Remove a node from the cluster."""
    if not cluster_manager:
        raise HTTPException(status_code=500, detail="Cluster manager not available")
    
    if node_id == cluster_manager.node_id:
        raise HTTPException(status_code=400, detail="Cannot remove self from cluster")
    
    if node_id not in cluster_manager.nodes:
        raise HTTPException(status_code=404, detail="Node not found in cluster")
    
    # Remove node
    del cluster_manager.nodes[node_id]
    
    # If removed node was leader, clear leader
    if cluster_manager.leader_node_id == node_id:
        cluster_manager.leader_node_id = None
    
    cluster_manager.save_cluster_state()
    
    return {
        "status": "removed",
        "node_id": node_id,
        "message": f"Node {node_id} removed from cluster"
    }

@router.get("/health")
async def cluster_health():
    """Check cluster system health."""
    if not cluster_manager:
        return {
            "status": "error",
            "message": "Cluster manager not available",
            "available": False
        }
    
    try:
        alive_nodes = len([n for n in cluster_manager.nodes.values() if n.is_alive()])
        total_nodes = len(cluster_manager.nodes)
        
        health_status = "healthy"
        if alive_nodes == 0:
            health_status = "critical"
        elif alive_nodes < total_nodes * 0.5:
            health_status = "degraded"
        elif alive_nodes < total_nodes:
            health_status = "warning"
        
        return {
            "status": health_status,
            "message": f"Cluster operational with {alive_nodes}/{total_nodes} nodes",
            "available": True,
            "cluster_size": total_nodes,
            "alive_nodes": alive_nodes,
            "has_leader": cluster_manager.leader_node_id is not None,
            "is_leader": cluster_manager.is_leader,
            "node_id": cluster_manager.node_id
        }
        
    except Exception as e:
        return {
            "status": "error",
            "message": f"Cluster health check failed: {e}",
            "available": True
        }
