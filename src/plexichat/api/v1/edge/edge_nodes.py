"""
NetLink Edge Nodes Management API
Advanced edge node management, deployment, and orchestration.
"""

from fastapi import APIRouter, HTTPException, Depends, Query, Body
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field
import asyncio

from ....core.performance.edge_computing_manager import (
    get_edge_computing_manager, 
    EdgeNode,
    NodeType,
    LoadLevel
)
from ....core.auth import require_auth, require_admin
from ....core.logging import get_logger

logger = get_logger(__name__)

# Create API router
router = APIRouter(prefix="/api/v1/edge/nodes", tags=["Edge Nodes"])

# Pydantic models for requests
class EdgeNodeCreate(BaseModel):
    """Model for creating a new edge node."""
    node_id: str = Field(..., description="Unique node identifier")
    node_type: NodeType = Field(..., description="Type of edge node")
    location: str = Field(..., description="Physical location")
    ip_address: str = Field(..., description="IP address")
    port: int = Field(8080, description="Port number")
    cpu_cores: int = Field(..., description="Number of CPU cores")
    memory_gb: float = Field(..., description="Memory in GB")
    storage_gb: float = Field(..., description="Storage in GB")
    network_bandwidth_mbps: float = Field(..., description="Network bandwidth in Mbps")
    latitude: Optional[float] = Field(None, description="Latitude coordinate")
    longitude: Optional[float] = Field(None, description="Longitude coordinate")
    region: Optional[str] = Field(None, description="Geographic region")
    supported_services: List[str] = Field(default_factory=list, description="Supported services")
    gpu_available: bool = Field(False, description="GPU availability")
    ai_acceleration: bool = Field(False, description="AI acceleration support")

class EdgeNodeUpdate(BaseModel):
    """Model for updating edge node configuration."""
    location: Optional[str] = None
    cpu_cores: Optional[int] = None
    memory_gb: Optional[float] = None
    storage_gb: Optional[float] = None
    network_bandwidth_mbps: Optional[float] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    region: Optional[str] = None
    supported_services: Optional[List[str]] = None
    gpu_available: Optional[bool] = None
    ai_acceleration: Optional[bool] = None
    max_connections: Optional[int] = None

class NodeDeploymentConfig(BaseModel):
    """Configuration for deploying services to edge nodes."""
    service_name: str = Field(..., description="Service to deploy")
    container_image: Optional[str] = Field(None, description="Container image")
    resource_requirements: Dict[str, Any] = Field(default_factory=dict, description="Resource requirements")
    environment_variables: Dict[str, str] = Field(default_factory=dict, description="Environment variables")
    replicas: int = Field(1, description="Number of replicas")
    auto_scale: bool = Field(True, description="Enable auto-scaling")

@router.post("/")
async def create_edge_node(
    node_data: EdgeNodeCreate,
    current_user: Dict = Depends(require_admin)
) -> Dict[str, Any]:
    """Create and register a new edge node."""
    try:
        manager = get_edge_computing_manager()
        
        # Create EdgeNode instance
        edge_node = EdgeNode(
            node_id=node_data.node_id,
            node_type=node_data.node_type,
            location=node_data.location,
            ip_address=node_data.ip_address,
            port=node_data.port,
            cpu_cores=node_data.cpu_cores,
            memory_gb=node_data.memory_gb,
            storage_gb=node_data.storage_gb,
            network_bandwidth_mbps=node_data.network_bandwidth_mbps,
            latitude=node_data.latitude,
            longitude=node_data.longitude,
            region=node_data.region,
            supported_services=node_data.supported_services,
            gpu_available=node_data.gpu_available,
            ai_acceleration=node_data.ai_acceleration
        )
        
        # Register the node
        success = await manager.register_edge_node(edge_node)
        
        if not success:
            raise HTTPException(status_code=400, detail="Failed to register edge node")
        
        logger.info(f"✅ Edge node created: {node_data.node_id} by {current_user.get('username')}")
        
        return {
            "success": True,
            "message": f"Edge node {node_data.node_id} created successfully",
            "node_id": node_data.node_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to create edge node: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/")
async def list_edge_nodes(
    node_type: Optional[NodeType] = Query(None, description="Filter by node type"),
    region: Optional[str] = Query(None, description="Filter by region"),
    active_only: bool = Query(True, description="Show only active nodes"),
    include_metrics: bool = Query(False, description="Include performance metrics"),
    current_user: Dict = Depends(require_auth)
) -> Dict[str, Any]:
    """List all edge nodes with advanced filtering and metrics."""
    try:
        manager = get_edge_computing_manager()
        
        # Get all nodes
        all_nodes = manager.edge_nodes
        
        # Apply filters
        filtered_nodes = {}
        for node_id, node in all_nodes.items():
            # Filter by active status
            if active_only and not node.is_active:
                continue
                
            # Filter by node type
            if node_type and node.node_type != node_type:
                continue
                
            # Filter by region
            if region and node.region != region:
                continue
                
            filtered_nodes[node_id] = node
        
        # Prepare response data
        nodes_data = []
        for node_id, node in filtered_nodes.items():
            node_data = {
                "node_id": node.node_id,
                "node_type": node.node_type.value,
                "location": node.location,
                "ip_address": node.ip_address,
                "port": node.port,
                "is_active": node.is_active,
                "is_healthy": node.is_healthy,
                "last_heartbeat": node.last_heartbeat.isoformat(),
                "region": node.region,
                "supported_services": getattr(node, 'supported_services', []),
                "gpu_available": getattr(node, 'gpu_available', False),
                "ai_acceleration": getattr(node, 'ai_acceleration', False)
            }
            
            # Include metrics if requested
            if include_metrics:
                node_data["metrics"] = {
                    "cpu_usage_percent": node.cpu_usage_percent,
                    "memory_usage_percent": node.memory_usage_percent,
                    "storage_usage_percent": node.storage_usage_percent,
                    "network_usage_percent": node.network_usage_percent,
                    "current_connections": node.current_connections,
                    "max_connections": node.max_connections,
                    "request_queue_size": node.request_queue_size
                }
            
            nodes_data.append(node_data)
        
        return {
            "success": True,
            "data": {
                "nodes": nodes_data,
                "total_count": len(nodes_data),
                "filters_applied": {
                    "node_type": node_type.value if node_type else None,
                    "region": region,
                    "active_only": active_only
                }
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to list edge nodes: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{node_id}")
async def get_edge_node(
    node_id: str,
    include_detailed_metrics: bool = Query(False, description="Include detailed performance metrics"),
    current_user: Dict = Depends(require_auth)
) -> Dict[str, Any]:
    """Get detailed information about a specific edge node."""
    try:
        manager = get_edge_computing_manager()
        
        if node_id not in manager.edge_nodes:
            raise HTTPException(status_code=404, detail=f"Edge node {node_id} not found")
        
        node = manager.edge_nodes[node_id]
        
        # Get detailed node information
        node_details = await manager.get_node_details(node_id)
        
        # Add additional information
        enhanced_details = {
            **node_details,
            "specifications": {
                "cpu_cores": node.cpu_cores,
                "memory_gb": node.memory_gb,
                "storage_gb": node.storage_gb,
                "network_bandwidth_mbps": node.network_bandwidth_mbps,
                "gpu_available": getattr(node, 'gpu_available', False),
                "ai_acceleration": getattr(node, 'ai_acceleration', False)
            },
            "geographic_info": {
                "latitude": node.latitude,
                "longitude": node.longitude,
                "region": node.region
            },
            "supported_services": getattr(node, 'supported_services', [])
        }
        
        # Include detailed metrics if requested
        if include_detailed_metrics:
            enhanced_details["detailed_metrics"] = await manager.get_node_performance_history(node_id)
        
        return {
            "success": True,
            "data": enhanced_details,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get edge node {node_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{node_id}")
async def update_edge_node(
    node_id: str,
    update_data: EdgeNodeUpdate,
    current_user: Dict = Depends(require_admin)
) -> Dict[str, Any]:
    """Update edge node configuration."""
    try:
        manager = get_edge_computing_manager()
        
        if node_id not in manager.edge_nodes:
            raise HTTPException(status_code=404, detail=f"Edge node {node_id} not found")
        
        node = manager.edge_nodes[node_id]
        
        # Update node properties
        update_dict = update_data.dict(exclude_unset=True)
        for key, value in update_dict.items():
            if hasattr(node, key):
                setattr(node, key, value)
        
        # Update routing table if location changed
        if 'latitude' in update_dict or 'longitude' in update_dict or 'region' in update_dict:
            await manager._update_routing_table()
        
        logger.info(f"✅ Edge node {node_id} updated by {current_user.get('username')}")
        
        return {
            "success": True,
            "message": f"Edge node {node_id} updated successfully",
            "updated_fields": list(update_dict.keys()),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to update edge node {node_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{node_id}")
async def remove_edge_node(
    node_id: str,
    force: bool = Query(False, description="Force removal even if node is active"),
    current_user: Dict = Depends(require_admin)
) -> Dict[str, Any]:
    """Remove an edge node from the system."""
    try:
        manager = get_edge_computing_manager()
        
        if node_id not in manager.edge_nodes:
            raise HTTPException(status_code=404, detail=f"Edge node {node_id} not found")
        
        node = manager.edge_nodes[node_id]
        
        # Check if node is active and force is not set
        if node.is_active and not force:
            raise HTTPException(
                status_code=400, 
                detail="Cannot remove active node. Use force=true to override."
            )
        
        # Remove the node
        success = await manager.remove_edge_node(node_id)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to remove edge node")
        
        logger.info(f"✅ Edge node {node_id} removed by {current_user.get('username')}")
        
        return {
            "success": True,
            "message": f"Edge node {node_id} removed successfully",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to remove edge node {node_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
