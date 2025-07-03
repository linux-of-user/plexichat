"""
Clustering Management API Endpoints
Comprehensive API for cluster management, load balancing, and failover.
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query
from fastapi.security import HTTPBearer
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field
import logging

from ....clustering import cluster_manager
from ....auth.dependencies import require_admin_auth, get_current_user
from ....core.exceptions import NetLinkException

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/clustering", tags=["clustering"])
security = HTTPBearer()


# Request/Response Models
class ClusterNodeRequest(BaseModel):
    name: str = Field(..., description="Node name")
    address: str = Field(..., description="Node address (host:port)")
    node_type: str = Field("main", description="Node type: main, gateway, antivirus, backup")
    encryption_enabled: bool = Field(True, description="Enable encrypted communication")
    max_connections: int = Field(1000, description="Maximum connections")
    weight: float = Field(1.0, description="Load balancing weight")


class ClusterNodeResponse(BaseModel):
    node_id: str
    name: str
    address: str
    node_type: str
    status: str
    last_seen: datetime
    connections: int
    cpu_usage: float
    memory_usage: float
    performance_score: float


class LoadBalancerConfig(BaseModel):
    algorithm: str = Field("ai_optimized", description="Load balancing algorithm")
    health_check_interval: int = Field(30, description="Health check interval in seconds")
    failure_threshold: int = Field(3, description="Failure threshold for failover")
    enable_sticky_sessions: bool = Field(False, description="Enable sticky sessions")


class FailoverConfig(BaseModel):
    enabled: bool = Field(True, description="Enable automatic failover")
    health_check_interval: int = Field(30, description="Health check interval in seconds")
    failure_threshold: int = Field(3, description="Failure threshold")
    recovery_timeout: int = Field(300, description="Recovery timeout in seconds")


class ClusterOverviewResponse(BaseModel):
    total_nodes: int
    active_nodes: int
    cluster_load: float
    performance_gain: float
    failover_events: int
    last_failover: Optional[datetime]


class TopologyNode(BaseModel):
    node_id: str
    name: str
    node_type: str
    status: str
    position: Dict[str, float]
    connections: List[str]


class TopologyResponse(BaseModel):
    nodes: List[TopologyNode]
    connections: List[Dict[str, Any]]
    cluster_health: str


# Overview and Status Endpoints
@router.get("/overview", response_model=ClusterOverviewResponse)
async def get_cluster_overview(
    current_user: dict = Depends(require_admin_auth)
):
    """Get cluster overview and metrics."""
    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()
        
        overview = await cluster_manager.get_cluster_overview()
        
        return ClusterOverviewResponse(
            total_nodes=overview.total_nodes,
            active_nodes=overview.active_nodes,
            cluster_load=overview.cluster_load_percentage,
            performance_gain=overview.performance_improvement_percentage,
            failover_events=overview.total_failover_events,
            last_failover=overview.last_failover_timestamp
        )
    except Exception as e:
        logger.error(f"Error getting cluster overview: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get cluster overview: {str(e)}")


@router.get("/health")
async def get_cluster_health(
    current_user: dict = Depends(require_admin_auth)
):
    """Get detailed cluster health information."""
    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()
        
        health = await cluster_manager.get_cluster_health()
        
        return {
            "overall_status": health.overall_status.value,
            "node_health": [
                {
                    "node_id": node.node_id,
                    "status": node.status.value,
                    "health_score": node.health_score,
                    "last_check": node.last_health_check.isoformat(),
                    "issues": node.health_issues
                }
                for node in health.node_health_status
            ],
            "cluster_metrics": {
                "total_requests": health.total_requests_processed,
                "average_response_time": health.average_response_time_ms,
                "error_rate": health.error_rate_percentage,
                "throughput": health.requests_per_second
            }
        }
    except Exception as e:
        logger.error(f"Error getting cluster health: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get cluster health: {str(e)}")


@router.get("/topology", response_model=TopologyResponse)
async def get_cluster_topology(
    current_user: dict = Depends(require_admin_auth)
):
    """Get cluster topology visualization data."""
    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()
        
        topology = await cluster_manager.get_cluster_topology()
        
        nodes = []
        for node in topology.nodes:
            nodes.append(TopologyNode(
                node_id=node.node_id,
                name=node.name,
                node_type=node.node_type.value,
                status=node.status.value,
                position={"x": node.position_x, "y": node.position_y},
                connections=node.connected_node_ids
            ))
        
        return TopologyResponse(
            nodes=nodes,
            connections=topology.connections,
            cluster_health=topology.overall_health.value
        )
    except Exception as e:
        logger.error(f"Error getting cluster topology: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get cluster topology: {str(e)}")


# Node Management
@router.get("/nodes", response_model=List[ClusterNodeResponse])
async def list_cluster_nodes(
    status_filter: Optional[str] = Query(None, description="Filter by node status"),
    node_type_filter: Optional[str] = Query(None, description="Filter by node type"),
    current_user: dict = Depends(require_admin_auth)
):
    """List cluster nodes with optional filtering."""
    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()
        
        from ....clustering.core.cluster_manager import NodeStatus, NodeType
        
        # Convert filters to enums
        status_enum = None
        if status_filter:
            try:
                status_enum = NodeStatus(status_filter.upper())
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid status filter: {status_filter}")
        
        type_enum = None
        if node_type_filter:
            try:
                type_enum = NodeType(node_type_filter.upper())
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid node type filter: {node_type_filter}")
        
        nodes = await cluster_manager.list_nodes(
            status_filter=status_enum,
            node_type_filter=type_enum
        )
        
        return [
            ClusterNodeResponse(
                node_id=node.node_id,
                name=node.name,
                address=node.address,
                node_type=node.node_type.value,
                status=node.status.value,
                last_seen=node.last_seen,
                connections=node.current_connections,
                cpu_usage=node.cpu_usage_percentage,
                memory_usage=node.memory_usage_percentage,
                performance_score=node.performance_score
            )
            for node in nodes
        ]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing cluster nodes: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list cluster nodes: {str(e)}")


@router.post("/nodes", response_model=ClusterNodeResponse)
async def add_cluster_node(
    request: ClusterNodeRequest,
    current_user: dict = Depends(require_admin_auth)
):
    """Add a new node to the cluster."""
    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()
        
        from ....clustering.core.cluster_manager import NodeType
        
        # Convert node type to enum
        try:
            node_type_enum = NodeType(request.node_type.upper())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid node type: {request.node_type}")
        
        node = await cluster_manager.add_node(
            name=request.name,
            address=request.address,
            node_type=node_type_enum,
            encryption_enabled=request.encryption_enabled,
            max_connections=request.max_connections,
            weight=request.weight
        )
        
        return ClusterNodeResponse(
            node_id=node.node_id,
            name=node.name,
            address=node.address,
            node_type=node.node_type.value,
            status=node.status.value,
            last_seen=node.last_seen,
            connections=node.current_connections,
            cpu_usage=node.cpu_usage_percentage,
            memory_usage=node.memory_usage_percentage,
            performance_score=node.performance_score
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding cluster node: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to add cluster node: {str(e)}")


@router.delete("/nodes/{node_id}")
async def remove_cluster_node(
    node_id: str,
    force: bool = Query(False, description="Force removal even if node is active"),
    current_user: dict = Depends(require_admin_auth)
):
    """Remove a node from the cluster."""
    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()
        
        success = await cluster_manager.remove_node(node_id, force=force)
        
        if not success:
            raise HTTPException(status_code=400, detail="Failed to remove node")
        
        return {
            "message": "Node removed successfully",
            "node_id": node_id,
            "forced": force
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing cluster node: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to remove cluster node: {str(e)}")


@router.post("/nodes/{node_id}/maintenance")
async def set_node_maintenance(
    node_id: str,
    enable: bool = Query(True, description="Enable or disable maintenance mode"),
    current_user: dict = Depends(require_admin_auth)
):
    """Set node maintenance mode."""
    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()
        
        if enable:
            await cluster_manager.enable_node_maintenance(node_id)
            message = "Node maintenance mode enabled"
        else:
            await cluster_manager.disable_node_maintenance(node_id)
            message = "Node maintenance mode disabled"
        
        return {
            "message": message,
            "node_id": node_id,
            "maintenance_enabled": enable
        }
    except Exception as e:
        logger.error(f"Error setting node maintenance: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to set node maintenance: {str(e)}")


# Load Balancer Management
@router.get("/load-balancer/config")
async def get_load_balancer_config(
    current_user: dict = Depends(require_admin_auth)
):
    """Get current load balancer configuration."""
    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()
        
        config = await cluster_manager.get_load_balancer_config()
        
        return {
            "algorithm": config.algorithm.value,
            "health_check_interval": config.health_check_interval_seconds,
            "failure_threshold": config.failure_threshold,
            "sticky_sessions_enabled": config.sticky_sessions_enabled,
            "weights": config.node_weights,
            "ai_optimization_enabled": config.ai_optimization_enabled
        }
    except Exception as e:
        logger.error(f"Error getting load balancer config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get load balancer config: {str(e)}")


@router.put("/load-balancer/config")
async def update_load_balancer_config(
    config: LoadBalancerConfig,
    current_user: dict = Depends(require_admin_auth)
):
    """Update load balancer configuration."""
    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()
        
        from ....clustering.core.load_balancer import LoadBalancingAlgorithm
        
        # Convert algorithm to enum
        try:
            algorithm_enum = LoadBalancingAlgorithm(config.algorithm.upper())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid algorithm: {config.algorithm}")
        
        await cluster_manager.update_load_balancer_config(
            algorithm=algorithm_enum,
            health_check_interval=config.health_check_interval,
            failure_threshold=config.failure_threshold,
            sticky_sessions_enabled=config.enable_sticky_sessions
        )
        
        return {
            "message": "Load balancer configuration updated",
            "algorithm": config.algorithm,
            "health_check_interval": config.health_check_interval,
            "failure_threshold": config.failure_threshold
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating load balancer config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update load balancer config: {str(e)}")


@router.get("/load-balancer/stats")
async def get_load_balancer_stats(
    current_user: dict = Depends(require_admin_auth)
):
    """Get load balancer statistics."""
    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()
        
        stats = await cluster_manager.get_load_balancer_stats()
        
        return {
            "total_requests": stats.total_requests,
            "requests_per_second": stats.current_rps,
            "average_response_time": stats.average_response_time_ms,
            "node_distribution": stats.node_request_distribution,
            "algorithm_performance": stats.algorithm_performance_metrics,
            "failover_count": stats.total_failovers,
            "last_updated": stats.last_updated.isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting load balancer stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get load balancer stats: {str(e)}")


# Performance Monitoring
@router.get("/performance/metrics")
async def get_performance_metrics(
    time_range: str = Query("1h", description="Time range: 1h, 6h, 24h, 7d"),
    current_user: dict = Depends(require_admin_auth)
):
    """Get cluster performance metrics over time."""
    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()
        
        metrics = await cluster_manager.get_performance_metrics(time_range)
        
        return {
            "time_range": time_range,
            "metrics": [
                {
                    "timestamp": metric.timestamp.isoformat(),
                    "total_requests": metric.total_requests,
                    "response_time_ms": metric.average_response_time_ms,
                    "throughput_rps": metric.requests_per_second,
                    "error_rate": metric.error_rate_percentage,
                    "cpu_usage": metric.cluster_cpu_usage_percentage,
                    "memory_usage": metric.cluster_memory_usage_percentage,
                    "performance_gain": metric.performance_improvement_percentage
                }
                for metric in metrics
            ]
        }
    except Exception as e:
        logger.error(f"Error getting performance metrics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get performance metrics: {str(e)}")


# Failover Management
@router.get("/failover/config")
async def get_failover_config(
    current_user: dict = Depends(require_admin_auth)
):
    """Get failover configuration."""
    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()
        
        config = await cluster_manager.get_failover_config()
        
        return {
            "enabled": config.enabled,
            "health_check_interval": config.health_check_interval_seconds,
            "failure_threshold": config.failure_threshold,
            "recovery_timeout": config.recovery_timeout_seconds,
            "automatic_recovery": config.automatic_recovery_enabled,
            "notification_enabled": config.notification_enabled
        }
    except Exception as e:
        logger.error(f"Error getting failover config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get failover config: {str(e)}")


@router.put("/failover/config")
async def update_failover_config(
    config: FailoverConfig,
    current_user: dict = Depends(require_admin_auth)
):
    """Update failover configuration."""
    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()
        
        await cluster_manager.update_failover_config(
            enabled=config.enabled,
            health_check_interval=config.health_check_interval,
            failure_threshold=config.failure_threshold,
            recovery_timeout=config.recovery_timeout
        )
        
        return {
            "message": "Failover configuration updated",
            "enabled": config.enabled,
            "health_check_interval": config.health_check_interval,
            "failure_threshold": config.failure_threshold,
            "recovery_timeout": config.recovery_timeout
        }
    except Exception as e:
        logger.error(f"Error updating failover config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update failover config: {str(e)}")


@router.get("/failover/history")
async def get_failover_history(
    limit: int = Query(100, description="Maximum number of events to return"),
    current_user: dict = Depends(require_admin_auth)
):
    """Get failover event history."""
    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()
        
        events = await cluster_manager.get_failover_history(limit=limit)
        
        return {
            "events": [
                {
                    "event_id": event.event_id,
                    "event_type": event.event_type.value,
                    "node_id": event.node_id,
                    "node_name": event.node_name,
                    "timestamp": event.timestamp.isoformat(),
                    "reason": event.reason,
                    "recovery_time_seconds": event.recovery_time_seconds,
                    "impact_level": event.impact_level.value
                }
                for event in events
            ],
            "total_events": len(events)
        }
    except Exception as e:
        logger.error(f"Error getting failover history: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get failover history: {str(e)}")


@router.post("/failover/test")
async def test_failover(
    node_id: str,
    current_user: dict = Depends(require_admin_auth)
):
    """Test failover for a specific node."""
    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()
        
        test_result = await cluster_manager.test_failover(node_id)
        
        return {
            "message": "Failover test completed",
            "node_id": node_id,
            "test_successful": test_result.success,
            "failover_time_ms": test_result.failover_time_ms,
            "recovery_time_ms": test_result.recovery_time_ms,
            "details": test_result.details
        }
    except Exception as e:
        logger.error(f"Error testing failover: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to test failover: {str(e)}")


# Hot Updates
@router.post("/hot-update")
async def perform_hot_update(
    update_package: str,
    target_nodes: List[str] = Query([], description="Target node IDs (empty for all)"),
    rollback_on_failure: bool = Query(True, description="Rollback on failure"),
    current_user: dict = Depends(require_admin_auth)
):
    """Perform hot update across cluster nodes."""
    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()
        
        update_result = await cluster_manager.perform_hot_update(
            update_package=update_package,
            target_nodes=target_nodes if target_nodes else None,
            rollback_on_failure=rollback_on_failure
        )
        
        return {
            "message": "Hot update initiated",
            "update_id": update_result.update_id,
            "target_nodes": update_result.target_nodes,
            "estimated_completion": update_result.estimated_completion.isoformat(),
            "rollback_enabled": rollback_on_failure
        }
    except Exception as e:
        logger.error(f"Error performing hot update: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to perform hot update: {str(e)}")


@router.get("/hot-update/{update_id}/status")
async def get_hot_update_status(
    update_id: str,
    current_user: dict = Depends(require_admin_auth)
):
    """Get status of hot update operation."""
    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()
        
        status = await cluster_manager.get_hot_update_status(update_id)
        
        return {
            "update_id": update_id,
            "status": status.status.value,
            "progress_percentage": status.progress_percentage,
            "completed_nodes": status.completed_nodes,
            "failed_nodes": status.failed_nodes,
            "current_phase": status.current_phase,
            "error_message": status.error_message
        }
    except Exception as e:
        logger.error(f"Error getting hot update status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get hot update status: {str(e)}")
