# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ....clustering import cluster_manager
from ....clustering.core.cluster_manager import NodeStatus, NodeType
from ....clustering.core.cluster_update_manager import (
from ....clustering.core.load_balancer import LoadBalancingAlgorithm




    from plexichat.infrastructure.utils.auth import require_admin_auth,

    API,
    APIRouter,
    BaseModel,
    Clustering,
    Comprehensive,
    Depends,
    DistributedStorageManager,
    Endpoints,
    Field,
    HTTPBearer,
    HTTPException,
    Management,
    Query,
    UpdateType,
    Version,
    """,
    ....auth.dependencies,
    ....clustering.storage.distributed_storage_manager,
    ....core.versioning.update_system,
    ....core.versioning.version_manager,
    =,
    __name__,
    and,
    balancing,
    cluster,
    failover.,
    fastapi,
    fastapi.security,
    for,
    from,
    import,
    load,
    logger,
    logging.getLogger,
    management,
    plexichat.infrastructure.utils.auth,
    pydantic,
)
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
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Get cluster overview and metrics."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

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
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Get detailed cluster health information."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

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
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Get cluster topology visualization data."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

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
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """List cluster nodes with optional filtering."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

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
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Add a new node to the cluster."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

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
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Remove a node from the cluster."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

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
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Set node maintenance mode."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

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
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Get current load balancer configuration."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

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
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Update load balancer configuration."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

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
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Get load balancer statistics."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

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
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Get cluster performance metrics over time."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

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
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Get failover configuration."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

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
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Update failover configuration."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

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
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Get failover event history."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

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
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Test failover for a specific node."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

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


# Cluster Update Management
class ClusterUpdateRequest(BaseModel):
    target_version: str = Field(..., description="Target version (e.g., 0b1)")
    update_type: str = Field("upgrade", description="Update type: upgrade, downgrade, reinstall")
    strategy: str = Field("rolling", description="Update strategy: rolling, parallel")
    target_nodes: List[str] = Field([], description="Target node IDs (empty for all)")
    force: bool = Field(False, description="Force update without confirmation")


class ClusterUpdateResponse(BaseModel):
    operation_id: str
    target_version: str
    update_type: str
    strategy: str
    target_nodes: List[str]
    current_phase: str
    overall_progress: float
    estimated_completion: Optional[str]
    node_statuses: Dict[str, Any]


@router.post("/updates/plan", response_model=ClusterUpdateResponse)
async def plan_cluster_update(
    request: ClusterUpdateRequest,
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Plan a cluster-wide update operation."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

        # Import update system components
            ClusterUpdateManager,
            ClusterUpdateStrategy,
        )
        # Initialize cluster update manager if not exists
        if not hasattr(cluster_manager, 'update_manager'):
            cluster_manager.update_manager = ClusterUpdateManager(cluster_manager)
            await cluster_manager.if update_manager and hasattr(update_manager, "initialize"): update_manager.initialize()

        # Parse parameters
        target_version = Version.parse(request.target_version)
        update_type = UpdateType(request.update_type.upper())
        strategy = ClusterUpdateStrategy(request.strategy.upper())

        # Plan update
        operation = await cluster_manager.update_manager.plan_cluster_update(
            target_version=target_version,
            update_type=update_type,
            strategy=strategy,
            target_nodes=request.target_nodes if request.target_nodes else None
        )

        return ClusterUpdateResponse(
            operation_id=operation.operation_id,
            target_version=str(operation.target_version),
            update_type=operation.update_type.value,
            strategy=operation.strategy.value,
            target_nodes=operation.target_nodes,
            current_phase=operation.current_phase.value,
            overall_progress=operation.overall_progress,
            estimated_completion=operation.estimated_completion.isoformat() if operation.estimated_completion else None,
            node_statuses={node_id: status.to_dict() for node_id, status in operation.node_statuses.items()}
        )

    except Exception as e:
        logger.error(f"Failed to plan cluster update: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/updates/{operation_id}/execute")
async def execute_cluster_update(
    operation_id: str,
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Execute a planned cluster update operation."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

        if not hasattr(cluster_manager, 'update_manager'):
            raise HTTPException(status_code=400, detail="Update manager not initialized")

        # Execute update in background
        asyncio.create_task(cluster_manager.update_manager.execute_cluster_update(operation_id))

        return {"message": f"Cluster update {operation_id} started", "operation_id": operation_id}

    except Exception as e:
        logger.error(f"Failed to execute cluster update: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/updates/{operation_id}/status", response_model=ClusterUpdateResponse)
async def get_cluster_update_status(
    operation_id: str,
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Get status of a cluster update operation."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

        if not hasattr(cluster_manager, 'update_manager'):
            raise HTTPException(status_code=400, detail="Update manager not initialized")

        status = cluster_manager.update_manager.get_operation_status(operation_id)
        if not status:
            raise HTTPException(status_code=404, detail=f"Operation {operation_id} not found")

        return ClusterUpdateResponse(**status)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get cluster update status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/updates/active", response_model=List[ClusterUpdateResponse])
async def list_active_cluster_updates(
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """List all active cluster update operations."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

        if not hasattr(cluster_manager, 'update_manager'):
            return []

        operations = cluster_manager.update_manager.list_active_operations()
        return [ClusterUpdateResponse(**op) for op in operations]

    except Exception as e:
        logger.error(f"Failed to list active cluster updates: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/updates/history")
async def get_cluster_update_history(
    limit: int = Query(10, description="Number of operations to return"),
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Get cluster update operation history."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

        if not hasattr(cluster_manager, 'update_manager'):
            return []

        history = cluster_manager.update_manager.list_operation_history(limit)
        return history

    except Exception as e:
        logger.error(f"Failed to get cluster update history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/updates/{operation_id}/rollback")
async def rollback_cluster_update(
    operation_id: str,
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Rollback a cluster update operation."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

        if not hasattr(cluster_manager, 'update_manager'):
            raise HTTPException(status_code=400, detail="Update manager not initialized")

        # Get operation
        operation = cluster_manager.update_manager.active_operations.get(operation_id)
        if not operation:
            raise HTTPException(status_code=404, detail=f"Operation {operation_id} not found")

        # Initiate rollback
        await cluster_manager.update_manager._rollback_cluster_update(operation)

        return {"message": f"Rollback initiated for operation {operation_id}"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to rollback cluster update: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Distributed Storage Management
class StorageOverviewResponse(BaseModel):
    total_nodes: int
    healthy_nodes: int
    total_capacity_gb: float
    used_capacity_gb: float
    available_capacity_gb: float
    usage_percentage: float
    total_data_objects: int
    replication_factor: int
    storage_strategy: str
    consistency_level: str


class StorageNodeResponse(BaseModel):
    node_id: str
    hostname: str
    ip_address: str
    port: int
    node_type: str
    total_capacity_gb: float
    used_capacity_gb: float
    available_capacity_gb: float
    usage_percentage: float
    performance_score: float
    reliability_score: float
    geographic_region: str
    last_heartbeat: str
    status: str
    is_healthy: bool


@router.get("/storage/overview", response_model=StorageOverviewResponse)
async def get_storage_overview(
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Get distributed storage system overview."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

        # Initialize storage manager if not exists
        if not hasattr(cluster_manager, 'storage_manager'):
            cluster_manager.storage_manager = DistributedStorageManager(cluster_manager)
            await cluster_manager.if storage_manager and hasattr(storage_manager, "initialize"): storage_manager.initialize()

        overview = cluster_manager.storage_manager.get_storage_overview()
        return StorageOverviewResponse(**overview)

    except Exception as e:
        logger.error(f"Failed to get storage overview: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/storage/nodes", response_model=List[StorageNodeResponse])
async def list_storage_nodes(
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """List all storage nodes with details."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

        if not hasattr(cluster_manager, 'storage_manager'):
            cluster_manager.storage_manager = DistributedStorageManager(cluster_manager)
            await cluster_manager.if storage_manager and hasattr(storage_manager, "initialize"): storage_manager.initialize()

        nodes = cluster_manager.storage_manager.get_node_details()
        return [StorageNodeResponse(**node) for node in nodes]

    except Exception as e:
        logger.error(f"Failed to list storage nodes: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/storage/distribution")
async def get_data_distribution(
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Get data distribution statistics across storage nodes."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

        if not hasattr(cluster_manager, 'storage_manager'):
            cluster_manager.storage_manager = DistributedStorageManager(cluster_manager)
            await cluster_manager.if storage_manager and hasattr(storage_manager, "initialize"): storage_manager.initialize()

        distribution = cluster_manager.storage_manager.get_data_distribution()
        return distribution

    except Exception as e:
        logger.error(f"Failed to get data distribution: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/storage/rebalance")
async def trigger_storage_rebalance(
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Trigger manual storage rebalancing."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

        if not hasattr(cluster_manager, 'storage_manager'):
            raise HTTPException(status_code=400, detail="Storage manager not initialized")

        # Trigger rebalancing in background
        asyncio.create_task(cluster_manager.storage_manager._rebalance_storage())

        return {"message": "Storage rebalancing initiated"}

    except Exception as e:
        logger.error(f"Failed to trigger storage rebalance: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/storage/cleanup")
async def trigger_storage_cleanup(
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Trigger manual storage cleanup."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

        if not hasattr(cluster_manager, 'storage_manager'):
            raise HTTPException(status_code=400, detail="Storage manager not initialized")

        # Trigger cleanup in background
        asyncio.create_task(cluster_manager.storage_manager._cleanup_orphaned_data())

        return {"message": "Storage cleanup initiated"}

    except Exception as e:
        logger.error(f"Failed to trigger storage cleanup: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Hot Updates (Legacy)
@router.post("/hot-update")
async def perform_hot_update(
    update_package: str,
    target_nodes: List[str] = Query([], description="Target node IDs (empty for all)"),
    rollback_on_failure: bool = Query(True, description="Rollback on failure"),
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Perform hot update across cluster nodes (legacy endpoint)."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

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
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Get status of hot update operation."""
    try:
        if not cluster_manager.initialized:
            await if cluster_manager and hasattr(cluster_manager, "initialize"): cluster_manager.initialize()

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
