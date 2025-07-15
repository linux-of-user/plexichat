import statistics
from datetime import datetime, timezone
from typing import Any, Dict, Optional


from ....core.auth import (
from ....core.logging import get_logger
from ....core.performance.edge_computing_manager import get_edge_computing_manager





from fastapi import APIRouter, Depends, HTTPException, Query

    from plexichat.infrastructure.utils.auth import require_admin,

    from,
    import,
    plexichat.infrastructure.utils.auth,
    require_auth,
)
"""
PlexiChat Edge Computing API Endpoints

Provides REST API endpoints for managing edge computing and auto-scaling functionality.
"""

logger = get_logger(__name__)

# Create API router
router = APIRouter(prefix="/api/v1/edge", tags=["Edge Computing"])


@router.get("/status")
async def get_edge_status(
    current_user: Dict = Depends(require_auth)
) -> Dict[str, Any]:
    """Get comprehensive edge computing system status."""
    try:
        manager = get_edge_computing_manager()

        if not manager.initialized:
            await if manager and hasattr(manager, "initialize"): manager.initialize()

        status = await manager.get_edge_status()

        return {
            "success": True,
            "data": status,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        logger.error(f" Failed to get edge status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/nodes")
async def list_edge_nodes(
    node_type: Optional[str] = Query(None, description="Filter by node type"),
    region: Optional[str] = Query(None, description="Filter by region"),
    active_only: bool = Query(True, description="Show only active nodes"),
    current_user: Dict = Depends(require_auth)
) -> Dict[str, Any]:
    """List all edge nodes with optional filtering."""
    try:
        manager = get_edge_computing_manager()

        nodes = []
        for node_id, node in manager.edge_nodes.items():
            # Apply filters
            if active_only and not node.is_active:
                continue

            if node_type and node.node_type.value != node_type:
                continue

            if region and node.region != region:
                continue

            # Get node details
            node_details = await manager.get_node_details(node_id)
            if node_details:
                nodes.append(node_details)

        return {
            "success": True,
            "data": {
                "nodes": nodes,
                "total_count": len(nodes),
                "filters_applied": {
                    "node_type": node_type,
                    "region": region,
                    "active_only": active_only
                }
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        logger.error(f" Failed to list edge nodes: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/nodes/{node_id}")
async def get_node_details(
    node_id: str,
    current_user: Dict = Depends(require_auth)
) -> Dict[str, Any]:
    """Get detailed information about a specific edge node."""
    try:
        manager = get_edge_computing_manager()

        node_details = await manager.get_node_details(node_id)

        if not node_details:
            raise HTTPException(status_code=404, detail=f"Node {node_id} not found")

        return {
            "success": True,
            "data": node_details,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Failed to get node details for {node_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/nodes/{node_id}/actions/drain")
async def drain_node(
    node_id: str,
    current_user: Dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin)
) -> Dict[str, Any]:
    """Gracefully drain connections from a node."""
    try:
        manager = get_edge_computing_manager()

        if node_id not in manager.edge_nodes:
            raise HTTPException(status_code=404, detail=f"Node {node_id} not found")

        # Start draining process
        await manager._drain_node_connections(node_id)

        logger.info(f" Node {node_id} draining initiated by {current_user.get('username')}")

        return {
            "success": True,
            "message": f"Node {node_id} draining initiated",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Failed to drain node {node_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/nodes/{node_id}/actions/activate")
async def activate_node(
    node_id: str,
    current_user: Dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin)
) -> Dict[str, Any]:
    """Activate a deactivated node."""
    try:
        manager = get_edge_computing_manager()

        if node_id not in manager.edge_nodes:
            raise HTTPException(status_code=404, detail=f"Node {node_id} not found")

        node = manager.edge_nodes[node_id]
        node.is_active = True
        node.is_healthy = True  # Assume healthy when manually activated

        # Update routing table
        await manager._update_routing_table()

        logger.info(f" Node {node_id} activated by {current_user.get('username')}")

        return {
            "success": True,
            "message": f"Node {node_id} activated",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Failed to activate node {node_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/nodes/{node_id}/actions/deactivate")
async def deactivate_node(
    node_id: str,
    current_user: Dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin)
) -> Dict[str, Any]:
    """Deactivate a node (remove from routing)."""
    try:
        manager = get_edge_computing_manager()

        if node_id not in manager.edge_nodes:
            raise HTTPException(status_code=404, detail=f"Node {node_id} not found")

        # Drain connections first
        await manager._drain_node_connections(node_id)

        # Remove from routing
        await manager._remove_node_from_routing(node_id)

        # Deactivate
        node = manager.edge_nodes[node_id]
        node.is_active = False

        logger.info(f" Node {node_id} deactivated by {current_user.get('username')}")

        return {
            "success": True,
            "message": f"Node {node_id} deactivated",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Failed to deactivate node {node_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scaling/status")
async def get_scaling_status(
    current_user: Dict = Depends(require_auth)
) -> Dict[str, Any]:
    """Get auto-scaling system status and recent decisions."""
    try:
        manager = get_edge_computing_manager()

        # Get recent scaling decisions
        recent_decisions = []
        for decision in list(manager.scaling_decisions)[-10:]:  # Last 10 decisions
            recent_decisions.append({
                "action": decision.action.value,
                "target_nodes": decision.target_nodes,
                "reason": decision.reason,
                "confidence": decision.confidence,
                "estimated_impact": decision.estimated_impact,
                "timestamp": decision.timestamp.isoformat()
            })

        return {
            "success": True,
            "data": {
                "auto_scaling_enabled": manager.config.get("auto_scaling_enabled", True),
                "scaling_cooldown_seconds": manager.scaling_cooldown_seconds,
                "last_scaling_action": manager.last_scaling_action.isoformat() if manager.last_scaling_action else None,
                "min_nodes": manager.min_nodes,
                "max_nodes": manager.max_nodes,
                "current_active_nodes": len([n for n in manager.edge_nodes.values() if n.is_active]),
                "recent_decisions": recent_decisions,
                "scaling_statistics": {
                    "total_scaling_actions": manager.edge_stats["scaling_actions_taken"],
                    "nodes_added": manager.edge_stats["nodes_added"],
                    "nodes_removed": manager.edge_stats["nodes_removed"]
                }
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        logger.error(f" Failed to get scaling status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scaling/actions/scale-up")
async def manual_scale_up(
    node_count: int = Query(1, description="Number of nodes to add"),
    current_user: Dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin)
) -> Dict[str, Any]:
    """Manually trigger scale-up operation."""
    try:
        manager = get_edge_computing_manager()

        if node_count < 1 or node_count > 10:
            raise HTTPException(status_code=400, detail="Node count must be between 1 and 10")

        # Check if we can scale up
        current_nodes = len([n for n in manager.edge_nodes.values() if n.is_active])
        if current_nodes + node_count > manager.max_nodes:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot scale up: would exceed maximum nodes ({manager.max_nodes})"
            )

        # Create target nodes list
        target_nodes = [f"manual_scale_up_{i}" for i in range(node_count)]

        # Execute scaling
        success = await manager._scale_up_nodes(target_nodes)

        if success:
            manager.edge_stats["scaling_actions_taken"] += 1
            manager.edge_stats["nodes_added"] += node_count

            logger.info(f" Manual scale-up of {node_count} nodes by {current_user.get('username')}")

            return {
                "success": True,
                "message": f"Successfully scaled up {node_count} nodes",
                "nodes_added": node_count,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Scale-up operation failed")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Failed to execute manual scale-up: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/routing/status")
async def get_routing_status(
    current_user: Dict = Depends(require_auth)
) -> Dict[str, Any]:
    """Get traffic routing system status."""
    try:
        manager = get_edge_computing_manager()

        # Get routing table summary
        routing_summary = {}
        for service, nodes in manager.routing_table.items():
            active_nodes = [
                node_id for node_id in nodes
                if node_id in manager.edge_nodes and manager.edge_nodes[node_id].is_active
            ]
            routing_summary[service] = {
                "total_nodes": len(nodes),
                "active_nodes": len(active_nodes),
                "node_ids": active_nodes
            }

        # Get traffic patterns summary
        traffic_summary = {}
        for service, weights in manager.traffic_patterns.items():
            total_weight = sum(weights.values())
            traffic_summary[service] = {
                "total_weight": total_weight,
                "node_count": len(weights),
                "average_weight": total_weight / len(weights) if weights else 0
            }

        return {
            "success": True,
            "data": {
                "geographic_routing_enabled": manager.enable_geographic_routing,
                "max_routing_distance_km": manager.max_routing_distance_km,
                "load_balancing_algorithm": manager.config.get("load_balancing_algorithm", "weighted_round_robin"),
                "routing_table": routing_summary,
                "traffic_patterns": traffic_summary,
                "statistics": {
                    "total_requests_routed": manager.edge_stats["total_requests_routed"],
                    "average_response_time_ms": manager.edge_stats["average_response_time_ms"],
                    "failovers_performed": manager.edge_stats["failovers_performed"]
                }
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        logger.error(f" Failed to get routing status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics")
async def get_edge_metrics(
    hours: int = Query(1, description="Hours of metrics to retrieve"),
    current_user: Dict = Depends(require_auth)
) -> Dict[str, Any]:
    """Get edge computing performance metrics."""
    try:
        manager = get_edge_computing_manager()

        if hours < 1 or hours > 168:  # Max 1 week
            raise HTTPException(status_code=400, detail="Hours must be between 1 and 168")

        # Get recent metrics
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        recent_metrics = [
            m for m in manager.load_history
            if m.timestamp >= cutoff_time
        ]

        if not recent_metrics:
            return {
                "success": True,
                "data": {
                    "metrics": [],
                    "summary": {},
                    "period_hours": hours
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        # Convert metrics to API format
        metrics_data = []
        for metric in recent_metrics:
            metrics_data.append({
                "timestamp": metric.timestamp.isoformat(),
                "requests_per_second": metric.total_requests_per_second,
                "response_time_ms": metric.average_response_time_ms,
                "error_rate_percent": metric.error_rate_percent,
                "cpu_usage_percent": metric.cpu_usage_percent,
                "memory_usage_percent": metric.memory_usage_percent,
                "network_usage_percent": metric.network_usage_percent,
                "active_connections": metric.active_connections,
                "queue_depth": metric.queue_depth
            })

        # Calculate summary statistics
        summary = {
            "avg_requests_per_second": statistics.mean([m.total_requests_per_second for m in recent_metrics]),
            "avg_response_time_ms": statistics.mean([m.average_response_time_ms for m in recent_metrics]),
            "avg_error_rate_percent": statistics.mean([m.error_rate_percent for m in recent_metrics]),
            "avg_cpu_usage_percent": statistics.mean([m.cpu_usage_percent for m in recent_metrics]),
            "avg_memory_usage_percent": statistics.mean([m.memory_usage_percent for m in recent_metrics]),
            "max_response_time_ms": max([m.average_response_time_ms for m in recent_metrics]),
            "max_error_rate_percent": max([m.error_rate_percent for m in recent_metrics]),
            "total_data_points": len(recent_metrics)
        }

        return {
            "success": True,
            "data": {
                "metrics": metrics_data,
                "summary": summary,
                "period_hours": hours
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Failed to get edge metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/initialize")
async def initialize_edge_computing(
    current_user: Dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin)
) -> Dict[str, Any]:
    """Initialize or reinitialize the edge computing system."""
    try:
        manager = get_edge_computing_manager()

        result = await if manager and hasattr(manager, "initialize"): manager.initialize()

        logger.info(f" Edge computing system initialized by {current_user.get('username')}")

        return {
            "success": True,
            "data": result,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        logger.error(f" Failed to initialize edge computing: {e}")
        raise HTTPException(status_code=500, detail=str(e))
