import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional







from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect

from plexichat.core.auth.dependencies import (
    from plexichat.infrastructure.utils.auth import require_admin_auth,
from plexichat.core.logging import get_logger
from plexichat.infrastructure.services.performance_service import get_performance_service

    from,
    import,
    plexichat.infrastructure.utils.auth,
    require_auth,
)
"""
PlexiChat Performance Monitoring API Endpoints

Comprehensive REST API endpoints for performance monitoring, metrics collection,
alerting, and dashboard visualization. Provides real-time and historical
performance data across all PlexiChat components.

Features:
- Real-time metrics API
- Historical data retrieval
- Performance alerts management
- Dashboard data aggregation
- Custom metrics collection
- Performance analytics
- Health scoring
- Trend analysis
"""

# Initialize router and logger
router = APIRouter(prefix="/performance", tags=["Performance Monitoring"])
logger = get_logger(__name__)

# WebSocket connection manager for real-time metrics
class MetricsConnectionManager:
    """Manages WebSocket connections for real-time metrics streaming."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.connection_filters: Dict[WebSocket, Dict[str, Any]] = {}

    async def connect(self, websocket: WebSocket, filters: Optional[Dict[str, Any]] = None):
        """Accept WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        if filters:
            self.connection_filters[websocket] = filters
        logger.info(f"Performance metrics WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if websocket in self.connection_filters:
            del self.connection_filters[websocket]
        logger.info(f"Performance metrics WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast_metrics(self, metrics_data: Dict[str, Any]):
        """Broadcast metrics to all connected clients."""
        if not self.active_connections:
            return

        disconnected = []
        for connection in self.active_connections:
            try:
                # Apply filters if specified
                filtered_data = self._apply_filters(metrics_data, self.connection_filters.get(connection, {}))
                await connection.send_text(json.dumps(filtered_data))
            except Exception as e:
                logger.error(f"Error broadcasting to WebSocket: {e}")
                disconnected.append(connection)

        # Clean up disconnected connections
        for connection in disconnected:
            self.disconnect(connection)

    def _apply_filters(self, data: Dict[str, Any], filters: Dict[str, Any]) -> Dict[str, Any]:
        """Apply filters to metrics data."""
        if not filters:
            return data

        filtered_data = {}

        # Filter by metric types
        if "metric_types" in filters:
            for metric_type in filters["metric_types"]:
                if metric_type in data:
                    filtered_data[metric_type] = data[metric_type]
        else:
            filtered_data = data

        # Filter by time range
        if "time_range" in filters:
            # This would implement time-based filtering
            pass

        return filtered_data

# Global connection manager
metrics_manager = MetricsConnectionManager()

# Background task for broadcasting metrics
async def metrics_broadcast_task():
    """Background task to broadcast metrics to WebSocket clients."""
    while True:
        try:
            performance_service = await get_performance_service()
            current_metrics = performance_service.get_current_metrics()

            # Add timestamp
            current_metrics["timestamp"] = datetime.now(timezone.utc).isoformat()

            await metrics_manager.broadcast_metrics(current_metrics)
            await asyncio.sleep(5)  # Broadcast every 5 seconds

        except Exception as e:
            logger.error(f"Metrics broadcast error: {e}")
            await asyncio.sleep(10)

# Start broadcast task
asyncio.create_task(metrics_broadcast_task())

# REST API Endpoints

@router.get("/metrics/current")
async def get_current_metrics(
    metric_types: Optional[str] = Query(None, description="Comma-separated list of metric types to include"),
    current_user: dict = Depends(require_auth)
):
    """Get current performance metrics."""
    try:
        performance_service = await get_performance_service()
        metrics = performance_service.get_current_metrics()

        # Filter by metric types if specified
        if metric_types:
            requested_types = [t.strip() for t in metric_types.split(",")]
            metrics = {k: v for k, v in metrics.items() if k in requested_types}

        return {
            "status": "success",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metrics": metrics
        }

    except Exception as e:
        logger.error(f"Error getting current metrics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get current metrics: {str(e)}")

@router.get("/metrics/historical")
async def get_historical_metrics(
    hours: int = Query(1, description="Number of hours of historical data", ge=1, le=168),
    metric_types: Optional[str] = Query(None, description="Comma-separated list of metric types"),
    resolution: str = Query("5m", description="Data resolution: 1m, 5m, 15m, 1h"),
    current_user: dict = Depends(require_auth)
):
    """Get historical performance metrics."""
    try:
        performance_service = await get_performance_service()
        metrics = performance_service.get_historical_metrics(hours)

        # Filter by metric types if specified
        if metric_types:
            requested_types = [t.strip() for t in metric_types.split(",")]
            metrics = {k: v for k, v in metrics.items() if k in requested_types}

        # Apply resolution downsampling if needed
        if resolution != "raw":
            metrics = _downsample_metrics(metrics, resolution)

        return {
            "status": "success",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "time_range": f"{hours}h",
            "resolution": resolution,
            "metrics": metrics
        }

    except Exception as e:
        logger.error(f"Error getting historical metrics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get historical metrics: {str(e)}")

@router.get("/summary")
async def get_performance_summary(
    current_user: dict = Depends(require_auth)
):
    """Get comprehensive performance summary."""
    try:
        performance_service = await get_performance_service()
        summary = performance_service.get_performance_summary()

        return {
            "status": "success",
            "summary": summary
        }

    except Exception as e:
        logger.error(f"Error getting performance summary: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get performance summary: {str(e)}")

@router.get("/health")
async def get_system_health(
    current_user: dict = Depends(require_auth)
):
    """Get system health status."""
    try:
        performance_service = await get_performance_service()
        current_metrics = performance_service.get_current_metrics()

        # Calculate health indicators
        health_status = {
            "overall_score": performance_service._calculate_health_score(current_metrics),
            "components": {
                "system": _calculate_component_health(current_metrics.get("system")),
                "application": _calculate_component_health(current_metrics.get("application")),
                "database": _calculate_component_health(current_metrics.get("database")),
                "cluster": _calculate_component_health(current_metrics.get("cluster")),
                "ai": _calculate_component_health(current_metrics.get("ai"))
            },
            "alerts": performance_service._get_active_alerts(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        return {
            "status": "success",
            "health": health_status
        }

    except Exception as e:
        logger.error(f"Error getting system health: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get system health: {str(e)}")

@router.post("/metrics/custom")
async def record_custom_metric(
    metric_data: Dict[str, Any],
    current_user: dict = Depends(require_auth)
):
    """Record custom performance metric."""
    try:
        performance_service = await get_performance_service()

        # Validate metric data
        if "name" not in metric_data or "value" not in metric_data:
            raise HTTPException(status_code=400, detail="Metric name and value are required")

        performance_service.add_custom_metric(metric_data["name"], metric_data["value"])

        return {
            "status": "success",
            "message": f"Custom metric '{metric_data['name']}' recorded",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        logger.error(f"Error recording custom metric: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to record custom metric: {str(e)}")

@router.get("/alerts")
async def get_performance_alerts(
    active_only: bool = Query(True, description="Return only active alerts"),
    hours: int = Query(24, description="Hours of alert history", ge=1, le=168),
    current_user: dict = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_auth)
):
    """Get performance alerts."""
    try:
        performance_service = await get_performance_service()

        if active_only:
            alerts = performance_service._get_active_alerts()
        else:
            # This would get historical alerts
            alerts = []  # Placeholder

        return {
            "status": "success",
            "alerts": alerts,
            "count": len(alerts),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        logger.error(f"Error getting performance alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get performance alerts: {str(e)}")

@router.get("/analytics/trends")
async def get_performance_trends(
    days: int = Query(7, description="Number of days for trend analysis", ge=1, le=30),
    metrics: Optional[str] = Query(None, description="Comma-separated list of metrics to analyze"),
    current_user: dict = Depends(require_auth)
):
    """Get performance trend analysis."""
    try:
        performance_service = await get_performance_service()
        historical_data = performance_service.get_historical_metrics(days * 24)

        # Calculate trends
        trends = performance_service._calculate_trends(historical_data)

        # Filter by requested metrics if specified
        if metrics:
            requested_metrics = [m.strip() for m in metrics.split(",")]
            trends = {k: v for k, v in trends.items() if k in requested_metrics}

        return {
            "status": "success",
            "time_period": f"{days} days",
            "trends": trends,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        logger.error(f"Error getting performance trends: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get performance trends: {str(e)}")

@router.get("/dashboard/data")
async def get_dashboard_data(
    current_user: dict = Depends(require_auth)
):
    """Get comprehensive dashboard data."""
    try:
        performance_service = await get_performance_service()

        # Gather all dashboard data
        dashboard_data = {
            "current_metrics": performance_service.get_current_metrics(),
            "summary": performance_service.get_performance_summary(),
            "recent_trends": performance_service._calculate_trends(
                performance_service.get_historical_metrics(24)
            ),
            "active_alerts": performance_service._get_active_alerts(),
            "health_score": performance_service._calculate_health_score(
                performance_service.get_current_metrics()
            ),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        return {
            "status": "success",
            "dashboard": dashboard_data
        }

    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard data: {str(e)}")

# WebSocket endpoint for real-time metrics
@router.websocket("/metrics/stream")
async def metrics_websocket(
    websocket: WebSocket,
    metric_types: Optional[str] = Query(None, description="Comma-separated list of metric types"),
    update_interval: int = Query(5, description="Update interval in seconds", ge=1, le=60)
):
    """WebSocket endpoint for real-time performance metrics streaming."""
    try:
        # Parse filters
        filters = {}
        if metric_types:
            filters["metric_types"] = [t.strip() for t in metric_types.split(",")]

        await metrics_manager.connect(websocket, filters)

        # Keep connection alive and handle client messages
        while True:
            try:
                # Wait for client messages (for filter updates)
                message = await asyncio.wait_for(websocket.receive_text(), timeout=1.0)

                # Handle filter update messages
                try:
                    msg_data = json.loads(message)
                    if msg_data.get("type") == "update_filter":
                        metrics_manager.connection_filters[websocket] = msg_data.get("filter", {})
                        logger.info("Updated WebSocket filters")
                except json.JSONDecodeError:
                    logger.warning("Invalid JSON message received from WebSocket client")

            except asyncio.TimeoutError:
                # No message received, continue
                pass
            except WebSocketDisconnect:
                break

    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        metrics_manager.disconnect(websocket)

# Helper functions

def _downsample_metrics(metrics: Dict[str, Any], resolution: str) -> Dict[str, Any]:
    """Downsample metrics data to specified resolution."""
    # This would implement actual downsampling logic
    # For now, return original data
    return metrics

def _calculate_component_health(component_metrics: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate health score for a component."""
    if not component_metrics:
        return {"score": 0, "status": "unknown", "issues": ["No data available"]}

    # This would implement actual health calculation logic
    return {
        "score": 85,
        "status": "healthy",
        "issues": []
    }

# Export router
__all__ = ["router"]
