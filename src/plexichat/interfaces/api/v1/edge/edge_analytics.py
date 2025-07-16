# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import logging

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


from ....core.auth import require_auth
from ....core.logging import get_logger
from ....core.performance.edge_computing_manager import get_edge_computing_manager


from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

"""
PlexiChat Edge Analytics API
Advanced analytics, monitoring, and insights for edge computing infrastructure.
"""

logger = get_logger(__name__)

# Create API router
router = APIRouter(prefix="/api/v1/edge/analytics", tags=["Edge Analytics"])


class AnalyticsTimeRange(BaseModel):
    """Time range for analytics queries."""

    start_time: datetime = Field(..., description="Start time for analytics")
    end_time: datetime = Field(..., description="End time for analytics")
    granularity: str = Field("hour", description="Data granularity (minute, hour, day)")


@router.get("/overview")
async def get_edge_overview(
    current_user: Dict = Depends(require_auth),
) -> Dict[str, Any]:
    """Get comprehensive edge computing overview and statistics."""
    try:
        manager = get_edge_computing_manager()

        # Get basic statistics
        total_nodes = len(manager.edge_nodes)
        active_nodes = sum(1 for node in manager.edge_nodes.values() if node.is_active)
        healthy_nodes = sum(
            1 for node in manager.edge_nodes.values() if node.is_healthy
        )

        # Calculate resource totals
        total_cpu_cores = sum(node.cpu_cores for node in manager.edge_nodes.values())
        total_memory_gb = sum(node.memory_gb for node in manager.edge_nodes.values())
        total_storage_gb = sum(node.storage_gb for node in manager.edge_nodes.values())

        # Calculate usage statistics
        avg_cpu_usage = sum(
            node.cpu_usage_percent for node in manager.edge_nodes.values()
        ) / max(total_nodes, 1)
        avg_memory_usage = sum(
            node.memory_usage_percent for node in manager.edge_nodes.values()
        ) / max(total_nodes, 1)
        avg_storage_usage = sum(
            node.storage_usage_percent for node in manager.edge_nodes.values()
        ) / max(total_nodes, 1)

        # Node type distribution
        node_type_distribution = {}
        for node in manager.edge_nodes.values():
            node_type = node.node_type.value
            node_type_distribution[node_type] = (
                node_type_distribution.get(node_type, 0) + 1
            )

        # Regional distribution
        regional_distribution = {}
        for node in manager.edge_nodes.values():
            region = getattr(node, "region", "Unknown")
            regional_distribution[region] = regional_distribution.get(region, 0) + 1

        # Load level distribution
        load_distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for node in manager.edge_nodes.values():
            if node.cpu_usage_percent < 30:
                load_distribution["low"] += 1
            elif node.cpu_usage_percent < 60:
                load_distribution["medium"] += 1
            elif node.cpu_usage_percent < 85:
                load_distribution["high"] += 1
            else:
                load_distribution["critical"] += 1

        # AI/GPU capabilities
        gpu_enabled_nodes = sum(
            1
            for node in manager.edge_nodes.values()
            if getattr(node, "gpu_available", False)
        )
        ai_enabled_nodes = sum(
            1
            for node in manager.edge_nodes.values()
            if getattr(node, "ai_acceleration", False)
        )

        return {
            "success": True,
            "data": {
                "summary": {
                    "total_nodes": total_nodes,
                    "active_nodes": active_nodes,
                    "healthy_nodes": healthy_nodes,
                    "health_percentage": (healthy_nodes / max(total_nodes, 1)) * 100,
                    "gpu_enabled_nodes": gpu_enabled_nodes,
                    "ai_enabled_nodes": ai_enabled_nodes,
                },
                "resources": {
                    "total_cpu_cores": total_cpu_cores,
                    "total_memory_gb": total_memory_gb,
                    "total_storage_gb": total_storage_gb,
                    "avg_cpu_usage_percent": round(avg_cpu_usage, 2),
                    "avg_memory_usage_percent": round(avg_memory_usage, 2),
                    "avg_storage_usage_percent": round(avg_storage_usage, 2),
                },
                "distributions": {
                    "node_types": node_type_distribution,
                    "regions": regional_distribution,
                    "load_levels": load_distribution,
                },
                "capabilities": {
                    "gpu_acceleration": gpu_enabled_nodes > 0,
                    "ai_processing": ai_enabled_nodes > 0,
                    "multi_region": len(regional_distribution) > 1,
                    "high_availability": healthy_nodes >= 2,
                },
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f" Failed to get edge overview: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/performance")
async def get_performance_analytics(
    time_range: str = Query("24h", description="Time range (1h, 6h, 24h, 7d, 30d)"),
    node_ids: Optional[List[str]] = Query(
        None, description="Specific node IDs to analyze"
    ),
    metrics: Optional[List[str]] = Query(
        None, description="Specific metrics to include"
    ),
    current_user: Dict = Depends(require_auth),
) -> Dict[str, Any]:
    """Get detailed performance analytics for edge nodes."""
    try:
        manager = get_edge_computing_manager()

        # Parse time range
        time_ranges = {
            "1h": timedelta(hours=1),
            "6h": timedelta(hours=6),
            "24h": timedelta(days=1),
            "7d": timedelta(days=7),
            "30d": timedelta(days=30),
        }

        if time_range not in time_ranges:
            raise HTTPException(status_code=400, detail="Invalid time range")

        end_time = datetime.now(timezone.utc)
        start_time = end_time - time_ranges[time_range]

        # Filter nodes if specified
        target_nodes = manager.edge_nodes
        if node_ids:
            target_nodes = {
                nid: node for nid, node in manager.edge_nodes.items() if nid in node_ids
            }

        # Default metrics if not specified
        if not metrics:
            metrics = [
                "cpu_usage",
                "memory_usage",
                "storage_usage",
                "network_usage",
                "response_time",
            ]

        # Collect performance data
        performance_data = {}
        for node_id, node in target_nodes.items():
            node_metrics = {}

            # Current metrics
            if "cpu_usage" in metrics:
                node_metrics["cpu_usage_percent"] = node.cpu_usage_percent
            if "memory_usage" in metrics:
                node_metrics["memory_usage_percent"] = node.memory_usage_percent
            if "storage_usage" in metrics:
                node_metrics["storage_usage_percent"] = node.storage_usage_percent
            if "network_usage" in metrics:
                node_metrics["network_usage_percent"] = node.network_usage_percent
            if "response_time" in metrics:
                node_metrics["avg_response_time_ms"] = getattr(
                    node, "avg_response_time_ms", 0
                )

            # Connection metrics
            node_metrics["current_connections"] = node.current_connections
            node_metrics["max_connections"] = node.max_connections
            node_metrics["connection_utilization"] = (
                node.current_connections / max(node.max_connections, 1)
            ) * 100

            # Health metrics
            node_metrics["is_healthy"] = node.is_healthy
            node_metrics["last_heartbeat"] = node.last_heartbeat.isoformat()

            performance_data[node_id] = node_metrics

        # Calculate aggregate statistics
        if performance_data:
            cpu_values = [
                data.get("cpu_usage_percent", 0) for data in performance_data.values()
            ]
            memory_values = [
                data.get("memory_usage_percent", 0)
                for data in performance_data.values()
            ]

            aggregates = {
                "avg_cpu_usage": sum(cpu_values) / len(cpu_values),
                "max_cpu_usage": max(cpu_values),
                "min_cpu_usage": min(cpu_values),
                "avg_memory_usage": sum(memory_values) / len(memory_values),
                "max_memory_usage": max(memory_values),
                "min_memory_usage": min(memory_values),
                "total_connections": sum(
                    data.get("current_connections", 0)
                    for data in performance_data.values()
                ),
            }
        else:
            aggregates = {}

        return {
            "success": True,
            "data": {
                "time_range": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                    "duration": time_range,
                },
                "node_performance": performance_data,
                "aggregates": aggregates,
                "metrics_included": metrics,
                "nodes_analyzed": len(performance_data),
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Failed to get performance analytics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/geographic")
async def get_geographic_analytics(
    current_user: Dict = Depends(require_auth),
) -> Dict[str, Any]:
    """Get geographic distribution and latency analytics."""
    try:
        manager = get_edge_computing_manager()

        # Collect geographic data
        geographic_data = []
        regional_stats = {}

        for node_id, node in manager.edge_nodes.items():
            if node.latitude is not None and node.longitude is not None:
                node_geo = {
                    "node_id": node_id,
                    "latitude": node.latitude,
                    "longitude": node.longitude,
                    "region": getattr(node, "region", "Unknown"),
                    "location": node.location,
                    "is_active": node.is_active,
                    "is_healthy": node.is_healthy,
                    "cpu_usage": node.cpu_usage_percent,
                    "connections": node.current_connections,
                    "node_type": node.node_type.value,
                }
                geographic_data.append(node_geo)

                # Regional statistics
                region = getattr(node, "region", "Unknown")
                if region not in regional_stats:
                    regional_stats[region] = {
                        "node_count": 0,
                        "active_nodes": 0,
                        "total_cpu_cores": 0,
                        "total_memory_gb": 0,
                        "avg_cpu_usage": 0,
                        "total_connections": 0,
                    }

                regional_stats[region]["node_count"] += 1
                if node.is_active:
                    regional_stats[region]["active_nodes"] += 1
                regional_stats[region]["total_cpu_cores"] += node.cpu_cores
                regional_stats[region]["total_memory_gb"] += node.memory_gb
                regional_stats[region]["avg_cpu_usage"] += node.cpu_usage_percent
                regional_stats[region]["total_connections"] += node.current_connections

        # Calculate averages for regional stats
        for region, stats in regional_stats.items():
            if stats["node_count"] > 0:
                stats["avg_cpu_usage"] = stats["avg_cpu_usage"] / stats["node_count"]

        # Calculate coverage metrics
        coverage_metrics = {
            "total_regions": len(regional_stats),
            "nodes_with_coordinates": len(geographic_data),
            "geographic_coverage": len(geographic_data)
            / max(len(manager.edge_nodes), 1)
            * 100,
            "multi_region_deployment": len(regional_stats) > 1,
        }

        return {
            "success": True,
            "data": {
                "geographic_nodes": geographic_data,
                "regional_statistics": regional_stats,
                "coverage_metrics": coverage_metrics,
                "map_center": (
                    {
                        "latitude": sum(node["latitude"] for node in geographic_data)
                        / max(len(geographic_data), 1),
                        "longitude": sum(node["longitude"] for node in geographic_data)
                        / max(len(geographic_data), 1),
                    }
                    if geographic_data
                    else None
                ),
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f" Failed to get geographic analytics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/predictions")
async def get_predictive_analytics(
    prediction_horizon: str = Query("24h", description="Prediction time horizon"),
    current_user: Dict = Depends(require_auth),
) -> Dict[str, Any]:
    """Get predictive analytics for capacity planning and scaling decisions."""
    try:
        manager = get_edge_computing_manager()

        # This would typically use machine learning models
        # For now, we'll provide trend-based predictions

        predictions = {}

        for node_id, node in manager.edge_nodes.items():
            # Simple trend-based prediction (would be replaced with ML models)
            current_cpu = node.cpu_usage_percent
            current_memory = node.memory_usage_percent
            current_connections = node.current_connections

            # Simulate trend analysis
            cpu_trend = 0.5 if current_cpu > 70 else -0.2  # Simplified trend
            memory_trend = 0.3 if current_memory > 80 else -0.1
            connection_trend = (
                2 if current_connections > node.max_connections * 0.8 else -1
            )

            predictions[node_id] = {
                "predicted_cpu_usage": min(100, max(0, current_cpu + cpu_trend * 24)),
                "predicted_memory_usage": min(
                    100, max(0, current_memory + memory_trend * 24)
                ),
                "predicted_connections": max(
                    0, current_connections + connection_trend * 24
                ),
                "scaling_recommendation": (
                    "scale_up"
                    if current_cpu > 80 or current_memory > 85
                    else "maintain"
                ),
                "risk_level": (
                    "high" if current_cpu > 85 or current_memory > 90 else "low"
                ),
                "predicted_load_level": (
                    "high" if current_cpu + cpu_trend * 24 > 80 else "normal"
                ),
            }

        # System-wide predictions
        total_nodes = len(manager.edge_nodes)
        high_risk_nodes = sum(
            1 for p in predictions.values() if p["risk_level"] == "high"
        )
        scale_up_recommendations = sum(
            1 for p in predictions.values() if p["scaling_recommendation"] == "scale_up"
        )

        system_predictions = {
            "capacity_utilization_trend": (
                "increasing"
                if scale_up_recommendations > total_nodes * 0.3
                else "stable"
            ),
            "recommended_new_nodes": max(0, scale_up_recommendations - 2),
            "system_health_forecast": (
                "degraded" if high_risk_nodes > total_nodes * 0.2 else "healthy"
            ),
            "peak_load_prediction": datetime.now(timezone.utc)
            + timedelta(hours=6),  # Simplified
        }

        return {
            "success": True,
            "data": {
                "prediction_horizon": prediction_horizon,
                "node_predictions": predictions,
                "system_predictions": system_predictions,
                "recommendations": {
                    "immediate_actions": [
                        (
                            f"Monitor {high_risk_nodes} high-risk nodes"
                            if high_risk_nodes > 0
                            else "System operating normally"
                        ),
                        (
                            f"Consider scaling up {scale_up_recommendations} nodes"
                            if scale_up_recommendations > 0
                            else "No scaling needed"
                        ),
                    ],
                    "capacity_planning": (
                        f"Add {system_predictions['recommended_new_nodes']} nodes in next 30 days"
                        if system_predictions["recommended_new_nodes"] > 0
                        else "Current capacity sufficient"
                    ),
                },
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f" Failed to get predictive analytics: {e}")
        raise HTTPException(status_code=500, detail=str(e))
