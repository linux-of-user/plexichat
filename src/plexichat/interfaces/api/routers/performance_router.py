"""
Performance Monitoring API Router

Provides REST API endpoints for performance monitoring, metrics, alerts, and dashboards.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field

from plexichat.core.monitoring.unified_monitoring_system import (
    unified_monitoring_system,
    record_metric,
    get_metrics,
    get_latest_metric,
    get_system_status
)
from plexichat.core.monitoring.metrics_collector import get_metrics_collector_status
from plexichat.core.database.manager import database_manager
from plexichat.interfaces.api.auth_utils import get_current_user

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/performance", tags=["performance"])

# Pydantic models for request/response
class MetricDataResponse(BaseModel):
    """Response model for metric data."""
    name: str
    value: float
    unit: str
    timestamp: str
    tags: Dict[str, str]

class AlertRuleRequest(BaseModel):
    """Request model for alert rule creation."""
    name: str = Field(..., description="Alert rule name")
    metric: str = Field(..., description="Metric name to monitor")
    threshold: float = Field(..., description="Threshold value")
    operator: str = Field(..., description="Comparison operator (> < >= <= == !=)")
    enabled: bool = Field(True, description="Whether the rule is enabled")
    cooldown_seconds: int = Field(300, description="Cooldown period in seconds")

class AlertRuleResponse(BaseModel):
    """Response model for alert rule."""
    name: str
    metric: str
    threshold: float
    operator: str
    enabled: bool
    cooldown: int

class AlertResponse(BaseModel):
    """Response model for alerts."""
    rule_id: str
    rule_name: str
    metric_name: str
    metric_value: float
    threshold: float
    operator: str
    severity: str
    message: str
    status: str
    acknowledged: bool
    created_at: str

class SystemStatusResponse(BaseModel):
    """Response model for system status."""
    initialized: bool
    total_metrics: int
    metric_types: int
    alert_rules: int
    recent_alerts: int

class MetricsSummaryResponse(BaseModel):
    """Response model for metrics summary."""
    metric_name: str
    count: int
    average: float
    minimum: float
    maximum: float
    latest_value: float
    latest_timestamp: str

# API Endpoints

    @router.get("/status", response_model=SystemStatusResponse)
    async def get_performance_status(user: Dict[str, Any] = Depends(get_current_user)):
        """Get overall performance monitoring system status."""
        try:
            status = get_system_status()
            return SystemStatusResponse(**status)
        except Exception as e:
            logger.error(f"Error getting performance status: {e}")
            raise HTTPException(status_code=500, detail="Failed to get performance status")

    @router.get("/collector/status")
    async def get_collector_status(user: Dict[str, Any] = Depends(get_current_user)):
        """Get metrics collector status."""
        try:
            return get_metrics_collector_status()
        except Exception as e:
            logger.error(f"Error getting collector status: {e}")
            raise HTTPException(status_code=500, detail="Failed to get collector status")

    @router.get("/metrics/{metric_name}", response_model=List[MetricDataResponse])
    async def get_metric_data(
        metric_name: str,
        hours_param: int = Query(24, ge=1, le=168, description="Hours of data to retrieve"),
        user: Dict[str, Any] = Depends(get_current_user)
    ):
        """Get metric data for a specific metric."""
        try:
            since = datetime.now() - timedelta(hours=hours_param)
            metrics = get_metrics(metric_name, since)

            return [
                MetricDataResponse(
                    name=m.name,
                    value=m.value,
                    unit=m.unit,
                    timestamp=m.timestamp.isoformat(),
                    tags=m.tags
                )
                for m in metrics
            ]
        except Exception as e:
            logger.error(f"Error getting metric data for {metric_name}: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to get metric data for {metric_name}")

    @router.get("/metrics/{metric_name}/latest", response_model=Optional[MetricDataResponse])
    async def get_latest_metric_data(
        metric_name: str,
        user: Dict[str, Any] = Depends(get_current_user)
    ):
        """Get the latest value for a specific metric."""
        try:
            metric = get_latest_metric(metric_name)
            if not metric:
                return None

            return MetricDataResponse(
                name=metric.name,
                value=metric.value,
                unit=metric.unit,
                timestamp=metric.timestamp.isoformat(),
                tags=metric.tags
            )
        except Exception as e:
            logger.error(f"Error getting latest metric data for {metric_name}: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to get latest metric data for {metric_name}")

    @router.get("/metrics/summary")
    async def get_metrics_summary(
        hours_param: int = Query(1, ge=1, le=24, description="Hours to summarize"),
        user: Dict[str, Any] = Depends(get_current_user)
    ):
        """Get summary of all metrics."""
        try:
            summaries = []
            since = datetime.now() - timedelta(hours=hours_param)

            # Get all metric names from the system
            metric_names = list(unified_monitoring_system.metrics.keys())

            for name in metric_names:
                metrics = get_metrics(name, since)
                if not metrics:
                    continue

                values = [m.value for m in metrics]
                latest = metrics[-1] if metrics else None

                summaries.append({
                    "metric_name": name,
                    "count": len(metrics),
                    "average": sum(values) / len(values) if values else 0,
                    "minimum": min(values) if values else 0,
                    "maximum": max(values) if values else 0,
                    "latest_value": latest.value if latest else 0,
                    "latest_timestamp": latest.timestamp.isoformat() if latest else None
                })

            return {"summaries": summaries, "period_hours": hours_param}
        except Exception as e:
            logger.error(f"Error getting metrics summary: {e}")
            raise HTTPException(status_code=500, detail="Failed to get metrics summary")

    @router.post("/metrics")
    async def record_custom_metric(
        metric_name: str = Query(..., description="Metric name"),
        value: float = Query(..., description="Metric value"),
        unit: str = Query("", description="Metric unit"),
        tags: Optional[str] = Query(None, description="JSON string of tags"),
        user: Dict[str, Any] = Depends(get_current_user)
    ):
        """Record a custom metric."""
        try:
            import json
            parsed_tags = json.loads(tags) if tags else {}

            record_metric(metric_name, value, unit, parsed_tags)
            return {"message": f"Metric {metric_name} recorded successfully", "value": value}
        except Exception as e:
            logger.error(f"Error recording custom metric: {e}")
            raise HTTPException(status_code=500, detail="Failed to record custom metric")

    @router.get("/alerts/rules", response_model=List[AlertRuleResponse])
    async def get_alert_rules(user: Dict[str, Any] = Depends(get_current_user)):
        """Get all alert rules."""
        try:
            rules = []
            for rule_name, rule in unified_monitoring_system.alert_rules.items():
                rules.append(AlertRuleResponse(
                    name=rule.name,
                    metric=rule.metric,
                    threshold=rule.threshold,
                    operator=rule.operator,
                    enabled=rule.enabled,
                    cooldown=rule.cooldown
                ))
            return rules
        except Exception as e:
            logger.error(f"Error getting alert rules: {e}")
            raise HTTPException(status_code=500, detail="Failed to get alert rules")

    @router.post("/alerts/rules", response_model=AlertRuleResponse)
    async def create_alert_rule(
        rule: AlertRuleRequest,
        user: Dict[str, Any] = Depends(get_current_user)
    ):
        """Create a new alert rule."""
        try:
            from plexichat.core.monitoring.unified_monitoring_system import AlertRule
            alert_rule = AlertRule(
                name=rule.name,
                metric=rule.metric,
                threshold=rule.threshold,
                operator=rule.operator,
                enabled=rule.enabled,
                cooldown=rule.cooldown_seconds
            )

            unified_monitoring_system.add_alert_rule(alert_rule)

            return AlertRuleResponse(
                name=alert_rule.name,
                metric=alert_rule.metric,
                threshold=alert_rule.threshold,
                operator=alert_rule.operator,
                enabled=alert_rule.enabled,
                cooldown=alert_rule.cooldown
            )
        except Exception as e:
            logger.error(f"Error creating alert rule: {e}")
            raise HTTPException(status_code=500, detail="Failed to create alert rule")

    @router.delete("/alerts/rules/{rule_name}")
    async def delete_alert_rule(
        rule_name: str,
        user: Dict[str, Any] = Depends(get_current_user)
    ):
        """Delete an alert rule."""
        try:
            unified_monitoring_system.remove_alert_rule(rule_name)
            return {"message": f"Alert rule {rule_name} deleted successfully"}
        except Exception as e:
            logger.error(f"Error deleting alert rule {rule_name}: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to delete alert rule {rule_name}")

    @router.get("/alerts", response_model=List[AlertResponse])
    async def get_alerts(
        hours_param: int = Query(24, ge=1, le=168, description="Hours of alerts to retrieve"),
        status_filter: Optional[str] = Query(None, description="Filter by alert status"),
        user: Dict[str, Any] = Depends(get_current_user)
    ):
        """Get alerts from the database."""
        try:
            async with database_manager.get_session() as session:
                # Build query
                query = """
                SELECT rule_id, rule_name, metric_name, metric_value, threshold, operator,
                       severity, message, status, acknowledged, created_at
                FROM alerts
                WHERE created_at >= ?
                """
                params = [(datetime.now() - timedelta(hours=hours_param)).isoformat()]

                if status_filter:
                    query += " AND status = ?"
                    params.append(status_filter)

                query += " ORDER BY created_at DESC"

                alerts_data = await session.fetchall(query, {"params": params})

                alerts = []
                for alert in alerts_data:
                    alerts.append(AlertResponse(
                        rule_id=alert["rule_id"],
                        rule_name=alert["rule_name"],
                        metric_name=alert["metric_name"],
                        metric_value=alert["metric_value"],
                        threshold=alert["threshold"],
                        operator=alert["operator"],
                        severity=alert["severity"],
                        message=alert["message"],
                        status=alert["status"],
                        acknowledged=alert["acknowledged"],
                        created_at=alert["created_at"]
                    ))

                return alerts
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            raise HTTPException(status_code=500, detail="Failed to get alerts")

    @router.post("/alerts/{alert_id}/acknowledge")
    async def acknowledge_alert(
        alert_id: str,
        user: Dict[str, Any] = Depends(get_current_user)
    ):
        """Acknowledge an alert."""
        try:
            async with database_manager.get_session() as session:
                await session.update(
                    "alerts",
                    {
                        "acknowledged": True,
                        "acknowledged_by": str(user["id"]),
                        "acknowledged_at": datetime.now().isoformat(),
                        "updated_at": datetime.now().isoformat()
                    },
                    {"id": alert_id}
                )
                await session.commit()

            return {"message": f"Alert {alert_id} acknowledged successfully"}
        except Exception as e:
            logger.error(f"Error acknowledging alert {alert_id}: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to acknowledge alert {alert_id}")

    @router.get("/dashboard")
    async def get_dashboard_data(
        hours_param: int = Query(24, ge=1, le=168, description="Hours of data for dashboard"),
        user: Dict[str, Any] = Depends(get_current_user)
    ):
        """Get comprehensive dashboard data."""
        try:
            dashboard_data = {
                "system_status": get_system_status(),
                "collector_status": get_metrics_collector_status(),
                "recent_metrics": {},
                "active_alerts": [],
                "metrics_summary": {}
            }

            # Get recent metrics for key system metrics
            key_metrics = [
                "cpu_usage_percent", "memory_percent", "disk_percent",
                "network_bytes_sent", "network_bytes_recv", "process_count"
            ]

            since = datetime.now() - timedelta(hours=hours_param)
            for metric_name in key_metrics:
                metrics = get_metrics(metric_name, since)
                if metrics:
                    dashboard_data["recent_metrics"][metric_name] = [
                        {
                            "value": m.value,
                            "timestamp": m.timestamp.isoformat(),
                            "unit": m.unit
                        }
                        for m in metrics[-20:]  # Last 20 data points
                    ]

            # Get active alerts
            async with database_manager.get_session() as session:
                alerts = await session.fetchall(
                    "SELECT * FROM alerts WHERE status = 'active' ORDER BY created_at DESC LIMIT 10",
                    {}
                )
                dashboard_data["active_alerts"] = [
                    {
                        "id": alert["id"],
                        "rule_name": alert["rule_name"],
                        "message": alert["message"],
                        "severity": alert["severity"],
                        "created_at": alert["created_at"]
                    }
                    for alert in alerts
                ]

            return dashboard_data
        except Exception as e:
            logger.error(f"Error getting dashboard data: {e}")
            raise HTTPException(status_code=500, detail="Failed to get dashboard data")