import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from ..monitoring.analytics_engine import AlertRule, analytics_engine

"""
AI Monitoring and Analytics API Endpoints
RESTful API endpoints for AI system monitoring, analytics, and alerting.
"""

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ai/monitoring", tags=["AI Monitoring"])

# Request/Response Models
class AlertRuleRequest(BaseModel):
    id: str = Field(..., description="Alert rule ID")
    name: str = Field(..., description="Alert rule name")
    condition: str = Field(..., description="Alert condition (Python expression)")
    threshold: float = Field(..., description="Alert threshold")
    window_minutes: int = Field(default=5, description="Time window in minutes")
    enabled: bool = Field(default=True, description="Enable alert rule")
    notification_channels: List[str] = Field(default_factory=list, description="Notification channels")

class UsageAnalyticsRequest(BaseModel):
    start_time: Optional[datetime] = Field(None, description="Start time for analytics")
    end_time: Optional[datetime] = Field(None, description="End time for analytics")
    user_id: Optional[str] = Field(None, description="Filter by user ID")
    model_id: Optional[str] = Field(None, description="Filter by model ID")
    provider: Optional[str] = Field(None, description="Filter by provider")

# Analytics Endpoints
@router.get("/analytics/usage")
async def get_usage_analytics(
    start_time: Optional[str] = Query(None, description="Start time (ISO format)"),
    end_time: Optional[str] = Query(None, description="End time (ISO format)"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    model_id: Optional[str] = Query(None, description="Filter by model ID"),
    provider: Optional[str] = Query(None, description="Filter by provider")
):
    """Get usage analytics."""
    try:
        # Parse datetime strings
        start_dt = None
        end_dt = None
        
        if start_time:
            start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        if end_time:
            end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        
        analytics = analytics_engine.get_usage_analytics(
            start_time=start_dt,
            end_time=end_dt,
            user_id=user_id,
            model_id=model_id,
            provider=provider
        )
        
        return {
            "status": "success",
            "analytics": analytics
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid datetime format: {str(e)}")
    except Exception as e:
        logger.error(f"Usage analytics error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get usage analytics: {str(e)}")

@router.get("/analytics/performance")
async def get_performance_analytics(
    hours: int = Query(24, description="Hours of data to analyze"),
    model_id: Optional[str] = Query(None, description="Filter by model ID"),
    provider: Optional[str] = Query(None, description="Filter by provider")
):
    """Get performance analytics."""
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)
        
        # Get performance metrics from buffer and database
        recent_metrics = [
            m for m in analytics_engine.performance_buffer 
            if m.timestamp >= start_time and 
            (not model_id or m.model_id == model_id) and
            (not provider or m.provider == provider)
        ]
        
        if not recent_metrics:
            return {
                "status": "success",
                "analytics": {
                    "period": {
                        "start": start_time.isoformat(),
                        "end": end_time.isoformat(),
                        "hours": hours
                    },
                    "summary": {
                        "total_requests": 0,
                        "success_rate": 0.0,
                        "avg_latency_ms": 0.0,
                        "p95_latency_ms": 0.0,
                        "p99_latency_ms": 0.0
                    },
                    "by_model": {},
                    "by_provider": {}
                }
            }
        
        # Calculate performance metrics
        total_requests = len(recent_metrics)
        successful_requests = sum(1 for m in recent_metrics if m.success)
        success_rate = successful_requests / total_requests if total_requests > 0 else 0.0
        
        latencies = [m.latency_ms for m in recent_metrics]
        latencies.sort()
        
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        p95_latency = latencies[int(len(latencies) * 0.95)] if latencies else 0.0
        p99_latency = latencies[int(len(latencies) * 0.99)] if latencies else 0.0
        
        # Group by model and provider
        by_model = {}
        by_provider = {}
        
        for metric in recent_metrics:
            # By model
            if metric.model_id not in by_model:
                by_model[metric.model_id] = {
                    "requests": 0,
                    "successful": 0,
                    "latencies": []
                }
            
            by_model[metric.model_id]["requests"] += 1
            if metric.success:
                by_model[metric.model_id]["successful"] += 1
            by_model[metric.model_id]["latencies"].append(metric.latency_ms)
            
            # By provider
            if metric.provider not in by_provider:
                by_provider[metric.provider] = {
                    "requests": 0,
                    "successful": 0,
                    "latencies": []
                }
            
            by_provider[metric.provider]["requests"] += 1
            if metric.success:
                by_provider[metric.provider]["successful"] += 1
            by_provider[metric.provider]["latencies"].append(metric.latency_ms)
        
        # Calculate stats for each group
        for model_stats in by_model.values():
            model_stats["success_rate"] = model_stats["successful"] / model_stats["requests"]
            model_stats["avg_latency"] = sum(model_stats["latencies"]) / len(model_stats["latencies"])
            del model_stats["latencies"]  # Remove raw data
        
        for provider_stats in by_provider.values():
            provider_stats["success_rate"] = provider_stats["successful"] / provider_stats["requests"]
            provider_stats["avg_latency"] = sum(provider_stats["latencies"]) / len(provider_stats["latencies"])
            del provider_stats["latencies"]  # Remove raw data
        
        return {
            "status": "success",
            "analytics": {
                "period": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                    "hours": hours
                },
                "summary": {
                    "total_requests": total_requests,
                    "success_rate": success_rate,
                    "avg_latency_ms": avg_latency,
                    "p95_latency_ms": p95_latency,
                    "p99_latency_ms": p99_latency
                },
                "by_model": by_model,
                "by_provider": by_provider
            }
        }
        
    except Exception as e:
        logger.error(f"Performance analytics error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get performance analytics: {str(e)}")

@router.get("/analytics/costs")
async def get_cost_analytics(
    days: int = Query(7, description="Days of data to analyze"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    model_id: Optional[str] = Query(None, description="Filter by model ID")
):
    """Get cost analytics."""
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)
        
        # Get cost metrics from buffer
        recent_costs = [
            m for m in analytics_engine.cost_buffer 
            if m.timestamp >= start_time and 
            (not user_id or m.user_id == user_id) and
            (not model_id or m.model_id == model_id)
        ]
        
        if not recent_costs:
            return {
                "status": "success",
                "analytics": {
                    "period": {
                        "start": start_time.isoformat(),
                        "end": end_time.isoformat(),
                        "days": days
                    },
                    "summary": {
                        "total_cost": 0.0,
                        "total_tokens": 0,
                        "avg_cost_per_token": 0.0
                    },
                    "by_user": {},
                    "by_model": {},
                    "by_provider": {},
                    "daily_breakdown": []
                }
            }
        
        # Calculate cost analytics
        total_cost = sum(m.cost for m in recent_costs)
        total_tokens = sum(m.tokens_used for m in recent_costs)
        avg_cost_per_token = total_cost / total_tokens if total_tokens > 0 else 0.0
        
        # Group by various dimensions
        by_user = {}
        by_model = {}
        by_provider = {}
        daily_costs = {}
        
        for metric in recent_costs:
            date_key = metric.timestamp.date().isoformat()
            
            # By user
            if metric.user_id not in by_user:
                by_user[metric.user_id] = {"cost": 0.0, "tokens": 0}
            by_user[metric.user_id]["cost"] += metric.cost
            by_user[metric.user_id]["tokens"] += metric.tokens_used
            
            # By model
            if metric.model_id not in by_model:
                by_model[metric.model_id] = {"cost": 0.0, "tokens": 0}
            by_model[metric.model_id]["cost"] += metric.cost
            by_model[metric.model_id]["tokens"] += metric.tokens_used
            
            # By provider
            if metric.provider not in by_provider:
                by_provider[metric.provider] = {"cost": 0.0, "tokens": 0}
            by_provider[metric.provider]["cost"] += metric.cost
            by_provider[metric.provider]["tokens"] += metric.tokens_used
            
            # Daily breakdown
            if date_key not in daily_costs:
                daily_costs[date_key] = {"cost": 0.0, "tokens": 0}
            daily_costs[date_key]["cost"] += metric.cost
            daily_costs[date_key]["tokens"] += metric.tokens_used
        
        # Convert daily breakdown to sorted list
        daily_breakdown = [
            {"date": date, "cost": data["cost"], "tokens": data["tokens"]}
            for date, data in sorted(daily_costs.items())
        ]
        
        return {
            "status": "success",
            "analytics": {
                "period": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                    "days": days
                },
                "summary": {
                    "total_cost": total_cost,
                    "total_tokens": total_tokens,
                    "avg_cost_per_token": avg_cost_per_token
                },
                "by_user": by_user,
                "by_model": by_model,
                "by_provider": by_provider,
                "daily_breakdown": daily_breakdown
            }
        }
        
    except Exception as e:
        logger.error(f"Cost analytics error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get cost analytics: {str(e)}")

# Alert Management Endpoints
@router.get("/alerts/rules")
async def list_alert_rules():
    """List all alert rules."""
    try:
        rules = []
        for rule in analytics_engine.alert_rules.values():
            rules.append({
                "id": rule.id,
                "name": rule.name,
                "condition": rule.condition,
                "threshold": rule.threshold,
                "window_minutes": rule.window_minutes,
                "enabled": rule.enabled,
                "notification_channels": rule.notification_channels,
                "last_triggered": rule.last_triggered.isoformat() if rule.last_triggered else None
            })
        
        return {
            "status": "success",
            "rules": rules
        }
        
    except Exception as e:
        logger.error(f"List alert rules error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list alert rules: {str(e)}")

@router.post("/alerts/rules")
async def create_alert_rule(request: AlertRuleRequest):
    """Create new alert rule."""
    try:
        rule = AlertRule(
            id=request.id,
            name=request.name,
            condition=request.condition,
            threshold=request.threshold,
            window_minutes=request.window_minutes,
            enabled=request.enabled,
            notification_channels=request.notification_channels
        )
        
        success = analytics_engine.add_alert_rule(rule)
        
        if success:
            return {
                "status": "success",
                "message": f"Alert rule '{request.name}' created successfully"
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to create alert rule")
            
    except Exception as e:
        logger.error(f"Create alert rule error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create alert rule: {str(e)}")

@router.get("/alerts/history")
async def get_alert_history(limit: int = Query(100, description="Maximum number of alerts to return")):
    """Get alert history."""
    try:
        history = analytics_engine.get_alert_history(limit)
        
        return {
            "status": "success",
            "alerts": history
        }
        
    except Exception as e:
        logger.error(f"Get alert history error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get alert history: {str(e)}")

# System Health Endpoints
@router.get("/health")
async def monitoring_health_check():
    """Get monitoring system health."""
    try:
        return {
            "status": "success",
            "monitoring": {
                "active": analytics_engine.monitoring_active,
                "usage_buffer_size": len(analytics_engine.usage_buffer),
                "performance_buffer_size": len(analytics_engine.performance_buffer),
                "cost_buffer_size": len(analytics_engine.cost_buffer),
                "alert_rules_count": len(analytics_engine.alert_rules),
                "recent_alerts_count": len(analytics_engine.alert_history)
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Monitoring health check error: {e}")
        raise HTTPException(status_code=500, detail=f"Monitoring health check failed: {str(e)}")

@router.post("/flush")
async def flush_metrics():
    """Manually flush metrics to database."""
    try:
        await analytics_engine.flush_metrics()
        
        return {
            "status": "success",
            "message": "Metrics flushed to database successfully"
        }
        
    except Exception as e:
        logger.error(f"Flush metrics error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to flush metrics: {str(e)}")

@router.post("/start")
async def start_monitoring():
    """Start monitoring system."""
    try:
        analytics_engine.start_monitoring()
        
        return {
            "status": "success",
            "message": "Monitoring system started"
        }
        
    except Exception as e:
        logger.error(f"Start monitoring error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start monitoring: {str(e)}")

@router.post("/stop")
async def stop_monitoring():
    """Stop monitoring system."""
    try:
        analytics_engine.stop_monitoring()
        
        return {
            "status": "success",
            "message": "Monitoring system stopped"
        }
        
    except Exception as e:
        logger.error(f"Stop monitoring error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to stop monitoring: {str(e)}")
