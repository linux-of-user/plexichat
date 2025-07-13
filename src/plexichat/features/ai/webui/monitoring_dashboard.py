"""
AI Monitoring Dashboard WebUI
Comprehensive web interface for AI system monitoring, analytics, and alerting.
"""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ..monitoring.analytics_engine import AlertRule, analytics_engine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/ai/monitoring", tags=["AI Monitoring WebUI"])
templates = Jinja2Templates(directory="src/plexichat/ai/webui/templates")

@router.get("/", response_class=HTMLResponse)
async def monitoring_dashboard(request: Request):
    """Main monitoring dashboard."""
    try:
        # Get system health
        health_data = {
            "monitoring_active": analytics_engine.monitoring_active,
            "usage_buffer_size": len(analytics_engine.usage_buffer),
            "performance_buffer_size": len(analytics_engine.performance_buffer),
            "cost_buffer_size": len(analytics_engine.cost_buffer),
            "alert_rules_count": len(analytics_engine.alert_rules),
            "recent_alerts_count": len(analytics_engine.alert_history)
        }
        
        # Get recent usage analytics (last 24 hours)
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=24)
        usage_analytics = analytics_engine.get_usage_analytics(start_time, end_time)
        
        # Get recent alerts
        recent_alerts = analytics_engine.get_alert_history(10)
        
        return templates.TemplateResponse("monitoring_dashboard.html", {
            "request": request,
            "health": health_data,
            "usage_analytics": usage_analytics,
            "recent_alerts": recent_alerts,
            "current_time": datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Monitoring dashboard error: {e}")
        raise HTTPException(status_code=500, detail=f"Dashboard error: {str(e)}")

@router.get("/analytics", response_class=HTMLResponse)
async def analytics_page(request: Request):
    """Analytics page with detailed charts and metrics."""
    try:
        # Get analytics for different time periods
        now = datetime.now(timezone.utc)
        
        # Last 24 hours
        analytics_24h = analytics_engine.get_usage_analytics(
            now - timedelta(hours=24), now
        )
        
        # Last 7 days
        analytics_7d = analytics_engine.get_usage_analytics(
            now - timedelta(days=7), now
        )
        
        # Last 30 days
        analytics_30d = analytics_engine.get_usage_analytics(
            now - timedelta(days=30), now
        )
        
        return templates.TemplateResponse("analytics.html", {
            "request": request,
            "analytics_24h": analytics_24h,
            "analytics_7d": analytics_7d,
            "analytics_30d": analytics_30d
        })
        
    except Exception as e:
        logger.error(f"Analytics page error: {e}")
        raise HTTPException(status_code=500, detail=f"Analytics error: {str(e)}")

@router.get("/performance", response_class=HTMLResponse)
async def performance_page(request: Request):
    """Performance monitoring page."""
    try:
        # Get performance metrics from buffer
        recent_metrics = list(analytics_engine.performance_buffer)
        
        # Calculate performance stats
        if recent_metrics:
            total_requests = len(recent_metrics)
            successful_requests = sum(1 for m in recent_metrics if m.success)
            success_rate = successful_requests / total_requests
            
            latencies = [m.latency_ms for m in recent_metrics]
            avg_latency = sum(latencies) / len(latencies)
            
            # Group by model and provider
            by_model = {}
            by_provider = {}
            
            for metric in recent_metrics:
                # By model
                if metric.model_id not in by_model:
                    by_model[metric.model_id] = {"requests": 0, "successful": 0, "latencies": []}
                by_model[metric.model_id]["requests"] += 1
                if metric.success:
                    by_model[metric.model_id]["successful"] += 1
                by_model[metric.model_id]["latencies"].append(metric.latency_ms)
                
                # By provider
                if metric.provider not in by_provider:
                    by_provider[metric.provider] = {"requests": 0, "successful": 0, "latencies": []}
                by_provider[metric.provider]["requests"] += 1
                if metric.success:
                    by_provider[metric.provider]["successful"] += 1
                by_provider[metric.provider]["latencies"].append(metric.latency_ms)
            
            # Calculate stats for each group
            for model_stats in by_model.values():
                model_stats["success_rate"] = model_stats["successful"] / model_stats["requests"]
                model_stats["avg_latency"] = sum(model_stats["latencies"]) / len(model_stats["latencies"])
            
            for provider_stats in by_provider.values():
                provider_stats["success_rate"] = provider_stats["successful"] / provider_stats["requests"]
                provider_stats["avg_latency"] = sum(provider_stats["latencies"]) / len(provider_stats["latencies"])
        else:
            total_requests = 0
            success_rate = 0.0
            avg_latency = 0.0
            by_model = {}
            by_provider = {}
        
        performance_data = {
            "total_requests": total_requests,
            "success_rate": success_rate,
            "avg_latency": avg_latency,
            "by_model": by_model,
            "by_provider": by_provider
        }
        
        return templates.TemplateResponse("performance.html", {
            "request": request,
            "performance": performance_data
        })
        
    except Exception as e:
        logger.error(f"Performance page error: {e}")
        raise HTTPException(status_code=500, detail=f"Performance error: {str(e)}")

@router.get("/costs", response_class=HTMLResponse)
async def costs_page(request: Request):
    """Cost tracking page."""
    try:
        # Get cost metrics from buffer
        recent_costs = list(analytics_engine.cost_buffer)
        
        if recent_costs:
            total_cost = sum(m.cost for m in recent_costs)
            total_tokens = sum(m.tokens_used for m in recent_costs)
            
            # Group by user, model, provider
            by_user = {}
            by_model = {}
            by_provider = {}
            
            for metric in recent_costs:
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
        else:
            total_cost = 0.0
            total_tokens = 0
            by_user = {}
            by_model = {}
            by_provider = {}
        
        cost_data = {
            "total_cost": total_cost,
            "total_tokens": total_tokens,
            "avg_cost_per_token": total_cost / total_tokens if total_tokens > 0 else 0.0,
            "by_user": by_user,
            "by_model": by_model,
            "by_provider": by_provider
        }
        
        return templates.TemplateResponse("costs.html", {
            "request": request,
            "costs": cost_data
        })
        
    except Exception as e:
        logger.error(f"Costs page error: {e}")
        raise HTTPException(status_code=500, detail=f"Costs error: {str(e)}")

@router.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    """Alerts management page."""
    try:
        # Get alert rules and history
        alert_rules = []
        for rule in analytics_engine.alert_rules.values():
            alert_rules.append({
                "id": rule.id,
                "name": rule.name,
                "condition": rule.condition,
                "threshold": rule.threshold,
                "window_minutes": rule.window_minutes,
                "enabled": rule.enabled,
                "notification_channels": rule.notification_channels,
                "last_triggered": rule.last_triggered.isoformat() if rule.last_triggered else None
            })
        
        alert_history = analytics_engine.get_alert_history(50)
        
        return templates.TemplateResponse("alerts.html", {
            "request": request,
            "alert_rules": alert_rules,
            "alert_history": alert_history
        })
        
    except Exception as e:
        logger.error(f"Alerts page error: {e}")
        raise HTTPException(status_code=500, detail=f"Alerts error: {str(e)}")

@router.post("/alerts/create")
async def create_alert_rule(
    request: Request,
    rule_id: str = Form(...),
    rule_name: str = Form(...),
    condition: str = Form(...),
    threshold: float = Form(...),
    window_minutes: int = Form(5),
    enabled: bool = Form(True),
    notification_channels: str = Form("")
):
    """Create new alert rule."""
    try:
        # Parse notification channels
        channels = [ch.strip() for ch in notification_channels.split(",") if ch.strip()]
        
        rule = AlertRule(
            id=rule_id,
            name=rule_name,
            condition=condition,
            threshold=threshold,
            window_minutes=window_minutes,
            enabled=enabled,
            notification_channels=channels
        )
        
        success = analytics_engine.add_alert_rule(rule)
        
        if success:
            return templates.TemplateResponse("alert_success.html", {
                "request": request,
                "message": f"Alert rule '{rule_name}' created successfully",
                "redirect_url": "/ui/ai/monitoring/alerts"
            })
        else:
            raise HTTPException(status_code=500, detail="Failed to create alert rule")
            
    except Exception as e:
        logger.error(f"Create alert rule error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create alert rule: {str(e)}")

@router.get("/api/metrics")
async def get_metrics_api():
    """API endpoint for real-time metrics (for AJAX updates)."""
    try:
        # Get current metrics
        health_data = {
            "monitoring_active": analytics_engine.monitoring_active,
            "usage_buffer_size": len(analytics_engine.usage_buffer),
            "performance_buffer_size": len(analytics_engine.performance_buffer),
            "cost_buffer_size": len(analytics_engine.cost_buffer),
            "alert_rules_count": len(analytics_engine.alert_rules),
            "recent_alerts_count": len(analytics_engine.alert_history)
        }
        
        # Get recent performance metrics
        recent_metrics = list(analytics_engine.performance_buffer)[-100:]  # Last 100 requests
        
        if recent_metrics:
            success_rate = sum(1 for m in recent_metrics if m.success) / len(recent_metrics)
            avg_latency = sum(m.latency_ms for m in recent_metrics) / len(recent_metrics)
        else:
            success_rate = 0.0
            avg_latency = 0.0
        
        # Get recent cost data
        recent_costs = list(analytics_engine.cost_buffer)[-100:]  # Last 100 requests
        total_cost = sum(m.cost for m in recent_costs)
        
        return {
            "status": "success",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "health": health_data,
            "performance": {
                "success_rate": success_rate,
                "avg_latency": avg_latency,
                "recent_requests": len(recent_metrics)
            },
            "costs": {
                "recent_total": total_cost,
                "recent_requests": len(recent_costs)
            }
        }
        
    except Exception as e:
        logger.error(f"Metrics API error: {e}")
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

@router.post("/control/start")
async def start_monitoring():
    """Start monitoring system."""
    try:
        analytics_engine.start_monitoring()
        return {"status": "success", "message": "Monitoring started"}
    except Exception as e:
        logger.error(f"Start monitoring error: {e}")
        return {"status": "error", "error": str(e)}

@router.post("/control/stop")
async def stop_monitoring():
    """Stop monitoring system."""
    try:
        analytics_engine.stop_monitoring()
        return {"status": "success", "message": "Monitoring stopped"}
    except Exception as e:
        logger.error(f"Stop monitoring error: {e}")
        return {"status": "error", "error": str(e)}

@router.post("/control/flush")
async def flush_metrics():
    """Flush metrics to database."""
    try:
        await analytics_engine.flush_metrics()
        return {"status": "success", "message": "Metrics flushed"}
    except Exception as e:
        logger.error(f"Flush metrics error: {e}")
        return {"status": "error", "error": str(e)}
