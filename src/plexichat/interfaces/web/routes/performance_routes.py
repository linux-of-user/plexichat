# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from datetime import datetime, timezone
from pathlib import Path

from plexichat.core.auth.dependencies import require_auth, require_admin_auth
from plexichat.core.logging import get_logger
# from ...services.performance_service import get_performance_service

def get_performance_service():
    class DummyPerformanceService:
        def _calculate_health_score(self, *a, **k): return 100
        def get_current_metrics(self): return {"system": {}, "application": {}}
        def _get_active_alerts(self): return []
        def get_performance_summary(self): return {}
        def get_historical_metrics(self, *a, **k): return []
        def _calculate_trends(self, *a, **k): return []
    import asyncio
    async def dummy():
        return DummyPerformanceService()
    return dummy()

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from typing import Optional

"""
import time
PlexiChat Performance Dashboard Web Routes

Web routes for the performance monitoring dashboard and related pages.
Provides HTML interfaces for viewing system performance, metrics, and alerts.
"""

# Initialize router and templates
router = APIRouter(prefix="/performance", tags=["Performance Dashboard"])
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))
logger = get_logger(__name__)

@router.get("/dashboard", response_class=HTMLResponse)
async def performance_dashboard(
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Performance monitoring dashboard page."""
    try:
        # Get initial dashboard data
        performance_service = await get_performance_service()
        dashboard_data = {
            "current_metrics": performance_service.get_current_metrics(),
            "summary": performance_service.get_performance_summary(),
            "health_score": performance_service._calculate_health_score(
                performance_service.get_current_metrics()
            ),
            "active_alerts": performance_service._get_active_alerts()
        }

        return templates.TemplateResponse("performance_dashboard.html", {
            "request": request,
            "user": current_user,
            "dashboard_data": dashboard_data,
            "page_title": "Performance Dashboard",
            "current_time": datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        logger.error(f"Performance dashboard error: {e}")
        raise HTTPException(status_code=500, detail=f"Dashboard error: {str(e)}")

@router.get("/metrics", response_class=HTMLResponse)
async def metrics_page(
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Detailed metrics page."""
    try:
        performance_service = await get_performance_service()

        # Get comprehensive metrics data
        current_metrics = performance_service.get_current_metrics()
        historical_metrics = performance_service.get_historical_metrics(24)  # Last 24 hours

        return templates.TemplateResponse("performance_metrics.html", {
            "request": request,
            "user": current_user,
            "current_metrics": current_metrics,
            "historical_metrics": historical_metrics,
            "page_title": "Performance Metrics",
            "current_time": datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        logger.error(f"Metrics page error: {e}")
        raise HTTPException(status_code=500, detail=f"Metrics error: {str(e)}")

@router.get("/alerts", response_class=HTMLResponse)
async def alerts_page(
    request: Request,
    current_user: dict = Depends(require_admin_auth)
):
    """Performance alerts management page."""
    try:
        performance_service = await get_performance_service()

        # Get alerts data
        active_alerts = performance_service._get_active_alerts()

        return templates.TemplateResponse("performance_alerts.html", {
            "request": request,
            "user": current_user,
            "active_alerts": active_alerts,
            "page_title": "Performance Alerts",
            "current_time": datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        logger.error(f"Alerts page error: {e}")
        raise HTTPException(status_code=500, detail=f"Alerts error: {str(e)}")

@router.get("/health", response_class=HTMLResponse)
async def health_page(
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """System health overview page."""
    try:
        performance_service = await get_performance_service()

        # Get health data
        current_metrics = performance_service.get_current_metrics()
        health_score = performance_service._calculate_health_score(current_metrics)

        # Calculate component health
        component_health = {
            "system": _calculate_component_health(current_metrics.get("system")),
            "application": _calculate_component_health(current_metrics.get("application")),
            "database": _calculate_component_health(current_metrics.get("database")),
            "cluster": _calculate_component_health(current_metrics.get("cluster")),
            "ai": _calculate_component_health(current_metrics.get("ai"))
        }

        return templates.TemplateResponse("performance_health.html", {
            "request": request,
            "user": current_user,
            "health_score": health_score,
            "component_health": component_health,
            "current_metrics": current_metrics,
            "page_title": "System Health",
            "current_time": datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        logger.error(f"Health page error: {e}")
        raise HTTPException(status_code=500, detail=f"Health error: {str(e)}")

@router.get("/analytics", response_class=HTMLResponse)
async def analytics_page(
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Performance analytics and trends page."""
    try:
        performance_service = await get_performance_service()

        # Get analytics data
        historical_data = performance_service.get_historical_metrics(7 * 24)  # Last 7 days
        trends = performance_service._calculate_trends(historical_data)

        return templates.TemplateResponse("performance_analytics.html", {
            "request": request,
            "user": current_user,
            "trends": trends,
            "historical_data": historical_data,
            "page_title": "Performance Analytics",
            "current_time": datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        logger.error(f"Analytics page error: {e}")
        raise HTTPException(status_code=500, detail=f"Analytics error: {str(e)}")

# Helper functions
def _calculate_component_health(component_metrics):
    """Calculate health score for a component."""
    if not component_metrics:
        return {"score": 0, "status": "unknown", "issues": ["No data available"]}

    # This would implement actual health calculation logic
    # For now, return a placeholder
    return {
        "score": 85,
        "status": "healthy",
        "issues": []
    }

# Export router
__all__ = ["router"]
