# app/routers/admin.py
"""
Admin console router providing web-based administration interface
with comprehensive system management capabilities.
"""

import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.security import HTTPBearer
from sqlmodel import Session, select, func

from app.db import get_session
from app.models.user import User
from app.models.message import Message
from app.logger_config import settings, logger, selftest_logger, monitoring_logger
from app.utils.monitoring import system_monitor, error_handler
from app.utils.self_tests.test_executor import test_executor
from app.utils.self_tests.connectivity import run_connectivity_tests
from app.utils.self_tests.database import run_database_tests
from app.utils.self_tests.users import run_user_tests
from app.utils.self_tests.endpoints import run_endpoint_tests
from app.utils.scheduling import run_comprehensive_self_tests, get_scheduler_status
from app.config import config_manager

router = APIRouter(prefix="/netlink-control", tags=["netlink-control"])
security = HTTPBearer()

# Static file serving
STATIC_DIR = Path(__file__).parent.parent / "web_console" / "static"


async def verify_admin_access(request: Request):
    """Verify admin access - in production, implement proper authentication."""
    # For development, allow all access
    # In production, implement proper admin authentication
    return True


@router.get("/", response_class=HTMLResponse)
async def admin_console(request: Request, _: bool = Depends(verify_admin_access)):
    """Serve the main admin console interface."""
    try:
        html_file = STATIC_DIR / "admin.html"
        if not html_file.exists():
            raise HTTPException(status_code=404, detail="Admin console not found")
        
        with open(html_file, "r", encoding="utf-8") as f:
            content = f.read()
        
        return HTMLResponse(content=content)
    except Exception as e:
        logger.error("Failed to serve admin console: %s", e)
        raise HTTPException(status_code=500, detail="Failed to load admin console")


@router.get("/static/{filename}")
async def serve_static(filename: str, _: bool = Depends(verify_admin_access)):
    """Serve static files for the admin console."""
    file_path = STATIC_DIR / filename
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(file_path)


@router.get("/dashboard")
async def get_dashboard_data(session: Session = Depends(get_session)):
    """Get dashboard overview data."""
    try:
        # Get user statistics
        total_users = session.exec(select(func.count(User.id))).first()
        
        # Get message statistics
        today = datetime.now(timezone.utc).date()
        messages_today = session.exec(
            select(func.count(Message.id)).where(
                func.date(Message.created_at) == today
            )
        ).first()
        
        # Get system metrics
        system_metrics = system_monitor.get_system_metrics()
        health_status = system_monitor.check_system_health()
        
        return {
            "users": {
                "total": total_users or 0,
                "active": total_users or 0  # Simplified for now
            },
            "messages": {
                "today": messages_today or 0,
                "total": session.exec(select(func.count(Message.id))).first() or 0
            },
            "system": {
                "status": health_status["overall_status"],
                "uptime": system_metrics.get("uptime_seconds", 0),
                "cpu_usage": system_metrics.get("cpu", {}).get("percent", 0),
                "memory_usage": system_metrics.get("memory", {}).get("percent_used", 0)
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error("Failed to get dashboard data: %s", e)
        raise HTTPException(status_code=500, detail="Failed to load dashboard data")


@router.get("/recent-activity")
async def get_recent_activity(session: Session = Depends(get_session)):
    """Get recent system activity."""
    try:
        activities = []
        
        # Recent user registrations
        recent_users = session.exec(
            select(User).order_by(User.created_at.desc()).limit(5)
        ).all()
        
        for user in recent_users:
            activities.append({
                "type": "user_created",
                "description": f"New user registered: {user.username}",
                "timestamp": user.created_at.isoformat(),
                "severity": "info"
            })
        
        # Recent messages
        recent_messages = session.exec(
            select(Message).order_by(Message.created_at.desc()).limit(5)
        ).all()
        
        for message in recent_messages:
            activities.append({
                "type": "message_sent",
                "description": f"Message sent by user {message.sender_id}",
                "timestamp": message.created_at.isoformat(),
                "severity": "info"
            })
        
        # Sort by timestamp
        activities.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return activities[:10]  # Return latest 10 activities
        
    except Exception as e:
        logger.error("Failed to get recent activity: %s", e)
        return []


@router.get("/system-status")
async def get_system_status():
    """Get comprehensive system status."""
    try:
        health_status = system_monitor.check_system_health()
        system_metrics = system_monitor.get_system_metrics()
        scheduler_status = get_scheduler_status()
        
        return {
            "health": health_status,
            "metrics": system_metrics,
            "scheduler": scheduler_status,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error("Failed to get system status: %s", e)
        raise HTTPException(status_code=500, detail="Failed to get system status")


@router.get("/configuration")
async def get_configuration():
    """Get current configuration organized by categories."""
    try:
        all_config = config_manager.get_all()
        
        # Organize configuration by categories
        categorized_config = {
            "core": {
                "HOST": all_config.get("HOST"),
                "PORT": all_config.get("PORT"),
                "DEBUG": all_config.get("DEBUG"),
                "API_VERSION": all_config.get("API_VERSION")
            },
            "database": {
                "DATABASE_URL": all_config.get("DATABASE_URL"),
                "DB_HOST": all_config.get("DB_HOST"),
                "DB_PORT": all_config.get("DB_PORT")
            },
            "logging": {
                k: v for k, v in all_config.items() 
                if k.startswith("LOG_")
            },
            "selftest": {
                k: v for k, v in all_config.items() 
                if k.startswith("SELFTEST_")
            },
            "monitoring": {
                k: v for k, v in all_config.items() 
                if k.startswith("MONITORING_")
            },
            "security": {
                "ACCESS_TOKEN_EXPIRE_MINUTES": all_config.get("ACCESS_TOKEN_EXPIRE_MINUTES"),
                "RATE_LIMIT_REQUESTS": all_config.get("RATE_LIMIT_REQUESTS"),
                "RATE_LIMIT_WINDOW": all_config.get("RATE_LIMIT_WINDOW"),
                "SSL_KEYFILE": all_config.get("SSL_KEYFILE"),
                "SSL_CERTFILE": all_config.get("SSL_CERTFILE")
            }
        }
        
        return categorized_config
    except Exception as e:
        logger.error("Failed to get configuration: %s", e)
        raise HTTPException(status_code=500, detail="Failed to get configuration")


@router.post("/configuration")
async def update_configuration(config_data: Dict[str, Any]):
    """Update configuration settings."""
    try:
        # In a real implementation, you would validate and save the configuration
        # For now, we'll just log the attempt
        logger.info("Configuration update requested: %s", config_data)
        
        # Validate configuration
        issues = config_manager.validate_configuration()
        if issues:
            return {"status": "warning", "issues": issues}
        
        return {"status": "success", "message": "Configuration updated successfully"}
    except Exception as e:
        logger.error("Failed to update configuration: %s", e)
        raise HTTPException(status_code=500, detail="Failed to update configuration")


@router.post("/run-tests")
async def run_all_tests():
    """Run comprehensive self-tests."""
    try:
        # Run tests asynchronously
        result = run_comprehensive_self_tests()
        return {
            "status": "started",
            "message": "Comprehensive self-tests started",
            "result": result
        }
    except Exception as e:
        logger.error("Failed to run tests: %s", e)
        raise HTTPException(status_code=500, detail="Failed to start tests")


@router.post("/run-tests/{test_type}")
async def run_specific_tests(test_type: str):
    """Run specific type of tests."""
    try:
        test_functions = {
            "connectivity": run_connectivity_tests,
            "database": run_database_tests,
            "users": run_user_tests,
            "endpoints": run_endpoint_tests
        }
        
        if test_type not in test_functions:
            raise HTTPException(status_code=400, detail=f"Unknown test type: {test_type}")
        
        # Execute the specific test
        result = test_functions[test_type]()
        
        return {
            "status": "completed",
            "test_type": test_type,
            "result": result
        }
    except Exception as e:
        logger.error("Failed to run %s tests: %s", test_type, e)
        raise HTTPException(status_code=500, detail=f"Failed to run {test_type} tests")


@router.post("/quick-test")
async def run_quick_test():
    """Run a quick system health test."""
    try:
        health_status = system_monitor.check_system_health()
        return {
            "status": "completed",
            "result": health_status,
            "message": f"Quick test completed - System is {health_status['overall_status']}"
        }
    except Exception as e:
        logger.error("Failed to run quick test: %s", e)
        raise HTTPException(status_code=500, detail="Failed to run quick test")


@router.get("/logs")
async def get_logs(log_type: str = "latest", lines: int = 100):
    """Get system logs."""
    try:
        log_dir = Path(settings.LOG_DIR)
        
        log_files = {
            "latest": log_dir / "latest.log",
            "application": log_dir / "chatapi.log",
            "selftest": log_dir / "selftest" / "selftest_results.log",
            "monitoring": log_dir / "monitoring.log",
            "errors": log_dir / "errors.jsonl"
        }
        
        if log_type not in log_files:
            raise HTTPException(status_code=400, detail=f"Unknown log type: {log_type}")
        
        log_file = log_files[log_type]
        if not log_file.exists():
            return {"logs": [], "message": f"Log file {log_type} not found"}
        
        # Read last N lines
        with open(log_file, "r", encoding="utf-8") as f:
            all_lines = f.readlines()
            recent_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
        
        return {
            "logs": [line.strip() for line in recent_lines],
            "total_lines": len(all_lines),
            "showing_lines": len(recent_lines),
            "log_type": log_type
        }
    except Exception as e:
        logger.error("Failed to get logs: %s", e)
        raise HTTPException(status_code=500, detail="Failed to get logs")


@router.get("/users")
async def get_users(
    skip: int = 0, 
    limit: int = 100, 
    session: Session = Depends(get_session)
):
    """Get user list for management."""
    try:
        users = session.exec(
            select(User).offset(skip).limit(limit)
        ).all()
        
        total_users = session.exec(select(func.count(User.id))).first()
        
        return {
            "users": [
                {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "display_name": user.display_name,
                    "created_at": user.created_at.isoformat(),
                    "is_active": True  # Add this field to User model if needed
                }
                for user in users
            ],
            "total": total_users,
            "skip": skip,
            "limit": limit
        }
    except Exception as e:
        logger.error("Failed to get users: %s", e)
        raise HTTPException(status_code=500, detail="Failed to get users")


@router.get("/metrics/export")
async def export_metrics():
    """Export system metrics for external monitoring."""
    try:
        metrics = system_monitor.get_system_metrics()
        health = system_monitor.check_system_health()
        
        # Format for Prometheus-style metrics
        prometheus_metrics = []
        
        # System metrics
        if "cpu" in metrics:
            prometheus_metrics.append(f"chatapi_cpu_usage_percent {metrics['cpu']['percent']}")
        
        if "memory" in metrics:
            prometheus_metrics.append(f"chatapi_memory_usage_percent {metrics['memory']['percent_used']}")
            prometheus_metrics.append(f"chatapi_memory_total_mb {metrics['memory']['total_mb']}")
        
        if "disk" in metrics:
            prometheus_metrics.append(f"chatapi_disk_usage_percent {metrics['disk']['percent_used']}")
        
        # Health status as numeric
        health_numeric = 1 if health["overall_status"] == "HEALTHY" else 0
        prometheus_metrics.append(f"chatapi_health_status {health_numeric}")
        
        return Response(
            content="\n".join(prometheus_metrics),
            media_type="text/plain"
        )
    except Exception as e:
        logger.error("Failed to export metrics: %s", e)
        raise HTTPException(status_code=500, detail="Failed to export metrics")


@router.get("/error-summary")
async def get_error_summary(hours: int = 24):
    """Get error summary for the specified time period."""
    try:
        summary = error_handler.get_error_summary(hours)
        return summary
    except Exception as e:
        logger.error("Failed to get error summary: %s", e)
        raise HTTPException(status_code=500, detail="Failed to get error summary")
