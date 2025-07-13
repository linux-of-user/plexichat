"""
PlexiChat Admin API Endpoints

Consolidated admin management API endpoints including:
- System administration
- User management
- Configuration management
- Monitoring and analytics
- Security controls

Merged from:
- admin.py
- admin_api.py
- admin_enhanced.py
- admin/communication_admin_endpoints.py
"""

import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/admin", tags=["Administration"])

# API Models
class SystemStatus(BaseModel):
    """System status model."""
    status: str
    uptime: float
    memory_usage: Dict[str, float]
    cpu_usage: float
    disk_usage: Dict[str, float]
    active_connections: int
    total_users: int
    timestamp: datetime

class UserManagementAction(str, Enum):
    """User management actions."""
    ACTIVATE = "activate"
    DEACTIVATE = "deactivate"
    SUSPEND = "suspend"
    BAN = "ban"
    UNBAN = "unban"
    DELETE = "delete"

class UserManagementRequest(BaseModel):
    """User management request."""
    user_id: str
    action: UserManagementAction
    reason: Optional[str] = None
    duration: Optional[int] = None  # Duration in hours for temporary actions

class ConfigurationUpdate(BaseModel):
    """Configuration update model."""
    section: str
    key: str
    value: Any
    description: Optional[str] = None

class SystemMetrics(BaseModel):
    """System metrics model."""
    requests_per_minute: float
    error_rate: float
    average_response_time: float
    active_sessions: int
    database_connections: int
    cache_hit_rate: float
    memory_usage_percent: float
    cpu_usage_percent: float

class SecurityEvent(BaseModel):
    """Security event model."""
    id: str
    event_type: str
    severity: str
    user_id: Optional[str]
    ip_address: str
    description: str
    timestamp: datetime
    resolved: bool = False

# System Administration Endpoints
@router.get("/status", response_model=SystemStatus)
async def get_system_status():
    """Get current system status."""
    try:
        from ....infrastructure.services.health import HealthCheckService
        
        health_service = HealthCheckService()
        status = await health_service.get_system_status()
        
        return SystemStatus(
            status=status.get("status", "unknown"),
            uptime=status.get("uptime", 0.0),
            memory_usage=status.get("memory_usage", {}),
            cpu_usage=status.get("cpu_usage", 0.0),
            disk_usage=status.get("disk_usage", {}),
            active_connections=status.get("active_connections", 0),
            total_users=status.get("total_users", 0),
            timestamp=datetime.now()
        )
        
    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/metrics", response_model=SystemMetrics)
async def get_system_metrics(
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None)
):
    """Get system performance metrics."""
    try:
        from ....infrastructure.monitoring.metrics_collector import MetricsCollector
        
        collector = MetricsCollector()
        
        if not start_time:
            start_time = datetime.now() - timedelta(hours=1)
        if not end_time:
            end_time = datetime.now()
            
        metrics = await collector.get_system_metrics(start_time, end_time)
        
        return SystemMetrics(
            requests_per_minute=metrics.get("requests_per_minute", 0.0),
            error_rate=metrics.get("error_rate", 0.0),
            average_response_time=metrics.get("average_response_time", 0.0),
            active_sessions=metrics.get("active_sessions", 0),
            database_connections=metrics.get("database_connections", 0),
            cache_hit_rate=metrics.get("cache_hit_rate", 0.0),
            memory_usage_percent=metrics.get("memory_usage_percent", 0.0),
            cpu_usage_percent=metrics.get("cpu_usage_percent", 0.0)
        )
        
    except Exception as e:
        logger.error(f"Failed to get system metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# User Management Endpoints
@router.get("/users")
async def list_users(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=1000),
    status: Optional[str] = Query(None),
    role: Optional[str] = Query(None)
):
    """List users with filtering and pagination."""
    try:
        from ....features.users.user_service import UserService
        
        user_service = UserService()
        users = await user_service.list_users(
            page=page,
            limit=limit,
            status=status,
            role=role
        )
        
        return users
        
    except Exception as e:
        logger.error(f"Failed to list users: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/users/{user_id}/manage")
async def manage_user(
    user_id: str,
    request: UserManagementRequest,
    background_tasks: BackgroundTasks
):
    """Perform user management actions."""
    try:
        from ....features.users.user_service import UserService
        
        user_service = UserService()
        await user_service.manage_user(
            user_id=user_id,
            action=request.action.value,
            reason=request.reason,
            duration=request.duration
        )
        
        # Log the action
        background_tasks.add_task(
            log_admin_action,
            action="user_management",
            target_user_id=user_id,
            details=request.dict()
        )
        
        return {"success": True, "message": f"User {request.action.value} action completed"}
        
    except Exception as e:
        logger.error(f"Failed to manage user {user_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Configuration Management Endpoints
@router.get("/config")
async def get_configuration():
    """Get current system configuration."""
    try:
        from ....core_system.config import get_config
        
        config = get_config()
        
        # Return sanitized config (remove sensitive data)
        sanitized_config = {
            "server": {
                "host": config.server.host,
                "port": config.server.port,
                "workers": config.server.workers,
                "debug": config.server.debug,
                "environment": config.server.environment
            },
            "database": {
                "pool_size": config.database.pool_size,
                "pool_timeout": config.database.pool_timeout,
                "echo": config.database.echo
            },
            "security": {
                "access_token_expire_minutes": config.security.access_token_expire_minutes,
                "password_min_length": config.security.password_min_length,
                "max_login_attempts": config.security.max_login_attempts
            },
            "logging": {
                "level": config.logging.level,
                "file_enabled": config.logging.file_enabled
            }
        }
        
        return sanitized_config
        
    except Exception as e:
        logger.error(f"Failed to get configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/config/update")
async def update_configuration(
    update: ConfigurationUpdate,
    background_tasks: BackgroundTasks
):
    """Update system configuration."""
    try:
        from ....core_system.config import set_setting

        # Validate the configuration key
        allowed_sections = ["server", "database", "security", "logging"]
        if update.section not in allowed_sections:
            raise HTTPException(status_code=400, detail=f"Invalid configuration section: {update.section}")
        
        # Update the configuration
        config_key = f"{update.section}.{update.key}"
        success = set_setting(config_key, update.value)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update configuration")
        
        # Log the configuration change
        background_tasks.add_task(
            log_admin_action,
            action="config_update",
            details=update.dict()
        )
        
        return {"success": True, "message": f"Configuration {config_key} updated successfully"}
        
    except Exception as e:
        logger.error(f"Failed to update configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Security Management Endpoints
@router.get("/security/events", response_model=List[SecurityEvent])
async def get_security_events(
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    resolved: Optional[bool] = Query(None)
):
    """Get security events."""
    try:
        from ....features.security.security_monitor import SecurityMonitor
        
        monitor = SecurityMonitor()
        events = await monitor.get_security_events(
            limit=limit,
            severity=severity,
            resolved=resolved
        )
        
        return [
            SecurityEvent(
                id=event.get("id", ""),
                event_type=event.get("event_type", ""),
                severity=event.get("severity", ""),
                user_id=event.get("user_id"),
                ip_address=event.get("ip_address", ""),
                description=event.get("description", ""),
                timestamp=event.get("timestamp", datetime.now()),
                resolved=event.get("resolved", False)
            )
            for event in events
        ]
        
    except Exception as e:
        logger.error(f"Failed to get security events: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/security/events/{event_id}/resolve")
async def resolve_security_event(
    event_id: str,
    background_tasks: BackgroundTasks
):
    """Resolve a security event."""
    try:
        from ....features.security.security_monitor import SecurityMonitor
        
        monitor = SecurityMonitor()
        await monitor.resolve_security_event(event_id)
        
        # Log the action
        background_tasks.add_task(
            log_admin_action,
            action="security_event_resolved",
            details={"event_id": event_id}
        )
        
        return {"success": True, "message": f"Security event {event_id} resolved"}
        
    except Exception as e:
        logger.error(f"Failed to resolve security event {event_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# System Control Endpoints
@router.post("/system/restart")
async def restart_system(background_tasks: BackgroundTasks):
    """Restart the system (graceful shutdown and restart)."""
    try:
        # Log the restart action
        background_tasks.add_task(
            log_admin_action,
            action="system_restart",
            details={"timestamp": datetime.now()}
        )
        
        # Schedule system restart
        background_tasks.add_task(schedule_system_restart)
        
        return {"success": True, "message": "System restart scheduled"}
        
    except Exception as e:
        logger.error(f"Failed to restart system: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/system/maintenance")
async def toggle_maintenance_mode(
    enabled: bool,
    message: Optional[str] = None,
    background_tasks: BackgroundTasks = None
):
    """Toggle maintenance mode."""
    try:
        from ....core_system.config import set_setting

        # Update maintenance mode setting
        set_setting("system.maintenance_mode", enabled)
        if message:
            set_setting("system.maintenance_message", message)
        
        # Log the action
        if background_tasks:
            background_tasks.add_task(
                log_admin_action,
                action="maintenance_mode_toggle",
                details={"enabled": enabled, "message": message}
            )
        
        status = "enabled" if enabled else "disabled"
        return {"success": True, "message": f"Maintenance mode {status}"}
        
    except Exception as e:
        logger.error(f"Failed to toggle maintenance mode: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Helper functions
async def log_admin_action(action: str, target_user_id: Optional[str] = None, details: Optional[Dict] = None):
    """Log administrative actions."""
    try:
        from ....infrastructure.services.audit_logger import AuditLogger
        
        audit_logger = AuditLogger()
        await audit_logger.log_admin_action(
            action=action,
            target_user_id=target_user_id,
            details=details,
            timestamp=datetime.now()
        )
        
    except Exception as e:
        logger.error(f"Failed to log admin action: {e}")

async def schedule_system_restart():
    """Schedule a graceful system restart."""
    try:
        import asyncio

        from ....infrastructure.utils.shutdown import GracefulShutdown

        # Wait a bit to allow the response to be sent
        await asyncio.sleep(2)
        
        shutdown_handler = GracefulShutdown()
        await shutdown_handler.restart_system()
        
    except Exception as e:
        logger.error(f"Failed to restart system: {e}")

# Export router
__all__ = ["router"]
