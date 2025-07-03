"""
Enhanced WebUI Server Management
Intelligent server management interface with hot updates, graceful restarts, and monitoring.
"""

import asyncio
import json
import logging
import os
import psutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Request, Form, HTTPException, BackgroundTasks, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from netlink.core.server_manager import server_manager, ServerState, UpdateType
from netlink.app.logger_config import logger

# Initialize router and templates
router = APIRouter(prefix="/ui/server", tags=["Server Management"])
templates = Jinja2Templates(directory="src/netlink/app/webui/templates")

# Authentication dependency (placeholder)
async def verify_admin_access():
    """Verify admin access for server management operations."""
    # TODO: Implement proper authentication
    return True

@router.get("/", response_class=HTMLResponse)
async def server_dashboard(request: Request):
    """Main server management dashboard."""
    try:
        # Get comprehensive server status
        status = server_manager.get_server_status()
        
        # Get system metrics
        system_metrics = _get_system_metrics()
        
        # Get recent logs
        recent_logs = _get_recent_logs(limit=50)
        
        # Prepare dashboard data
        dashboard_data = {
            "server_info": status.get('server_info', {}),
            "health": status.get('health', {}),
            "resources": status.get('resources', {}),
            "configuration": status.get('configuration', {}),
            "system_metrics": system_metrics,
            "recent_logs": recent_logs,
            "uptime": status.get('uptime_formatted', '0 seconds'),
            "can_restart": status['server_info'].get('state') in ['running', 'idle'],
            "can_stop": status['server_info'].get('state') in ['running', 'idle'],
            "can_start": status['server_info'].get('state') in ['stopped', 'error'],
            "update_available": _check_for_updates(),
            "backup_info": _get_backup_info()
        }
        
        return templates.TemplateResponse("server_dashboard.html", {
            "request": request,
            "data": dashboard_data,
            "page_title": "Server Management Dashboard"
        })
        
    except Exception as e:
        logger.error(f"Server dashboard error: {e}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e),
            "page_title": "Server Dashboard Error"
        })

@router.post("/action/start")
async def start_server_action(
    request: Request,
    background_tasks: BackgroundTasks,
    _: bool = Depends(verify_admin_access)
):
    """Start the server."""
    try:
        if server_manager.server_info.state == ServerState.RUNNING:
            return JSONResponse({
                "success": True,
                "message": "Server is already running",
                "status": server_manager.server_info.state.value
            })
        
        # Start server in background
        background_tasks.add_task(server_manager.start_server)
        
        return JSONResponse({
            "success": True,
            "message": "Server start initiated",
            "status": ServerState.STARTING.value
        })
        
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        return JSONResponse({
            "success": False,
            "message": str(e)
        }, status_code=500)

@router.post("/action/stop")
async def stop_server_action(
    request: Request,
    graceful: bool = Form(True),
    timeout: int = Form(30),
    background_tasks: BackgroundTasks,
    _: bool = Depends(verify_admin_access)
):
    """Stop the server."""
    try:
        if server_manager.server_info.state == ServerState.STOPPED:
            return JSONResponse({
                "success": True,
                "message": "Server is already stopped",
                "status": server_manager.server_info.state.value
            })
        
        # Stop server in background
        background_tasks.add_task(
            server_manager.stop_server,
            graceful=graceful,
            timeout=timeout
        )
        
        return JSONResponse({
            "success": True,
            "message": f"Server {'graceful' if graceful else 'force'} stop initiated",
            "status": ServerState.STOPPING.value
        })
        
    except Exception as e:
        logger.error(f"Failed to stop server: {e}")
        return JSONResponse({
            "success": False,
            "message": str(e)
        }, status_code=500)

@router.post("/action/restart")
async def restart_server_action(
    request: Request,
    graceful: bool = Form(True),
    create_backup: bool = Form(False),
    background_tasks: BackgroundTasks,
    _: bool = Depends(verify_admin_access)
):
    """Restart the server intelligently."""
    try:
        # Create backup if requested
        if create_backup:
            backup_name = f"pre_restart_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            server_manager.create_backup(backup_name)
        
        # Restart server in background
        background_tasks.add_task(server_manager.restart_server)
        
        return JSONResponse({
            "success": True,
            "message": "Server restart initiated",
            "status": ServerState.RESTARTING.value,
            "backup_created": create_backup
        })
        
    except Exception as e:
        logger.error(f"Failed to restart server: {e}")
        return JSONResponse({
            "success": False,
            "message": str(e)
        }, status_code=500)

@router.post("/action/hot-update")
async def apply_hot_update_action(
    request: Request,
    update_type: str = Form(...),
    description: str = Form(""),
    files: str = Form("[]"),
    background_tasks: BackgroundTasks,
    _: bool = Depends(verify_admin_access)
):
    """Apply hot update without server restart."""
    try:
        from netlink.core.server_manager import UpdateInfo, UpdateType
        
        # Parse files list
        try:
            files_list = json.loads(files) if files else []
        except json.JSONDecodeError:
            files_list = []
        
        # Create update info
        update_info = UpdateInfo(
            id=f"hot_update_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            type=UpdateType(update_type),
            version="",
            description=description,
            files=files_list,
            backup_required=True,
            restart_required=False
        )
        
        # Apply hot update in background
        background_tasks.add_task(server_manager.apply_hot_update, update_info)
        
        return JSONResponse({
            "success": True,
            "message": "Hot update initiated",
            "update_id": update_info.id,
            "update_type": update_type,
            "files_count": len(files_list)
        })
        
    except Exception as e:
        logger.error(f"Failed to apply hot update: {e}")
        return JSONResponse({
            "success": False,
            "message": str(e)
        }, status_code=500)

@router.get("/status")
async def get_server_status():
    """Get real-time server status."""
    try:
        status = server_manager.get_server_status()
        system_metrics = _get_system_metrics()
        
        return JSONResponse({
            "success": True,
            "data": {
                "server_info": status.get('server_info', {}),
                "health": status.get('health', {}),
                "resources": status.get('resources', {}),
                "system_metrics": system_metrics,
                "uptime": status.get('uptime_formatted', '0 seconds'),
                "timestamp": datetime.now().isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Failed to get server status: {e}")
        return JSONResponse({
            "success": False,
            "message": str(e)
        }, status_code=500)

@router.get("/logs")
async def get_server_logs(
    limit: int = 100,
    level: str = "all",
    since: str = None
):
    """Get server logs with filtering."""
    try:
        logs = _get_recent_logs(limit=limit, level=level, since=since)
        
        return JSONResponse({
            "success": True,
            "data": {
                "logs": logs,
                "count": len(logs),
                "timestamp": datetime.now().isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Failed to get server logs: {e}")
        return JSONResponse({
            "success": False,
            "message": str(e)
        }, status_code=500)

@router.post("/backup/create")
async def create_backup_action(
    request: Request,
    backup_name: str = Form(None),
    include_data: bool = Form(True),
    include_config: bool = Form(True),
    include_logs: bool = Form(False),
    _: bool = Depends(verify_admin_access)
):
    """Create server backup."""
    try:
        if not backup_name:
            backup_name = f"manual_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        backup_path = server_manager.create_backup(backup_name)
        
        return JSONResponse({
            "success": True,
            "message": "Backup created successfully",
            "backup_path": str(backup_path),
            "backup_name": backup_name
        })
        
    except Exception as e:
        logger.error(f"Failed to create backup: {e}")
        return JSONResponse({
            "success": False,
            "message": str(e)
        }, status_code=500)

@router.get("/updates/check")
async def check_for_updates():
    """Check for available updates."""
    try:
        updates = _check_for_updates()
        
        return JSONResponse({
            "success": True,
            "data": {
                "updates_available": len(updates) > 0,
                "updates": updates,
                "last_check": datetime.now().isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Failed to check for updates: {e}")
        return JSONResponse({
            "success": False,
            "message": str(e)
        }, status_code=500)

@router.get("/health/detailed")
async def get_detailed_health():
    """Get detailed health information."""
    try:
        status = server_manager.get_server_status()
        health = status.get('health', {})
        
        # Enhanced health checks
        detailed_health = {
            "overall_status": health.get('status', 'unknown'),
            "components": {
                "database": _check_database_health(),
                "filesystem": _check_filesystem_health(),
                "network": _check_network_health(),
                "memory": _check_memory_health(),
                "disk": _check_disk_health()
            },
            "issues": health.get('issues', []),
            "recommendations": _get_health_recommendations(health),
            "last_check": datetime.now().isoformat()
        }
        
        return JSONResponse({
            "success": True,
            "data": detailed_health
        })
        
    except Exception as e:
        logger.error(f"Failed to get detailed health: {e}")
        return JSONResponse({
            "success": False,
            "message": str(e)
        }, status_code=500)

# Helper functions
def _get_system_metrics() -> Dict[str, Any]:
    """Get comprehensive system metrics."""
    try:
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        
        # Memory metrics
        memory = psutil.virtual_memory()
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        
        # Network metrics
        network = psutil.net_io_counters()
        
        return {
            "cpu": {
                "percent": cpu_percent,
                "count": cpu_count,
                "load_avg": os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
            },
            "memory": {
                "total": memory.total,
                "available": memory.available,
                "percent": memory.percent,
                "used": memory.used
            },
            "disk": {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": (disk.used / disk.total) * 100
            },
            "network": {
                "bytes_sent": network.bytes_sent,
                "bytes_recv": network.bytes_recv,
                "packets_sent": network.packets_sent,
                "packets_recv": network.packets_recv
            }
        }
    except Exception as e:
        logger.error(f"Failed to get system metrics: {e}")
        return {}

def _get_recent_logs(limit: int = 100, level: str = "all", since: str = None) -> List[Dict[str, Any]]:
    """Get recent log entries."""
    try:
        logs = []
        log_file = Path("logs/netlink.log")
        
        if log_file.exists():
            with open(log_file, 'r') as f:
                lines = f.readlines()
                
            # Parse recent log lines
            for line in lines[-limit:]:
                if line.strip():
                    # Simple log parsing - in production would use proper log parser
                    parts = line.strip().split(' - ', 3)
                    if len(parts) >= 3:
                        logs.append({
                            "timestamp": parts[0] if len(parts) > 0 else "",
                            "level": parts[1] if len(parts) > 1 else "INFO",
                            "message": parts[2] if len(parts) > 2 else line.strip(),
                            "raw": line.strip()
                        })
        
        return logs
    except Exception as e:
        logger.error(f"Failed to get recent logs: {e}")
        return []

def _check_for_updates() -> List[Dict[str, Any]]:
    """Check for available updates."""
    # Placeholder implementation
    return []

def _get_backup_info() -> Dict[str, Any]:
    """Get backup information."""
    try:
        backup_dir = Path("backups/server")
        if not backup_dir.exists():
            return {"count": 0, "latest": None, "total_size": 0}
        
        backups = list(backup_dir.glob("*.tar.gz"))
        total_size = sum(backup.stat().st_size for backup in backups)
        
        latest_backup = None
        if backups:
            latest_backup = max(backups, key=lambda x: x.stat().st_mtime)
            latest_backup = {
                "name": latest_backup.name,
                "size": latest_backup.stat().st_size,
                "created": datetime.fromtimestamp(latest_backup.stat().st_mtime).isoformat()
            }
        
        return {
            "count": len(backups),
            "latest": latest_backup,
            "total_size": total_size
        }
    except Exception as e:
        logger.error(f"Failed to get backup info: {e}")
        return {"count": 0, "latest": None, "total_size": 0}

def _check_database_health() -> Dict[str, Any]:
    """Check database health."""
    # Placeholder implementation
    return {"status": "healthy", "connections": 5, "response_time": 0.05}

def _check_filesystem_health() -> Dict[str, Any]:
    """Check filesystem health."""
    try:
        disk = psutil.disk_usage('/')
        return {
            "status": "healthy" if disk.percent < 90 else "warning",
            "usage_percent": disk.percent,
            "free_space": disk.free
        }
    except:
        return {"status": "unknown"}

def _check_network_health() -> Dict[str, Any]:
    """Check network health."""
    # Placeholder implementation
    return {"status": "healthy", "latency": 0.02, "bandwidth": "1Gbps"}

def _check_memory_health() -> Dict[str, Any]:
    """Check memory health."""
    try:
        memory = psutil.virtual_memory()
        return {
            "status": "healthy" if memory.percent < 85 else "warning",
            "usage_percent": memory.percent,
            "available": memory.available
        }
    except:
        return {"status": "unknown"}

def _check_disk_health() -> Dict[str, Any]:
    """Check disk health."""
    try:
        disk = psutil.disk_usage('/')
        return {
            "status": "healthy" if disk.percent < 80 else "warning",
            "usage_percent": disk.percent,
            "free_space": disk.free
        }
    except:
        return {"status": "unknown"}

def _get_health_recommendations(health: Dict[str, Any]) -> List[str]:
    """Get health recommendations based on current status."""
    recommendations = []
    
    # Add recommendations based on health status
    if health.get('status') == 'warning':
        recommendations.append("Consider restarting the server to clear any memory leaks")
        recommendations.append("Check log files for any recurring errors")
    
    return recommendations
