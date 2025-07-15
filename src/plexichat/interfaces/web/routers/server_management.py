import logging
from datetime import datetime
from typing import List, Optional



from datetime import datetime
from datetime import datetime



from datetime import datetime
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.security import HTTPBearer
from pydantic import BaseModel

from plexichat.core.server_manager import ServerState, UpdateInfo, UpdateType, server_manager
from plexichat.infrastructure.utils.auth import verify_admin_token

"""
PlexiChat Server Management API
Comprehensive server management endpoints for hot reload, updates, and monitoring.
"""

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/server", tags=["server-management"])
security = HTTPBearer()

class ServerActionRequest(BaseModel):
    """Server action request model."""
    action: str
    graceful: bool = True
    timeout: Optional[int] = None
    backup: bool = True

class UpdateRequest(BaseModel):
    """Update request model."""
    update_id: str
    update_type: UpdateType
    version: str
    description: str
    files: List[str]
    force: bool = False

class BackupRequest(BaseModel):
    """Backup request model."""
    backup_name: Optional[str] = None
    include_data: bool = True
    include_logs: bool = False

@router.get("/status")
async def get_server_status():
    """Get comprehensive server status."""
    try:
        status = server_manager.get_server_status()
        return {
            "success": True,
            "data": status
        }
    except Exception as e:
        logger.error(f"Failed to get server status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/start")
async def start_server(
    background_tasks: BackgroundTasks,
    token: str = Depends(security)
):
    """Start the PlexiChat server."""
    verify_admin_token(token.credentials)

    try:
        if server_manager.server_info.state == ServerState.RUNNING:
            return {
                "success": True,
                "message": "Server is already running",
                "status": server_manager.server_info.state.value
            }

        # Start server in background
        background_tasks.add_task(server_manager.start_server)

        return {
            "success": True,
            "message": "Server start initiated",
            "status": ServerState.STARTING.value
        }

    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/stop")
async def stop_server(
    request: ServerActionRequest,
    background_tasks: BackgroundTasks,
    token: str = Depends(security)
):
    """Stop the PlexiChat server."""
    verify_admin_token(token.credentials)

    try:
        if server_manager.server_info.state == ServerState.STOPPED:
            return {
                "success": True,
                "message": "Server is already stopped",
                "status": server_manager.server_info.state.value
            }

        # Stop server in background
        background_tasks.add_task(
            server_manager.stop_server,
            graceful=request.graceful,
            timeout=request.timeout
        )

        return {
            "success": True,
            "message": f"Server {'graceful' if request.graceful else 'force'} stop initiated",
            "status": ServerState.STOPPING.value
        }

    except Exception as e:
        logger.error(f"Failed to stop server: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/restart")
async def restart_server(
    request: ServerActionRequest,
    background_tasks: BackgroundTasks,
    token: str = Depends(security)
):
    """Restart the PlexiChat server."""
    verify_admin_token(token.credentials)

    try:
        # Create backup if requested
        if request.backup:
            backup_name = f"pre_restart_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            server_manager.create_backup(backup_name)

        # Restart server in background
        background_tasks.add_task(server_manager.restart_server)

        return {
            "success": True,
            "message": "Server restart initiated",
            "status": ServerState.RESTARTING.value,
            "backup_created": request.backup
        }

    except Exception as e:
        logger.error(f"Failed to restart server: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/update/hot")
async def apply_hot_update(
    request: UpdateRequest,
    background_tasks: BackgroundTasks,
    token: str = Depends(security)
):
    """Apply hot update without server restart."""
    verify_admin_token(token.credentials)

    try:
        # Create update info
        update_info = UpdateInfo(
            id=request.update_id,
            type=request.update_type,
            version=request.version,
            description=request.description,
            files=request.files,
            backup_required=True,
            restart_required=False
        )

        # Apply hot update in background
        background_tasks.add_task(server_manager.apply_hot_update, update_info)

        return {
            "success": True,
            "message": "Hot update initiated",
            "update_id": request.update_id,
            "update_type": request.update_type.value,
            "files_count": len(request.files)
        }

    except Exception as e:
        logger.error(f"Failed to apply hot update: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def get_server_health():
    """Get server health status."""
    try:
        status = server_manager.get_server_status()
        health = status.get('health', {})

        return {
            "success": True,
            "data": {
                "status": health.get('status', 'unknown'),
                "issues": health.get('issues', []),
                "uptime": status.get('uptime_formatted', '0 seconds'),
                "memory_usage": status['server_info'].get('memory_usage', 0),
                "cpu_usage": status['server_info'].get('cpu_usage', 0),
                "state": status['server_info'].get('state', 'unknown')
            }
        }

    except Exception as e:
        logger.error(f"Failed to get server health: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/integrity")
async def check_server_integrity(token: str = Depends(security)):
    """Check server integrity."""
    verify_admin_token(token.credentials)

    try:
        integrity_results = server_manager.check_integrity()

        return {
            "success": True,
            "data": integrity_results
        }

    except Exception as e:
        logger.error(f"Failed to check integrity: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/backup/create")
async def create_backup(
    request: BackupRequest,
    token: str = Depends(security)
):
    """Create server backup."""
    verify_admin_token(token.credentials)

    try:
        backup_path = server_manager.create_backup(request.backup_name)

        return {
            "success": True,
            "message": "Backup created successfully",
            "backup_path": backup_path,
            "backup_name": request.backup_name or backup_path.split('/')[-1]
        }

    except Exception as e:
        logger.error(f"Failed to create backup: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/backup/list")
async def list_backups(token: str = Depends(security)):
    """List available backups."""
    verify_admin_token(token.credentials)

    try:
        backups = server_manager.list_backups()

        return {
            "success": True,
            "data": {
                "backups": backups,
                "count": len(backups)
            }
        }

    except Exception as e:
        logger.error(f"Failed to list backups: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/backup/restore/{backup_name}")
async def restore_backup(
    backup_name: str,
    background_tasks: BackgroundTasks,
    token: str = Depends(security)
):
    """Restore server from backup."""
    verify_admin_token(token.credentials)

    try:
        # Restore backup in background
        background_tasks.add_task(server_manager.restore_backup, backup_name)

        return {
            "success": True,
            "message": "Backup restore initiated",
            "backup_name": backup_name
        }

    except Exception as e:
        logger.error(f"Failed to restore backup: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/metrics")
async def get_server_metrics():
    """Get detailed server metrics."""
    try:
        status = server_manager.get_server_status()
        resources = status.get('resources', {})

        return {
            "success": True,
            "data": {
                "timestamp": datetime.now().isoformat(),
                "server_info": status['server_info'],
                "resources": resources,
                "health": status.get('health', {}),
                "configuration": status.get('configuration', {})
            }
        }

    except Exception as e:
        logger.error(f"Failed to get server metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/maintenance/enable")
async def enable_maintenance_mode(token: str = Depends(security)):
    """Enable maintenance mode."""
    verify_admin_token(token.credentials)

    try:
        server_manager.server_info.state = ServerState.MAINTENANCE

        return {
            "success": True,
            "message": "Maintenance mode enabled",
            "status": ServerState.MAINTENANCE.value
        }

    except Exception as e:
        logger.error(f"Failed to enable maintenance mode: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/maintenance/disable")
async def disable_maintenance_mode(token: str = Depends(security)):
    """Disable maintenance mode."""
    verify_admin_token(token.credentials)

    try:
        server_manager.server_info.state = ServerState.RUNNING

        return {
            "success": True,
            "message": "Maintenance mode disabled",
            "status": ServerState.RUNNING.value
        }

    except Exception as e:
        logger.error(f"Failed to disable maintenance mode: {e}")
        raise HTTPException(status_code=500, detail=str(e))
