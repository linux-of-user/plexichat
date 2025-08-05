#!/usr/bin/env python3
"""
Backup Management WebUI Router

Provides a web interface for managing backups through the unified backup system.
"""

import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Request, Depends, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from pydantic import BaseModel

# Import backup system
try:
    from plexichat.core.backup import (
        get_backup_manager, BackupType, BackupStatus,
        create_database_backup, create_files_backup, create_full_backup,
        restore_backup, list_backups
    )
    BACKUP_AVAILABLE = True
except ImportError:
    BACKUP_AVAILABLE = False

# Import authentication
try:
    from plexichat.interfaces.api.v1.auth import get_current_user
    AUTH_AVAILABLE = True
except ImportError:
    AUTH_AVAILABLE = False
    async def get_current_user(): return {"id": "admin", "username": "admin", "is_admin": True}

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/backup", tags=["Backup Management"])

# Templates setup
templates_path = Path(__file__).parent.parent / "templates"
templates = None
if templates_path.exists():
    templates = Jinja2Templates(directory=str(templates_path))

class BackupCreateRequest(BaseModel):
    """Backup creation request model."""
    backup_type: str
    name: Optional[str] = None
    include_paths: Optional[List[str]] = None

class RestoreRequest(BaseModel):
    """Restore request model."""
    backup_id: str
    restore_path: Optional[str] = None

@router.get("/", response_class=HTMLResponse)
async def backup_dashboard(request: Request, current_user: dict = Depends(get_current_user)):
    """Main backup management dashboard."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    
    # Check admin permissions
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    backup_manager = get_backup_manager()
    
    # Get backup statistics
    stats = backup_manager.get_backup_stats()
    
    # Get recent backups
    recent_backups = backup_manager.list_backups()[:10]  # Last 10 backups
    
    if templates:
        return templates.TemplateResponse(
            "admin/backup_management.html",
            {
                "request": request,
                "stats": stats,
                "recent_backups": recent_backups,
                "backup_types": [bt.value for bt in BackupType],
                "current_user": current_user
            }
        )
    
    # Fallback HTML
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PlexiChat Backup Management</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container-fluid">
            <div class="row">
                <div class="col-12">
                    <h2><i class="fas fa-archive"></i> Backup Management</h2>
                    <div class="row">
                        <div class="col-md-3">
                            <div class="card">
                                <div class="card-body">
                                    <h5>Total Backups</h5>
                                    <h3>{stats['total_backups']}</h3>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card">
                                <div class="card-body">
                                    <h5>Completed</h5>
                                    <h3 class="text-success">{stats['completed_backups']}</h3>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card">
                                <div class="card-body">
                                    <h5>Failed</h5>
                                    <h3 class="text-danger">{stats['failed_backups']}</h3>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card">
                                <div class="card-body">
                                    <h5>Total Size</h5>
                                    <h3>{stats['total_size_mb']} MB</h3>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="mt-4">
                        <button class="btn btn-primary" onclick="createBackup('database')">
                            <i class="fas fa-database"></i> Database Backup
                        </button>
                        <button class="btn btn-info" onclick="createBackup('files')">
                            <i class="fas fa-folder"></i> Files Backup
                        </button>
                        <button class="btn btn-success" onclick="createBackup('full')">
                            <i class="fas fa-archive"></i> Full Backup
                        </button>
                    </div>
                </div>
            </div>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            async function createBackup(type) {{
                try {{
                    const response = await fetch('/backup/api/create', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ backup_type: type }})
                    }});
                    if (response.ok) {{
                        alert('Backup started successfully');
                        location.reload();
                    }} else {{
                        alert('Failed to start backup');
                    }}
                }} catch (error) {{
                    alert('Error: ' + error.message);
                }}
            }}
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@router.get("/api/list")
async def list_all_backups(
    backup_type: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """List all backups."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backup_type_enum = BackupType(backup_type) if backup_type else None
        backups = list_backups(backup_type_enum)
        
        # Convert to serializable format
        backup_list = []
        for backup in backups:
            backup_list.append({
                "backup_id": backup.backup_id,
                "name": backup.name,
                "backup_type": backup.backup_type.value,
                "size": backup.size,
                "created_at": backup.created_at.isoformat(),
                "status": backup.status.value,
                "error_message": backup.error_message,
                "checksum": backup.checksum
            })
        
        return JSONResponse(content={"backups": backup_list})
        
    except Exception as e:
        logger.error(f"List backups error: {e}")
        raise HTTPException(status_code=500, detail="Failed to list backups")

@router.post("/api/create")
async def create_backup_endpoint(
    backup_request: BackupCreateRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Create a new backup."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backup_type = backup_request.backup_type.lower()
        
        # Start backup in background
        if backup_type == "database":
            background_tasks.add_task(create_database_backup, backup_request.name)
        elif backup_type == "files":
            background_tasks.add_task(create_files_backup, backup_request.name, backup_request.include_paths)
        elif backup_type == "full":
            background_tasks.add_task(create_full_backup, backup_request.name)
        else:
            raise HTTPException(status_code=400, detail="Invalid backup type")
        
        logger.info(f"Backup creation started by {current_user['username']}: {backup_type}")
        
        return JSONResponse(content={
            "success": True,
            "message": f"{backup_type.title()} backup started successfully"
        })
        
    except Exception as e:
        logger.error(f"Create backup error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create backup")

@router.post("/api/restore")
async def restore_backup_endpoint(
    restore_request: RestoreRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Restore a backup."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        # Start restore in background
        background_tasks.add_task(restore_backup, restore_request.backup_id, restore_request.restore_path)
        
        logger.info(f"Backup restore started by {current_user['username']}: {restore_request.backup_id}")
        
        return JSONResponse(content={
            "success": True,
            "message": "Backup restore started successfully"
        })
        
    except Exception as e:
        logger.error(f"Restore backup error: {e}")
        raise HTTPException(status_code=500, detail="Failed to restore backup")

@router.delete("/api/delete/{backup_id}")
async def delete_backup_endpoint(
    backup_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a backup."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backup_manager = get_backup_manager()
        success = backup_manager.delete_backup(backup_id)
        
        if success:
            logger.info(f"Backup deleted by {current_user['username']}: {backup_id}")
            return JSONResponse(content={
                "success": True,
                "message": "Backup deleted successfully"
            })
        else:
            raise HTTPException(status_code=404, detail="Backup not found")
        
    except Exception as e:
        logger.error(f"Delete backup error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete backup")

@router.get("/api/stats")
async def get_backup_stats(current_user: dict = Depends(get_current_user)):
    """Get backup statistics."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backup_manager = get_backup_manager()
        stats = backup_manager.get_backup_stats()
        return JSONResponse(content=stats)
        
    except Exception as e:
        logger.error(f"Get backup stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get backup statistics")

@router.post("/api/cleanup")
async def cleanup_old_backups(current_user: dict = Depends(get_current_user)):
    """Clean up old backups."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backup_manager = get_backup_manager()
        deleted_count = backup_manager.cleanup_old_backups()
        
        logger.info(f"Backup cleanup performed by {current_user['username']}: {deleted_count} backups deleted")
        
        return JSONResponse(content={
            "success": True,
            "message": f"Cleaned up {deleted_count} old backups"
        })
        
    except Exception as e:
        logger.error(f"Cleanup backups error: {e}")
        raise HTTPException(status_code=500, detail="Failed to cleanup backups")

# Export router
__all__ = ["router"]
