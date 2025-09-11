#!/usr/bin/env python3
"""
Backup Management WebUI Router

Provides a web interface for managing backups through the unified backup system.
"""

import inspect
import asyncio
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Request, Depends, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from pydantic import BaseModel

# Import backup system
try:
    from plexichat.features.backup import (
        get_backup_manager, BackupType, BackupStatus,
        create_database_backup, create_files_backup, create_full_backup,
        restore_backup, list_backups
    )
    BACKUP_AVAILABLE = True
except Exception:
    # If import fails, mark as unavailable. The fallback stubs below will be used.
    BACKUP_AVAILABLE = False
    # Create minimal local stubs to avoid NameErrors later
    def get_backup_manager():
        raise RuntimeError("Backup system not available")

    class BackupType:
        DATABASE = "database"
        FILES = "files"
        FULL = "full"

    class BackupStatus:
        PENDING = "pending"
        RUNNING = "running"
        COMPLETED = "completed"
        FAILED = "failed"

    async def create_database_backup(*args, **kwargs):
        raise RuntimeError("Backup system not available")

    async def create_files_backup(*args, **kwargs):
        raise RuntimeError("Backup system not available")

    async def create_full_backup(*args, **kwargs):
        raise RuntimeError("Backup system not available")

    async def restore_backup(*args, **kwargs):
        raise RuntimeError("Backup system not available")

    async def list_backups(*args, **kwargs):
        return []

# Import authentication (use unified FastAPI adapter)
from plexichat.core.auth.fastapi_adapter import require_admin

# Unified logging
from plexichat.core.logging import get_logger
logger = get_logger(__name__)

# Create router
router = APIRouter(prefix="/backup", tags=["Backup Management"])

# Templates setup
templates_path = Path(__file__).parent.parent / "templates"
templates = None
if templates_path.exists():
    templates = Jinja2Templates(directory=str(templates_path))


# Request/response models
class BackupCreateRequest(BaseModel):
    """Backup creation request model."""
    backup_type: str
    name: Optional[str] = None
    include_paths: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    retention_days: Optional[int] = None


class RestoreRequest(BaseModel):
    """Restore request model."""
    backup_id: str
    restore_path: Optional[str] = None
    dry_run: Optional[bool] = False


class ScheduleCreateRequest(BaseModel):
    name: str
    cron_expression: str
    data_sources: List[str]
    backup_strategy: Optional[str] = "scheduled"
    backup_type: Optional[str] = "incremental"
    security_level: Optional[str] = "standard"
    retention_days: Optional[int] = None
    target_nodes: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


class RetentionUpdateRequest(BaseModel):
    backup_id: Optional[str] = None
    schedule_id: Optional[str] = None
    retention_days: int


class RecoveryRequest(BaseModel):
    plan_id: str
    backup_id: Optional[str] = None
    target_time: Optional[str] = None  # ISO timestamp
    dry_run: Optional[bool] = False


# Helper utilities to work with possibly-async manager implementations
async def _maybe_await(value):
    """Await value if it's awaitable, otherwise return directly."""
    if inspect.isawaitable(value):
        return await value
    return value


def _bg_schedule_coroutine(coro):
    """Schedule an awaitable coroutine to run in the background (used with FastAPI BackgroundTasks)."""
    # BackgroundTasks will call this function synchronously, so we create a task for the coroutine
    try:
        asyncio.create_task(coro)
    except RuntimeError:
        # No running loop; create one to run the coroutine in background
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.create_task(coro)


def _get_manager_method(manager, candidates: List[str]):
    """Return the first-found method on manager matching one of the candidate names."""
    for name in candidates:
        if hasattr(manager, name):
            return getattr(manager, name)
    return None


# Endpoints

@router.get("/", response_class=HTMLResponse)
async def backup_dashboard(request: Request, current_user: dict = Depends(require_admin)):
    """Main backup management dashboard."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")

    try:
        backup_manager = get_backup_manager()

        # Attempt to obtain statistics via common method names
        stats_method = _get_manager_method(backup_manager, ["get_backup_stats", "get_stats", "get_backup_statistics", "get_backup_statistics_sync"])
        stats = {}
        if stats_method:
            stats_raw = stats_method()
            stats = await _maybe_await(stats_raw)
        else:
            # Fallback to minimal statistics via listing
            backups = await _maybe_await(_get_manager_method(backup_manager, ["list_backups", "list_all_backups"])(limit=100))
            total = len(backups)
            completed = sum(1 for b in backups if getattr(b, "status", str(b.get("status", ""))).lower() in ("completed", "success"))
            failed = sum(1 for b in backups if getattr(b, "status", str(b.get("status", ""))).lower() in ("failed", "error"))
            total_size = sum(getattr(b, "size", b.get("size", 0)) for b in backups)
            stats = {
                "total_backups": total,
                "completed_backups": completed,
                "failed_backups": failed,
                "total_size_mb": round(total_size / (1024 * 1024), 2)
            }

        # Recent backups
        list_method = _get_manager_method(backup_manager, ["list_backups", "list_all_backups", "list"])
        recent_backups = []
        if list_method:
            recent = list_method()
            recent = await _maybe_await(recent)
            # recent may be list of objects or dicts
            try:
                # Normalize to list of dicts
                normalized = []
                for b in recent:
                    if hasattr(b, "backup_id"):
                        normalized.append({
                            "backup_id": getattr(b, "backup_id", None),
                            "name": getattr(b, "name", None),
                            "backup_type": getattr(getattr(b, "backup_type", ""), "value", getattr(b, "backup_type", "")),
                            "size": getattr(b, "size", getattr(b, "original_size", 0)),
                            "created_at": getattr(b, "created_at", getattr(b, "created", None))
                        })
                    elif isinstance(b, dict):
                        normalized.append(b)
                recent_backups = normalized[:10]
            except Exception:
                recent_backups = (recent[:10] if isinstance(recent, list) else [])

        if templates:
            return templates.TemplateResponse(
                "admin/backup_management.html",
                {
                    "request": request,
                    "stats": stats,
                    "recent_backups": recent_backups,
                    "backup_types": [getattr(bt, "value", bt) for bt in (BackupType.__dict__.keys() if isinstance(BackupType, type) else [])] if isinstance(BackupType, type) else [BackupType.DATABASE, BackupType.FILES, BackupType.FULL],
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
                                        <h3>{stats.get('total_backups', 0)}</h3>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card">
                                    <div class="card-body">
                                        <h5>Completed</h5>
                                        <h3 class="text-success">{stats.get('completed_backups', 0)}</h3>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card">
                                    <div class="card-body">
                                        <h5>Failed</h5>
                                        <h3 class="text-danger">{stats.get('failed_backups', 0)}</h3>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card">
                                    <div class="card-body">
                                        <h5>Total Size</h5>
                                        <h3>{stats.get('total_size_mb', 0)} MB</h3>
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
                async function createBackup(type){{
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
                            const body = await response.json();
                            alert('Failed to start backup: ' + (body.detail || JSON.stringify(body)));
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

    except Exception as e:
        logger.exception("Failed to render backup dashboard")
        raise HTTPException(status_code=500, detail="Failed to load backup dashboard")


@router.get("/api/list")
async def list_all_backups(
    backup_type: Optional[str] = None,
    current_user: dict = Depends(require_admin)
):
    """List all backups."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")

    try:
        backup_manager = get_backup_manager()

        # If a direct list_backups import exists, prefer it; otherwise use manager
        try:
            if callable(list_backups):
                backups = list_backups(backup_type) if backup_type else list_backups()
                backups = await _maybe_await(backups)
            else:
                raise Exception("list_backups not callable")
        except Exception:
            list_method = _get_manager_method(backup_manager, ["list_backups", "list_all_backups", "list"])
            if not list_method:
                raise HTTPException(status_code=500, detail="Backup listing not available")
            backups = list_method(backup_type) if backup_type else list_method()
            backups = await _maybe_await(backups)

        # Convert to serializable format
        backup_list = []
        for backup in backups:
            try:
                # support both object-like and dict-like backups
                if hasattr(backup, "backup_id"):
                    backup_list.append({
                        "backup_id": getattr(backup, "backup_id", None),
                        "name": getattr(backup, "name", None),
                        "backup_type": getattr(getattr(backup, "backup_type", ""), "value", getattr(backup, "backup_type", "")),
                        "size": getattr(backup, "size", getattr(backup, "original_size", 0)),
                        "created_at": getattr(backup, "created_at", getattr(backup, "created", None)).isoformat() if getattr(backup, "created_at", None) else None,
                        "status": getattr(getattr(backup, "status", ""), "value", getattr(backup, "status", "")),
                        "error_message": getattr(backup, "error_message", None),
                        "checksum": getattr(backup, "checksum", getattr(backup, "hash", None))
                    })
                elif isinstance(backup, dict):
                    item = backup.copy()
                    if "created_at" in item and hasattr(item["created_at"], "isoformat"):
                        item["created_at"] = item["created_at"].isoformat()
                    backup_list.append(item)
            except Exception:
                # Last-resort: convert to string representation
                backup_list.append({"raw": str(backup)})

        return JSONResponse(content={"backups": backup_list})

    except Exception as e:
        logger.exception("List backups error")
        raise HTTPException(status_code=500, detail="Failed to list backups")


@router.post("/api/create")
async def create_backup_endpoint(
    backup_request: BackupCreateRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_admin)
):
    """Create a new backup."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")

    try:
        backup_type = (backup_request.backup_type or "").lower()
        backup_manager = get_backup_manager()

        # Prefer manager.create_backup if available
        manager_create = _get_manager_method(backup_manager, ["create_backup", "start_backup", "create_backup_task"])
        if manager_create:
            # Prepare params - manager may expect different signature, but pass common ones
            coro = manager_create(
                data={"name": backup_request.name} if backup_type != "files" else {},
                backup_strategy=getattr(BackupType, backup_type.upper(), backup_type) if hasattr(BackupType, "__dict__") else backup_type,
                backup_type=backup_request.backup_type,
                user_id=current_user.get("id"),
                tags=backup_request.tags,
                retention_days=backup_request.retention_days,
                metadata={"initiated_by": current_user.get("username")}
            )
            # manager_create may be coroutine or sync - schedule it in background
            background_tasks.add_task(_bg_schedule_coroutine, coro)
        else:
            # Fall back to older module-level helpers
            if backup_type == "database":
                task = create_database_backup(backup_request.name)
            elif backup_type == "files":
                task = create_files_backup(backup_request.name, backup_request.include_paths)
            elif backup_type == "full":
                task = create_full_backup(backup_request.name)
            else:
                raise HTTPException(status_code=400, detail="Invalid backup type")

            # schedule task (task may be coroutine)
            background_tasks.add_task(_bg_schedule_coroutine, task)

        logger.info(f"Backup creation started by {current_user.get('username')}: {backup_type}")

        return JSONResponse(content={
            "success": True,
            "message": f"{backup_type.title()} backup started successfully"
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Create backup error")
        raise HTTPException(status_code=500, detail="Failed to create backup")


@router.post("/api/restore")
async def restore_backup_endpoint(
    restore_request: RestoreRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_admin)
):
    """Restore a backup."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")

    try:
        backup_manager = get_backup_manager()
        manager_restore = _get_manager_method(backup_manager, ["restore_backup", "execute_restore", "start_restore"])

        if manager_restore:
            coro = manager_restore(restore_request.backup_id, restore_request.restore_path)
            background_tasks.add_task(_bg_schedule_coroutine, coro)
        else:
            # Fallback to module-level restore_backup (may be sync or async)
            task = restore_backup(restore_request.backup_id, restore_request.restore_path)
            background_tasks.add_task(_bg_schedule_coroutine, task)

        logger.info(f"Backup restore started by {current_user.get('username')}: {restore_request.backup_id}")

        return JSONResponse(content={
            "success": True,
            "message": "Backup restore started successfully"
        })

    except Exception as e:
        logger.exception("Restore backup error")
        raise HTTPException(status_code=500, detail="Failed to restore backup")


@router.delete("/api/delete/{backup_id}")
async def delete_backup_endpoint(
    backup_id: str,
    current_user: dict = Depends(require_admin)
):
    """Delete a backup."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")

    try:
        backup_manager = get_backup_manager()
        delete_method = _get_manager_method(backup_manager, ["delete_backup", "remove_backup"])
        if not delete_method:
            raise HTTPException(status_code=500, detail="Delete operation not supported by backup manager")

        result = delete_method(backup_id)
        result = await _maybe_await(result)

        if result:
            logger.info(f"Backup deleted by {current_user.get('username')}: {backup_id}")
            return JSONResponse(content={
                "success": True,
                "message": "Backup deleted successfully"
            })
        else:
            raise HTTPException(status_code=404, detail="Backup not found")

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Delete backup error")
        raise HTTPException(status_code=500, detail="Failed to delete backup")


@router.get("/api/stats")
async def get_backup_stats(current_user: dict = Depends(require_admin)):
    """Get backup statistics."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")

    try:
        backup_manager = get_backup_manager()
        stats_method = _get_manager_method(backup_manager, ["get_backup_stats", "get_stats", "get_backup_statistics"])
        if not stats_method:
            # Try to assemble minimal stats
            list_method = _get_manager_method(backup_manager, ["list_backups", "list_all_backups", "list"])
            if not list_method:
                raise HTTPException(status_code=500, detail="Statistics not available")
            backups = await _maybe_await(list_method(limit=1000))
            total = len(backups)
            completed = sum(1 for b in backups if getattr(b, "status", str(b.get("status", ""))).lower() in ("completed", "success"))
            failed = sum(1 for b in backups if getattr(b, "status", str(b.get("status", ""))).lower() in ("failed", "error"))
            total_size = sum(getattr(b, "size", b.get("size", 0)) for b in backups)
            stats = {
                "total_backups": total,
                "completed_backups": completed,
                "failed_backups": failed,
                "total_size_mb": round(total_size / (1024 * 1024), 2)
            }
            return JSONResponse(content=stats)

        stats = stats_method()
        stats = await _maybe_await(stats)
        return JSONResponse(content=stats)

    except Exception as e:
        logger.exception("Get backup stats error")
        raise HTTPException(status_code=500, detail="Failed to get backup statistics")


@router.post("/api/cleanup")
async def cleanup_old_backups(current_user: dict = Depends(require_admin)):
    """Clean up old backups."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")

    try:
        backup_manager = get_backup_manager()
        cleanup_method = _get_manager_method(backup_manager, ["cleanup_old_backups", "cleanup_expired_backups", "cleanup"])
        if not cleanup_method:
            raise HTTPException(status_code=500, detail="Cleanup not supported by backup manager")

        deleted_count = cleanup_method()
        deleted_count = await _maybe_await(deleted_count)

        logger.info(f"Backup cleanup performed by {current_user.get('username')}: {deleted_count} backups deleted")

        return JSONResponse(content={
            "success": True,
            "message": f"Cleaned up {deleted_count} old backups"
        })

    except Exception as e:
        logger.exception("Cleanup backups error")
        raise HTTPException(status_code=500, detail="Failed to cleanup backups")


# Additional endpoints for scheduling, verification, retention, recovery, and details

@router.get("/api/schedules")
async def list_schedules(current_user: dict = Depends(require_admin)):
    """List configured backup schedules."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")

    try:
        backup_manager = get_backup_manager()
        schedules = {}
        # Manager may expose 'schedules' attribute or method
        if hasattr(backup_manager, "schedules"):
            schedules = getattr(backup_manager, "schedules")
            schedules = await _maybe_await(schedules) if inspect.isawaitable(schedules) else schedules
        else:
            list_method = _get_manager_method(backup_manager, ["list_schedules", "get_schedules"])
            if list_method:
                schedules = list_method()
                schedules = await _maybe_await(schedules)
            else:
                schedules = {}
        # Normalize schedules to simple dict
        serialized = {}
        try:
            for sid, s in schedules.items():
                if hasattr(s, "__dict__"):
                    sd = s.__dict__.copy()
                    # isoformat datetimes
                    if sd.get("created_at") and hasattr(sd["created_at"], "isoformat"):
                        sd["created_at"] = sd["created_at"].isoformat()
                    if sd.get("last_run") and hasattr(sd["last_run"], "isoformat"):
                        sd["last_run"] = sd["last_run"].isoformat()
                    if sd.get("next_run") and hasattr(sd["next_run"], "isoformat"):
                        sd["next_run"] = sd["next_run"].isoformat()
                    serialized[sid] = sd
                elif isinstance(s, dict):
                    serialized[sid] = s
                else:
                    serialized[sid] = str(s)
        except Exception:
            serialized = {str(k): str(v) for k, v in schedules.items()}

        return JSONResponse(content={"schedules": serialized})

    except Exception as e:
        logger.exception("List schedules error")
        raise HTTPException(status_code=500, detail="Failed to list schedules")


@router.post("/api/schedules")
async def create_schedule_endpoint(schedule: ScheduleCreateRequest, current_user: dict = Depends(require_admin)):
    """Create a new backup schedule."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")

    try:
        backup_manager = get_backup_manager()
        create_method = _get_manager_method(backup_manager, ["create_backup_schedule", "add_schedule", "create_schedule"])
        if not create_method:
            raise HTTPException(status_code=500, detail="Schedule creation not supported by backup manager")

        coro = create_method(
            name=schedule.name,
            cron_expression=schedule.cron_expression,
            data_sources=schedule.data_sources,
            backup_strategy=getattr(schedule, "backup_strategy", None),
            backup_type=getattr(schedule, "backup_type", None),
            security_level=getattr(schedule, "security_level", None),
            retention_days=schedule.retention_days or None,
            target_nodes=schedule.target_nodes or None,
            tags=schedule.tags or None,
            metadata=schedule.metadata or None
        )
        result = await _maybe_await(coro)
        return JSONResponse(content={"success": True, "schedule_id": result})

    except Exception as e:
        logger.exception("Create schedule error")
        raise HTTPException(status_code=500, detail="Failed to create schedule")


@router.delete("/api/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str, current_user: dict = Depends(require_admin)):
    """Delete a backup schedule."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    try:
        backup_manager = get_backup_manager()
        delete_method = _get_manager_method(backup_manager, ["delete_schedule", "remove_schedule", "delete_backup_schedule"])
        if not delete_method:
            raise HTTPException(status_code=500, detail="Schedule deletion not supported by backup manager")
        result = delete_method(schedule_id)
        result = await _maybe_await(result)
        return JSONResponse(content={"success": bool(result)})
    except Exception as e:
        logger.exception("Delete schedule error")
        raise HTTPException(status_code=500, detail="Failed to delete schedule")


@router.post("/api/schedules/run/{schedule_id}")
async def run_schedule_now(schedule_id: str, background_tasks: BackgroundTasks, current_user: dict = Depends(require_admin)):
    """Trigger a schedule to run immediately."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    try:
        backup_manager = get_backup_manager()
        run_method = _get_manager_method(backup_manager, ["run_schedule", "execute_schedule", "_run_schedule_by_id"])
        if run_method:
            coro = run_method(schedule_id)
            background_tasks.add_task(_bg_schedule_coroutine, coro)
            return JSONResponse(content={"success": True, "message": "Schedule triggered"})
        # Fallback: fetch schedule and create backups for each data source
        if hasattr(backup_manager, "schedules"):
            schedules = getattr(backup_manager, "schedules")
            schedule = schedules.get(schedule_id)
            if not schedule:
                raise HTTPException(status_code=404, detail="Schedule not found")
            # Kick off immediate backups for each data source
            for ds in getattr(schedule, "data_sources", []):
                create_coro = _get_manager_method(backup_manager, ["create_backup", "start_backup"])(
                    data={"source": ds, "timestamp": None},
                    backup_strategy=getattr(schedule, "backup_strategy", None),
                    backup_type=getattr(schedule, "backup_type", None),
                    data_source=ds,
                    metadata={"scheduled_run": True}
                )
                background_tasks.add_task(_bg_schedule_coroutine, create_coro)
            return JSONResponse(content={"success": True, "message": "Schedule executed"})
        raise HTTPException(status_code=500, detail="Unable to execute schedule")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Run schedule error")
        raise HTTPException(status_code=500, detail="Failed to run schedule")


@router.get("/api/backup/{backup_id}")
async def get_backup_details(backup_id: str, current_user: dict = Depends(require_admin)):
    """Get detailed backup metadata and status."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    try:
        backup_manager = get_backup_manager()
        get_method = _get_manager_method(backup_manager, ["get_backup_details", "get_backup", "fetch_backup"])
        if not get_method:
            raise HTTPException(status_code=500, detail="Backup details not supported by backup manager")
        details = get_method(backup_id)
        details = await _maybe_await(details)
        # Serialize
        if hasattr(details, "__dict__"):
            data = details.__dict__.copy()
            # Convert datetimes
            for k, v in list(data.items()):
                if hasattr(v, "isoformat"):
                    try:
                        data[k] = v.isoformat()
                    except Exception:
                        data[k] = str(v)
            return JSONResponse(content={"backup": data})
        elif isinstance(details, dict):
            return JSONResponse(content={"backup": details})
        else:
            return JSONResponse(content={"backup": str(details)})
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Get backup details error")
        raise HTTPException(status_code=500, detail="Failed to get backup details")


@router.post("/api/backup/{backup_id}/verify")
async def verify_backup_endpoint(backup_id: str, deep: bool = False, background_tasks: BackgroundTasks = None, current_user: dict = Depends(require_admin)):
    """Trigger verification of a backup (integrity, encryption, distribution)."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    try:
        backup_manager = get_backup_manager()
        verify_method = _get_manager_method(backup_manager, ["verify_backup", "verify", "run_verification"])
        if not verify_method:
            raise HTTPException(status_code=500, detail="Verification not supported by backup manager")

        # Schedule verification in background
        coro = verify_method(backup_id, deep_verify=deep) if "deep_verify" in inspect.signature(verify_method).parameters else verify_method(backup_id, deep)
        if background_tasks is not None:
            background_tasks.add_task(_bg_schedule_coroutine, coro)
            return JSONResponse(content={"success": True, "message": "Verification scheduled"})
        else:
            # If no BackgroundTasks provided, run and return result
            result = await _maybe_await(coro)
            return JSONResponse(content={"success": True, "result": result})
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Verify backup error")
        raise HTTPException(status_code=500, detail="Failed to verify backup")


@router.get("/api/verification/{verification_id}")
async def get_verification_result(verification_id: str, current_user: dict = Depends(require_admin)):
    """Retrieve verification result by id."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    try:
        backup_manager = get_backup_manager()
        # Manager may expose verification_results dict
        if hasattr(backup_manager, "verification_results"):
            results = getattr(backup_manager, "verification_results")
            res = results.get(verification_id)
            if not res:
                raise HTTPException(status_code=404, detail="Verification result not found")
            # Serialize dataclass-like or dict
            if hasattr(res, "__dict__"):
                data = res.__dict__.copy()
                if data.get("verified_at") and hasattr(data["verified_at"], "isoformat"):
                    data["verified_at"] = data["verified_at"].isoformat()
                return JSONResponse(content={"verification": data})
            elif isinstance(res, dict):
                return JSONResponse(content={"verification": res})
            else:
                return JSONResponse(content={"verification": str(res)})
        else:
            raise HTTPException(status_code=500, detail="Verification results not supported")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Get verification result error")
        raise HTTPException(status_code=500, detail="Failed to get verification result")


@router.get("/api/backup/{backup_id}/download")
async def download_backup(backup_id: str, current_user: dict = Depends(require_admin)):
    """Download an archived backup file if available."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    try:
        backup_manager = get_backup_manager()
        # Managers may expose methods to export or fetch file path
        export_method = _get_manager_method(backup_manager, ["export_backup", "get_backup_file_path", "get_backup_path", "download_backup"])
        if not export_method:
            raise HTTPException(status_code=404, detail="Download not supported for backups")

        path_or_coro = export_method(backup_id)
        result = await _maybe_await(path_or_coro)
        # result may be a path string or bytes
        if isinstance(result, str) and Path(result).exists():
            return FileResponse(path=result, filename=Path(result).name)
        elif isinstance(result, (bytes, bytearray)):
            # Write to a temporary file in-memory response is not supported directly; create temp file
            import tempfile
            tf = tempfile.NamedTemporaryFile(delete=False)
            tf.write(result)
            tf.flush()
            tf.close()
            return FileResponse(path=tf.name, filename=f"backup_{backup_id}.bin")
        else:
            raise HTTPException(status_code=404, detail="Backup file not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Download backup error")
        raise HTTPException(status_code=500, detail="Failed to download backup")


@router.put("/api/retention")
async def update_retention_policy(payload: RetentionUpdateRequest, current_user: dict = Depends(require_admin)):
    """Update retention policy for a backup or schedule."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    try:
        backup_manager = get_backup_manager()
        update_method = _get_manager_method(backup_manager, ["update_retention_policy", "set_retention", "update_backup_retention"])
        if not update_method:
            # Try direct update on schedule or backup metadata
            if payload.schedule_id and hasattr(backup_manager, "schedules"):
                schedule = backup_manager.schedules.get(payload.schedule_id)
                if not schedule:
                    raise HTTPException(status_code=404, detail="Schedule not found")
                schedule.retention_days = payload.retention_days
                return JSONResponse(content={"success": True})
            elif payload.backup_id:
                # Attempt to fetch and update backup metadata
                get_method = _get_manager_method(backup_manager, ["get_backup_details", "get_backup"])
                if not get_method:
                    raise HTTPException(status_code=500, detail="Retention update not supported")
                backup = await _maybe_await(get_method(payload.backup_id))
                if hasattr(backup, "metadata"):
                    backup.metadata = getattr(backup, "metadata", {})
                    backup.metadata["retention_days"] = payload.retention_days
                    # persist if manager provides save/update
                    save_method = _get_manager_method(backup_manager, ["update_backup_metadata", "save_backup"])
                    if save_method:
                        await _maybe_await(save_method(backup.backup_id, backup.metadata))
                    return JSONResponse(content={"success": True})
            raise HTTPException(status_code=500, detail="Retention update not supported")
        result = update_method(payload.backup_id, payload.schedule_id, payload.retention_days)
        result = await _maybe_await(result)
        return JSONResponse(content={"success": bool(result)})
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Update retention error")
        raise HTTPException(status_code=500, detail="Failed to update retention policy")


@router.post("/api/recover")
async def execute_recovery_endpoint(payload: RecoveryRequest, background_tasks: BackgroundTasks, current_user: dict = Depends(require_admin)):
    """Execute a disaster recovery plan or restore operation."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    try:
        backup_manager = get_backup_manager()
        exec_method = _get_manager_method(backup_manager, ["execute_recovery", "run_recovery", "execute_recovery_plan"])
        if not exec_method:
            raise HTTPException(status_code=500, detail="Recovery execution not supported")

        # Convert ISO timestamp if provided
        target_time = None
        if payload.target_time:
            try:
                from datetime import datetime
                target_time = datetime.fromisoformat(payload.target_time)
            except Exception:
                target_time = None

        coro = exec_method(
            plan_id=payload.plan_id,
            backup_id=payload.backup_id,
            target_time=target_time,
            dry_run=payload.dry_run
        )
        # Schedule in background and return immediate ack
        background_tasks.add_task(_bg_schedule_coroutine, coro)
        logger.info(f"Recovery plan {payload.plan_id} triggered by {current_user.get('username')}")
        return JSONResponse(content={"success": True, "message": "Recovery started"})
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Execute recovery error")
        raise HTTPException(status_code=500, detail="Failed to execute recovery")


# Export router
__all__ = ["router"]
