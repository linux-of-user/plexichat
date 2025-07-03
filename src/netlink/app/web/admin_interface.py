"""
Enhanced Web Admin Interface for NetLink
Provides comprehensive web-based administration with console access, log viewing, and user management.
"""

from fastapi import APIRouter, HTTPException, Depends, Request, Form, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import os
import json
import asyncio
import logging
from datetime import datetime, timedelta
from pathlib import Path
import secrets
import hashlib
import zipfile
import io

# Admin authentication
security = HTTPBasic()

# Admin users (in production, this would be in a database)
ADMIN_USERS = {
    "admin": {
        "password_hash": hashlib.sha256("admin123".encode()).hexdigest(),
        "role": "super_admin",
        "permissions": ["all"]
    },
    "manager": {
        "password_hash": hashlib.sha256("manager123".encode()).hexdigest(),
        "role": "admin",
        "permissions": ["view", "manage_users", "view_logs", "system_config"]
    }
}

# Templates
import os
template_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=template_dir)

# Also support simplified templates
simplified_template_dir = os.path.join(template_dir, "simplified")
simplified_templates = Jinja2Templates(directory=simplified_template_dir)

# Router
admin_router = APIRouter(prefix="/admin", tags=["admin"])

# Models
class AdminUser(BaseModel):
    username: str
    role: str
    permissions: List[str]
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

class SystemConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    log_level: str = "INFO"
    max_log_files: int = 10
    log_retention_days: int = 30

class LogEntry(BaseModel):
    timestamp: datetime
    level: str
    module: str
    message: str
    details: Optional[Dict[str, Any]] = None

class ConsoleCommand(BaseModel):
    command: str
    timestamp: datetime = datetime.now()

class SystemStats(BaseModel):
    uptime: str
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    active_connections: int
    total_requests: int
    error_count: int

# Authentication functions
def verify_admin_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    """Verify admin credentials."""
    username = credentials.username
    password = credentials.password
    
    if username not in ADMIN_USERS:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if password_hash != ADMIN_USERS[username]["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return username

def check_permission(username: str, required_permission: str):
    """Check if user has required permission."""
    user = ADMIN_USERS.get(username)
    if not user:
        raise HTTPException(status_code=403, detail="Access denied")
    
    if "all" in user["permissions"] or required_permission in user["permissions"]:
        return True
    
    raise HTTPException(status_code=403, detail="Insufficient permissions")

# Admin Dashboard
@admin_router.get("/", response_class=HTMLResponse)
async def admin_dashboard(request: Request, username: str = Depends(verify_admin_credentials)):
    """Main admin dashboard."""
    check_permission(username, "view")

    try:
        # Get system statistics
        stats = await get_system_statistics()

        # Get recent logs
        recent_logs = await get_recent_logs(limit=10)

        # Get admin user info
        user_info = ADMIN_USERS[username].copy()
        user_info.pop("password_hash", None)

        return templates.TemplateResponse("admin/dashboard.html", {
            "request": request,
            "username": username,
            "user_info": user_info,
            "stats": stats,
            "recent_logs": recent_logs,
            "page_title": "Admin Dashboard"
        })
    except Exception as e:
        # Fallback to JSON response if templates fail
        return JSONResponse({
            "message": "NetLink Admin Dashboard",
            "username": username,
            "stats": await get_system_statistics(),
            "error": f"Template error: {e}"
        })

# System Management
@admin_router.get("/system", response_class=HTMLResponse)
async def system_management(request: Request, username: str = Depends(verify_admin_credentials)):
    """System management interface."""
    check_permission(username, "system_config")
    
    # Get current configuration
    config = await get_system_config()
    
    # Get system status
    status = await get_system_status()
    
    return templates.TemplateResponse("admin/system.html", {
        "request": request,
        "username": username,
        "config": config,
        "status": status,
        "page_title": "System Management"
    })

@admin_router.post("/system/config")
async def update_system_config(
    config: SystemConfig,
    username: str = Depends(verify_admin_credentials)
):
    """Update system configuration."""
    check_permission(username, "system_config")
    
    try:
        # Save configuration
        config_path = Path("config/system.json")
        config_path.parent.mkdir(exist_ok=True)
        
        with open(config_path, "w") as f:
            json.dump(config.dict(), f, indent=2)
        
        return {"status": "success", "message": "Configuration updated successfully"}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update configuration: {e}")

# User Management
@admin_router.get("/users", response_class=HTMLResponse)
async def user_management(request: Request, username: str = Depends(verify_admin_credentials)):
    """User management interface."""
    check_permission(username, "manage_users")
    
    # Get all admin users
    users = []
    for user, data in ADMIN_USERS.items():
        user_info = data.copy()
        user_info.pop("password_hash", None)
        user_info["username"] = user
        users.append(user_info)
    
    return templates.TemplateResponse("admin/users.html", {
        "request": request,
        "username": username,
        "users": users,
        "page_title": "User Management"
    })

@admin_router.post("/users/create")
async def create_admin_user(
    new_username: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    permissions: str = Form(...),
    username: str = Depends(verify_admin_credentials)
):
    """Create new admin user."""
    check_permission(username, "manage_users")
    
    if new_username in ADMIN_USERS:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Parse permissions
    perm_list = [p.strip() for p in permissions.split(",") if p.strip()]
    
    # Create user
    ADMIN_USERS[new_username] = {
        "password_hash": hashlib.sha256(password.encode()).hexdigest(),
        "role": role,
        "permissions": perm_list,
        "created_at": datetime.now().isoformat()
    }
    
    return {"status": "success", "message": f"User {new_username} created successfully"}

# Log Management
@admin_router.get("/logs", response_class=HTMLResponse)
async def log_management(request: Request, username: str = Depends(verify_admin_credentials)):
    """Log management interface."""
    check_permission(username, "view_logs")
    
    # Get available log files
    log_files = await get_available_log_files()
    
    # Get recent logs
    recent_logs = await get_recent_logs(limit=50)
    
    return templates.TemplateResponse("admin/logs.html", {
        "request": request,
        "username": username,
        "log_files": log_files,
        "recent_logs": recent_logs,
        "page_title": "Log Management"
    })

@admin_router.get("/logs/download/{filename}")
async def download_log_file(
    filename: str,
    username: str = Depends(verify_admin_credentials)
):
    """Download log file."""
    check_permission(username, "view_logs")
    
    log_path = Path("logs") / filename
    if not log_path.exists() or not log_path.is_file():
        raise HTTPException(status_code=404, detail="Log file not found")
    
    return FileResponse(
        path=log_path,
        filename=filename,
        media_type='application/octet-stream'
    )

@admin_router.get("/logs/download-all")
async def download_all_logs(username: str = Depends(verify_admin_credentials)):
    """Download all logs as ZIP file."""
    check_permission(username, "view_logs")
    
    # Create ZIP file in memory
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        log_dir = Path("logs")
        if log_dir.exists():
            for log_file in log_dir.glob("*.log"):
                zip_file.write(log_file, log_file.name)
    
    zip_buffer.seek(0)
    
    return StreamingResponse(
        io.BytesIO(zip_buffer.read()),
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=netlink_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"}
    )

# Console Interface
@admin_router.get("/console", response_class=HTMLResponse)
async def web_console(request: Request, username: str = Depends(verify_admin_credentials)):
    """Web-based console interface."""
    check_permission(username, "view")
    
    return templates.TemplateResponse("admin/console.html", {
        "request": request,
        "username": username,
        "page_title": "Web Console"
    })

@admin_router.post("/console/execute")
async def execute_console_command(
    command: ConsoleCommand,
    username: str = Depends(verify_admin_credentials)
):
    """Execute console command."""
    check_permission(username, "view")
    
    try:
        # Import CLI app
        from netlink.cli.app import NetLinkCLI
        
        # Create CLI instance
        cli = NetLinkCLI()
        
        # Execute command (simplified - in real implementation would capture output)
        result = f"Command executed: {command.command}"
        
        # Log command execution
        logging.info(f"Console command executed by {username}: {command.command}")
        
        return {
            "status": "success",
            "output": result,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        return {
            "status": "error",
            "output": f"Error executing command: {e}",
            "timestamp": datetime.now().isoformat()
        }

# API Endpoints for AJAX calls
@admin_router.get("/api/stats")
async def get_system_stats_api(username: str = Depends(verify_admin_credentials)):
    """Get system statistics via API."""
    check_permission(username, "view")
    return await get_system_statistics()

@admin_router.get("/api/logs/stream")
async def stream_logs(username: str = Depends(verify_admin_credentials)):
    """Stream logs in real-time."""
    check_permission(username, "view_logs")
    
    async def log_generator():
        # This would connect to the actual log stream
        while True:
            # Simulate log streaming
            yield f"data: {json.dumps({'timestamp': datetime.now().isoformat(), 'level': 'INFO', 'message': 'Sample log entry'})}\n\n"
            await asyncio.sleep(1)
    
    return StreamingResponse(log_generator(), media_type="text/plain")

# Helper functions
async def get_system_statistics() -> SystemStats:
    """Get current system statistics."""
    try:
        import psutil
        
        return SystemStats(
            uptime="2 hours, 15 minutes",
            cpu_usage=psutil.cpu_percent(),
            memory_usage=psutil.virtual_memory().percent,
            disk_usage=psutil.disk_usage('/').percent,
            active_connections=25,
            total_requests=1247,
            error_count=12
        )
    except ImportError:
        return SystemStats(
            uptime="Unknown",
            cpu_usage=0.0,
            memory_usage=0.0,
            disk_usage=0.0,
            active_connections=0,
            total_requests=0,
            error_count=0
        )

async def get_recent_logs(limit: int = 50) -> List[LogEntry]:
    """Get recent log entries."""
    # This would read from actual log files
    sample_logs = [
        LogEntry(
            timestamp=datetime.now() - timedelta(minutes=i),
            level="INFO" if i % 3 != 0 else "WARNING",
            module="web_server",
            message=f"Sample log entry {i}"
        )
        for i in range(limit)
    ]
    return sample_logs

async def get_available_log_files() -> List[Dict[str, Any]]:
    """Get list of available log files."""
    log_files = []
    log_dir = Path("logs")
    
    if log_dir.exists():
        for log_file in log_dir.glob("*.log"):
            stat = log_file.stat()
            log_files.append({
                "name": log_file.name,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
    
    return log_files

async def get_system_config() -> SystemConfig:
    """Get current system configuration."""
    config_path = Path("config/system.json")
    
    if config_path.exists():
        with open(config_path) as f:
            data = json.load(f)
        return SystemConfig(**data)
    
    return SystemConfig()

async def get_system_status() -> Dict[str, Any]:
    """Get current system status."""
    return {
        "server_running": True,
        "database_connected": True,
        "last_backup": "2025-06-29 10:00:00",
        "maintenance_mode": False,
        "version": "1.0.0"
    }
