"""
NetLink Web Interface
Provides HTML pages and web-based interfaces.
"""

from fastapi import APIRouter, Request, Depends, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
import os
import asyncio

# Import authentication (with fallback)
try:
    from app.routers.login import get_current_user
    from app.auth.login_manager import login_manager
    AUTH_AVAILABLE = True
except ImportError:
    AUTH_AVAILABLE = False
    get_current_user = None
    login_manager = None

# Import settings
try:
    from app.logger_config import settings
except ImportError:
    class MockSettings:
        APP_NAME = "NetLink"
        APP_VERSION = "1.0.0"
    settings = MockSettings()

# Import updater
try:
    from app.core.updater import updater
    UPDATE_AVAILABLE = True
except ImportError:
    UPDATE_AVAILABLE = False
    updater = None

# Setup templates
templates_dir = Path(__file__).parent.parent / "web" / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

router = APIRouter(prefix="/web", tags=["web"])

# Authentication dependency
def require_auth():
    """Require authentication for protected routes."""
    if not AUTH_AVAILABLE:
        raise HTTPException(status_code=500, detail="Authentication not available")
    return get_current_user

def require_admin():
    """Require admin privileges."""
    if not AUTH_AVAILABLE:
        raise HTTPException(status_code=500, detail="Authentication not available")
    # For now, simplified admin check
    return True

@router.get("/", response_class=HTMLResponse)
async def web_dashboard(request: Request):
    """Main web dashboard."""
    return templates.TemplateResponse("dashboard/index.html", {
        "request": request,
        "title": f"{settings.APP_NAME} Dashboard",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION
    })

@router.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    """Admin dashboard."""
    return templates.TemplateResponse("admin/dashboard.html", {
        "request": request,
        "title": "Admin Dashboard",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "update_available": UPDATE_AVAILABLE
    })

@router.get("/admin/file-editor", response_class=HTMLResponse)
async def file_editor(request: Request):
    """File editor interface."""
    return templates.TemplateResponse("admin/file_editor.html", {
        "request": request,
        "title": "File Editor - NetLink Admin",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION
    })

@router.get("/admin/setup-tutorials", response_class=HTMLResponse)
async def setup_tutorials(request: Request):
    """Setup tutorials interface."""
    return templates.TemplateResponse("admin/setup_tutorials.html", {
        "request": request,
        "title": "Setup Tutorials - NetLink Admin",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION
    })

@router.get("/docs/interactive", response_class=HTMLResponse)
async def interactive_api_docs(request: Request):
    """Interactive API documentation with live testing capabilities."""
    return templates.TemplateResponse("api_docs.html", {
        "request": request,
        "api_version": settings.APP_VERSION,
        "app_name": settings.APP_NAME,
        "title": "API Documentation"
    })

# Update System Endpoints (Web UI Only)
@router.get("/admin/updates")
async def updates_page(request: Request):
    """Updates management page."""
    if not UPDATE_AVAILABLE:
        raise HTTPException(status_code=500, detail="Update system not available")

    return templates.TemplateResponse("admin/updates.html", {
        "request": request,
        "title": "System Updates",
        "app_name": settings.APP_NAME,
        "current_version": settings.APP_VERSION
    })

@router.post("/admin/updates/check")
async def check_updates():
    """Check for available updates."""
    if not UPDATE_AVAILABLE:
        return {"error": "Update system not available"}

    try:
        result = updater.check_for_updates()
        return result
    except Exception as e:
        return {"error": str(e)}

@router.post("/admin/updates/start")
async def start_update(background_tasks: BackgroundTasks, force: bool = False):
    """Start hot update process."""
    if not UPDATE_AVAILABLE:
        return {"error": "Update system not available"}

    try:
        # Check for updates first
        update_info = updater.check_for_updates()

        if "error" in update_info:
            return update_info

        if not update_info["update_available"] and not force:
            return {"success": False, "message": "No updates available"}

        # Start hot update in background
        background_tasks.add_task(perform_hot_update, update_info)

        return {
            "success": True,
            "message": "Hot update started",
            "update_type": "hot",
            "new_version": update_info.get("latest_version")
        }

    except Exception as e:
        return {"error": str(e)}

@router.get("/admin/updates/status")
async def update_status():
    """Get update status."""
    if not UPDATE_AVAILABLE:
        return {"error": "Update system not available"}

    # Check if staging directory exists (indicates pending restart update)
    staging_dir = Path(".update_staging")
    has_pending_restart = staging_dir.exists()

    return {
        "update_available": UPDATE_AVAILABLE,
        "current_version": settings.APP_VERSION,
        "has_pending_restart": has_pending_restart,
        "last_check": "Not implemented yet"
    }

async def perform_hot_update(update_info):
    """Perform hot update in background."""
    try:
        if not update_info.get("download_url"):
            return

        # Download update
        update_file = updater.download_update(update_info["download_url"])

        # Apply hot update
        success = updater.apply_hot_update(update_file)

        if success:
            print("Hot update completed successfully")
        else:
            print("Hot update failed")

    except Exception as e:
        print(f"Hot update error: {e}")

@router.get("/testing", response_class=HTMLResponse)
async def testing_interface(request: Request, current_user: User = Depends(get_current_user)):
    """Self-testing interface."""
    return templates.TemplateResponse("testing/interface.html", {
        "request": request,
        "user": current_user,
        "title": "System Testing Interface"
    })

@router.get("/cli", response_class=HTMLResponse)
async def web_cli_interface(request: Request, current_user: User = Depends(get_current_user)):
    """Web-based CLI interface."""
    return templates.TemplateResponse("cli.html", {
        "request": request,
        "user": current_user,
        "title": "Web CLI Interface"
    })

@router.get("/backup", response_class=HTMLResponse)
async def backup_management(request: Request, current_user: User = Depends(require_admin)):
    """Backup management interface."""
    return templates.TemplateResponse("admin/backup.html", {
        "request": request,
        "user": current_user,
        "title": "Backup Management"
    })

@router.get("/analytics", response_class=HTMLResponse)
async def analytics_dashboard(request: Request, current_user: User = Depends(require_admin)):
    """Analytics and monitoring dashboard."""
    return templates.TemplateResponse("admin/analytics.html", {
        "request": request,
        "user": current_user,
        "title": "Analytics Dashboard"
    })

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page."""
    return templates.TemplateResponse("auth/login.html", {
        "request": request,
        "title": "Login"
    })

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Registration page."""
    return templates.TemplateResponse("auth/register.html", {
        "request": request,
        "title": "Register"
    })

@router.get("/profile", response_class=HTMLResponse)
async def user_profile(request: Request, current_user: User = Depends(get_current_user)):
    """User profile page."""
    return templates.TemplateResponse("user/profile.html", {
        "request": request,
        "user": current_user,
        "title": "User Profile"
    })

@router.get("/chat", response_class=HTMLResponse)
async def chat_interface(request: Request, current_user: User = Depends(get_current_user)):
    """Main chat interface."""
    return templates.TemplateResponse("chat/interface.html", {
        "request": request,
        "user": current_user,
        "title": "Chat Interface"
    })

@router.get("/files", response_class=HTMLResponse)
async def file_manager(request: Request, current_user: User = Depends(get_current_user)):
    """File management interface."""
    return templates.TemplateResponse("files/manager.html", {
        "request": request,
        "user": current_user,
        "title": "File Manager"
    })

@router.get("/settings", response_class=HTMLResponse)
async def user_settings(request: Request, current_user: User = Depends(get_current_user)):
    """User settings page."""
    return templates.TemplateResponse("user/settings.html", {
        "request": request,
        "user": current_user,
        "title": "Settings"
    })

@router.get("/help", response_class=HTMLResponse)
async def help_center(request: Request):
    """Help center and documentation."""
    return templates.TemplateResponse("docs/help.html", {
        "request": request,
        "title": "Help Center"
    })

@router.get("/status", response_class=HTMLResponse)
async def system_status(request: Request):
    """System status page."""
    return templates.TemplateResponse("status/system.html", {
        "request": request,
        "title": "System Status"
    })

# Redirect routes for convenience
@router.get("/docs")
async def docs_redirect():
    """Redirect to interactive docs."""
    return RedirectResponse(url="/web/docs/interactive")

@router.get("/admin/backup")
async def backup_redirect():
    """Redirect to backup management."""
    return RedirectResponse(url="/web/backup")

@router.get("/admin/analytics")
async def analytics_redirect():
    """Redirect to analytics dashboard."""
    return RedirectResponse(url="/web/analytics")

# API for web interface data
@router.get("/api/dashboard/stats")
async def dashboard_stats(current_user: User = Depends(get_current_user)):
    """Get dashboard statistics."""
    # This would return real statistics
    return {
        "users_online": 42,
        "messages_today": 1337,
        "files_uploaded": 89,
        "system_uptime": "5 days, 12 hours",
        "api_requests": 15420,
        "backup_health": "healthy"
    }

@router.get("/api/system/health")
async def web_system_health():
    """Get system health for web interface."""
    return {
        "status": "healthy",
        "services": {
            "database": "online",
            "redis": "online",
            "websocket": "online",
            "backup_system": "online"
        },
        "metrics": {
            "cpu_usage": 25.5,
            "memory_usage": 68.2,
            "disk_usage": 45.1
        }
    }

@router.get("/api/notifications")
async def get_notifications(current_user: User = Depends(get_current_user)):
    """Get user notifications."""
    return {
        "notifications": [
            {
                "id": 1,
                "type": "info",
                "title": "Welcome to NetLink",
                "message": "Your account has been successfully created.",
                "timestamp": "2024-01-15T10:30:00Z",
                "read": False
            },
            {
                "id": 2,
                "type": "success",
                "title": "Backup Completed",
                "message": "Your data has been successfully backed up.",
                "timestamp": "2024-01-15T09:15:00Z",
                "read": True
            }
        ]
    }

# Error handlers for web routes
@router.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    """Handle 404 errors for web routes."""
    return templates.TemplateResponse("errors/404.html", {
        "request": request,
        "title": "Page Not Found"
    }, status_code=404)

@router.exception_handler(403)
async def forbidden_handler(request: Request, exc: HTTPException):
    """Handle 403 errors for web routes."""
    return templates.TemplateResponse("errors/403.html", {
        "request": request,
        "title": "Access Forbidden"
    }, status_code=403)

@router.exception_handler(500)
async def server_error_handler(request: Request, exc: HTTPException):
    """Handle 500 errors for web routes."""
    return templates.TemplateResponse("errors/500.html", {
        "request": request,
        "title": "Server Error"
    }, status_code=500)
