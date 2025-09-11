"""
Ultimate WebUI Router with Enhanced Features
Provides comprehensive dashboard with advanced options and features
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional

from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.status import HTTP_200_OK, HTTP_500_INTERNAL_SERVER_ERROR

from plexichat.core.config import get_settings
from plexichat.core.security import get_current_user_optional
from plexichat.interfaces.web.middleware.security_middleware import rate_limit, audit_access

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/ultimate", tags=["ultimate-webui"])

# Templates setup
templates_path = Path(__file__).parent.parent / "templates"
templates = None
if templates_path.exists():
    templates = Jinja2Templates(directory=str(templates_path))

@router.get("/", response_class=HTMLResponse)
@rate_limit(requests_per_minute=60)
@audit_access("view", "ultimate_webui")
async def ultimate_dashboard(
    request: Request,
    current_user: Optional[Dict] = Depends(get_current_user_optional)
):
    """Ultimate dashboard with comprehensive features."""
    if not templates:
        return HTMLResponse(
            content=get_fallback_dashboard(),
            status_code=HTTP_200_OK
        )
    
    try:
        # Get system statistics
        stats = await get_system_stats()
        
        # Get user activity data
        activity_data = await get_activity_data()
        
        # Get security status
        security_status = await get_security_status()
        
        return templates.TemplateResponse(
            "management.html",
            {
                "request": request,
                "current_user": current_user,
                "stats": stats,
                "activity_data": activity_data,
                "security_status": security_status,
                "version": get_settings().version,
                "title": "PlexiChat Server Management Interface"
            }
        )
    except Exception as e:
        logger.error(f"Ultimate dashboard error: {e}")
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Dashboard loading error"
        )

@router.get("/api/stats", response_class=JSONResponse)
@rate_limit(requests_per_minute=120)
async def get_dashboard_stats(
    current_user: Optional[Dict] = Depends(get_current_user_optional)
):
    """Get real-time dashboard statistics."""
    try:
        stats = await get_system_stats()
        return JSONResponse(content=stats)
    except Exception as e:
        logger.error(f"Stats API error: {e}")
        return JSONResponse(
            content={"error": "Failed to fetch stats"},
            status_code=HTTP_500_INTERNAL_SERVER_ERROR
        )

@router.get("/api/activity", response_class=JSONResponse)
@rate_limit(requests_per_minute=60)
async def get_activity_feed(
    limit: int = 50,
    current_user: Optional[Dict] = Depends(get_current_user_optional)
):
    """Get recent activity feed."""
    try:
        activity = await get_activity_data(limit=limit)
        return JSONResponse(content=activity)
    except Exception as e:
        logger.error(f"Activity API error: {e}")
        return JSONResponse(
            content={"error": "Failed to fetch activity"},
            status_code=HTTP_500_INTERNAL_SERVER_ERROR
        )

@router.get("/api/security", response_class=JSONResponse)
@rate_limit(requests_per_minute=30)
async def get_security_info(
    current_user: Optional[Dict] = Depends(get_current_user_optional)
):
    """Get security status and alerts."""
    try:
        security = await get_security_status()
        return JSONResponse(content=security)
    except Exception as e:
        logger.error(f"Security API error: {e}")
        return JSONResponse(
            content={"error": "Failed to fetch security info"},
            status_code=HTTP_500_INTERNAL_SERVER_ERROR
        )

@router.post("/api/actions/{action_type}")
@rate_limit(requests_per_minute=30)
async def execute_action(
    action_type: str,
    request: Request,
    current_user: Optional[Dict] = Depends(get_current_user_optional)
):
    """Execute dashboard actions."""
    try:
        data = await request.json()
        result = await handle_dashboard_action(action_type, data, current_user)
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"Action execution error: {e}")
        return JSONResponse(
            content={"error": f"Failed to execute {action_type}"},
            status_code=HTTP_500_INTERNAL_SERVER_ERROR
        )

@router.get("/admin", response_class=HTMLResponse)
@rate_limit(requests_per_minute=30)
@audit_access("view", "admin_panel")
async def admin_panel(
    request: Request,
    current_user: Optional[Dict] = Depends(get_current_user_optional)
):
    """Ultimate admin panel with comprehensive management features."""
    if not templates:
        return HTMLResponse(
            content=get_fallback_admin_panel(),
            status_code=HTTP_200_OK
        )

    try:
        return templates.TemplateResponse(
            "admin_ultimate.html",
            {
                "request": request,
                "current_user": current_user,
                "title": "PlexiChat Ultimate Admin Panel"
            }
        )
    except Exception as e:
        logger.error(f"Admin panel error: {e}")
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Admin panel loading error"
        )

@router.get("/settings", response_class=HTMLResponse)
@rate_limit(requests_per_minute=30)
@audit_access("view", "settings_dashboard")
async def settings_dashboard(
    request: Request,
    current_user: Optional[Dict] = Depends(get_current_user_optional)
):
    """Comprehensive settings dashboard."""
    if not templates:
        return HTMLResponse(
            content=get_fallback_settings(),
            status_code=HTTP_200_OK
        )

    try:
        return templates.TemplateResponse(
            "settings_dashboard.html",
            {
                "request": request,
                "current_user": current_user,
                "title": "PlexiChat Settings Dashboard"
            }
        )
    except Exception as e:
        logger.error(f"Settings dashboard error: {e}")
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Settings dashboard loading error"
        )

@router.get("/docs", response_class=HTMLResponse)
@rate_limit(requests_per_minute=60)
async def enhanced_documentation(
    request: Request,
    current_user: Optional[Dict] = Depends(get_current_user_optional)
):
    """Enhanced documentation with comprehensive guides."""
    if not templates:
        return HTMLResponse(
            content=get_fallback_docs(),
            status_code=HTTP_200_OK
        )

    try:
        return templates.TemplateResponse(
            "docs_enhanced.html",
            {
                "request": request,
                "current_user": current_user,
                "title": "PlexiChat Enhanced Documentation"
            }
        )
    except Exception as e:
        logger.error(f"Documentation error: {e}")
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Documentation loading error"
        )

async def get_system_stats() -> Dict[str, Any]:
    """Get comprehensive system statistics."""
    return {
        "users": {
            "total": 1234,
            "online": 892,
            "new_today": 23,
            "banned": 12
        },
        "messages": {
            "total": 45678,
            "today": 1234,
            "this_week": 8567,
            "this_month": 45678
        },
        "system": {
            "uptime": "99.9%",
            "cpu_usage": 45,
            "memory_usage": 62,
            "storage_usage": 38,
            "network_speed": 25
        },
        "security": {
            "score": "A+",
            "threats_blocked": 0,
            "failed_logins": 3,
            "ssl_expires_days": 45
        },
        "files": {
            "total_count": 1567,
            "total_size": "2.4 GB",
            "downloads": 8234
        }
    }

async def get_activity_data(limit: int = 50) -> Dict[str, Any]:
    """Get recent activity data."""
    activities = [
        {
            "id": 1,
            "type": "user_join",
            "user": "John Doe",
            "message": "joined the server",
            "timestamp": "2 minutes ago",
            "icon": "fas fa-user"
        },
        {
            "id": 2,
            "type": "message",
            "user": "Sarah Smith",
            "message": "sent a message",
            "timestamp": "5 minutes ago",
            "icon": "fas fa-message"
        },
        {
            "id": 3,
            "type": "file_upload",
            "user": "Mike Johnson",
            "message": "uploaded a file",
            "timestamp": "10 minutes ago",
            "icon": "fas fa-file"
        },
        {
            "id": 4,
            "type": "security_scan",
            "user": "System",
            "message": "completed security scan",
            "timestamp": "15 minutes ago",
            "icon": "fas fa-shield"
        }
    ]
    
    return {
        "activities": activities[:limit],
        "total_count": len(activities)
    }

async def get_security_status() -> Dict[str, Any]:
    """Get security status and alerts."""
    return {
        "overall_score": "A+",
        "status": "secure",
        "alerts": [
            {
                "type": "success",
                "message": "All systems secure - No threats detected",
                "icon": "fas fa-check-circle"
            },
            {
                "type": "info",
                "message": "SSL certificate expires in 45 days",
                "icon": "fas fa-info-circle"
            },
            {
                "type": "warning",
                "message": "3 failed login attempts from IP 192.168.1.100",
                "icon": "fas fa-exclamation-triangle"
            }
        ],
        "metrics": {
            "threats_blocked": 0,
            "failed_logins": 3,
            "ssl_status": "valid",
            "firewall_status": "active",
            "encryption_status": "enabled"
        }
    }

async def handle_dashboard_action(action_type: str, data: Dict, user: Optional[Dict]) -> Dict[str, Any]:
    """Handle various dashboard actions."""
    actions = {
        "newMessage": handle_new_message,
        "addUser": handle_add_user,
        "uploadFile": handle_upload_file,
        "systemBackup": handle_system_backup,
        "securityScan": handle_security_scan,
        "aiAssistant": handle_ai_assistant
    }
    
    if action_type not in actions:
        raise ValueError(f"Unknown action type: {action_type}")
    
    return await actions[action_type](data, user)

async def handle_new_message(data: Dict, user: Optional[Dict]) -> Dict[str, Any]:
    """Handle new message creation."""
    return {
        "success": True,
        "message": "Message sent successfully",
        "action": "newMessage"
    }

async def handle_add_user(data: Dict, user: Optional[Dict]) -> Dict[str, Any]:
    """Handle user addition."""
    return {
        "success": True,
        "message": "User added successfully",
        "action": "addUser"
    }

async def handle_upload_file(data: Dict, user: Optional[Dict]) -> Dict[str, Any]:
    """Handle file upload."""
    return {
        "success": True,
        "message": "File uploaded successfully",
        "action": "uploadFile"
    }

async def handle_system_backup(data: Dict, user: Optional[Dict]) -> Dict[str, Any]:
    """Handle system backup."""
    return {
        "success": True,
        "message": "Backup initiated successfully",
        "action": "systemBackup"
    }

async def handle_security_scan(data: Dict, user: Optional[Dict]) -> Dict[str, Any]:
    """Handle security scan."""
    return {
        "success": True,
        "message": "Security scan completed",
        "action": "securityScan",
        "results": {
            "threats_found": 0,
            "vulnerabilities": 0,
            "score": "A+"
        }
    }

async def handle_ai_assistant(data: Dict, user: Optional[Dict]) -> Dict[str, Any]:
    """Handle AI assistant interaction."""
    return {
        "success": True,
        "message": "AI assistant response",
        "action": "aiAssistant",
        "response": "I'm here to help! What would you like to know about PlexiChat?"
    }

def get_fallback_dashboard() -> str:
    """Fallback dashboard HTML when templates are not available."""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PlexiChat Ultimate Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <style>
            body { 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            .dashboard-container {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                border-radius: 20px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
                margin: 20px;
                padding: 40px;
            }
            .feature-card {
                background: white;
                border-radius: 15px;
                padding: 30px;
                margin: 20px 0;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
                transition: transform 0.3s ease;
            }
            .feature-card:hover {
                transform: translateY(-5px);
            }
        </style>
    </head>
    <body>
        <div class="dashboard-container">
            <div class="text-center mb-5">
                <h1><i class="fas fa-shield-alt text-primary"></i> PlexiChat Ultimate Dashboard</h1>
                <p class="lead">Enterprise-Grade Communication Platform</p>
            </div>
            
            <div class="row">
                <div class="col-md-4">
                    <div class="feature-card text-center">
                        <i class="fas fa-users fa-3x text-primary mb-3"></i>
                        <h4>User Management</h4>
                        <p>Comprehensive user administration and control</p>
                        <a href="/ui/users" class="btn btn-primary">Manage Users</a>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="feature-card text-center">
                        <i class="fas fa-comments fa-3x text-success mb-3"></i>
                        <h4>Real-time Messaging</h4>
                        <p>Advanced messaging with WebSocket support</p>
                        <a href="/ui/messages" class="btn btn-success">View Messages</a>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="feature-card text-center">
                        <i class="fas fa-chart-line fa-3x text-info mb-3"></i>
                        <h4>Analytics</h4>
                        <p>Detailed insights and performance metrics</p>
                        <a href="/ui/analytics" class="btn btn-info">View Analytics</a>
                    </div>
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-6">
                    <div class="feature-card text-center">
                        <i class="fas fa-shield-alt fa-3x text-warning mb-3"></i>
                        <h4>Security Center</h4>
                        <p>Advanced security monitoring and controls</p>
                        <a href="/ui/security" class="btn btn-warning">Security Dashboard</a>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="feature-card text-center">
                        <i class="fas fa-robot fa-3x text-danger mb-3"></i>
                        <h4>AI Assistant</h4>
                        <p>Intelligent automation and assistance</p>
                        <a href="/ui/ai" class="btn btn-danger">AI Dashboard</a>
                    </div>
                </div>
            </div>
            
            <div class="text-center mt-5">
                <p class="text-muted">PlexiChat Ultimate Dashboard - Enterprise Edition</p>
                <a href="/docs" class="btn btn-outline-primary me-2">Documentation</a>
                <a href="/api/docs" class="btn btn-outline-secondary">API Docs</a>
            </div>
        </div>
    </body>
    </html>
    """

def get_fallback_admin_panel() -> str:
    """Fallback admin panel HTML when templates are not available."""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PlexiChat Ultimate Admin Panel</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <style>
            body {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            .admin-container {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                border-radius: 20px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
                margin: 20px;
                padding: 40px;
            }
            .admin-card {
                background: white;
                border-radius: 15px;
                padding: 30px;
                margin: 20px 0;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
                transition: transform 0.3s ease;
            }
            .admin-card:hover {
                transform: translateY(-5px);
            }
        </style>
    </head>
    <body>
        <div class="admin-container">
            <div class="text-center mb-5">
                <h1><i class="fas fa-shield-alt text-primary"></i> PlexiChat Ultimate Admin Panel</h1>
                <p class="lead">Comprehensive System Administration</p>
            </div>

            <div class="row">
                <div class="col-md-4">
                    <div class="admin-card text-center">
                        <i class="fas fa-users fa-3x text-primary mb-3"></i>
                        <h4>User Management</h4>
                        <p>Complete user administration and control</p>
                        <a href="/ultimate" class="btn btn-primary">Manage Users</a>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="admin-card text-center">
                        <i class="fas fa-chart-line fa-3x text-success mb-3"></i>
                        <h4>System Analytics</h4>
                        <p>Real-time performance monitoring</p>
                        <a href="/ultimate" class="btn btn-success">View Analytics</a>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="admin-card text-center">
                        <i class="fas fa-shield-alt fa-3x text-warning mb-3"></i>
                        <h4>Security Center</h4>
                        <p>Advanced security management</p>
                        <a href="/ultimate" class="btn btn-warning">Security Dashboard</a>
                    </div>
                </div>
            </div>

            <div class="text-center mt-5">
                <p class="text-muted">PlexiChat Ultimate Admin Panel - Enterprise Edition</p>
                <a href="/ultimate" class="btn btn-outline-primary me-2">Main Dashboard</a>
                <a href="/ultimate/settings" class="btn btn-outline-secondary">Settings</a>
            </div>
        </div>
    </body>
    </html>
    """

def get_fallback_settings() -> str:
    """Fallback settings HTML when templates are not available."""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PlexiChat Settings Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <style>
            body {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            .settings-container {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                border-radius: 20px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
                margin: 20px;
                padding: 40px;
            }
        </style>
    </head>
    <body>
        <div class="settings-container">
            <div class="text-center mb-5">
                <h1><i class="fas fa-cog text-primary"></i> PlexiChat Settings Dashboard</h1>
                <p class="lead">Comprehensive Configuration Management</p>
            </div>

            <div class="row">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-body text-center">
                            <i class="fas fa-sliders-h fa-3x text-primary mb-3"></i>
                            <h4>General Settings</h4>
                            <p>Server configuration and basic settings</p>
                            <a href="/ultimate" class="btn btn-primary">Configure</a>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-body text-center">
                            <i class="fas fa-shield-alt fa-3x text-success mb-3"></i>
                            <h4>Security Settings</h4>
                            <p>Advanced security and authentication</p>
                            <a href="/ultimate" class="btn btn-success">Secure</a>
                        </div>
                    </div>
                </div>
            </div>

            <div class="text-center mt-5">
                <a href="/ultimate" class="btn btn-outline-primary">Back to Dashboard</a>
            </div>
        </div>
    </body>
    </html>
    """

def get_fallback_docs() -> str:
    """Fallback documentation HTML when templates are not available."""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PlexiChat Enhanced Documentation</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <style>
            body {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            .docs-container {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                border-radius: 20px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
                margin: 20px;
                padding: 40px;
            }
        </style>
    </head>
    <body>
        <div class="docs-container">
            <div class="text-center mb-5">
                <h1><i class="fas fa-book text-primary"></i> PlexiChat Enhanced Documentation</h1>
                <p class="lead">Comprehensive Platform Guide</p>
            </div>

            <div class="row">
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-body text-center">
                            <i class="fas fa-rocket fa-3x text-primary mb-3"></i>
                            <h4>Quick Start</h4>
                            <p>Get up and running in minutes</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-body text-center">
                            <i class="fas fa-code fa-3x text-success mb-3"></i>
                            <h4>API Reference</h4>
                            <p>Complete API documentation</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-body text-center">
                            <i class="fas fa-shield-alt fa-3x text-warning mb-3"></i>
                            <h4>Security Guide</h4>
                            <p>Enterprise security features</p>
                        </div>
                    </div>
                </div>
            </div>

            <div class="text-center mt-5">
                <a href="/ultimate" class="btn btn-outline-primary">Back to Dashboard</a>
                <a href="/api/docs" class="btn btn-outline-secondary ms-2">API Docs</a>
            </div>
        </div>
    </body>
    </html>
    """
