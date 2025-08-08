"""
PlexiChat Web Admin Router

Web interface for administrative operations.
"""

from datetime import datetime
from typing import Optional, Dict, Any

from fastapi import APIRouter, Request, Depends, HTTPException, Form, status, Body
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from plexichat.core.auth.admin_manager import admin_manager
from plexichat.core.config import settings
from plexichat.core.plugins.unified_plugin_manager import unified_plugin_manager
from plexichat.core.logging import get_logger
from plexichat.infrastructure.utils.rate_limiting import rate_limit
import re
from starlette.middleware.base import BaseHTTPMiddleware


# Security headers from security.txt
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "Pragma": "no-cache"
}

# Middleware to add security headers to all responses
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers[k] = v
        return response

# Input validation and sanitization helpers
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_.-]{3,32}$')
EMAIL_REGEX = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
PASSWORD_MIN_LENGTH = 8

# Reference: security.txt - Input Validation, Authentication & Authorization

def sanitize_input(value: str) -> str:
    value = value.strip()
    value = re.sub(r'<.*?>', '', value)  # Remove HTML tags
    value = re.sub(r'["\'`;]', '', value)  # Remove dangerous chars
    return value

def validate_username(username: str) -> bool:
    return bool(USERNAME_REGEX.match(username))

def validate_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))

def validate_password(password: str) -> bool:
    return len(password) >= PASSWORD_MIN_LENGTH

logger = get_logger(__name__)

# Initialize router
router = APIRouter(prefix="/admin", tags=["admin"])

# Initialize templates
templates = Jinja2Templates(directory="src/plexichat/interfaces/web/templates")

# Import enhanced security decorators
try:
    from plexichat.core.security.security_decorators import (
        secure_endpoint, require_auth, rate_limit, audit_access, validate_input,
        SecurityLevel, RequiredPermission, admin_endpoint
    )
    from plexichat.core.logging_advanced.advanced_logging_system import (
        get_enhanced_logging_system, LogCategory, LogLevel, PerformanceTracker, SecurityMetrics
    )
    ENHANCED_SECURITY_AVAILABLE = True
    
    # Get enhanced logging system
    logging_system = get_enhanced_logging_system()
    if logging_system:
        enhanced_logger = logging_system.get_logger(__name__)
        logger.info("Enhanced security and logging initialized for admin")
    else:
        enhanced_logger = None
        
except ImportError as e:
    logger.warning(f"Enhanced security not available for admin: {e}")
    # Fallback decorators
    def secure_endpoint(*args, **kwargs):
        def decorator(func): return func
        return decorator
    
    def admin_endpoint(*args, **kwargs):
        def decorator(func): return func
        return decorator
    
    class SecurityLevel:
        ADMIN = 4
        SYSTEM = 5
    
    class RequiredPermission:
        ADMIN = "admin"
        SYSTEM = "system"
    
    ENHANCED_SECURITY_AVAILABLE = False
    enhanced_logger = None
    logging_system = None

class AdminLoginRequest(BaseModel):
    """Admin login request model.
        username: str
    password: str

class AdminCreateRequest(BaseModel):
    """Admin creation request model."""
        username: str
    email: str
    password: str
    role: str = "admin"

async def get_current_admin(request: Request) -> Optional[Dict[str, Any]]:
    """Get current authenticated admin from session."""
    if not admin_manager:
        return None
    try:
        token = request.cookies.get("admin_session")
        if not token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header[7:]
        if not token:
            return None
        admin = admin_manager.validate_session(token)
        if admin:
            return {
                "username": admin.username,
                "email": admin.email,
                "role": admin.role,
                "permissions": admin.permissions,
                "token": token
            }
        return None
    except Exception as e:
        logger.error(f"Error getting current admin: {e}")
        return None

async def require_admin(request: Request) -> Dict[str, Any]:
    """Require admin authentication."""
    admin = await get_current_admin(request)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin authentication required"
        )
    return admin

def get_client_ip(request: Request) -> str:
    if hasattr(request, 'client') and request.client and getattr(request.client, 'host', None):
        return request.client.host
    return 'unknown'

@router.get("/", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    admin = await require_admin(request)
    """Admin dashboard page."""
    if not admin:
        return RedirectResponse(url="/admin/login", status_code=302)
    try:
        context = {
            "request": request,
            "admin": admin,
            "system_info": {
                "timestamp": datetime.now().isoformat(),
                "admin_count": len(admin_manager.admins) if admin_manager else 0,
                "active_sessions": len(admin_manager.sessions) if admin_manager else 0
            }
        }
        return templates.TemplateResponse("admin/dashboard.html", context)
    except Exception:
        return HTMLResponse(f"<h1>Admin Dashboard</h1><p>Welcome, {admin['username']}!</p>")

@router.get("/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    """Admin login page."""
    try:
        return templates.TemplateResponse("admin/login.html", {"request": request})
    except Exception:
        return HTMLResponse("<h1>Admin Login</h1><form method='post'><input name='username' placeholder='Username'><input name='password' type='password' placeholder='Password'><button>Login</button></form>")

@router.post("/login")
@admin_endpoint(
    permissions=[RequiredPermission.ADMIN],
    rate_limit_rpm=10,
    audit_action="admin_login"
)
async def admin_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    if not admin_manager:
        raise HTTPException(status_code=500, detail="Admin manager not available")
    try:
        ip_address = get_client_ip(request)
        user_agent = request.headers.get("User-Agent")
        
        # Enhanced logging for admin authentication
        if enhanced_logger and logging_system:
            logging_system.set_context(
                username=username,
                endpoint="/admin/login",
                method="POST",
                ip_address=ip_address
            )
            
            enhanced_logger.info(
                f"Admin authentication attempt for {username}",
                extra={
                    "category": LogCategory.AUTH,
                    "metadata": {
                        "username": username,
                        "client_ip": ip_address,
                        "user_agent": user_agent,
                        "auth_type": "admin_login"
                    },
                    "tags": ["admin", "authentication", "security_critical"]
                }
            )
        
        token = await admin_manager.authenticate(username, password, ip_address, user_agent)
        if not token:
            # Enhanced failed login logging
            if enhanced_logger:
                enhanced_logger.warning(
                    f"Admin login failed for {username}",
                    extra={
                        "category": LogCategory.SECURITY,
                        "security": {"failed_authentications": 1, "threat_score": 0.5},
                        "metadata": {"username": username, "client_ip": ip_address, "failure_reason": "invalid_credentials"},
                        "tags": ["admin", "login_failed", "security_event"]
                    }
                )
            else:
                logger.warning(f"Admin login failed for {username} from {ip_address}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
            
        # Enhanced successful login logging
        if enhanced_logger:
            enhanced_logger.info(
                f"Admin login successful for {username}",
                extra={
                    "category": LogCategory.AUTH,
                    "metadata": {"username": username, "client_ip": ip_address, "auth_success": True},
                    "tags": ["admin", "login_success", "security_event"]
                }
            )
        else:
            logger.info(f"Admin login: {username} from {ip_address}")
        response = RedirectResponse(url="/admin/", status_code=302)
        response.set_cookie(
            key="admin_session",
            value=token,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=28800
        )
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during admin login for {username}: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@router.post("/logout")
@rate_limit(requests_per_minute=30, key_func=lambda request: f"admin_logout:{get_client_ip(request)}")
async def admin_logout(request: Request):
    admin = await require_admin(request)
    if not admin_manager:
        raise HTTPException(status_code=500, detail="Admin manager not available")
    try:
        token = admin["token"]
        admin_manager.logout(token)
        logger.info(f"Admin logout: {admin['username']} from {get_client_ip(request)}")
        response = RedirectResponse(url="/admin/login", status_code=302)
        response.delete_cookie("admin_session")
        return response
    except Exception as e:
        logger.error(f"Error during admin logout for {admin['username']}: {e}")
        raise HTTPException(status_code=500, detail="Logout failed")

@router.get("/users")
@rate_limit(requests_per_minute=30, key_func=lambda request: f"admin_users:{get_client_ip(request)}")
async def admin_users(request: Request):
    admin = await require_admin(request)
    if not admin_manager:
        raise HTTPException(status_code=500, detail="Admin manager not available")
    try:
        admins = admin_manager.list_admins()
        logger.info(f"Admin user management page accessed by {admin['username']} from {get_client_ip(request)}")
        context = {
            "request": request,
            "admin": admin,
            "admins": admins
        }
        return templates.TemplateResponse("admin/users.html", context)
    except Exception as e:
        logger.error(f"Error loading admin users for {admin['username']}: {e}")
        raise HTTPException(status_code=500, detail="Failed to load users")

@router.post("/users")
@rate_limit(requests_per_minute=20, key_func=lambda request: f"admin_create_user:{get_client_ip(request)}")
async def create_admin_user(
    request: Request,
    admin_create: AdminCreateRequest = Body(...),
    admin: dict = Depends(require_admin)
):
    if not admin_manager:
        raise HTTPException(status_code=500, detail="Admin manager not available")
    username = sanitize_input(admin_create.username)
    email = sanitize_input(admin_create.email)
    if not validate_username(username):
        logger.warning(f"Invalid username attempted for admin creation: {username}")
        return JSONResponse({"success": False, "error": "Invalid username format."})
    if not validate_email(email):
        logger.warning(f"Invalid email attempted for admin creation: {email}")
        return JSONResponse({"success": False, "error": "Invalid email format."})
    if not validate_password(admin_create.password):
        logger.warning(f"Weak password attempted for admin creation: {username}")
        return JSONResponse({"success": False, "error": f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."})
    if not admin_manager.has_permission(admin["username"], "user_management"):
        logger.warning(f"Permission denied: {admin['username']} tried to create admin user {username} from {get_client_ip(request)}")
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    try:
        success = admin_manager.create_admin(
            username,
            email,
            admin_create.password,
            admin_create.role
        )
        if success:
            logger.info(f"Admin user {username} created by {admin['username']} from {get_client_ip(request)}")
            return JSONResponse({"success": True, "message": "Admin user created"})
        else:
            logger.warning(f"Failed to create admin user {username} by {admin['username']} from {get_client_ip(request)}")
            raise HTTPException(status_code=400, detail="Failed to create admin user")
    except Exception as e:
        logger.error(f"Error creating admin user {username} by {admin['username']}: {e}")
        raise HTTPException(status_code=500, detail="Failed to create user")

class PasswordResetRequest(BaseModel):
    username: str
    new_password: str
    current_password: Optional[str] = None  # Only for self-service

@router.post("/users/reset-password")
@rate_limit(requests_per_minute=10, key_func=lambda request: f"admin_reset_password:{get_client_ip(request)}")
async def admin_reset_password(
    request: Request,
    reset_request: PasswordResetRequest = Body(...),
    admin: dict = Depends(require_admin)
):
    if not admin_manager:
        raise HTTPException(status_code=500, detail="Admin manager not available")
    if not admin_manager.has_permission(admin["username"], "user_management"):
        logger.warning(f"Permission denied: {admin['username']} tried to reset password for {reset_request.username} from {get_client_ip(request)}")
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    if reset_request.username == "admin" and admin["username"] != "admin":
        logger.warning(f"Permission denied: {admin['username']} tried to reset super_admin password from {get_client_ip(request)}")
        raise HTTPException(status_code=403, detail="Only super_admin can reset their own password")
    success = admin_manager.reset_password(reset_request.username, reset_request.new_password, by_admin=admin["username"])
    if success:
        logger.info(f"Password for {reset_request.username} reset by {admin['username']} from {get_client_ip(request)}")
        return JSONResponse({"success": True, "message": f"Password for {reset_request.username} reset"})
    else:
        logger.warning(f"Failed password reset for {reset_request.username} by {admin['username']} from {get_client_ip(request)}")
        raise HTTPException(status_code=400, detail="Failed to reset password")

@router.post("/reset-password")
@rate_limit(requests_per_minute=5, key_func=lambda request: f"self_reset_password:{get_client_ip(request)}")
async def self_reset_password(
    request: Request,
    reset_request: PasswordResetRequest = Body(...),
    admin: dict = Depends(require_admin)
):
    if not admin_manager:
        raise HTTPException(status_code=500, detail="Admin manager not available")
    if reset_request.username != admin["username"]:
        logger.warning(f"Permission denied: {admin['username']} tried to self-reset password for {reset_request.username} from {get_client_ip(request)}")
        raise HTTPException(status_code=403, detail="Can only reset your own password here")
    if not reset_request.current_password:
        logger.warning(f"Password reset denied: {admin['username']} did not provide current password from {get_client_ip(request)}")
        raise HTTPException(status_code=400, detail="Current password required")
    success = admin_manager.reset_password(reset_request.username, reset_request.new_password, by_admin=admin["username"], current_password=reset_request.current_password)
    if success:
        logger.info(f"Admin {admin['username']} reset their own password from {get_client_ip(request)}")
        return JSONResponse({"success": True, "message": "Password reset successful"})
    else:
        logger.warning(f"Failed self password reset for {admin['username']} from {get_client_ip(request)}")
        raise HTTPException(status_code=400, detail="Failed to reset password")

@router.get("/system")
async def admin_system(request: Request):
    admin = await require_admin(request)
    """Admin system status page."""
    try:
        system_info = {
            "timestamp": datetime.now().isoformat(),
            "admin_count": len(admin_manager.admins) if admin_manager else 0,
            "active_sessions": len(admin_manager.sessions) if admin_manager else 0,
            "settings": settings
        }
        context = {
            "request": request,
            "admin": admin,
            "system_info": system_info
        }
        return templates.TemplateResponse("admin/system.html", context)
    except Exception as e:
        logger.error(f"Error loading system info: {e}")
        raise HTTPException(status_code=500, detail="Failed to load system info")

@router.get("/api/status")
async def api_status(_admin: dict = Depends(require_admin)):
    """Get system status via API."""
    return JSONResponse({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "admin_count": len(admin_manager.admins) if admin_manager else 0,
        "active_sessions": len(admin_manager.sessions) if admin_manager else 0
    })

@router.get("/api/admins")
async def api_list_admins(_admin: dict = Depends(require_admin)):
    """List admin users via API."""
    if not admin_manager:
        raise HTTPException(status_code=500, detail="Admin manager not available")
    admins = admin_manager.list_admins()
    return JSONResponse([
        {
            "username": a.username,
            "email": a.email,
            "role": a.role,
            "is_active": a.is_active,
            "created_at": a.created_at.isoformat(),
            "last_login": a.last_login.isoformat() if a.last_login else None
        }
        for a in admins
    ])

@router.get("/plugin-module-requests", response_class=JSONResponse)
async def list_plugin_module_requests(request: Request):
    _admin = await require_admin(request)
    """List all plugin module import requests from plugins."""
    isolation_manager = unified_plugin_manager.isolation_manager
    return {"requests": isolation_manager.get_plugin_module_requests()}

@router.post("/grant-plugin-module", response_class=JSONResponse)
async def grant_plugin_module(
    plugin_name: str = Form(...),
    module_name: str = Form(...),
    _admin: dict = Depends(require_admin)
):
    """Grant a plugin permission to import a module."""
    isolation_manager = unified_plugin_manager.isolation_manager
    isolation_manager.grant_plugin_module_permission(plugin_name, module_name)
    return {"success": True, "plugin": plugin_name, "module": module_name}

@router.post("/revoke-plugin-module", response_class=JSONResponse)
async def revoke_plugin_module(
    plugin_name: str = Form(...),
    module_name: str = Form(...),
    _admin: dict = Depends(require_admin)
):
    """Revoke a plugin's permission to import a module."""
    isolation_manager = unified_plugin_manager.isolation_manager
    isolation_manager.revoke_plugin_module_permission(plugin_name, module_name)
    return {"success": True, "plugin": plugin_name, "module": module_name}

__all__ = ["router"]
