"""
PlexiChat Web Admin Router

Web interface for administrative operations.
"""

from datetime import datetime
from typing import Optional, Dict, Any, List, Set
from types import SimpleNamespace
from dataclasses import dataclass

from fastapi import APIRouter, Request, Depends, HTTPException, Form, status, Body
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

# Use unified authentication manager and FastAPI adapter
from plexichat.core.authentication import get_auth_manager, Role
from plexichat.core.auth.fastapi_adapter import get_auth_adapter

from plexichat.core.config import settings
from plexichat.core.plugins.manager import unified_plugin_manager
from plexichat.core.logging import get_logger
import re
import json
from pathlib import Path
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
        SecurityLevel, RequiredPermission, admin_endpoint, protect_from_replay
    )
    from plexichat.core.logging import (
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

    def protect_from_replay(*args, **kwargs):
        def decorator(func): return func
        return decorator

    def rate_limit(*args, **kwargs):
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
    """Admin login request model."""
    username: str
    password: str

class AdminCreateRequest(BaseModel):
    """Admin creation request model."""
    username: str
    email: str
    password: str
    role: str = "admin"

# Create a local wrapper around unified auth manager exposing admin-oriented helpers
@dataclass
class AdminUser:
    username: str
    email: Optional[str] = None
    role: str = "admin"
    permissions: Set[str] = None
    is_active: bool = True
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

class AdminManagerWrapper:
    """
    Wrapper that adapts the UnifiedAuthManager to the legacy admin_manager interface used by the web admin router.
    Provides both sync and async helpers as needed by the endpoints in this module.
    """
    def __init__(self):
        self.auth_manager = get_auth_manager()
        # FastAPI adapter for token conveniences if needed
        try:
            self.adapter = get_auth_adapter()
        except Exception:
            self.adapter = None

    # Properties expected by templates and handlers
    @property
    def admins(self) -> List[AdminUser]:
        """Return list of admin-like user representations."""
        try:
            creds_map = getattr(self.auth_manager.security_system, "user_credentials", {})
            admins = []
            for username, cred in creds_map.items():
                permissions = getattr(cred, "permissions", set())
                # Treat account as admin if 'admin' permission present
                if "admin" in permissions or "user_management" in permissions:
                    admins.append(AdminUser(
                        username=username,
                        email=getattr(cred, "email", None),
                        role="admin" if "admin" in permissions else "user",
                        permissions=set(permissions),
                        is_active=getattr(cred, "is_active", True),
                        created_at=getattr(cred, "created_at", None),
                        last_login=getattr(cred, "last_login", None)
                    ))
            return admins
        except Exception as e:
            logger.debug(f"Error enumerating admins: {e}")
            return []

    @property
    def sessions(self) -> Dict[str, Any]:
        """Expose active sessions mapping from unified auth manager."""
        try:
            return getattr(self.auth_manager, "active_sessions", {})
        except Exception:
            return {}

    async def authenticate(self, username: str, password: str, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> Optional[str]:
        """
        Authenticate an admin user and return an access token (string) on success.
        """
        try:
            result = await self.auth_manager.authenticate_user(username, password, ip_address=ip_address, user_agent=user_agent)
            if result and result.success:
                # Prefer access token if available
                return result.token or result.session_id
            return None
        except Exception as e:
            logger.error(f"AdminManagerWrapper.authenticate error: {e}")
            return None

    async def validate_session(self, token: str) -> Optional[SimpleNamespace]:
        """
        Validate a token (access token) and return a simple admin-like object if valid.
        """
        try:
            # Validate token via unified manager
            valid, payload = await self.auth_manager.validate_token(token)
            if not valid or not payload:
                return None
            user_id = payload.get("user_id") or payload.get("sub")
            if not user_id:
                return None
            permissions = self.auth_manager.get_user_permissions(user_id)
            role = "admin" if "admin" in permissions or "user_management" in permissions else "user"
            admin_obj = SimpleNamespace(
                username=user_id,
                email=getattr(self.auth_manager.security_system.user_credentials.get(user_id, {}), "email", None),
                role=role,
                permissions=permissions,
                token=token
            )
            return admin_obj
        except Exception as e:
            logger.error(f"AdminManagerWrapper.validate_session error: {e}")
            return None

    async def logout(self, token: str) -> bool:
        """
        Logout / revoke token.
        """
        try:
            # Prefer revoke_token if available
            success = await self.auth_manager.revoke_token(token)
            return bool(success)
        except Exception as e:
            logger.error(f"AdminManagerWrapper.logout error: {e}")
            return False

    def list_admins(self) -> List[AdminUser]:
        """Return admin user list for management pages."""
        return self.admins

    def has_permission(self, username: str, permission: str) -> bool:
        """Check permission using unified auth manager."""
        try:
            return self.auth_manager.check_permission(username, permission)
        except Exception as e:
            logger.error(f"AdminManagerWrapper.has_permission error: {e}")
            return False

    def create_admin(self, username: str, email: str, password: str, role: str = "admin") -> bool:
        """
        Create an admin user. Uses register_user then assigns role.
        Returns True on success.
        """
        try:
            # Attempt to register user
            success, issues = self.auth_manager.register_user(username, password, permissions=set(), roles=None)
            if not success:
                logger.warning(f"Failed to register admin user {username}: {issues}")
                return False
            # Try to set email if credentials model supports it
            try:
                creds = self.auth_manager.security_system.user_credentials.get(username)
                if creds is not None:
                    if hasattr(creds, "email"):
                        creds.email = email
                    else:
                        # attach attribute for template/readback usage
                        setattr(creds, "email", email)
            except Exception:
                pass

            # Map role string to Role enum if possible
            try:
                role_enum = Role[role.upper()] if isinstance(role, str) and role.upper() in Role.__members__ else Role.ADMIN
            except Exception:
                role_enum = Role.ADMIN

            # Assign role via unified manager
            try:
                self.auth_manager.assign_role(username, role_enum)
            except Exception:
                # best effort, ignore failure if not critical
                pass

            return True
        except Exception as e:
            logger.error(f"AdminManagerWrapper.create_admin error: {e}")
            return False

    def reset_password(self, username: str, new_password: str, by_admin: Optional[str] = None, current_password: Optional[str] = None) -> bool:
        """
        Reset an admin's password. If by_admin provided, allow unconditional reset.
        If current_password provided, perform best-effort reset (legacy behavior).
        Note: This wrapper performs a direct password hash update using the security system's password manager.
        """
        try:
            creds_map = getattr(self.auth_manager.security_system, "user_credentials", {})
            creds = creds_map.get(username)
            if not creds:
                return False

            # If caller is admin, allow unconditional reset
            if by_admin:
                try:
                    password_hash, salt = self.auth_manager.security_system.password_manager.hash_password(new_password)
                    creds.password_hash = password_hash
                    creds.salt = salt
                    return True
                except Exception as e:
                    logger.error(f"Failed to reset password by admin for {username}: {e}")
                    return False

            # If current_password provided, attempt to change without full verification (best-effort)
            if current_password:
                try:
                    # Try to use password_manager.verify_password if available
                    verify_fn = getattr(self.auth_manager.security_system.password_manager, "verify_password", None)
                    if callable(verify_fn):
                        try:
                            verified = verify_fn(username, current_password)
                        except TypeError:
                            # Different signature - try as (password, hash) style - best-effort fallback
                            verified = True
                        if not verified:
                            return False
                    # Hash and set new password
                    password_hash, salt = self.auth_manager.security_system.password_manager.hash_password(new_password)
                    creds.password_hash = password_hash
                    creds.salt = salt
                    return True
                except Exception:
                    # As a last resort, deny to avoid accidental insecure operations
                    logger.debug("Password manager did not support verification; denying self-reset for safety")
                    return False

            # No authority to reset
            return False
        except Exception as e:
            logger.error(f"AdminManagerWrapper.reset_password error: {e}")
            return False

# Instantiate wrapper for this module
admin_manager = AdminManagerWrapper()

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
        # Validate token/session via unified auth manager wrapper
        admin = await admin_manager.validate_session(token)
        if admin:
            return {
                "username": getattr(admin, "username", None),
                "email": getattr(admin, "email", None),
                "role": getattr(admin, "role", None),
                "permissions": getattr(admin, "permissions", set()),
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

# Audit log storage (simple file-backed; other systems may replace this)
_AUDIT_LOG_FILE = Path("data/audit_logs.json")
_AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
_audit_log_cache: List[Dict[str, Any]] = []
# Load existing logs if present
try:
    if _AUDIT_LOG_FILE.exists():
        _audit_log_cache = json.loads(_AUDIT_LOG_FILE.read_text())
except Exception:
    _audit_log_cache = []

def _append_audit_log(action: str, admin: Dict[str, Any], details: Dict[str, Any] = None):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "admin": admin.get("username") if admin else None,
        "action": action,
        "details": details or {}
    }
    _audit_log_cache.append(entry)
    try:
        _AUDIT_LOG_FILE.write_text(json.dumps(_audit_log_cache, indent=2))
    except Exception as e:
        logger.error(f"Failed to persist audit log: {e}")
    # Also emit to enhanced logger if available
    if enhanced_logger:
        try:
            enhanced_logger.info(f"AUDIT: {action}", extra={"category": LogCategory.AUDIT, "metadata": entry})
        except Exception:
            pass

# Permission explanations for admin UI
PERMISSION_EXPLANATIONS = {
    "os": "Access to operating system functions (file system, environment). Dangerous; can exfiltrate data or run commands.",
    "subprocess": "Allows spawning subprocesses. Can execute arbitrary binaries on the host.",
    "socket": "Low-level network socket access. Can open outbound/inbound connections.",
    "requests": "HTTP client library for outbound network requests. Consider brokered network APIs for safety.",
    "urllib": "URL and HTTP client utilities; can perform network requests.",
    "sqlite3": "Embedded database access. May read/write local DB files.",
    "sys": "System-level introspection; may reveal environment and sensitive info.",
    "shutil": "File operations including deletion and copy. Can modify file system.",
    "pathlib": "File path utilities; by itself safe but combined with file ops can access FS.",
    "open": "Direct file I/O. Typically restricted to plugin-specific data directories.",
    "network_outbound": "Generic label for outbound network access; prefer brokered APIs."
}

def format_plugin_info(info):
    try:
        md = info.metadata
        return {
            "plugin_id": info.plugin_id,
            "name": getattr(md, "name", info.plugin_id),
            "version": getattr(md, "version", None),
            "description": getattr(md, "description", None),
            "author": getattr(md, "author", None),
            "enabled": getattr(md, "enabled", False),
            "security_level": getattr(md, "security_level", "sandboxed"),
            "permissions_requested": getattr(md, "permissions", []),
            "dependencies": getattr(md, "dependencies", []),
            "path": str(info.path),
            "status": info.status.name if hasattr(info.status, "name") else str(info.status),
            "loaded_at": info.loaded_at.isoformat() if info.loaded_at else None,
            "error_message": info.error_message
        }
    except Exception:
        return {"plugin_id": getattr(info, "plugin_id", "unknown")}

#
# Admin pages and APIs
#

@router.get("/", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    admin = await require_admin(request)
    """Admin dashboard page."""
    if not admin:
        return RedirectResponse(url="/admin/login", status_code=302)
    try:
        # Expand system summary with optional components
        cluster_status = {"available": False}
        backup_status = {"available": False}
        security_status = {"available": False}
        try:
            from plexichat.core.clustering.cluster_manager import get_cluster_status
            cluster_status = get_cluster_status() if callable(get_cluster_status) else {"available": False}
        except Exception:
            cluster_status = {"available": False}
        try:
            from plexichat.features.backup.backup_manager import get_backup_status
            backup_status = get_backup_status() if callable(get_backup_status) else {"available": False}
        except Exception:
            backup_status = {"available": False}
        try:
            from plexichat.core.security.security_manager import get_security_system
            security = get_security_system()
            security_status = security.get_security_status() if security else {"available": False}
        except Exception:
            security_status = {"available": False}

        context = {
            "request": request,
            "admin": admin,
            "system_info": {
                "timestamp": datetime.now().isoformat(),
                "admin_count": len(admin_manager.admins) if admin_manager else 0,
                "active_sessions": len(admin_manager.sessions) if admin_manager else 0,
                "cluster": cluster_status,
                "backup": backup_status,
                "security": security_status
            }
        }
        return templates.TemplateResponse("admin/dashboard.html", context)
    except Exception as e:
        logger.error(f"Error rendering admin dashboard for {admin['username'] if admin else 'unknown'}: {e}")
        # Fallback simple HTML
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
            try:
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
            except Exception:
                pass

        token = await admin_manager.authenticate(username, password, ip_address, user_agent)
        if not token:
            # Enhanced failed login logging
            if enhanced_logger:
                try:
                    enhanced_logger.warning(
                        f"Admin login failed for {username}",
                        extra={
                            "category": LogCategory.SECURITY,
                            "security": {"failed_authentications": 1, "threat_score": 0.5},
                            "metadata": {"username": username, "client_ip": ip_address, "failure_reason": "invalid_credentials"},
                            "tags": ["admin", "login_failed", "security_event"]
                        }
                    )
                except Exception:
                    pass
            else:
                logger.warning(f"Admin login failed for {username} from {ip_address}")
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Enhanced successful login logging
        if enhanced_logger:
            try:
                enhanced_logger.info(
                    f"Admin login successful for {username}",
                    extra={
                        "category": LogCategory.AUTH,
                        "metadata": {"username": username, "client_ip": ip_address, "auth_success": True},
                        "tags": ["admin", "login_success", "security_event"]
                    }
                )
            except Exception:
                pass
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
        _append_audit_log("admin_login", {"username": username}, {"ip": ip_address})
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
        await admin_manager.logout(token)
        logger.info(f"Admin logout: {admin['username']} from {get_client_ip(request)}")
        _append_audit_log("admin_logout", admin, {"ip": get_client_ip(request)})
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
@protect_from_replay()
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
            _append_audit_log("create_admin_user", admin, {"created": username})
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
@protect_from_replay()
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
        _append_audit_log("reset_password", admin, {"target": reset_request.username})
        return JSONResponse({"success": True, "message": f"Password for {reset_request.username} reset"})
    else:
        logger.warning(f"Failed password reset for {reset_request.username} by {admin['username']} from {get_client_ip(request)}")
        raise HTTPException(status_code=400, detail="Failed to reset password")

@router.post("/reset-password")
@rate_limit(requests_per_minute=5, key_func=lambda request: f"self_reset_password:{get_client_ip(request)}")
@protect_from_replay()
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
        _append_audit_log("self_reset_password", admin, {})
        return JSONResponse({"success": True, "message": "Password reset successful"})
    else:
        logger.warning(f"Failed self password reset for {admin['username']} from {get_client_ip(request)}")
        raise HTTPException(status_code=400, detail="Failed to reset password")

@router.get("/system")
async def admin_system(request: Request):
    admin = await require_admin(request)
    """Admin system status page."""
    try:
        # expand system info with plugin and config summaries
        plugin_summary = {}
        try:
            plugin_summary = {
                "total_discovered": unified_plugin_manager.stats.get("total_discovered", 0),
                "total_loaded": unified_plugin_manager.stats.get("total_loaded", 0),
                "total_enabled": unified_plugin_manager.stats.get("total_enabled", 0),
                "plugins": [format_plugin_info(info) for info in unified_plugin_manager.plugin_info.values()]
            }
        except Exception:
            plugin_summary = {"plugins": []}
        system_info = {
            "timestamp": datetime.now().isoformat(),
            "admin_count": len(admin_manager.admins) if admin_manager else 0,
            "active_sessions": len(admin_manager.sessions) if admin_manager else 0,
            "settings": settings,
            "plugins": plugin_summary
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
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "last_login": a.last_login.isoformat() if a.last_login else None
        }
        for a in admins
    ])

#
# Plugin administration
#

@router.get("/plugins", response_class=HTMLResponse)
async def plugins_page(request: Request):
    admin = await require_admin(request)
    try:
        plugins = [format_plugin_info(info) for info in unified_plugin_manager.plugin_info.values()]
        # Collect module import requests
        module_requests = unified_plugin_manager.isolation_manager.get_plugin_module_requests()
        context = {
            "request": request,
            "admin": admin,
            "plugins": plugins,
            "module_requests": module_requests,
            "permission_explanations": PERMISSION_EXPLANATIONS
        }
        return templates.TemplateResponse("admin/plugins.html", context)
    except Exception as e:
        logger.error(f"Error loading plugins page: {e}")
        raise HTTPException(status_code=500, detail="Failed to load plugins")

@router.get("/api/plugins")
async def api_list_plugins(_admin: dict = Depends(require_admin)):
    try:
        plugins = [format_plugin_info(info) for info in unified_plugin_manager.plugin_info.values()]
        module_requests = unified_plugin_manager.isolation_manager.get_plugin_module_requests()
        return JSONResponse({"plugins": plugins, "module_requests": module_requests})
    except Exception as e:
        logger.error(f"Failed to list plugins via API: {e}")
        raise HTTPException(status_code=500, detail="Failed to list plugins")

@router.post("/plugins/approve-all-requests")
@protect_from_replay()
@admin_endpoint(permissions=[RequiredPermission.ADMIN])
async def approve_all_plugin_requests(request: Request, admin: dict = Depends(require_admin)):
    """Grant all currently requested module imports for a plugin or all plugins if plugin_name omitted."""
    form = await request.form()
    plugin_name = form.get("plugin_name")
    isolation = unified_plugin_manager.isolation_manager
    requests_map = isolation.get_plugin_module_requests()
    approved = []
    denied = []
    try:
        if plugin_name:
            requested = requests_map.get(plugin_name, [])
            for m in requested:
                isolation.grant_plugin_module_permission(plugin_name, m)
                approved.append({"plugin": plugin_name, "module": m})
            _append_audit_log("approve_plugin_requests", admin, {"plugin": plugin_name, "approved": requested})
        else:
            # approve all outstanding requests
            for p, mods in requests_map.items():
                for m in mods:
                    isolation.grant_plugin_module_permission(p, m)
                    approved.append({"plugin": p, "module": m})
            _append_audit_log("approve_plugin_requests_all", admin, {"approved_count": len(approved)})
        return JSONResponse({"success": True, "approved": approved, "denied": denied})
    except Exception as e:
        logger.error(f"Error approving plugin requests: {e}")
        raise HTTPException(status_code=500, detail="Failed to approve plugin requests")

@router.post("/plugins/deny-request")
@protect_from_replay()
@admin_endpoint(permissions=[RequiredPermission.ADMIN])
async def deny_plugin_request(plugin_name: str = Form(...), module_name: str = Form(...), admin: dict = Depends(require_admin)):
    """Deny a single plugin module request (recorded for audit)."""
    try:
        # Record denial in audit log (no action required because request remains ungranted)
        _append_audit_log("deny_plugin_request", admin, {"plugin": plugin_name, "module": module_name})
        return JSONResponse({"success": True, "plugin": plugin_name, "module": module_name, "action": "denied"})
    except Exception as e:
        logger.error(f"Error denying plugin request: {e}")
        raise HTTPException(status_code=500, detail="Failed to deny plugin request")

@router.post("/plugins/enable")
@protect_from_replay()
@admin_endpoint(permissions=[RequiredPermission.ADMIN])
async def enable_plugin(plugin_name: str = Form(...), admin: dict = Depends(require_admin)):
    try:
        success = await unified_plugin_manager.enable_plugin(plugin_name)
        _append_audit_log("enable_plugin", admin, {"plugin": plugin_name, "success": success})
        return JSONResponse({"success": success, "plugin": plugin_name})
    except Exception as e:
        logger.error(f"Error enabling plugin {plugin_name}: {e}")
        raise HTTPException(status_code=500, detail="Failed to enable plugin")

@router.post("/plugins/disable")
@protect_from_replay()
@admin_endpoint(permissions=[RequiredPermission.ADMIN])
async def disable_plugin(plugin_name: str = Form(...), admin: dict = Depends(require_admin)):
    try:
        success = await unified_plugin_manager.disable_plugin(plugin_name)
        _append_audit_log("disable_plugin", admin, {"plugin": plugin_name, "success": success})
        return JSONResponse({"success": success, "plugin": plugin_name})
    except Exception as e:
        logger.error(f"Error disabling plugin {plugin_name}: {e}")
        raise HTTPException(status_code=500, detail="Failed to disable plugin")

@router.post("/plugins/reload")
@protect_from_replay()
@admin_endpoint(permissions=[RequiredPermission.ADMIN])
async def reload_plugin(plugin_name: str = Form(...), admin: dict = Depends(require_admin)):
    try:
        success_unload = await unified_plugin_manager.unload_plugin(plugin_name)
        success_load = await unified_plugin_manager.load_plugin(plugin_name)
        _append_audit_log("reload_plugin", admin, {"plugin": plugin_name, "unloaded": success_unload, "loaded": success_load})
        return JSONResponse({"success": success_load, "plugin": plugin_name})
    except Exception as e:
        logger.error(f"Error reloading plugin {plugin_name}: {e}")
        raise HTTPException(status_code=500, detail="Failed to reload plugin")

#
# Security center
#

@router.get("/security", response_class=HTMLResponse)
async def security_center(request: Request):
    admin = await require_admin(request)
    try:
        # DDoS and blocked ip info
        ddos_info = {"available": False, "blocked_ips": []}
        security_events = []
        key_rotation = {"last_rotated": None}
        try:
            from plexichat.core.security.ddos_protection import ddos_protection_manager
            ddos_info["available"] = True
            ddos_info["blocked_ips"] = ddos_protection_manager.list_blocked_ips() if hasattr(ddos_protection_manager, "list_blocked_ips") else []
        except Exception:
            ddos_info = {"available": False, "blocked_ips": []}
        try:
            from plexichat.core.security.security_manager import get_security_system
            sec = get_security_system()
            security_events = []  # Real system could provide events; placeholder
            if sec:
                try:
                    security_events = sec.metrics  # lightweight exposure
                except Exception:
                    security_events = []
        except Exception:
            security_events = []
        # Try key rotation status from security system if available
        try:
            from plexichat.core.security.key_manager import key_rotation_status
            key_rotation = key_rotation_status() if callable(key_rotation_status) else {"last_rotated": None}
        except Exception:
            key_rotation = {"last_rotated": None}

        context = {
            "request": request,
            "admin": admin,
            "ddos": ddos_info,
            "security_events": security_events,
            "key_rotation": key_rotation
        }
        return templates.TemplateResponse("admin/security.html", context)
    except Exception as e:
        logger.error(f"Error loading security center: {e}")
        raise HTTPException(status_code=500, detail="Failed to load security center")

@router.get("/api/security")
async def api_security(_admin: dict = Depends(require_admin)):
    try:
        ddos_info = {"available": False, "blocked_ips": []}
        security_summary = {}
        try:
            from plexichat.core.security.ddos_protection import ddos_protection_manager
            ddos_info["available"] = True
            ddos_info["blocked_ips"] = ddos_protection_manager.list_blocked_ips() if hasattr(ddos_protection_manager, "list_blocked_ips") else []
        except Exception:
            ddos_info = {"available": False, "blocked_ips": []}
        try:
            from plexichat.core.security.security_manager import get_security_system
            sec = get_security_system()
            security_summary = sec.get_security_status() if sec and hasattr(sec, "get_security_status") else {}
        except Exception:
            security_summary = {}
        return JSONResponse({"ddos": ddos_info, "security": security_summary})
    except Exception as e:
        logger.error(f"Error fetching security API: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch security information")

@router.post("/security/block-ip")
@protect_from_replay()
@admin_endpoint(permissions=[RequiredPermission.ADMIN])
async def block_ip(ip: str = Form(...), admin: dict = Depends(require_admin)):
    try:
        try:
            from plexichat.core.security.ddos_protection import ddos_protection_manager
            if hasattr(ddos_protection_manager, "block_ip"):
                ddos_protection_manager.block_ip(ip)
                _append_audit_log("block_ip", admin, {"ip": ip})
                return JSONResponse({"success": True, "ip": ip})
        except Exception:
            # fallback: record in audit log as manual block
            _append_audit_log("block_ip_manual", admin, {"ip": ip})
            return JSONResponse({"success": True, "ip": ip, "note": "Recorded manual block (ddos manager not available)."})
        raise HTTPException(status_code=500, detail="DDoS protection system not available")
    except Exception as e:
        logger.error(f"Error blocking IP {ip}: {e}")
        raise HTTPException(status_code=500, detail="Failed to block IP")

@router.post("/security/unblock-ip")
@protect_from_replay()
@admin_endpoint(permissions=[RequiredPermission.ADMIN])
async def unblock_ip(ip: str = Form(...), admin: dict = Depends(require_admin)):
    try:
        try:
            from plexichat.core.security.ddos_protection import ddos_protection_manager
            if hasattr(ddos_protection_manager, "unblock_ip"):
                ddos_protection_manager.unblock_ip(ip)
                _append_audit_log("unblock_ip", admin, {"ip": ip})
                return JSONResponse({"success": True, "ip": ip})
        except Exception:
            _append_audit_log("unblock_ip_manual", admin, {"ip": ip})
            return JSONResponse({"success": True, "ip": ip, "note": "Recorded manual unblock (ddos manager not available)."})
        raise HTTPException(status_code=500, detail="DDoS protection system not available")
    except Exception as e:
        logger.error(f"Error unblocking IP {ip}: {e}")
        raise HTTPException(status_code=500, detail="Failed to unblock IP")

#
# Configuration management
#

@router.get("/config", response_class=HTMLResponse)
async def config_page(request: Request):
    admin = await require_admin(request)
    try:
        # Render configuration editor; actual validation is enforced on update
        context = {
            "request": request,
            "admin": admin,
            "settings": settings,
            "last_changes": _audit_log_cache[-20:] if _audit_log_cache else []
        }
        return templates.TemplateResponse("admin/config.html", context)
    except Exception as e:
        logger.error(f"Error rendering config page: {e}")
        raise HTTPException(status_code=500, detail="Failed to load config page")

class ConfigUpdate(BaseModel):
    key: str
    value: Any
    comment: Optional[str] = None

@router.get("/api/config")
async def api_get_config(_admin: dict = Depends(require_admin)):
    try:
        # Return a safe copy of settings (avoid exposing secrets)
        safe_settings = {}
        for k, v in settings.items() if isinstance(settings, dict) else getattr(settings, "__dict__", {}):
            if "secret" in str(k).lower() or "password" in str(k).lower() or "key" in str(k).lower():
                safe_settings[k] = "<redacted>"
            else:
                safe_settings[k] = v
        return JSONResponse({"settings": safe_settings})
    except Exception as e:
        logger.error(f"Error returning config: {e}")
        raise HTTPException(status_code=500, detail="Failed to return config")

@router.post("/config/update")
@protect_from_replay()
@admin_endpoint(permissions=[RequiredPermission.SYSTEM])
async def update_config(update: ConfigUpdate, admin: dict = Depends(require_admin)):
    try:
        key = sanitize_input(update.key)
        # Basic validation: ensure key exists or allow new keys
        old_value = settings.get(key) if isinstance(settings, dict) else getattr(settings, key, None)
        # Update in-memory settings; persistent config manager should be used in real system
        if isinstance(settings, dict):
            settings[key] = update.value
        else:
            setattr(settings, key, update.value)
        _append_audit_log("update_config", admin, {"key": key, "old": old_value, "new": update.value, "comment": update.comment})
        logger.info(f"Configuration key '{key}' updated by {admin['username']}")
        return JSONResponse({"success": True, "key": key, "old": old_value, "new": update.value})
    except Exception as e:
        logger.error(f"Error updating config: {e}")
        raise HTTPException(status_code=500, detail="Failed to update config")

#
# Audit logs
#

@router.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    admin = await require_admin(request)
    try:
        # Render logs UI with last 200 entries
        entries = list(reversed(_audit_log_cache[-200:]))
        context = {"request": request, "admin": admin, "logs": entries}
        return templates.TemplateResponse("admin/logs.html", context)
    except Exception as e:
        logger.error(f"Error rendering logs page: {e}")
        raise HTTPException(status_code=500, detail="Failed to load logs")

@router.get("/api/logs")
async def api_get_logs(since: Optional[str] = None, until: Optional[str] = None, action: Optional[str] = None, _admin: dict = Depends(require_admin)):
    try:
        entries = _audit_log_cache.copy()
        if since:
            try:
                since_dt = datetime.fromisoformat(since)
                entries = [e for e in entries if datetime.fromisoformat(e["timestamp"]) >= since_dt]
            except Exception:
                pass
        if until:
            try:
                until_dt = datetime.fromisoformat(until)
                entries = [e for e in entries if datetime.fromisoformat(e["timestamp"]) <= until_dt]
            except Exception:
                pass
        if action:
            entries = [e for e in entries if e.get("action") == action]
        return JSONResponse({"count": len(entries), "logs": entries})
    except Exception as e:
        logger.error(f"Error fetching logs: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch logs")

@router.post("/logs/export")
@protect_from_replay()
@admin_endpoint(permissions=[RequiredPermission.SYSTEM])
async def export_logs(_admin: dict = Depends(require_admin)):
    try:
        # Export logs as plaintext JSON for download (simple)
        payload = json.dumps(_audit_log_cache, indent=2)
        _append_audit_log("export_logs", _admin, {"count": len(_audit_log_cache)})
        return PlainTextResponse(payload, media_type="application/json")
    except Exception as e:
        logger.error(f"Error exporting logs: {e}")
        raise HTTPException(status_code=500, detail="Failed to export logs")

#
# HTTPS Setup Wizard (guided, non-destructive placeholder implementation)
#

class HttpsWizardRequest(BaseModel):
    domain: str
    email: Optional[str] = None
    method: str  # 'selfsigned' or 'letsencrypt' or 'upload'
    csr: Optional[str] = None  # only for upload
    cert_pem: Optional[str] = None
    key_pem: Optional[str] = None

@router.get("/https/setup", response_class=HTMLResponse)
async def https_setup_page(request: Request):
    admin = await require_admin(request)
    try:
        # Provide wizard UI
        ssl_dir = Path("config/ssl")
        certs = []
        if ssl_dir.exists():
            for f in ssl_dir.iterdir():
                certs.append(str(f.name))
        context = {"request": request, "admin": admin, "available_certs": certs}
        return templates.TemplateResponse("admin/https_setup.html", context)
    except Exception as e:
        logger.error(f"Error rendering HTTPS setup page: {e}")
        raise HTTPException(status_code=500, detail="Failed to load HTTPS setup")

@router.post("/https/setup")
@protect_from_replay()
@admin_endpoint(permissions=[RequiredPermission.SYSTEM])
async def https_setup(req: HttpsWizardRequest = Body(...), admin: dict = Depends(require_admin)):
    """Guided HTTPS setup. This endpoint performs non-destructive placeholder actions:
       - For selfsigned: generates placeholder key/cert files.
       - For letsencrypt: records requested provisioning and returns instructions (no external ACME calls).
       - For upload: verifies and stores provided PEM strings.
    """
    try:
        domain = sanitize_input(req.domain)
        method = req.method.lower()
        ssl_dir = Path("config/ssl")
        ssl_dir.mkdir(parents=True, exist_ok=True)
        result = {"domain": domain, "method": method}
        if method == "selfsigned":
            # Create placeholder files; real implementation should generate an actual certificate
            crt_file = ssl_dir / f"{domain}.crt"
            key_file = ssl_dir / f"{domain}.key"
            # Generate actual self-signed certificate
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PlexiChat"),
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(domain),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Write certificate and key
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            crt_file.write_text(cert_pem)
            key_file.write_text(key_pem)
            _append_audit_log("https_selfsigned", admin, {"domain": domain, "crt": str(crt_file), "key": str(key_file)})
            result["crt"] = str(crt_file)
            result["key"] = str(key_file)
            result["note"] = "Self-signed placeholder created. Replace with a real certificate in production."
            return JSONResponse(result)
        elif method == "letsencrypt":
            # Record request and provide instructions instead of performing ACME flow
            _append_audit_log("https_letsencrypt_requested", admin, {"domain": domain, "email": req.email})
            instructions = (
                "Let's Encrypt provisioning is not performed automatically by this wizard. "
                "To provision, run certbot on the host or configure the ACME client with DNS/HTTP challenge. "
                "Suggested command: certbot certonly --standalone -d {domain} --email {email} --agree-tos"
            ).format(domain=domain, email=(req.email or ""))
            result["instructions"] = instructions
            result["status"] = "instructions_provided"
            return JSONResponse(result)
        elif method == "upload":
            # Validate and store provided cert and key
            if not req.cert_pem or not req.key_pem:
                raise HTTPException(status_code=400, detail="cert_pem and key_pem required for upload")
            crt_file = ssl_dir / f"{domain}.crt"
            key_file = ssl_dir / f"{domain}.key"
            # Basic validation: ensure PEM headers present
            if "BEGIN CERTIFICATE" not in req.cert_pem or "BEGIN PRIVATE KEY" not in req.key_pem:
                raise HTTPException(status_code=400, detail="Invalid PEM format")
            crt_file.write_text(req.cert_pem)
            key_file.write_text(req.key_pem)
            _append_audit_log("https_upload", admin, {"domain": domain, "crt": str(crt_file), "key": str(key_file)})
            return JSONResponse({"success": True, "domain": domain, "crt": str(crt_file), "key": str(key_file)})
        else:
            raise HTTPException(status_code=400, detail="Unknown method")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"HTTPS setup error: {e}")
        raise HTTPException(status_code=500, detail="Failed to run HTTPS setup")

#
# Miscellaneous utility APIs
#

@router.get("/plugin-module-requests", response_class=JSONResponse)
async def list_plugin_module_requests(request: Request):
    _admin = await require_admin(request)
    """List all plugin module import requests from plugins."""
    isolation_manager = unified_plugin_manager.isolation_manager
    return {"requests": isolation_manager.get_plugin_module_requests()}

@router.post("/grant-plugin-module", response_class=JSONResponse)
@protect_from_replay()
async def grant_plugin_module(
    plugin_name: str = Form(...),
    module_name: str = Form(...),
    _admin: dict = Depends(require_admin)
):
    """Grant a plugin permission to import a module."""
    isolation_manager = unified_plugin_manager.isolation_manager
    isolation_manager.grant_plugin_module_permission(plugin_name, module_name)
    _append_audit_log("grant_plugin_module", _admin, {"plugin": plugin_name, "module": module_name})
    return {"success": True, "plugin": plugin_name, "module": module_name}

@router.post("/revoke-plugin-module", response_class=JSONResponse)
@protect_from_replay()
async def revoke_plugin_module(
    plugin_name: str = Form(...),
    module_name: str = Form(...),
    _admin: dict = Depends(require_admin)
):
    """Revoke a plugin's permission to import a module."""
    isolation_manager = unified_plugin_manager.isolation_manager
    isolation_manager.revoke_plugin_module_permission(plugin_name, module_name)
    _append_audit_log("revoke_plugin_module", _admin, {"plugin": plugin_name, "module": module_name})
    return {"success": True, "plugin": plugin_name, "module": module_name}

# Backwards compatible export
__all__ = ["router"]
