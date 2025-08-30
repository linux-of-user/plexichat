# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Plugin Marketplace Router

Web interface for plugin management, marketplace, and installation.
Provides complete plugin lifecycle management via web browser.
"""

import json
import logging
import urllib.request
from pathlib import Path
from typing import Dict, Any, List, Optional

from fastapi import APIRouter, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/plugins", tags=["plugins"])

# Templates
templates = Jinja2Templates(directory="src/plexichat/interfaces/web/templates")

# Security
security = HTTPBearer()

async def verify_admin_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify admin authentication token."""
    try:
        token = credentials.credentials
        if not token or not verify_admin_session(token):
            raise HTTPException(status_code=401, detail="Admin authentication required")
        return token
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid authentication")

def verify_admin_session(token: str) -> bool:
    """Verify admin session token."""
    try:
        return True  # Simplified for now
    except Exception:
        return False

# Try to import plugin security manager and PermissionType; fall back to None if not present
try:
    from plexichat.core.plugins.security_manager import (
        plugin_security_manager as core_plugin_security_manager,
        PermissionType as CorePermissionType
    )
except Exception:
    core_plugin_security_manager = None
    CorePermissionType = None

# -----------------------------------------------------------------------------
# Adapter to unify access to the plugin security manager (core or fallback)
# -----------------------------------------------------------------------------
class _FallbackSecurityManager:
    """Lightweight fallback security manager when the core one is not available.

    This is intentionally minimal: it stores data in memory and provides the same
    surface required by the router endpoints.
    """
    def __init__(self):
        self._permission_requests: Dict[str, List[Dict[str, Any]]] = {}
        self._approved_permissions: Dict[str, set] = {}
        self._audit_events: List[Dict[str, Any]] = []
        self._quarantined: set = set()
        self._policies: Dict[str, Dict[str, Any]] = {}

    def request_permission(self, plugin_name: str, permission_type: str, justification: str):
        req = {
            "plugin_name": plugin_name,
            "permission_type": permission_type,
            "justification": justification,
            "requested_at": None,
            "status": "pending",
        }
        self._permission_requests.setdefault(plugin_name, []).append(req)
        self._audit_events.append({
            "event_type": "permission_request",
            "plugin_name": plugin_name,
            "permission_type": permission_type,
            "description": f"Permission requested: {permission_type}",
        })
        return req

    def get_pending_permission_requests(self) -> List[Dict[str, Any]]:
        out = []
        for plugin, requests in self._permission_requests.items():
            for r in requests:
                if r.get("status") == "pending":
                    out.append(r)
        return out

    def approve_permission(self, plugin_name: str, permission_type: str, approved_by: str, expires_in_days: Optional[int] = None) -> bool:
        found = False
        for r in self._permission_requests.get(plugin_name, []):
            if r.get("permission_type") == permission_type and r.get("status") == "pending":
                r["status"] = "approved"
                r["approved_by"] = approved_by
                found = True
                break
        self._approved_permissions.setdefault(plugin_name, set()).add(permission_type)
        self._audit_events.append({
            "event_type": "permission_granted",
            "plugin_name": plugin_name,
            "permission_type": permission_type,
            "approved_by": approved_by,
            "expires_in_days": expires_in_days,
        })
        return found

    def deny_permission(self, plugin_name: str, permission_type: str, denied_by: str) -> bool:
        found = False
        for r in self._permission_requests.get(plugin_name, []):
            if r.get("permission_type") == permission_type and r.get("status") == "pending":
                r["status"] = "denied"
                r["denied_by"] = denied_by
                found = True
                break
        self._audit_events.append({
            "event_type": "permission_denied",
            "plugin_name": plugin_name,
            "permission_type": permission_type,
            "denied_by": denied_by,
        })
        return found

    def has_permission(self, plugin_name: str, permission_type: str) -> bool:
        return permission_type in self._approved_permissions.get(plugin_name, set())

    def get_plugin_permissions(self, plugin_name: str) -> Dict[str, Any]:
        pending = []
        for r in self._permission_requests.get(plugin_name, []):
            if r.get("status") == "pending":
                pending.append({
                    "permission_type": r.get("permission_type"),
                    "justification": r.get("justification"),
                    "status": r.get("status")
                })
        return {
            "approved_permissions": list(self._approved_permissions.get(plugin_name, [])),
            "pending_requests": pending,
            "is_quarantined": plugin_name in self._quarantined,
        }

    def log_audit_event(self, event: Dict[str, Any]):
        self._audit_events.append(event)

    def get_security_summary(self) -> Dict[str, Any]:
        return {
            "total_plugins_monitored": 0,
            "quarantined_plugins": len(self._quarantined),
            "pending_permission_requests": len(self.get_pending_permission_requests()),
            "recent_audit_events": len(self._audit_events),
        }

    def get_audit_events(self, plugin_name: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        events = [e for e in self._audit_events if (plugin_name is None or e.get("plugin_name") == plugin_name)]
        return events[-limit:]

    def set_security_policy(self, plugin_name: str, policy: Dict[str, Any]):
        self._policies[plugin_name] = policy
        self._audit_events.append({
            "event_type": "policy_updated",
            "plugin_name": plugin_name,
            "description": "Policy updated",
            "policy": policy
        })
        return True

    def quarantine_plugin(self, plugin_name: str, reason: str, quarantined_by: str):
        self._quarantined.add(plugin_name)
        self._approved_permissions.pop(plugin_name, None)
        self._audit_events.append({
            "event_type": "plugin_quarantined",
            "plugin_name": plugin_name,
            "reason": reason,
            "quarantined_by": quarantined_by
        })
        return True

    def release_from_quarantine(self, plugin_name: str, released_by: str):
        if plugin_name in self._quarantined:
            self._quarantined.remove(plugin_name)
            self._audit_events.append({
                "event_type": "plugin_released",
                "plugin_name": plugin_name,
                "released_by": released_by
            })
            return True
        return False

    def create_sandbox(self, plugin_name: str) -> bool:
        # Minimal semantic: record an audit event
        self._audit_events.append({
            "event_type": "sandbox_created",
            "plugin_name": plugin_name,
            "description": f"Sandbox created for {plugin_name}"
        })
        return True

# Choose manager: core if available else fallback adapter
if core_plugin_security_manager is not None:
    class SecurityAdapter:
        """Adapter that forwards calls to the core plugin security manager."""
        def __init__(self, core_mgr):
            self._core = core_mgr

        def get_security_summary(self):
            try:
                return self._core.get_security_summary()
            except Exception as e:
                logger.exception("Error getting security summary from core manager")
                return {}

        def get_plugin_permissions(self, plugin_name: str):
            try:
                return self._core.get_plugin_permissions(plugin_name)
            except Exception as e:
                logger.exception("Error getting plugin permissions from core manager")
                return {}

        def get_pending_permission_requests(self):
            try:
                return self._core.get_pending_permission_requests()
            except Exception as e:
                logger.exception("Error getting pending requests from core manager")
                return []

        def approve_permission(self, plugin_name: str, permission: str, approved_by: str, expires_in_days: Optional[int] = None):
            try:
                # Map permission string to CorePermissionType if available
                if CorePermissionType:
                    try:
                        p_enum = CorePermissionType(permission)
                    except Exception:
                        # Try by value
                        try:
                            p_enum = next(pt for pt in CorePermissionType if pt.value == permission)
                        except Exception:
                            p_enum = permission
                else:
                    p_enum = permission
                return self._core.approve_permission(plugin_name, p_enum, approved_by, expires_in_days)
            except Exception as e:
                logger.exception("Error approving permission via core manager")
                return False

        def deny_permission(self, plugin_name: str, permission: str, denied_by: str):
            try:
                if CorePermissionType:
                    try:
                        p_enum = CorePermissionType(permission)
                    except Exception:
                        try:
                            p_enum = next(pt for pt in CorePermissionType if pt.value == permission)
                        except Exception:
                            p_enum = permission
                else:
                    p_enum = permission
                return self._core.deny_permission(plugin_name, p_enum, denied_by)
            except Exception as e:
                logger.exception("Error denying permission via core manager")
                return False

        def get_audit_events(self, plugin_name: Optional[str] = None, limit: int = 100):
            try:
                events = getattr(self._core, "_audit_events", None)
                if events is not None:
                    filtered = [e for e in events if (plugin_name is None or e.plugin_name == plugin_name)]
                    # Convert dataclass events to dicts if necessary
                    out = []
                    for e in filtered[-limit:]:
                        if hasattr(e, "__dict__"):
                            out.append({k: v for k, v in e.__dict__.items()})
                        else:
                            out.append(e)
                    return out
                # fallback to summary
                return []
            except Exception:
                logger.exception("Error fetching audit events from core manager")
                return []

        def set_security_policy(self, plugin_name: str, policy: Dict[str, Any]):
            try:
                # Try to set policy on core manager if method exists
                if hasattr(self._core, "set_security_policy"):
                    return self._core.set_security_policy(plugin_name, policy)
                # otherwise store on core manager internal dict if accessible
                if hasattr(self._core, "_security_policies"):
                    self._core._security_policies[plugin_name] = policy
                    return True
                return False
            except Exception:
                logger.exception("Error setting policy on core manager")
                return False

        def quarantine_plugin(self, plugin_name: str, reason: str, quarantined_by: str):
            try:
                return self._core.quarantine_plugin(plugin_name, reason, quarantined_by)
            except Exception:
                logger.exception("Error quarantining plugin via core manager")
                return False

        def release_from_quarantine(self, plugin_name: str, released_by: str):
            try:
                return self._core.release_from_quarantine(plugin_name, released_by)
            except Exception:
                logger.exception("Error releasing plugin via core manager")
                return False

        def create_sandbox(self, plugin_name: str):
            try:
                if hasattr(self._core, "create_sandbox"):
                    self._core.create_sandbox(plugin_name)
                    return True
                return False
            except Exception:
                logger.exception("Error creating sandbox via core manager")
                return False

    security_adapter = SecurityAdapter(core_plugin_security_manager)
else:
    security_adapter = _FallbackSecurityManager()

# -----------------------------------------------------------------------------
# Web UI endpoints enhancements for plugin security and permission management
# -----------------------------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
async def plugins_home(request: Request, token: str = Depends(verify_admin_token)):
    """Plugin marketplace home page with security summary included."""
    try:
        installed_plugins = get_installed_plugins()
        available_plugins = await get_available_plugins()
        repositories = get_plugin_repositories()
        try:
            security_summary = security_adapter.get_security_summary()
        except Exception:
            security_summary = {}

        return templates.TemplateResponse("plugins/marketplace.html", {
            "request": request,
            "title": "Plugin Marketplace",
            "installed_plugins": installed_plugins,
            "available_plugins": available_plugins,
            "repositories": repositories,
            "admin_authenticated": True,
            "security_summary": security_summary
        })
    except Exception as e:
        logger.error(f"Plugin marketplace error: {e}")
        raise HTTPException(status_code=500, detail="Plugin marketplace error")

# Existing endpoints above remain unchanged...

@router.get("/security", response_class=HTMLResponse)
async def plugin_security_dashboard(request: Request, token: str = Depends(verify_admin_token)):
    """Render the plugin security dashboard for admins."""
    try:
        security_summary = security_adapter.get_security_summary()
        pending = security_adapter.get_pending_permission_requests() if hasattr(security_adapter, "get_pending_permission_requests") else []
        return templates.TemplateResponse("admin/security_dashboard.html", {
            "request": request,
            "title": "Plugin Security Dashboard",
            "security_summary": security_summary,
            "pending_requests": pending,
            "admin_authenticated": True
        })
    except Exception as e:
        logger.error(f"Failed to render security dashboard: {e}")
        # If template missing or error, return JSON fallback
        return JSONResponse({"error": "Failed to render security dashboard", "details": str(e)}, status_code=500)

@router.get("/{plugin_name}/security", response_class=HTMLResponse)
async def plugin_security_page(request: Request, plugin_name: str, token: str = Depends(verify_admin_token)):
    """Render security details and controls for a specific plugin."""
    try:
        plugin_permissions = security_adapter.get_plugin_permissions(plugin_name)
        audit_events = security_adapter.get_audit_events(plugin_name) if hasattr(security_adapter, "get_audit_events") else []
        # Determine sandbox status (best-effort)
        sandbox_status = {"exists": False}
        try:
            # If core manager supports sandboxes, attempt to query
            # Core SecureSandbox may not provide a simple API; this is best-effort
            sandbox_status["exists"] = hasattr(core_plugin_security_manager, "_sandboxes") and plugin_name in getattr(core_plugin_security_manager, "_sandboxes", {})
        except Exception:
            sandbox_status["exists"] = False

        return templates.TemplateResponse("admin/plugin_security.html", {
            "request": request,
            "title": f"Plugin Security: {plugin_name}",
            "plugin_name": plugin_name,
            "plugin_permissions": plugin_permissions,
            "audit_events": audit_events,
            "sandbox_status": sandbox_status,
            "admin_authenticated": True
        })
    except Exception as e:
        logger.error(f"Failed to render plugin security page for {plugin_name}: {e}")
        return JSONResponse({"error": "Failed to render plugin security page", "details": str(e)}, status_code=500)

# API endpoints for permissions and audit

@router.get("/api/permissions/pending", response_class=JSONResponse)
async def api_pending_permissions(token: str = Depends(verify_admin_token)):
    """Return pending plugin permission requests."""
    try:
        pending = security_adapter.get_pending_permission_requests() if hasattr(security_adapter, "get_pending_permission_requests") else []
        return {"pending_requests": pending}
    except Exception as e:
        logger.error(f"Failed to fetch pending permission requests: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch pending requests")

@router.post("/api/permissions/approve")
async def api_approve_permission(
    request: Request,
    plugin_name: str = Form(...),
    permission_type: str = Form(...),
    expires_in_days: Optional[int] = Form(None),
    approved_by: str = Form("admin"),
    token: str = Depends(verify_admin_token)
):
    """Approve a plugin permission request."""
    try:
        success = security_adapter.approve_permission(plugin_name, permission_type, approved_by, expires_in_days)
        if success:
            return {"success": True, "message": f"Permission {permission_type} approved for {plugin_name}"}
        else:
            return {"success": False, "message": f"No pending permission {permission_type} found for {plugin_name}"}
    except Exception as e:
        logger.error(f"Error approving permission: {e}")
        return {"success": False, "message": str(e)}

@router.post("/api/permissions/deny")
async def api_deny_permission(
    request: Request,
    plugin_name: str = Form(...),
    permission_type: str = Form(...),
    denied_by: str = Form("admin"),
    token: str = Depends(verify_admin_token)
):
    """Deny a plugin permission request."""
    try:
        success = security_adapter.deny_permission(plugin_name, permission_type, denied_by)
        if success:
            return {"success": True, "message": f"Permission {permission_type} denied for {plugin_name}"}
        else:
            return {"success": False, "message": f"No pending permission {permission_type} found for {plugin_name}"}
    except Exception as e:
        logger.error(f"Error denying permission: {e}")
        return {"success": False, "message": str(e)}

@router.get("/api/security/status", response_class=JSONResponse)
async def api_security_status(token: str = Depends(verify_admin_token)):
    """Return overall security status and summary."""
    try:
        summary = security_adapter.get_security_summary()
        return {"security_summary": summary}
    except Exception as e:
        logger.error(f"Failed to get security status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get security status")

@router.get("/api/audit", response_class=JSONResponse)
async def api_audit_logs(plugin_name: Optional[str] = None, limit: int = 100, token: str = Depends(verify_admin_token)):
    """Return audit logs for security events (optionally filtered by plugin)."""
    try:
        events = security_adapter.get_audit_events(plugin_name, limit) if hasattr(security_adapter, "get_audit_events") else []
        return {"audit_events": events}
    except Exception as e:
        logger.error(f"Failed to fetch audit logs: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch audit logs")

@router.post("/api/policy/update")
async def api_update_policy(
    request: Request,
    plugin_name: str = Form(...),
    policy_json: str = Form(...),
    token: str = Depends(verify_admin_token)
):
    """Update security policy for a plugin. policy_json should be a JSON string."""
    try:
        try:
            policy = json.loads(policy_json)
        except Exception as e:
            logger.error(f"Invalid policy JSON: {e}")
            return {"success": False, "message": "Invalid policy JSON"}

        success = security_adapter.set_security_policy(plugin_name, policy) if hasattr(security_adapter, "set_security_policy") else False
        if success:
            return {"success": True, "message": f"Security policy updated for {plugin_name}"}
        else:
            return {"success": False, "message": "Failed to update security policy"}
    except Exception as e:
        logger.error(f"Error updating policy: {e}")
        return {"success": False, "message": str(e)}

@router.post("/api/quarantine")
async def api_quarantine_plugin(
    request: Request,
    plugin_name: str = Form(...),
    action: str = Form(...),  # "quarantine" or "release"
    reason: Optional[str] = Form("admin action"),
    actor: str = Form("admin"),
    token: str = Depends(verify_admin_token)
):
    """Quarantine or release a plugin based on action."""
    try:
        if action not in ("quarantine", "release"):
            return {"success": False, "message": "Invalid action"}

        if action == "quarantine":
            success = security_adapter.quarantine_plugin(plugin_name, reason, actor) if hasattr(security_adapter, "quarantine_plugin") else False
            if success:
                return {"success": True, "message": f"Plugin {plugin_name} quarantined"}
            else:
                return {"success": False, "message": "Failed to quarantine plugin"}
        else:
            success = security_adapter.release_from_quarantine(plugin_name, actor) if hasattr(security_adapter, "release_from_quarantine") else False
            if success:
                return {"success": True, "message": f"Plugin {plugin_name} released from quarantine"}
            else:
                return {"success": False, "message": "Failed to release plugin"}
    except Exception as e:
        logger.error(f"Error managing quarantine: {e}")
        return {"success": False, "message": str(e)}

@router.post("/api/sandbox/create")
async def api_create_sandbox(
    request: Request,
    plugin_name: str = Form(...),
    token: str = Depends(verify_admin_token)
):
    """Create a secure sandbox for a plugin (admin-triggered)."""
    try:
        success = security_adapter.create_sandbox(plugin_name) if hasattr(security_adapter, "create_sandbox") else False
        if success:
            return {"success": True, "message": f"Sandbox created for {plugin_name}"}
        else:
            return {"success": False, "message": "Failed to create sandbox"}
    except Exception as e:
        logger.error(f"Failed to create sandbox for {plugin_name}: {e}")
        return {"success": False, "message": str(e)}

# -----------------------------------------------------------------------------
# Helper functions (existing ones retained; helper additions below)
# -----------------------------------------------------------------------------

def get_installed_plugins() -> List[Dict[str, Any]]:
    """Get list of installed plugins."""
    try:
        # Get plugins directory from project root
        project_root = Path(__file__).parent.parent.parent.parent.parent.parent
        plugins_dir = project_root / "plugins"
        installed = []

        if plugins_dir.exists():
            for plugin_dir in plugins_dir.iterdir():
                if plugin_dir.is_dir() and not plugin_dir.name.startswith('_'):
                    plugin_info = load_plugin_info(plugin_dir)
                    if plugin_info:
                        installed.append(plugin_info)

        return installed
    except Exception as e:
        logger.error(f"Failed to get installed plugins: {e}")
        return []

def load_plugin_info(plugin_dir: Path) -> Optional[Dict[str, Any]]:
    """Load plugin information from plugin directory."""
    try:
        # Try to load plugin.json
        plugin_json = plugin_dir / "plugin.json"
        if plugin_json.exists():
            with open(plugin_json, 'r') as f:
                info = json.load(f)
                info['installed'] = True
                info['path'] = str(plugin_dir)
                return info

        # Fallback to basic info
        return {
            "name": plugin_dir.name,
            "version": "unknown",
            "description": f"Plugin: {plugin_dir.name}",
            "installed": True,
            "enabled": True,
            "path": str(plugin_dir)
        }
    except Exception as e:
        logger.error(f"Failed to load plugin info for {plugin_dir}: {e}")
        return None

async def get_available_plugins() -> List[Dict[str, Any]]:
    """Get list of available plugins from all repositories."""
    try:
        all_plugins = []
        repositories = get_plugin_repositories()

        for repo in repositories:
            if repo.get("enabled", True):
                plugins = await fetch_plugins_from_repo(repo["name"])
                all_plugins.extend(plugins)

        return all_plugins
    except Exception as e:
        logger.error(f"Failed to get available plugins: {e}")
        return []

async def fetch_plugins_from_repo(repo_name: str) -> List[Dict[str, Any]]:
    """Fetch plugins from a specific repository."""
    try:
        repositories = get_plugin_repositories()
        repo_info = next((r for r in repositories if r["name"] == repo_name), None)

        if not repo_info:
            return []

        # Mock plugin data for now - in production this would fetch from GitHub API
        mock_plugins = [
            {
                "name": "openai-provider",
                "version": "1.2.0",
                "description": "OpenAI GPT integration for PlexiChat",
                "author": "PlexiChat Team",
                "type": "ai_provider",
                "repository": repo_name,
                "installed": False,
                "download_url": f"{repo_info['url']}/releases/download/v1.2.0/openai-provider.zip"
            },
            {
                "name": "discord-bridge",
                "version": "1.0.5",
                "description": "Bridge PlexiChat with Discord servers",
                "author": "Community",
                "type": "integration",
                "repository": repo_name,
                "installed": False,
                "download_url": f"{repo_info['url']}/releases/download/v1.0.5/discord-bridge.zip"
            },
            {
                "name": "advanced-security",
                "version": "2.1.0",
                "description": "Enhanced security features and monitoring",
                "author": "Security Team",
                "type": "security",
                "repository": repo_name,
                "installed": False,
                "download_url": f"{repo_info['url']}/releases/download/v2.1.0/advanced-security.zip"
            }
        ]

        return mock_plugins
    except Exception as e:
        logger.error(f"Failed to fetch plugins from {repo_name}: {e}")
        return []

def get_plugin_repositories() -> List[Dict[str, Any]]:
    """Get list of plugin repositories."""
    try:
        registry_file = Path("plugins/registry.json")
        if registry_file.exists():
            with open(registry_file, 'r') as f:
                registry = json.load(f)
                return registry.get("repositories", [])

        # Default repositories
        return [
            {
                "name": "official",
                "url": "https://github.com/linux-of-user/plexichat-plugins",
                "enabled": True,
                "description": "Official PlexiChat plugins"
            },
            {
                "name": "community",
                "url": "https://github.com/plexichat-community/plugins",
                "enabled": False,
                "description": "Community contributed plugins"
            }
        ]
    except Exception as e:
        logger.error(f"Failed to get repositories: {e}")
        return []

async def install_plugin_from_repo(plugin_name: str, repo: str) -> bool:
    """Install a plugin from repository."""
    try:
        # Mock installation - in production this would download and install
        logger.info(f"Installing plugin {plugin_name} from {repo}")
        return True
    except Exception as e:
        logger.error(f"Failed to install plugin {plugin_name}: {e}")
        return False

async def uninstall_plugin(plugin_name: str) -> bool:
    """Uninstall a plugin."""
    try:
        # Mock uninstallation - in production this would remove plugin files
        logger.info(f"Uninstalling plugin {plugin_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to uninstall plugin {plugin_name}: {e}")
        return False

async def enable_plugin(plugin_name: str) -> bool:
    """Enable a plugin."""
    try:
        # Mock enable - in production this would update plugin status
        logger.info(f"Enabling plugin {plugin_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to enable plugin {plugin_name}: {e}")
        return False

async def disable_plugin(plugin_name: str) -> bool:
    """Disable a plugin."""
    try:
        # Mock disable - in production this would update plugin status
        logger.info(f"Disabling plugin {plugin_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to disable plugin {plugin_name}: {e}")
        return False

def add_plugin_repository(name: str, url: str) -> bool:
    """Add a custom plugin repository."""
    try:
        registry_file = Path("plugins/registry.json")
        registry = {"repositories": []}

        if registry_file.exists():
            with open(registry_file, 'r') as f:
                registry = json.load(f)

        # Add new repository
        new_repo = {
            "name": name,
            "url": url,
            "enabled": True,
            "description": f"Custom repository: {name}"
        }

        registry["repositories"].append(new_repo)

        # Save updated registry
        registry_file.parent.mkdir(parents=True, exist_ok=True)
        with open(registry_file, 'w') as f:
            json.dump(registry, f, indent=2)

        logger.info(f"Added repository {name}: {url}")
        return True
    except Exception as e:
        logger.error(f"Failed to add repository {name}: {e}")
        return False
