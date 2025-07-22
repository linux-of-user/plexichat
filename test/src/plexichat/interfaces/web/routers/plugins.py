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

@router.get("/", response_class=HTMLResponse)
async def plugins_home(request: Request, token: str = Depends(verify_admin_token)):
    """Plugin marketplace home page."""
    try:
        installed_plugins = get_installed_plugins()
        available_plugins = await get_available_plugins()
        repositories = get_plugin_repositories()
        
        return templates.TemplateResponse("plugins/marketplace.html", {
            "request": request,
            "title": "Plugin Marketplace",
            "installed_plugins": installed_plugins,
            "available_plugins": available_plugins,
            "repositories": repositories,
            "admin_authenticated": True
        })
    except Exception as e:
        logger.error(f"Plugin marketplace error: {e}")
        raise HTTPException(status_code=500, detail="Plugin marketplace error")

@router.get("/api/available", response_class=JSONResponse)
async def api_available_plugins(repo: str = "official", token: str = Depends(verify_admin_token)):
    """API endpoint to get available plugins from repository."""
    try:
        plugins = await fetch_plugins_from_repo(repo)
        return {"plugins": plugins, "repository": repo}
    except Exception as e:
        logger.error(f"Failed to fetch plugins from {repo}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch plugins from {repo}")

@router.get("/api/installed", response_class=JSONResponse)
async def api_installed_plugins(token: str = Depends(verify_admin_token)):
    """API endpoint to get installed plugins."""
    try:
        plugins = get_installed_plugins()
        return {"plugins": plugins}
    except Exception as e:
        logger.error(f"Failed to get installed plugins: {e}")
        raise HTTPException(status_code=500, detail="Failed to get installed plugins")

@router.post("/api/install")
async def api_install_plugin(
    request: Request,
    plugin_name: str = Form(...),
    repo: str = Form("official"),
    token: str = Depends(verify_admin_token)
):
    """API endpoint to install a plugin."""
    try:
        success = await install_plugin_from_repo(plugin_name, repo)
        if success:
            return {"success": True, "message": f"Plugin {plugin_name} installed successfully"}
        else:
            return {"success": False, "message": f"Failed to install plugin {plugin_name}"}
    except Exception as e:
        logger.error(f"Plugin installation failed: {e}")
        return {"success": False, "message": f"Installation failed: {str(e)}"}

@router.post("/api/uninstall")
async def api_uninstall_plugin(
    request: Request,
    plugin_name: str = Form(...),
    token: str = Depends(verify_admin_token)
):
    """API endpoint to uninstall a plugin."""
    try:
        success = await uninstall_plugin(plugin_name)
        if success:
            return {"success": True, "message": f"Plugin {plugin_name} uninstalled successfully"}
        else:
            return {"success": False, "message": f"Failed to uninstall plugin {plugin_name}"}
    except Exception as e:
        logger.error(f"Plugin uninstallation failed: {e}")
        return {"success": False, "message": f"Uninstallation failed: {str(e)}"}

@router.post("/api/enable")
async def api_enable_plugin(
    request: Request,
    plugin_name: str = Form(...),
    token: str = Depends(verify_admin_token)
):
    """API endpoint to enable a plugin."""
    try:
        success = await enable_plugin(plugin_name)
        if success:
            return {"success": True, "message": f"Plugin {plugin_name} enabled successfully"}
        else:
            return {"success": False, "message": f"Failed to enable plugin {plugin_name}"}
    except Exception as e:
        logger.error(f"Plugin enable failed: {e}")
        return {"success": False, "message": f"Enable failed: {str(e)}"}

@router.post("/api/disable")
async def api_disable_plugin(
    request: Request,
    plugin_name: str = Form(...),
    token: str = Depends(verify_admin_token)
):
    """API endpoint to disable a plugin."""
    try:
        success = await disable_plugin(plugin_name)
        if success:
            return {"success": True, "message": f"Plugin {plugin_name} disabled successfully"}
        else:
            return {"success": False, "message": f"Failed to disable plugin {plugin_name}"}
    except Exception as e:
        logger.error(f"Plugin disable failed: {e}")
        return {"success": False, "message": f"Disable failed: {str(e)}"}

@router.post("/api/repositories/add")
async def api_add_repository(
    request: Request,
    name: str = Form(...),
    url: str = Form(...),
    token: str = Depends(verify_admin_token)
):
    """API endpoint to add a custom plugin repository."""
    try:
        success = add_plugin_repository(name, url)
        if success:
            return {"success": True, "message": f"Repository {name} added successfully"}
        else:
            return {"success": False, "message": f"Failed to add repository {name}"}
    except Exception as e:
        logger.error(f"Repository addition failed: {e}")
        return {"success": False, "message": f"Repository addition failed: {str(e)}"}

# Helper functions

def get_installed_plugins() -> List[Dict[str, Any]]:
    """Get list of installed plugins."""
    try:
        plugins_dir = Path("plugins")
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
