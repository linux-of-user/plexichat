"""
Enhanced Plugin Management API endpoints for PlexiChat.
Provides comprehensive plugin management with zip installation, security scanning,
auto-updates, and dashboard functionality.
"""

import tempfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from plexichat.app.logger_config import logger
from plexichat.app.plugins.enhanced_plugin_manager import (
    PluginSource,
    PluginStatus,
    get_enhanced_plugin_manager,
)


# Pydantic models for API
class PluginInstallRequest(BaseModel):
    source: PluginSource = PluginSource.LOCAL
    auto_enable: bool = True

class PluginUpdateRequest(BaseModel):
    plugin_name: str
    auto_update: bool = False

class PluginAutoUpdateRequest(BaseModel):
    plugin_name: str
    enabled: bool

class PluginUninstallRequest(BaseModel):
    plugin_name: str
    remove_data: bool = False

class PluginSecurityScanRequest(BaseModel):
    plugin_name: str

router = APIRouter(prefix="/api/v1/plugins/enhanced", tags=["Enhanced Plugin Management"])

@router.get("/dashboard")
async def get_plugin_dashboard():
    """Get comprehensive plugin dashboard data."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        dashboard_data = plugin_manager.get_plugin_dashboard_data()
        
        return {
            "success": True,
            "data": dashboard_data
        }
        
    except Exception as e:
        logger.error(f"Failed to get plugin dashboard: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/install")
async def install_plugin_from_zip(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    source: str = Form(default="local"),
    auto_enable: bool = Form(default=True)
):
    """Install plugin from uploaded ZIP file."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        
        # Validate file type
        if not file.filename.lower().endswith('.zip'):
            raise HTTPException(status_code=400, detail="Only ZIP files are supported")
        
        # Save uploaded file to temporary location
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_path = Path(temp_file.name)
        
        try:
            # Parse source
            plugin_source = PluginSource(source.lower())
        except ValueError:
            plugin_source = PluginSource.LOCAL
        
        # Install plugin
        result = await plugin_manager.install_plugin_from_zip(temp_path, plugin_source)
        
        # Clean up temp file
        temp_path.unlink(missing_ok=True)
        
        if result["success"]:
            # Auto-enable if requested
            if auto_enable and "plugin_name" in result:
                enable_result = plugin_manager.enable_plugin(result["plugin_name"])
                if enable_result:
                    result["auto_enabled"] = True
                else:
                    result["auto_enabled"] = False
                    result["enable_warning"] = "Plugin installed but failed to auto-enable"
            
            return {
                "success": True,
                "data": result
            }
        else:
            raise HTTPException(status_code=400, detail=result["error"])
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to install plugin: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/uninstall")
async def uninstall_plugin(request: PluginUninstallRequest):
    """Uninstall plugin with optional data removal."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        result = await plugin_manager.uninstall_plugin(request.plugin_name, request.remove_data)
        
        if result["success"]:
            return {
                "success": True,
                "data": result
            }
        else:
            raise HTTPException(status_code=400, detail=result["error"])
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to uninstall plugin: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/updates")
async def check_plugin_updates(plugin_name: Optional[str] = None):
    """Check for plugin updates."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        result = await plugin_manager.check_for_updates(plugin_name)
        
        if result["success"]:
            return {
                "success": True,
                "data": result
            }
        else:
            raise HTTPException(status_code=400, detail=result["error"])
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to check for updates: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/update")
async def update_plugin(request: PluginUpdateRequest, background_tasks: BackgroundTasks):
    """Update plugin to latest version."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        
        # Run update in background for large plugins
        background_tasks.add_task(
            plugin_manager.update_plugin,
            request.plugin_name,
            request.auto_update
        )
        
        return {
            "success": True,
            "message": f"Plugin '{request.plugin_name}' update started in background"
        }
        
    except Exception as e:
        logger.error(f"Failed to start plugin update: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/auto-update")
async def set_plugin_auto_update(request: PluginAutoUpdateRequest):
    """Enable or disable auto-update for a plugin."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        result = plugin_manager.set_plugin_auto_update(request.plugin_name, request.enabled)
        
        if result["success"]:
            return {
                "success": True,
                "data": result
            }
        else:
            raise HTTPException(status_code=400, detail=result["error"])
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to set auto-update: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/auto-update/run")
async def run_auto_updates(background_tasks: BackgroundTasks):
    """Run auto-updates for all eligible plugins."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        
        # Run auto-updates in background
        background_tasks.add_task(plugin_manager.auto_update_plugins)
        
        return {
            "success": True,
            "message": "Auto-update process started in background"
        }
        
    except Exception as e:
        logger.error(f"Failed to start auto-updates: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/security/scan")
async def rescan_plugin_security(request: PluginSecurityScanRequest):
    """Re-scan plugin for security issues."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        result = await plugin_manager.rescan_plugin_security(request.plugin_name)
        
        if result["success"]:
            return {
                "success": True,
                "data": result
            }
        else:
            raise HTTPException(status_code=400, detail=result["error"])
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to rescan plugin security: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/security/overview")
async def get_security_overview():
    """Get security overview of all plugins."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        dashboard_data = plugin_manager.get_plugin_dashboard_data()
        
        security_data = {
            "overview": dashboard_data.get("security_overview", {}),
            "high_risk_plugins": [],
            "quarantined_plugins": [],
            "unsigned_plugins": []
        }
        
        # Extract security details
        for plugin in dashboard_data.get("plugins", []):
            security = plugin.get("security", {})
            
            if security.get("risk_level") in ["high", "critical"]:
                security_data["high_risk_plugins"].append({
                    "name": plugin["name"],
                    "risk_level": security["risk_level"],
                    "reason": security.get("quarantine_reason")
                })
            
            if plugin["status"] == "quarantined":
                security_data["quarantined_plugins"].append({
                    "name": plugin["name"],
                    "reason": security.get("quarantine_reason"),
                    "scan_date": security.get("scan_date")
                })
            
            if not security.get("signature_valid", True):
                security_data["unsigned_plugins"].append({
                    "name": plugin["name"],
                    "source": plugin["source"]
                })
        
        return {
            "success": True,
            "data": security_data
        }
        
    except Exception as e:
        logger.error(f"Failed to get security overview: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/quarantine/cleanup")
async def cleanup_quarantine(days_old: int = 30):
    """Clean up old quarantined plugins."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        result = await plugin_manager.cleanup_quarantine(days_old)
        
        if result["success"]:
            return {
                "success": True,
                "data": result
            }
        else:
            raise HTTPException(status_code=400, detail=result["error"])
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cleanup quarantine: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status/{plugin_name}")
async def get_plugin_status(plugin_name: str):
    """Get detailed status of a specific plugin."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        dashboard_data = plugin_manager.get_plugin_dashboard_data()
        
        # Find plugin in dashboard data
        plugin_data = None
        for plugin in dashboard_data.get("plugins", []):
            if plugin["name"] == plugin_name:
                plugin_data = plugin
                break
        
        if not plugin_data:
            raise HTTPException(status_code=404, detail=f"Plugin '{plugin_name}' not found")
        
        # Add additional status information
        plugin_data["is_loaded"] = plugin_name in plugin_manager.loaded_plugins
        plugin_data["is_enabled"] = plugin_manager.plugin_status.get(plugin_name) == PluginStatus.ENABLED
        
        if plugin_name in plugin_manager.loaded_plugins:
            plugin_instance = plugin_manager.loaded_plugins[plugin_name]
            plugin_data["api_endpoints"] = plugin_instance.get_api_endpoints()
            if hasattr(plugin_instance, 'get_cli_commands'):
                plugin_data["cli_commands"] = plugin_instance.get_cli_commands()
        
        return {
            "success": True,
            "data": plugin_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get plugin status: {e}")
        raise HTTPException(status_code=500, detail=str(e))
