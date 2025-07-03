"""
Plugin Dashboard Web Interface for NetLink
Provides comprehensive plugin management through web interface.
"""

from typing import Dict, List, Any, Optional
from fastapi import APIRouter, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import json

from netlink.app.plugins.enhanced_plugin_manager import get_enhanced_plugin_manager, PluginSource
from netlink.app.logger_config import logger

router = APIRouter(prefix="/ui/plugins", tags=["Plugin Dashboard"])
templates = Jinja2Templates(directory="src/netlink/app/webui/templates")

@router.get("/", response_class=HTMLResponse)
async def plugin_dashboard(request: Request):
    """Main plugin dashboard page."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        dashboard_data = plugin_manager.get_plugin_dashboard_data()
        
        return templates.TemplateResponse("plugin_dashboard.html", {
            "request": request,
            "dashboard_data": dashboard_data,
            "page_title": "Plugin Dashboard"
        })
        
    except Exception as e:
        logger.error(f"Failed to load plugin dashboard: {e}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e),
            "page_title": "Plugin Dashboard Error"
        })

@router.get("/install", response_class=HTMLResponse)
async def plugin_install_page(request: Request):
    """Plugin installation page."""
    return templates.TemplateResponse("plugin_install.html", {
        "request": request,
        "page_title": "Install Plugin",
        "sources": [source.value for source in PluginSource]
    })

@router.post("/install")
async def install_plugin_web(
    request: Request,
    file: UploadFile = File(...),
    source: str = Form(default="local"),
    auto_enable: bool = Form(default=True)
):
    """Handle plugin installation from web interface."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        
        # Validate file
        if not file.filename.lower().endswith('.zip'):
            return templates.TemplateResponse("plugin_install.html", {
                "request": request,
                "error": "Only ZIP files are supported",
                "page_title": "Install Plugin",
                "sources": [source.value for source in PluginSource]
            })
        
        # Save uploaded file temporarily
        import tempfile
        from pathlib import Path
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_path = Path(temp_file.name)
        
        try:
            plugin_source = PluginSource(source.lower())
        except ValueError:
            plugin_source = PluginSource.LOCAL
        
        # Install plugin
        result = await plugin_manager.install_plugin_from_zip(temp_path, plugin_source)
        
        # Clean up
        temp_path.unlink(missing_ok=True)
        
        if result["success"]:
            # Auto-enable if requested
            if auto_enable and "plugin_name" in result:
                plugin_manager.enable_plugin(result["plugin_name"])
            
            return RedirectResponse(url="/ui/plugins/?success=installed", status_code=303)
        else:
            return templates.TemplateResponse("plugin_install.html", {
                "request": request,
                "error": result["error"],
                "page_title": "Install Plugin",
                "sources": [source.value for source in PluginSource]
            })
        
    except Exception as e:
        logger.error(f"Failed to install plugin via web: {e}")
        return templates.TemplateResponse("plugin_install.html", {
            "request": request,
            "error": str(e),
            "page_title": "Install Plugin",
            "sources": [source.value for source in PluginSource]
        })

@router.get("/plugin/{plugin_name}", response_class=HTMLResponse)
async def plugin_details(request: Request, plugin_name: str):
    """Plugin details page."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        dashboard_data = plugin_manager.get_plugin_dashboard_data()
        
        # Find plugin
        plugin_data = None
        for plugin in dashboard_data.get("plugins", []):
            if plugin["name"] == plugin_name:
                plugin_data = plugin
                break
        
        if not plugin_data:
            return templates.TemplateResponse("error.html", {
                "request": request,
                "error": f"Plugin '{plugin_name}' not found",
                "page_title": "Plugin Not Found"
            })
        
        # Add additional information
        plugin_data["is_loaded"] = plugin_name in plugin_manager.loaded_plugins
        plugin_data["metadata"] = plugin_manager.plugin_metadata.get(plugin_name, {})
        
        if plugin_name in plugin_manager.loaded_plugins:
            plugin_instance = plugin_manager.loaded_plugins[plugin_name]
            plugin_data["api_endpoints"] = plugin_instance.get_api_endpoints()
            if hasattr(plugin_instance, 'get_cli_commands'):
                plugin_data["cli_commands"] = plugin_instance.get_cli_commands()
        
        return templates.TemplateResponse("plugin_details.html", {
            "request": request,
            "plugin": plugin_data,
            "page_title": f"Plugin: {plugin_name}"
        })
        
    except Exception as e:
        logger.error(f"Failed to load plugin details: {e}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e),
            "page_title": "Plugin Details Error"
        })

@router.post("/plugin/{plugin_name}/enable")
async def enable_plugin_web(plugin_name: str):
    """Enable plugin via web interface."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        success = plugin_manager.enable_plugin(plugin_name)
        
        if success:
            return RedirectResponse(url=f"/ui/plugins/plugin/{plugin_name}?success=enabled", status_code=303)
        else:
            return RedirectResponse(url=f"/ui/plugins/plugin/{plugin_name}?error=enable_failed", status_code=303)
        
    except Exception as e:
        logger.error(f"Failed to enable plugin {plugin_name}: {e}")
        return RedirectResponse(url=f"/ui/plugins/plugin/{plugin_name}?error={str(e)}", status_code=303)

@router.post("/plugin/{plugin_name}/disable")
async def disable_plugin_web(plugin_name: str):
    """Disable plugin via web interface."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        success = plugin_manager.disable_plugin(plugin_name)
        
        if success:
            return RedirectResponse(url=f"/ui/plugins/plugin/{plugin_name}?success=disabled", status_code=303)
        else:
            return RedirectResponse(url=f"/ui/plugins/plugin/{plugin_name}?error=disable_failed", status_code=303)
        
    except Exception as e:
        logger.error(f"Failed to disable plugin {plugin_name}: {e}")
        return RedirectResponse(url=f"/ui/plugins/plugin/{plugin_name}?error={str(e)}", status_code=303)

@router.post("/plugin/{plugin_name}/uninstall")
async def uninstall_plugin_web(plugin_name: str, remove_data: bool = Form(default=False)):
    """Uninstall plugin via web interface."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        result = await plugin_manager.uninstall_plugin(plugin_name, remove_data)
        
        if result["success"]:
            return RedirectResponse(url="/ui/plugins/?success=uninstalled", status_code=303)
        else:
            return RedirectResponse(url=f"/ui/plugins/plugin/{plugin_name}?error={result['error']}", status_code=303)
        
    except Exception as e:
        logger.error(f"Failed to uninstall plugin {plugin_name}: {e}")
        return RedirectResponse(url=f"/ui/plugins/plugin/{plugin_name}?error={str(e)}", status_code=303)

@router.post("/plugin/{plugin_name}/update")
async def update_plugin_web(plugin_name: str):
    """Update plugin via web interface."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        result = await plugin_manager.update_plugin(plugin_name)
        
        if result["success"]:
            return RedirectResponse(url=f"/ui/plugins/plugin/{plugin_name}?success=updated", status_code=303)
        else:
            return RedirectResponse(url=f"/ui/plugins/plugin/{plugin_name}?error={result['error']}", status_code=303)
        
    except Exception as e:
        logger.error(f"Failed to update plugin {plugin_name}: {e}")
        return RedirectResponse(url=f"/ui/plugins/plugin/{plugin_name}?error={str(e)}", status_code=303)

@router.get("/security", response_class=HTMLResponse)
async def security_overview(request: Request):
    """Plugin security overview page."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        dashboard_data = plugin_manager.get_plugin_dashboard_data()
        
        # Extract security information
        security_data = {
            "overview": dashboard_data.get("security_overview", {}),
            "high_risk_plugins": [],
            "quarantined_plugins": [],
            "unsigned_plugins": [],
            "outdated_scans": []
        }
        
        for plugin in dashboard_data.get("plugins", []):
            security = plugin.get("security", {})
            
            if security.get("risk_level") in ["high", "critical"]:
                security_data["high_risk_plugins"].append(plugin)
            
            if plugin["status"] == "quarantined":
                security_data["quarantined_plugins"].append(plugin)
            
            if not security.get("signature_valid", True):
                security_data["unsigned_plugins"].append(plugin)
            
            if security.get("scan_date"):
                from datetime import datetime
                scan_date = datetime.fromisoformat(security["scan_date"])
                if (datetime.now() - scan_date).days > 30:
                    security_data["outdated_scans"].append(plugin)
        
        return templates.TemplateResponse("plugin_security.html", {
            "request": request,
            "security_data": security_data,
            "page_title": "Plugin Security"
        })
        
    except Exception as e:
        logger.error(f"Failed to load security overview: {e}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e),
            "page_title": "Security Overview Error"
        })

@router.post("/security/scan/{plugin_name}")
async def rescan_plugin_web(plugin_name: str):
    """Re-scan plugin security via web interface."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        result = await plugin_manager.rescan_plugin_security(plugin_name)
        
        if result["success"]:
            return RedirectResponse(url="/ui/plugins/security?success=scanned", status_code=303)
        else:
            return RedirectResponse(url=f"/ui/plugins/security?error={result['error']}", status_code=303)
        
    except Exception as e:
        logger.error(f"Failed to rescan plugin {plugin_name}: {e}")
        return RedirectResponse(url=f"/ui/plugins/security?error={str(e)}", status_code=303)

@router.post("/updates/check")
async def check_updates_web():
    """Check for plugin updates via web interface."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        result = await plugin_manager.check_for_updates()
        
        if result["success"]:
            return RedirectResponse(url="/ui/plugins/?success=updates_checked", status_code=303)
        else:
            return RedirectResponse(url=f"/ui/plugins/?error={result['error']}", status_code=303)
        
    except Exception as e:
        logger.error(f"Failed to check updates: {e}")
        return RedirectResponse(url=f"/ui/plugins/?error={str(e)}", status_code=303)

@router.post("/updates/auto-run")
async def run_auto_updates_web():
    """Run auto-updates via web interface."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        result = await plugin_manager.auto_update_plugins()
        
        if result["success"]:
            return RedirectResponse(url="/ui/plugins/?success=auto_updated", status_code=303)
        else:
            return RedirectResponse(url=f"/ui/plugins/?error={result['error']}", status_code=303)
        
    except Exception as e:
        logger.error(f"Failed to run auto-updates: {e}")
        return RedirectResponse(url=f"/ui/plugins/?error={str(e)}", status_code=303)
