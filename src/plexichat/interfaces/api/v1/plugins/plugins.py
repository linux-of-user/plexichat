import logging

import json
from typing import Any, Dict


from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from plexichat.app.logger_config import logger
from plexichat.app.plugins.plugin_manager import get_plugin_manager

"""
Plugin Management API endpoints for PlexiChat.
Provides comprehensive plugin management and monitoring capabilities.
"""


# Pydantic models for API
class PluginActionRequest(BaseModel, Optional):
    plugin_name: str


class PluginConfigRequest(BaseModel):
    plugin_name: str
    config: Dict[str, Any]


router = APIRouter(prefix="/api/v1/plugins", tags=["Plugin Management"])


@router.get("/")
async def list_plugins():
    """Get list of all available plugins."""
    try:
        plugin_manager = get_plugin_manager()

        # Get discovered plugins
        discovered = plugin_manager.discover_plugins()

        # Get loaded plugins info
        loaded_plugins = plugin_manager.get_loaded_plugins()

        plugins_list = []
        for plugin_name in discovered:
            if plugin_name in loaded_plugins:
                plugin_info = loaded_plugins[plugin_name]
                plugin_info["status"] = "loaded"
            else:
                # Get basic info from config file
                try:
                    config_file = (
                        plugin_manager.plugins_dir / plugin_name / "plugin.json"
                    )
                    if config_file.exists():
                        with open(config_file, "r") as f:
                            config = json.load(f)

                        plugin_info = {
                            "metadata": {
                                "name": config.get("name", plugin_name),
                                "version": config.get("version", "unknown"),
                                "description": config.get(
                                    "description", "No description"
                                ),
                                "author": config.get("author", "Unknown"),
                                "enabled": config.get("enabled", True),
                            },
                            "config": config,
                            "status": "discovered",
                        }
                    else:
                        plugin_info = {
                            "metadata": {
                                "name": plugin_name,
                                "version": "unknown",
                                "description": "No configuration found",
                                "author": "Unknown",
                                "enabled": False,
                            },
                            "status": "invalid",
                        }
                except Exception as e:
                    plugin_info = {
                        "metadata": {
                            "name": plugin_name,
                            "version": "unknown",
                            "description": f"Error reading config: {e}",
                            "author": "Unknown",
                            "enabled": False,
                        },
                        "status": "error",
                    }

            plugin_info["name"] = plugin_name
            plugins_list.append(plugin_info)

        return {
            "success": True,
            "plugins": plugins_list,
            "total_count": len(plugins_list),
        }

    except Exception as e:
        logger.error(f"Failed to list plugins: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/loaded")
async def get_loaded_plugins():
    """Get information about loaded plugins."""
    try:
        plugin_manager = get_plugin_manager()
        loaded_plugins = plugin_manager.get_loaded_plugins()

        return {
            "success": True,
            "loaded_plugins": loaded_plugins,
            "count": len(loaded_plugins),
        }

    except Exception as e:
        logger.error(f"Failed to get loaded plugins: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
async def get_plugin_statistics():
    """Get plugin system statistics."""
    try:
        plugin_manager = get_plugin_manager()
        stats = plugin_manager.get_plugin_statistics()

        return {"success": True, "statistics": stats}

    except Exception as e:
        logger.error(f"Failed to get plugin statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/load")
async def load_plugin(request: PluginActionRequest):
    """Load a specific plugin."""
    try:
        plugin_manager = get_plugin_manager()
        success = plugin_manager.load_plugin(request.plugin_name)

        if success:
            return {
                "success": True,
                "message": f"Plugin '{request.plugin_name}' loaded successfully",
            }
        else:
            raise HTTPException(
                status_code=400, detail=f"Failed to load plugin '{request.plugin_name}'"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to load plugin {request.plugin_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/unload")
async def unload_plugin(request: PluginActionRequest):
    """Unload a specific plugin."""
    try:
        plugin_manager = get_plugin_manager()
        success = plugin_manager.unload_plugin(request.plugin_name)

        if success:
            return {
                "success": True,
                "message": f"Plugin '{request.plugin_name}' unloaded successfully",
            }
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to unload plugin '{request.plugin_name}'",
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to unload plugin {request.plugin_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reload")
async def reload_plugin(request: PluginActionRequest):
    """Reload a specific plugin."""
    try:
        plugin_manager = get_plugin_manager()
        success = plugin_manager.reload_plugin(request.plugin_name)

        if success:
            return {
                "success": True,
                "message": f"Plugin '{request.plugin_name}' reloaded successfully",
            }
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to reload plugin '{request.plugin_name}'",
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to reload plugin {request.plugin_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/enable")
async def enable_plugin(request: PluginActionRequest):
    """Enable a specific plugin."""
    try:
        plugin_manager = get_plugin_manager()
        success = plugin_manager.enable_plugin(request.plugin_name)

        if success:
            return {
                "success": True,
                "message": f"Plugin '{request.plugin_name}' enabled successfully",
            }
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to enable plugin '{request.plugin_name}'",
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to enable plugin {request.plugin_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/disable")
async def disable_plugin(request: PluginActionRequest):
    """Disable a specific plugin."""
    try:
        plugin_manager = get_plugin_manager()
        success = plugin_manager.disable_plugin(request.plugin_name)

        if success:
            return {
                "success": True,
                "message": f"Plugin '{request.plugin_name}' disabled successfully",
            }
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to disable plugin '{request.plugin_name}'",
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to disable plugin {request.plugin_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/load_all")
async def load_all_plugins(background_tasks: BackgroundTasks):
    """Load all available plugins."""
    try:
        plugin_manager = get_plugin_manager()

        # Load plugins in background
        background_tasks.add_task(plugin_manager.load_all_plugins)

        return {"success": True, "message": "Loading all plugins in background"}

    except Exception as e:
        logger.error(f"Failed to start loading all plugins: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/discover")
async def discover_plugins():
    """Discover all available plugins."""
    try:
        plugin_manager = get_plugin_manager()
        discovered = plugin_manager.discover_plugins()

        return {
            "success": True,
            "discovered_plugins": discovered,
            "count": len(discovered),
        }

    except Exception as e:
        logger.error(f"Failed to discover plugins: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{plugin_name}")
async def get_plugin_info(plugin_name: str):
    """Get detailed information about a specific plugin."""
    try:
        plugin_manager = get_plugin_manager()
        loaded_plugins = plugin_manager.get_loaded_plugins()

        if plugin_name in loaded_plugins:
            plugin_info = loaded_plugins[plugin_name]
            plugin_info["status"] = "loaded"

            return {"success": True, "plugin": plugin_info}
        else:
            # Check if plugin exists but is not loaded
            discovered = plugin_manager.discover_plugins()
            if plugin_name in discovered:
                return {
                    "success": True,
                    "plugin": {
                        "name": plugin_name,
                        "status": "discovered_not_loaded",
                        "message": "Plugin discovered but not loaded",
                    },
                }
            else:
                raise HTTPException(
                    status_code=404, detail=f"Plugin '{plugin_name}' not found"
                )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get plugin info for {plugin_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{plugin_name}/endpoints")
async def get_plugin_endpoints(plugin_name: str):
    """Get API endpoints provided by a specific plugin."""
    try:
        plugin_manager = get_plugin_manager()

        if plugin_name not in plugin_manager.loaded_plugins:
            raise HTTPException(
                status_code=404, detail=f"Plugin '{plugin_name}' not loaded"
            )

        plugin = plugin_manager.loaded_plugins[plugin_name]
        endpoints = plugin.get_api_endpoints()

        return {
            "success": True,
            "plugin_name": plugin_name,
            "endpoints": endpoints,
            "count": len(endpoints),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get plugin endpoints for {plugin_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{plugin_name}/commands")
async def get_plugin_commands(plugin_name: str):
    """Get CLI commands provided by a specific plugin."""
    try:
        plugin_manager = get_plugin_manager()

        if plugin_name not in plugin_manager.loaded_plugins:
            raise HTTPException(
                status_code=404, detail=f"Plugin '{plugin_name}' not loaded"
            )

        plugin = plugin_manager.loaded_plugins[plugin_name]
        commands = plugin.get_cli_commands()

        return {
            "success": True,
            "plugin_name": plugin_name,
            "commands": commands,
            "count": len(commands),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get plugin commands for {plugin_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
