"""PlexiChat Plugins"""

import logging
from typing import Any, Dict, List

try:
    from .plugin_manager import (
        PluginManager, PlexiChatPlugin, PluginInfo,
        plugin_manager, load_plugin, unload_plugin,
        enable_plugin, disable_plugin, emit_plugin_event, get_plugins
    )
    logger = logging.getLogger(__name__)
    logger.info("Plugin modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import plugin modules: {e}")

__all__ = [
    "PluginManager",
    "PlexiChatPlugin",
    "PluginInfo",
    "plugin_manager",
    "load_plugin",
    "unload_plugin",
    "enable_plugin",
    "disable_plugin",
    "emit_plugin_event",
    "get_plugins",
]

__version__ = "1.0.0"
