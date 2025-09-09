# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Core Plugin System - SINGLE SOURCE OF TRUTH

Consolidates ALL plugin management functionality from:
- core/plugins/plugin_manager.py - INTEGRATED
- infrastructure/modules/plugin_manager.py - INTEGRATED
- infrastructure/modules/enhanced_plugin_manager.py - INTEGRATED
- infrastructure/modules/plugin_test_manager.py - INTEGRATED

Provides a single, unified interface for all plugin operations.
"""

import warnings
from typing import Any, Dict, List, Optional

# Import unified plugin system (NEW SINGLE SOURCE OF TRUTH)
try:
    from plexichat.core.plugins.manager import (  # Main classes; Data classes; Main functions; Exceptions
        PluginError,
        PluginInfo,
        PluginInterface,
        PluginIsolationManager,
        PluginMetadata,
        PluginStatus,
        PluginTestManager,
        PluginType,
        SecurityLevel,
        UnifiedPluginManager,
        disable_plugin,
        discover_plugins,
        emit_event,
        enable_plugin,
        execute_command,
        get_all_plugins_info,
        get_plugin_info,
        get_plugin_manager,
        load_plugin,
        unified_plugin_manager,
        unload_plugin,
    )

    # Backward compatibility aliases
    plugin_manager = unified_plugin_manager
    PluginManager = UnifiedPluginManager

except ImportError as e:
    # Fallback definitions if unified plugin system fails to import
    import logging

    warnings.warn(
        f"Failed to import unified plugin system: {e}. Using fallback plugin system.",
        ImportWarning,
        stacklevel=2,
    )

    logger = logging.getLogger(__name__)

    class PluginType:
        CORE = "core"
        FEATURE = "feature"
        INTEGRATION = "integration"
        EXTENSION = "extension"

    class PluginStatus:
        UNKNOWN = "unknown"
        DISCOVERED = "discovered"
        LOADED = "loaded"
        ENABLED = "enabled"
        DISABLED = "disabled"
        ERROR = "error"

    class SecurityLevel:
        TRUSTED = "trusted"
        SANDBOXED = "sandboxed"
        RESTRICTED = "restricted"

    class PluginError(Exception):
        pass

    class PluginInterface:
        def __init__(self, plugin_id: str, config: Optional[Dict[str, Any]] = None):
            self.plugin_id = plugin_id
            self.config = config or {}

        async def initialize(self) -> bool:
            return True

        async def shutdown(self) -> bool:
            return True

    class UnifiedPluginManager:
        def __init__(self):
            self.plugins = {}

        async def initialize(self) -> bool:
            return True

        async def discover_plugins(self) -> List[str]:
            return []

        async def load_plugin(self, plugin_name: str) -> bool:
            return False

        async def unload_plugin(self, plugin_name: str) -> bool:
            return False

        def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
            return None

        async def shutdown(self) -> None:
            pass

    unified_plugin_manager = UnifiedPluginManager()
    plugin_manager = unified_plugin_manager
    PluginManager = UnifiedPluginManager

    async def get_plugin_manager():
        return unified_plugin_manager

    async def discover_plugins():
        return []

    async def load_plugin(plugin_name: str):
        return False

    async def unload_plugin(plugin_name: str):
        return False

    async def enable_plugin(plugin_name: str):
        return False

    async def disable_plugin(plugin_name: str):
        return False

    def get_plugin_info(plugin_name: str):
        return None

    def get_all_plugins_info():
        return {}

    async def execute_command(command_name: str, *args, **kwargs):
        raise PluginError("Plugin system not available")

    async def emit_event(event_name: str, *args, **kwargs):
        return []

    # Fallback classes
    class PluginMetadata:
        pass

    class PluginInfo:
        pass

    class PluginIsolationManager:
        pass

    class PluginTestManager:
        pass


# Legacy initialization function for backward compatibility
async def initialize_plugin_system() -> bool:
    """Initialize the plugin system (backward compatibility)."""
    try:
        return await unified_plugin_manager.initialize()
    except Exception as e:
        import logging

        logger = logging.getLogger(__name__)
        logger.error(f"Failed to initialize plugin system: {e}")
        return False


async def get_plugin_manager_instance():
    """Get the plugin manager instance (backward compatibility)."""
    return unified_plugin_manager


# Legacy aliases for backward compatibility
PlexiChatPlugin = PluginInterface
emit_plugin_event = emit_event


def get_plugins():
    """Get all plugins info (backward compatibility)."""
    return get_all_plugins_info()


# Export all the main classes and functions
__all__ = [
    # Unified plugin system (NEW SINGLE SOURCE OF TRUTH)
    "UnifiedPluginManager",
    "unified_plugin_manager",
    "PluginInterface",
    "PluginIsolationManager",
    "PluginTestManager",
    # Data classes
    "PluginMetadata",
    "PluginInfo",
    "PluginType",
    "PluginStatus",
    "SecurityLevel",
    # Main functions
    "get_plugin_manager",
    "discover_plugins",
    "load_plugin",
    "unload_plugin",
    "enable_plugin",
    "disable_plugin",
    "get_plugin_info",
    "get_all_plugins_info",
    "execute_command",
    "emit_event",
    # Backward compatibility aliases
    "plugin_manager",
    "PluginManager",
    "PlexiChatPlugin",
    "emit_plugin_event",
    "get_plugins",
    # Legacy functions
    "initialize_plugin_system",
    "get_plugin_manager_instance",
    # Exceptions
    "PluginError",
]

from plexichat.core.config_manager import get_config

__version__ = get_config("system.version", "0.0.0")
