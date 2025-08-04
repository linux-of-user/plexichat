"""
PlexiChat Plugins Internal API - SINGLE SOURCE OF TRUTH

This file provides the internal API that existing plugins expect.
It bridges the gap between the old plugin system and the new unified system.

GENERATED AUTOMATICALLY - DO NOT EDIT MANUALLY
"""

import logging
from typing import Any, Dict, List, Optional, Callable
from abc import ABC, abstractmethod

try:
    from .unified_plugin_manager import (
        PluginInterface as UnifiedPluginInterface,
        PluginMetadata,
        PluginInfo,
        PluginType,
        SecurityLevel,
        PluginStatus,
        unified_plugin_manager
    )
    from .sdk import EnhancedPluginAPI, EnhancedPluginConfig, EnhancedBasePlugin
    from ..logging import get_logger
    from ..config.manager import get_config
    
    logger = get_logger(__name__)
    config = get_config()
except ImportError:
    logger = logging.getLogger(__name__)
    config = {}
    UnifiedPluginInterface = object
    PluginMetadata = object
    PluginInfo = object
    PluginType = None
    SecurityLevel = None
    PluginStatus = None
    unified_plugin_manager = None


class PluginInterface(ABC):
    """
    Legacy plugin interface for backward compatibility.
    
    This class provides the interface that existing plugins expect,
    while internally using the new unified plugin system.
    """
    
    def __init__(self, name: str, version: str = "1.0.0", description: str = ""):
        self.name = name
        self.version = version
        self.description = description
        self.logger = logging.getLogger(f"plugin.{name}")
        self._initialized = False
        self._api = None
        
        # Create enhanced config for internal use
        self._config = EnhancedPluginConfig(
            name=name,
            version=version,
            description=description,
            author="Unknown",
            plugin_type="feature",
            security_level="sandboxed"
        )
        
        # Initialize enhanced API
        try:
            self._api = EnhancedPluginAPI(name, self._config)
        except Exception as e:
            logger.error(f"Failed to initialize enhanced API for plugin {name}: {e}")
    
    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the plugin."""
        pass
    
    async def cleanup(self):
        """Cleanup plugin resources."""
        pass
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {}}
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "initialized": self._initialized
        }
    
    # Provide access to enhanced API features
    @property
    def api(self) -> Optional[EnhancedPluginAPI]:
        """Get access to enhanced plugin API."""
        return self._api
    
    async def cache_get(self, key: str) -> Optional[Any]:
        """Get value from cache (legacy wrapper)."""
        if self._api:
            return await self._api.cache_get(key)
        return None
    
    async def cache_set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache (legacy wrapper)."""
        if self._api:
            return await self._api.cache_set(key, value, ttl)
        return False
    
    async def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value (legacy wrapper)."""
        if self._api:
            return await self._api.get_config(key, default)
        return default
    
    async def set_config(self, key: str, value: Any) -> bool:
        """Set configuration value (legacy wrapper)."""
        if self._api:
            return await self._api.set_config(key, value)
        return False


class PluginManager:
    """
    Legacy plugin manager for backward compatibility.
    
    This class provides the interface that existing code expects,
    while internally using the new unified plugin system.
    """
    
    def __init__(self):
        self.plugins = {}
        self.logger = logging.getLogger("plugin_manager")
        self._unified_manager = unified_plugin_manager
    
    async def load_plugin(self, plugin_name: str) -> bool:
        """Load a plugin by name."""
        try:
            if self._unified_manager:
                return await self._unified_manager.load_plugin(plugin_name)
            return False
        except Exception as e:
            self.logger.error(f"Failed to load plugin {plugin_name}: {e}")
            return False
    
    async def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin by name."""
        try:
            if self._unified_manager:
                return await self._unified_manager.unload_plugin(plugin_name)
            return False
        except Exception as e:
            self.logger.error(f"Failed to unload plugin {plugin_name}: {e}")
            return False
    
    async def get_plugin(self, plugin_name: str) -> Optional[PluginInterface]:
        """Get a loaded plugin by name."""
        try:
            if self._unified_manager and plugin_name in self._unified_manager.loaded_plugins:
                return self._unified_manager.loaded_plugins[plugin_name]
            return None
        except Exception as e:
            self.logger.error(f"Failed to get plugin {plugin_name}: {e}")
            return None
    
    def get_all_plugins(self) -> Dict[str, PluginInterface]:
        """Get all loaded plugins."""
        try:
            if self._unified_manager:
                return self._unified_manager.loaded_plugins
            return {}}}
        except Exception as e:
            self.logger.error(f"Failed to get all plugins: {e}")
            return {}}}
    
    async def discover_plugins(self) -> List[str]:
        """Discover available plugins."""
        try:
            if self._unified_manager:
                await self._unified_manager.discover_plugins()
                return list(self._unified_manager.plugin_info.keys())
            return []
        except Exception as e:
            self.logger.error(f"Failed to discover plugins: {e}")
            return []
    
    async def reload_plugin(self, plugin_name: str) -> bool:
        """Reload a plugin."""
        try:
            if self._unified_manager:
                await self._unified_manager.unload_plugin(plugin_name)
                return await self._unified_manager.load_plugin(plugin_name, force_reload=True)
            return False
        except Exception as e:
            self.logger.error(f"Failed to reload plugin {plugin_name}: {e}")
            return False


# Create global instances for backward compatibility
plugin_manager = PluginManager()


# Legacy functions for backward compatibility
async def load_plugin(plugin_name: str) -> bool:
    """Load a plugin (legacy function)."""
    return await plugin_manager.load_plugin(plugin_name)


async def unload_plugin(plugin_name: str) -> bool:
    """Unload a plugin (legacy function)."""
    return await plugin_manager.unload_plugin(plugin_name)


async def get_plugin(plugin_name: str) -> Optional[PluginInterface]:
    """Get a plugin (legacy function)."""
    return await plugin_manager.get_plugin(plugin_name)


def get_all_plugins() -> Dict[str, PluginInterface]:
    """Get all plugins (legacy function)."""
    return plugin_manager.get_all_plugins()


async def discover_plugins() -> List[str]:
    """Discover plugins (legacy function)."""
    return await plugin_manager.discover_plugins()


async def reload_plugin(plugin_name: str) -> bool:
    """Reload a plugin (legacy function)."""
    return await plugin_manager.reload_plugin(plugin_name)


# Export all legacy interfaces
__all__ = [
    # Main classes
    "PluginInterface",
    "PluginManager",
    "plugin_manager",
    
    # Legacy functions
    "load_plugin",
    "unload_plugin", 
    "get_plugin",
    "get_all_plugins",
    "discover_plugins",
    "reload_plugin",
    
    # Data classes (for compatibility)
    "PluginMetadata",
    "PluginInfo",
    "PluginType",
    "SecurityLevel",
    "PluginStatus",
]
