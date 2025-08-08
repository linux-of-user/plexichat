"""
Legacy plugin system for PlexiChat.

This module provides backward compatibility for existing plugins
while internally using the new unified plugin system.
"""

import logging
from typing import Any, Dict, List, Optional, Callable
from abc import ABC, abstractmethod

# Try to import components individually to handle missing modules gracefully
try:
    from .unified_plugin_manager import unified_plugin_manager
except ImportError:
    unified_plugin_manager = None

try:
    from .sdk import EnhancedPluginAPI, EnhancedPluginConfig
except ImportError:
    EnhancedPluginAPI = None
    EnhancedPluginConfig = None

try:
    from ..logging import get_logger
    logger = get_logger(__name__)
except ImportError:
    logger = logging.getLogger(__name__)

try:
    from ..config.manager import get_config
    config = get_config()
except ImportError:
    config = {}

# Create placeholder classes for compatibility
class PluginMetadata:
    """Placeholder for plugin metadata."""
    pass

class PluginInfo:
    """Placeholder for plugin info."""
    pass

class PluginType:
    """Placeholder for plugin type."""
    pass

class SecurityLevel:
    """Placeholder for security level."""
    pass

class PluginStatus:
    """Placeholder for plugin status."""
    pass


class PluginInterface(ABC):
    """Legacy plugin interface for backward compatibility."""
    
    def __init__(self, name: str, version: str = "1.0.0", description: str = ""):
        self.name = name
        self.version = version
        self.description = description
        self._initialized = False
        self._config = None
        self._api = None
        
        # Create enhanced config for internal use (if available)
        try:
            if EnhancedPluginConfig is not None:
                self._config = EnhancedPluginConfig(
                    name=name,
                    version=version,
                    description=description,
                    author="Unknown",
                    plugin_type="feature",
                    security_level="sandboxed"
                )
            else:
                self._config = None
        except Exception:
            self._config = None
        
        # Initialize enhanced API (if available)
        try:
            if EnhancedPluginAPI is not None and self._config:
                self._api = EnhancedPluginAPI(name, self._config)
            else:
                self._api = None
        except Exception as e:
            logger.error(f"Failed to initialize enhanced API for plugin {name}: {e}")
            self._api = None
    
    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the plugin."""
        pass
    
    async def cleanup(self):
        """Cleanup plugin resources."""
        self._initialized = False
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "initialized": self._initialized
        }
    
    @property
    def api(self) -> Optional[Any]:
        """Get access to enhanced plugin API."""
        return self._api
    
    # Legacy cache methods (wrappers)
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


class PluginManager:
    """Legacy plugin manager for backward compatibility."""
    
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
        """Get a plugin by name."""
        try:
            if self._unified_manager:
                return await self._unified_manager.get_plugin(plugin_name)
            return None
        except Exception as e:
            self.logger.error(f"Failed to get plugin {plugin_name}: {e}")
            return None
    
    def get_all_plugins(self) -> Dict[str, PluginInterface]:
        """Get all loaded plugins."""
        try:
            if self._unified_manager:
                return self._unified_manager.get_all_plugins()
            return {}
        except Exception as e:
            self.logger.error(f"Failed to get all plugins: {e}")
            return {}
    
    async def discover_plugins(self) -> List[str]:
        """Discover available plugins."""
        try:
            if self._unified_manager:
                return await self._unified_manager.discover_plugins()
            return []
        except Exception as e:
            self.logger.error(f"Failed to discover plugins: {e}")
            return []
    
    async def reload_plugin(self, plugin_name: str) -> bool:
        """Reload a plugin."""
        try:
            if self._unified_manager:
                return await self._unified_manager.reload_plugin(plugin_name)
            return False
        except Exception as e:
            self.logger.error(f"Failed to reload plugin {plugin_name}: {e}")
            return False


# Global plugin manager instance
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
