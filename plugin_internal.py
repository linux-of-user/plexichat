"""
Plugin Internal Interface Module

This module provides the internal plugin interface classes and types
that plugins use to integrate with the PlexiChat system.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class PluginType(Enum):
    """Plugin type enumeration."""
    FEATURE = "feature"
    UTILITY = "utility"
    INTEGRATION = "integration"
    AI_PROVIDER = "ai_provider"
    SECURITY = "security"
    ANALYTICS = "analytics"
    COMMUNICATION = "communication"
    STORAGE = "storage"
    INTERFACE = "interface"


class PluginStatus(Enum):
    """Plugin status enumeration."""
    INACTIVE = "inactive"
    LOADING = "loading"
    ACTIVE = "active"
    ERROR = "error"
    DISABLED = "disabled"


class SecurityLevel(Enum):
    """Security level enumeration."""
    MINIMAL = "minimal"
    STANDARD = "standard"
    ELEVATED = "elevated"
    TRUSTED = "trusted"


class ModulePriority(Enum):
    """Module priority enumeration."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ModuleCapability:
    """Module capability definition."""
    name: str
    description: str = ""
    required: bool = False
    version: str = "1.0.0"


@dataclass
class ModulePermissions:
    """Module permissions definition."""
    api_access: bool = False
    network_access: bool = False
    file_system_access: bool = False
    database_access: bool = False
    admin_access: bool = False
    plugin_management: bool = False
    system_access: bool = False
    user_data_access: bool = False
    capabilities: List[ModuleCapability] = field(default_factory=list)


@dataclass
class PluginMetadata:
    """Plugin metadata definition."""
    name: str
    version: str
    description: str = ""
    author: str = ""
    plugin_type: PluginType = PluginType.FEATURE
    enabled: bool = True
    priority: ModulePriority = ModulePriority.NORMAL
    dependencies: List[str] = field(default_factory=list)
    permissions: Optional[ModulePermissions] = None
    config_schema: Optional[Dict[str, Any]] = None
    api_endpoints: List[str] = field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def __post_init__(self):
        if self.permissions is None:
            self.permissions = ModulePermissions()
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()


class PluginInterface:
    """Base plugin interface that all plugins should inherit from."""
    
    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version
        self.status = PluginStatus.INACTIVE
        self.logger = logging.getLogger(f"plugin.{name}")
        self._metadata: Optional[PluginMetadata] = None
        self._config: Dict[str, Any] = {}
    
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        if self._metadata is None:
            self._metadata = PluginMetadata(
                name=self.name,
                version=self.version
            )
        return self._metadata
    
    def get_required_permissions(self) -> ModulePermissions:
        """Get required permissions for this plugin."""
        return self.get_metadata().permissions or ModulePermissions()
    
    def initialize(self, config: Optional[Dict[str, Any]] = None) -> bool:
        """Initialize the plugin."""
        try:
            self._config = config or {}
            self.status = PluginStatus.LOADING
            result = self.on_initialize()
            if result:
                self.status = PluginStatus.ACTIVE
            else:
                self.status = PluginStatus.ERROR
            return result
        except Exception as e:
            self.logger.error(f"Failed to initialize plugin {self.name}: {e}")
            self.status = PluginStatus.ERROR
            return False
    
    def shutdown(self) -> bool:
        """Shutdown the plugin."""
        try:
            result = self.on_shutdown()
            self.status = PluginStatus.INACTIVE
            return result
        except Exception as e:
            self.logger.error(f"Failed to shutdown plugin {self.name}: {e}")
            return False
    
    def on_initialize(self) -> bool:
        """Override this method to implement plugin initialization logic."""
        return True
    
    def on_shutdown(self) -> bool:
        """Override this method to implement plugin shutdown logic."""
        return True
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self._config.get(key, default)
    
    def set_config(self, key: str, value: Any) -> None:
        """Set configuration value."""
        self._config[key] = value


# Convenience functions for backward compatibility
def create_plugin_metadata(**kwargs) -> PluginMetadata:
    """Create plugin metadata."""
    return PluginMetadata(**kwargs)


def create_module_permissions(**kwargs) -> ModulePermissions:
    """Create module permissions."""
    return ModulePermissions(**kwargs)


def create_module_capability(name: str, **kwargs) -> ModuleCapability:
    """Create module capability."""
    return ModuleCapability(name=name, **kwargs)


# Export all public classes and functions
__all__ = [
    'PluginInterface',
    'PluginMetadata', 
    'PluginType',
    'PluginStatus',
    'SecurityLevel',
    'ModulePriority',
    'ModuleCapability',
    'ModulePermissions',
    'create_plugin_metadata',
    'create_module_permissions',
    'create_module_capability',
]
