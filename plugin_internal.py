"""
PlexiChat Plugin Internal Interface System
==========================================

This module provides the core interfaces and classes for the PlexiChat plugin system.
It defines the contracts that all plugins must implement and provides base classes
for different types of plugins.

This is a critical infrastructure module that enables the plugin architecture.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional, Union
from datetime import datetime


logger = logging.getLogger(__name__)


class PluginType(Enum):
    """Types of plugins supported by PlexiChat."""
    CORE = "core"
    AI_PROVIDER = "ai_provider"
    MIDDLEWARE = "middleware"
    INTERFACE = "interface"
    UTILITY = "utility"
    SECURITY = "security"
    INTEGRATION = "integration"


class PluginStatus(Enum):
    """Plugin status states."""
    NOT_LOADED = "not_loaded"
    LOADING = "loading"
    LOADED = "loaded"
    ACTIVE = "active"
    ERROR = "error"
    DISABLED = "disabled"


@dataclass
class ModulePermissions:
    """Permissions required by a plugin module."""
    network_access: bool = False
    file_system_access: bool = False
    database_access: bool = False
    admin_access: bool = False
    system_access: bool = False


@dataclass
class ModuleCapability:
    """Capability provided by a plugin module."""
    name: str
    description: str
    version: str = "1.0.0"


@dataclass
class PluginMetadata:
    """Metadata for a plugin."""
    name: str
    version: str
    description: str = ""
    author: str = ""
    plugin_type: PluginType = PluginType.UTILITY
    dependencies: Optional[List[str]] = None
    permissions: Optional[List[ModulePermissions]] = None
    capabilities: Optional[List[ModuleCapability]] = None
    config_schema: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if self.permissions is None:
            self.permissions = []
        if self.capabilities is None:
            self.capabilities = []
        if self.config_schema is None:
            self.config_schema = {}


class PluginInterface(ABC):
    """Base interface that all plugins must implement."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.status = PluginStatus.NOT_LOADED
        self.initialized = False
        self.last_error: Optional[Exception] = None
        self.logger = logging.getLogger(f"plugin.{name}")
    
    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the plugin. Return True if successful."""
        pass
    
    @abstractmethod
    async def shutdown(self) -> bool:
        """Shutdown the plugin. Return True if successful."""
        pass
    
    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        pass
    
    def get_status(self) -> Dict[str, Any]:
        """Get plugin status information."""
        return {
            "name": self.name,
            "status": self.status.value,
            "initialized": self.initialized,
            "last_error": str(self.last_error) if self.last_error else None,
            "metadata": self.get_metadata().__dict__
        }


@dataclass
class AIRequest:
    """Request object for AI providers."""
    prompt: str
    model: Optional[str] = None
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    system_prompt: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    user_id: Optional[str] = None
    conversation_id: Optional[str] = None


@dataclass
class AIResponse:
    """Response object from AI providers."""
    content: str
    model: str
    tokens_used: int = 0
    finish_reason: str = "completed"
    metadata: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    @property
    def success(self) -> bool:
        """Check if the response was successful."""
        return self.error is None


class AIProviderInterface(PluginInterface):
    """Interface for AI provider plugins."""
    
    @abstractmethod
    async def generate_response(self, request: AIRequest) -> AIResponse:
        """Generate a response from the AI provider."""
        pass
    
    @abstractmethod
    async def stream_response(self, request: AIRequest):
        """Stream a response from the AI provider."""
        pass
    
    @abstractmethod
    def get_available_models(self) -> List[str]:
        """Get list of available models."""
        pass
    
    @abstractmethod
    def validate_model(self, model: str) -> bool:
        """Validate if a model is available."""
        pass


class MiddlewareInterface(PluginInterface):
    """Interface for middleware plugins."""
    
    @abstractmethod
    async def process_request(self, request: Any) -> Any:
        """Process incoming request."""
        pass
    
    @abstractmethod
    async def process_response(self, response: Any) -> Any:
        """Process outgoing response."""
        pass


class IntegrationInterface(PluginInterface):
    """Interface for integration plugins."""
    
    @abstractmethod
    async def connect(self) -> bool:
        """Connect to external service."""
        pass
    
    @abstractmethod
    async def disconnect(self) -> bool:
        """Disconnect from external service."""
        pass
    
    @abstractmethod
    async def test_connection(self) -> bool:
        """Test connection to external service."""
        pass


# Plugin registry for tracking loaded plugins
_plugin_registry: Dict[str, PluginInterface] = {}


def register_plugin(plugin: PluginInterface) -> bool:
    """Register a plugin in the global registry."""
    try:
        _plugin_registry[plugin.name] = plugin
        logger.info(f"Plugin '{plugin.name}' registered successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to register plugin '{plugin.name}': {e}")
        return False


def unregister_plugin(name: str) -> bool:
    """Unregister a plugin from the global registry."""
    try:
        if name in _plugin_registry:
            del _plugin_registry[name]
            logger.info(f"Plugin '{name}' unregistered successfully")
            return True
        else:
            logger.warning(f"Plugin '{name}' not found in registry")
            return False
    except Exception as e:
        logger.error(f"Failed to unregister plugin '{name}': {e}")
        return False


def get_plugin(name: str) -> Optional[PluginInterface]:
    """Get a plugin from the registry."""
    return _plugin_registry.get(name)


def get_all_plugins() -> Dict[str, PluginInterface]:
    """Get all registered plugins."""
    return _plugin_registry.copy()


def get_plugins_by_type(plugin_type: PluginType) -> List[PluginInterface]:
    """Get all plugins of a specific type."""
    return [
        plugin for plugin in _plugin_registry.values()
        if plugin.get_metadata().plugin_type == plugin_type
    ]


# Export all public interfaces
__all__ = [
    'PluginInterface',
    'AIProviderInterface', 
    'MiddlewareInterface',
    'IntegrationInterface',
    'PluginMetadata',
    'PluginType',
    'PluginStatus',
    'ModulePermissions',
    'ModuleCapability',
    'AIRequest',
    'AIResponse',
    'register_plugin',
    'unregister_plugin',
    'get_plugin',
    'get_all_plugins',
    'get_plugins_by_type'
]
