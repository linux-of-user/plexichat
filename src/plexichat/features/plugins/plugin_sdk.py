"""
PlexiChat Plugin SDK

Software Development Kit for creating PlexiChat plugins.
Provides high-level APIs and utilities for plugin development.
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Union

try:
    from plexichat.core.plugins.plugin_manager import PlexiChatPlugin, PluginInfo
    from plexichat.infrastructure.modules.plugin_manager import PluginInterface, PluginMetadata
    from plexichat.app.logger_config import get_logger
    from plexichat.core.config import settings
except ImportError:
    PlexiChatPlugin = object
    PluginInterface = object
    PluginInfo = object
    PluginMetadata = object
    get_logger = logging.getLogger
    settings = {}

logger = get_logger(__name__)

@dataclass
class PluginConfig:
    """Plugin configuration structure."""
    name: str
    version: str
    description: str
    author: str
    email: Optional[str] = None
    license: str = "MIT"
    homepage: Optional[str] = None
    repository: Optional[str] = None
    category: str = "utility"
    tags: List[str] = None
    permissions: List[str] = None
    dependencies: List[str] = None
    min_plexichat_version: str = "1.0.0"
    api_version: str = "v1"
    enabled: bool = True

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.permissions is None:
            self.permissions = []
        if self.dependencies is None:
            self.dependencies = []

class PluginAPI:
    """High-level API for plugin operations."""
    
    def __init__(self, plugin_name: str):
        self.plugin_name = plugin_name
        self.logger = get_logger(f"plugin.{plugin_name}.api")
        self._config = {}
        self._event_handlers = {}
    
    # Configuration Management
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self._config.get(key, default)
    
    def set_config(self, key: str, value: Any) -> None:
        """Set configuration value."""
        self._config[key] = value
    
    def load_config(self, config_path: Optional[Path] = None) -> Dict[str, Any]:
        """Load configuration from file."""
        if config_path is None:
            config_path = Path(f"plugins/{self.plugin_name}/config.json")
        
        try:
            if config_path.exists():
                with open(config_path, 'r') as f:
                    self._config = json.load(f)
            return self._config
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            return {}
    
    def save_config(self, config_path: Optional[Path] = None) -> bool:
        """Save configuration to file."""
        if config_path is None:
            config_path = Path(f"plugins/{self.plugin_name}/config.json")
        
        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w') as f:
                json.dump(self._config, f, indent=2)
            return True
        except Exception as e:
            self.logger.error(f"Error saving config: {e}")
            return False
    
    # Event System
    def on(self, event: str, handler: Callable) -> None:
        """Register event handler."""
        if event not in self._event_handlers:
            self._event_handlers[event] = []
        self._event_handlers[event].append(handler)
    
    def emit(self, event: str, data: Any = None) -> None:
        """Emit event to handlers."""
        if event in self._event_handlers:
            for handler in self._event_handlers[event]:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        asyncio.create_task(handler(data))
                    else:
                        handler(data)
                except Exception as e:
                    self.logger.error(f"Error in event handler for {event}: {e}")
    
    # Messaging API
    async def send_message(self, channel_id: str, content: str, 
                          message_type: str = "text") -> Optional[str]:
        """Send a message to a channel."""
        try:
            # This would integrate with the actual messaging system
            message_data = {
                "channel_id": channel_id,
                "content": content,
                "type": message_type,
                "timestamp": datetime.now().isoformat(),
                "plugin": self.plugin_name
            }
            
            self.logger.info(f"Sending message to channel {channel_id}: {content[:50]}...")
            # Return mock message ID for now
            return f"msg_{datetime.now().timestamp()}"
            
        except Exception as e:
            self.logger.error(f"Error sending message: {e}")
            return None
    
    async def edit_message(self, message_id: str, content: str) -> bool:
        """Edit an existing message."""
        try:
            self.logger.info(f"Editing message {message_id}: {content[:50]}...")
            return True
        except Exception as e:
            self.logger.error(f"Error editing message: {e}")
            return False
    
    async def delete_message(self, message_id: str) -> bool:
        """Delete a message."""
        try:
            self.logger.info(f"Deleting message {message_id}")
            return True
        except Exception as e:
            self.logger.error(f"Error deleting message: {e}")
            return False
    
    # File Operations
    async def upload_file(self, file_path: Path, channel_id: str) -> Optional[str]:
        """Upload a file to a channel."""
        try:
            if not file_path.exists():
                self.logger.error(f"File not found: {file_path}")
                return None
            
            self.logger.info(f"Uploading file {file_path.name} to channel {channel_id}")
            # Return mock file ID for now
            return f"file_{datetime.now().timestamp()}"
            
        except Exception as e:
            self.logger.error(f"Error uploading file: {e}")
            return None
    
    # Database Operations (if permitted)
    async def query_database(self, query: str, params: Optional[Dict] = None) -> List[Dict]:
        """Execute database query."""
        try:
            self.logger.info(f"Executing database query: {query[:100]}...")
            # This would integrate with the actual database system
            return []
        except Exception as e:
            self.logger.error(f"Error executing database query: {e}")
            return []
    
    # HTTP Requests
    async def make_request(self, method: str, url: str, 
                          headers: Optional[Dict] = None,
                          data: Optional[Dict] = None) -> Optional[Dict]:
        """Make HTTP request."""
        try:
            self.logger.info(f"Making {method} request to {url}")
            # This would use aiohttp or similar
            return {"status": "success", "data": {}}
        except Exception as e:
            self.logger.error(f"Error making HTTP request: {e}")
            return None

class SDKPlugin(PluginInterface):
    """Enhanced plugin base class using the SDK."""
    
    def __init__(self, config: PluginConfig):
        super().__init__(config.name, config.version)
        self.config = config
        self.api = PluginAPI(config.name)
        self.logger = get_logger(f"plugin.{config.name}")
        
        # Load configuration
        self.api.load_config()
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get plugin metadata."""
        return asdict(self.config)
    
    @abstractmethod
    async def on_load(self) -> bool:
        """Called when plugin is loaded."""
        pass
    
    @abstractmethod
    async def on_unload(self) -> bool:
        """Called when plugin is unloaded."""
        pass
    
    async def on_enable(self) -> bool:
        """Called when plugin is enabled."""
        return True
    
    async def on_disable(self) -> bool:
        """Called when plugin is disabled."""
        return True
    
    async def on_message(self, message_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle message events."""
        return None
    
    async def on_user_join(self, user_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle user join events."""
        return None
    
    async def on_user_leave(self, user_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle user leave events."""
        return None
    
    async def on_file_upload(self, file_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle file upload events."""
        return None
    
    def get_commands(self) -> Dict[str, Callable]:
        """Get plugin commands."""
        return {}
    
    def get_api_routes(self) -> List[Dict[str, Any]]:
        """Get API routes provided by this plugin."""
        return []
    
    def get_ui_pages(self) -> List[Dict[str, Any]]:
        """Get UI pages provided by this plugin."""
        return []

class PluginBuilder:
    """Builder class for creating plugins."""
    
    def __init__(self, name: str):
        self.config = PluginConfig(
            name=name,
            version="1.0.0",
            description="",
            author=""
        )
        self._handlers = {}
        self._commands = {}
        self._routes = []
        self._ui_pages = []
    
    def version(self, version: str) -> 'PluginBuilder':
        """Set plugin version."""
        self.config.version = version
        return self
    
    def description(self, description: str) -> 'PluginBuilder':
        """Set plugin description."""
        self.config.description = description
        return self
    
    def author(self, author: str, email: Optional[str] = None) -> 'PluginBuilder':
        """Set plugin author."""
        self.config.author = author
        if email:
            self.config.email = email
        return self
    
    def category(self, category: str) -> 'PluginBuilder':
        """Set plugin category."""
        self.config.category = category
        return self
    
    def tags(self, *tags: str) -> 'PluginBuilder':
        """Set plugin tags."""
        self.config.tags = list(tags)
        return self
    
    def permissions(self, *permissions: str) -> 'PluginBuilder':
        """Set required permissions."""
        self.config.permissions = list(permissions)
        return self
    
    def dependencies(self, *dependencies: str) -> 'PluginBuilder':
        """Set plugin dependencies."""
        self.config.dependencies = list(dependencies)
        return self
    
    def on_message(self, handler: Callable) -> 'PluginBuilder':
        """Set message handler."""
        self._handlers['message'] = handler
        return self
    
    def on_user_join(self, handler: Callable) -> 'PluginBuilder':
        """Set user join handler."""
        self._handlers['user_join'] = handler
        return self
    
    def command(self, name: str, handler: Callable) -> 'PluginBuilder':
        """Add command handler."""
        self._commands[name] = handler
        return self
    
    def api_route(self, path: str, method: str, handler: Callable) -> 'PluginBuilder':
        """Add API route."""
        self._routes.append({
            "path": path,
            "method": method,
            "handler": handler
        })
        return self
    
    def ui_page(self, name: str, path: str, title: str) -> 'PluginBuilder':
        """Add UI page."""
        self._ui_pages.append({
            "name": name,
            "path": path,
            "title": title
        })
        return self
    
    def build(self) -> SDKPlugin:
        """Build the plugin."""
        class BuiltPlugin(SDKPlugin):
            def __init__(self, config, handlers, commands, routes, ui_pages):
                super().__init__(config)
                self._handlers = handlers
                self._commands = commands
                self._routes = routes
                self._ui_pages = ui_pages
            
            async def on_load(self):
                self.logger.info(f"Plugin {self.config.name} loaded")
                return True
            
            async def on_unload(self):
                self.logger.info(f"Plugin {self.config.name} unloaded")
                return True
            
            async def on_message(self, message_data):
                if 'message' in self._handlers:
                    return await self._handlers['message'](message_data)
                return None
            
            async def on_user_join(self, user_data):
                if 'user_join' in self._handlers:
                    return await self._handlers['user_join'](user_data)
                return None
            
            def get_commands(self):
                return self._commands
            
            def get_api_routes(self):
                return self._routes
            
            def get_ui_pages(self):
                return self._ui_pages
        
        return BuiltPlugin(self.config, self._handlers, self._commands, self._routes, self._ui_pages)

# Convenience functions
def create_plugin(name: str) -> PluginBuilder:
    """Create a new plugin using the builder pattern."""
    return PluginBuilder(name)

def register_plugin(plugin: SDKPlugin) -> bool:
    """Register a plugin with the system."""
    try:
        logger.info(f"Registering plugin: {plugin.config.name}")
        # This would integrate with the actual plugin manager
        return True
    except Exception as e:
        logger.error(f"Error registering plugin: {e}")
        return False

__all__ = [
    "PluginConfig", "PluginAPI", "SDKPlugin", "PluginBuilder",
    "create_plugin", "register_plugin"
]
