"""
Modular Plugin System for NetLink.
Provides comprehensive plugin management with auto-discovery, loading, and lifecycle management.
"""

import os
import sys
import json
import importlib
import inspect
from typing import Dict, List, Any, Optional, Type, Callable
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod

from netlink.app.logger_config import logger


@dataclass
class PluginMetadata:
    """Plugin metadata information."""
    name: str
    version: str
    description: str
    author: str
    email: Optional[str] = None
    website: Optional[str] = None
    license: str = "MIT"
    dependencies: List[str] = None
    api_version: str = "1.0"
    enabled: bool = True
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []


class PluginInterface(ABC):
    """Base interface for all NetLink plugins."""
    
    def __init__(self):
        self.metadata: Optional[PluginMetadata] = None
        self.manager: Optional['PluginManager'] = None
        self.enabled = True
    
    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the plugin. Return True if successful."""
        pass
    
    @abstractmethod
    def shutdown(self) -> bool:
        """Shutdown the plugin. Return True if successful."""
        pass
    
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        if not self.metadata:
            raise NotImplementedError("Plugin must define metadata")
        return self.metadata
    
    def get_api_endpoints(self) -> List[Dict[str, Any]]:
        """Get API endpoints provided by this plugin."""
        return []
    
    def get_cli_commands(self) -> List[Dict[str, Any]]:
        """Get CLI commands provided by this plugin."""
        return []
    
    def get_gui_components(self) -> List[Dict[str, Any]]:
        """Get GUI components provided by this plugin."""
        return []
    
    def on_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle incoming messages. Return modified message or None."""
        return message
    
    def on_file_upload(self, file_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle file uploads. Return modified file info or None."""
        return file_info
    
    def on_user_login(self, user_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle user login events. Return modified user info or None."""
        return user_info


class PluginManager:
    """Comprehensive plugin manager with auto-discovery and lifecycle management."""
    
    def __init__(self, plugins_dir: str = "plugins"):
        self.plugins_dir = Path(plugins_dir)
        self.loaded_plugins: Dict[str, PluginInterface] = {}
        self.plugin_metadata: Dict[str, PluginMetadata] = {}
        self.plugin_configs: Dict[str, Dict[str, Any]] = {}
        self.hooks: Dict[str, List[Callable]] = {}
        
        # Ensure plugins directory exists
        self.plugins_dir.mkdir(exist_ok=True)
        
        # Create example plugin if directory is empty
        if not any(self.plugins_dir.iterdir()):
            self._create_example_plugin()
        
        logger.info(f"🔌 Plugin manager initialized: {self.plugins_dir}")
    
    def _create_example_plugin(self):
        """Create an example plugin for demonstration."""
        example_dir = self.plugins_dir / "example_plugin"
        example_dir.mkdir(exist_ok=True)
        
        # Create __init__.py
        init_file = example_dir / "__init__.py"
        with open(init_file, 'w') as f:
            f.write('"""Example NetLink Plugin"""\n')
        
        # Create plugin.py
        plugin_file = example_dir / "plugin.py"
        with open(plugin_file, 'w') as f:
            f.write('''"""
Example NetLink Plugin
Demonstrates the plugin system capabilities.
"""

from netlink.app.plugins.plugin_manager import PluginInterface, PluginMetadata


class ExamplePlugin(PluginInterface):
    """Example plugin demonstrating the plugin system."""
    
    def __init__(self):
        super().__init__()
        self.metadata = PluginMetadata(
            name="Example Plugin",
            version="1.0.0",
            description="Demonstrates NetLink plugin capabilities",
            author="NetLink Team",
            email="plugins@netlink.example.com",
            dependencies=[]
        )
    
    def initialize(self) -> bool:
        """Initialize the example plugin."""
        print("🔌 Example plugin initialized!")
        return True
    
    def shutdown(self) -> bool:
        """Shutdown the example plugin."""
        print("🔌 Example plugin shutting down!")
        return True
    
    def get_api_endpoints(self):
        """Provide API endpoints."""
        return [
            {
                "path": "/api/v1/plugins/example/hello",
                "method": "GET",
                "handler": self.hello_endpoint,
                "description": "Example hello endpoint"
            }
        ]
    
    def get_cli_commands(self):
        """Provide CLI commands."""
        return [
            {
                "command": "example",
                "handler": self.example_command,
                "description": "Example plugin command"
            }
        ]
    
    def hello_endpoint(self):
        """Example API endpoint."""
        return {"message": "Hello from Example Plugin!", "plugin": self.metadata.name}
    
    def example_command(self, args):
        """Example CLI command."""
        print(f"Example plugin command executed with args: {args}")
    
    def on_message(self, message):
        """Process incoming messages."""
        # Add plugin signature to messages
        if "plugins" not in message:
            message["plugins"] = []
        message["plugins"].append("example_plugin")
        return message


# Plugin entry point
def get_plugin_class():
    """Return the plugin class for auto-discovery."""
    return ExamplePlugin
''')
        
        # Create plugin.json
        config_file = example_dir / "plugin.json"
        with open(config_file, 'w') as f:
            json.dump({
                "name": "Example Plugin",
                "version": "1.0.0",
                "description": "Demonstrates NetLink plugin capabilities",
                "author": "NetLink Team",
                "main": "plugin.py",
                "class": "ExamplePlugin",
                "enabled": True,
                "settings": {
                    "example_setting": "default_value",
                    "debug_mode": False
                }
            }, f, indent=2)
        
        logger.info("📝 Created example plugin")
    
    def discover_plugins(self) -> List[str]:
        """Discover all available plugins."""
        plugins = []
        
        for plugin_dir in self.plugins_dir.iterdir():
            if plugin_dir.is_dir() and not plugin_dir.name.startswith('.'):
                config_file = plugin_dir / "plugin.json"
                if config_file.exists():
                    plugins.append(plugin_dir.name)
                    logger.info(f"🔍 Discovered plugin: {plugin_dir.name}")
        
        return plugins
    
    def load_plugin(self, plugin_name: str) -> bool:
        """Load a specific plugin."""
        try:
            plugin_dir = self.plugins_dir / plugin_name
            config_file = plugin_dir / "plugin.json"
            
            if not config_file.exists():
                logger.error(f"Plugin config not found: {plugin_name}")
                return False
            
            # Load plugin configuration
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            if not config.get("enabled", True):
                logger.info(f"Plugin disabled: {plugin_name}")
                return False
            
            # Import plugin module
            plugin_module_path = f"plugins.{plugin_name}.{config.get('main', 'plugin').replace('.py', '')}"
            
            # Add plugins directory to Python path
            plugins_path = str(self.plugins_dir.parent)
            if plugins_path not in sys.path:
                sys.path.insert(0, plugins_path)
            
            try:
                plugin_module = importlib.import_module(plugin_module_path)
            except ImportError as e:
                logger.error(f"Failed to import plugin {plugin_name}: {e}")
                return False
            
            # Get plugin class
            plugin_class_name = config.get("class", "Plugin")
            if hasattr(plugin_module, "get_plugin_class"):
                plugin_class = plugin_module.get_plugin_class()
            elif hasattr(plugin_module, plugin_class_name):
                plugin_class = getattr(plugin_module, plugin_class_name)
            else:
                logger.error(f"Plugin class not found: {plugin_class_name}")
                return False
            
            # Instantiate plugin
            plugin_instance = plugin_class()
            plugin_instance.manager = self
            
            # Initialize plugin
            if plugin_instance.initialize():
                self.loaded_plugins[plugin_name] = plugin_instance
                self.plugin_metadata[plugin_name] = plugin_instance.get_metadata()
                self.plugin_configs[plugin_name] = config
                
                # Register hooks
                self._register_plugin_hooks(plugin_name, plugin_instance)
                
                logger.info(f"✅ Loaded plugin: {plugin_name}")
                return True
            else:
                logger.error(f"Failed to initialize plugin: {plugin_name}")
                return False
                
        except Exception as e:
            logger.error(f"Error loading plugin {plugin_name}: {e}")
            return False
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a specific plugin."""
        try:
            if plugin_name not in self.loaded_plugins:
                logger.warning(f"Plugin not loaded: {plugin_name}")
                return False
            
            plugin = self.loaded_plugins[plugin_name]
            
            # Shutdown plugin
            if plugin.shutdown():
                # Unregister hooks
                self._unregister_plugin_hooks(plugin_name)
                
                # Remove from loaded plugins
                del self.loaded_plugins[plugin_name]
                del self.plugin_metadata[plugin_name]
                del self.plugin_configs[plugin_name]
                
                logger.info(f"🔌 Unloaded plugin: {plugin_name}")
                return True
            else:
                logger.error(f"Failed to shutdown plugin: {plugin_name}")
                return False
                
        except Exception as e:
            logger.error(f"Error unloading plugin {plugin_name}: {e}")
            return False
    
    def reload_plugin(self, plugin_name: str) -> bool:
        """Reload a specific plugin."""
        if plugin_name in self.loaded_plugins:
            if not self.unload_plugin(plugin_name):
                return False
        
        return self.load_plugin(plugin_name)
    
    def load_all_plugins(self) -> Dict[str, bool]:
        """Load all discovered plugins."""
        results = {}
        plugins = self.discover_plugins()
        
        for plugin_name in plugins:
            results[plugin_name] = self.load_plugin(plugin_name)
        
        loaded_count = sum(results.values())
        logger.info(f"🔌 Loaded {loaded_count}/{len(plugins)} plugins")
        
        return results
    
    def _register_plugin_hooks(self, plugin_name: str, plugin: PluginInterface):
        """Register plugin hooks."""
        # Register message hooks
        if hasattr(plugin, 'on_message'):
            if 'message' not in self.hooks:
                self.hooks['message'] = []
            self.hooks['message'].append(plugin.on_message)
        
        # Register file upload hooks
        if hasattr(plugin, 'on_file_upload'):
            if 'file_upload' not in self.hooks:
                self.hooks['file_upload'] = []
            self.hooks['file_upload'].append(plugin.on_file_upload)
        
        # Register user login hooks
        if hasattr(plugin, 'on_user_login'):
            if 'user_login' not in self.hooks:
                self.hooks['user_login'] = []
            self.hooks['user_login'].append(plugin.on_user_login)
    
    def _unregister_plugin_hooks(self, plugin_name: str):
        """Unregister plugin hooks."""
        plugin = self.loaded_plugins[plugin_name]
        
        # Remove from all hook lists
        for hook_type, hook_list in self.hooks.items():
            hooks_to_remove = []
            for hook in hook_list:
                if hasattr(hook, '__self__') and hook.__self__ == plugin:
                    hooks_to_remove.append(hook)
            
            for hook in hooks_to_remove:
                hook_list.remove(hook)
    
    def execute_hooks(self, hook_type: str, data: Any) -> Any:
        """Execute all hooks of a specific type."""
        if hook_type not in self.hooks:
            return data
        
        result = data
        for hook in self.hooks[hook_type]:
            try:
                hook_result = hook(result)
                if hook_result is not None:
                    result = hook_result
            except Exception as e:
                logger.error(f"Hook execution error: {e}")
        
        return result
    
    def get_loaded_plugins(self) -> Dict[str, Dict[str, Any]]:
        """Get information about all loaded plugins."""
        plugins_info = {}
        
        for plugin_name, plugin in self.loaded_plugins.items():
            metadata = self.plugin_metadata[plugin_name]
            config = self.plugin_configs[plugin_name]
            
            plugins_info[plugin_name] = {
                "metadata": asdict(metadata),
                "config": config,
                "api_endpoints": plugin.get_api_endpoints(),
                "cli_commands": plugin.get_cli_commands(),
                "gui_components": plugin.get_gui_components(),
                "enabled": plugin.enabled
            }
        
        return plugins_info
    
    def get_plugin_statistics(self) -> Dict[str, Any]:
        """Get plugin system statistics."""
        discovered = self.discover_plugins()
        loaded = len(self.loaded_plugins)
        
        hook_counts = {hook_type: len(hooks) for hook_type, hooks in self.hooks.items()}
        
        return {
            "total_discovered": len(discovered),
            "total_loaded": loaded,
            "load_success_rate": (loaded / len(discovered) * 100) if discovered else 0,
            "hook_counts": hook_counts,
            "plugins_directory": str(self.plugins_dir),
            "last_updated": datetime.now().isoformat()
        }
    
    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin."""
        try:
            config_file = self.plugins_dir / plugin_name / "plugin.json"
            
            if config_file.exists():
                with open(config_file, 'r') as f:
                    config = json.load(f)
                
                config["enabled"] = True
                
                with open(config_file, 'w') as f:
                    json.dump(config, f, indent=2)
                
                # Load if not already loaded
                if plugin_name not in self.loaded_plugins:
                    return self.load_plugin(plugin_name)
                
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to enable plugin {plugin_name}: {e}")
            return False
    
    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin."""
        try:
            # Unload if loaded
            if plugin_name in self.loaded_plugins:
                if not self.unload_plugin(plugin_name):
                    return False
            
            # Update config
            config_file = self.plugins_dir / plugin_name / "plugin.json"
            
            if config_file.exists():
                with open(config_file, 'r') as f:
                    config = json.load(f)
                
                config["enabled"] = False
                
                with open(config_file, 'w') as f:
                    json.dump(config, f, indent=2)
                
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to disable plugin {plugin_name}: {e}")
            return False


# Global plugin manager instance
plugin_manager = PluginManager()


def get_plugin_manager() -> PluginManager:
    """Get the global plugin manager instance."""
    return plugin_manager


def initialize_plugins():
    """Initialize the plugin system."""
    try:
        results = plugin_manager.load_all_plugins()
        loaded_count = sum(results.values())
        total_count = len(results)
        
        logger.info(f"🔌 Plugin system initialized: {loaded_count}/{total_count} plugins loaded")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize plugin system: {e}")
        return False
