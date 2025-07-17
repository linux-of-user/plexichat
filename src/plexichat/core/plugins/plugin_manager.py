"""
PlexiChat Plugin Manager

Plugin management with threading and performance optimization.
"""

import asyncio
import importlib
import inspect
import logging
import sys
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type
from dataclasses import dataclass

try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

try:
    from plexichat.core.threading.thread_manager import async_thread_manager, submit_task
except ImportError:
    async_thread_manager = None
    submit_task = None

try:
    from plexichat.core.analytics.analytics_manager import track_event
except ImportError:
    track_event = None

try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None

@dataclass
class PluginInfo:
    """Plugin information."""
    plugin_id: str
    name: str
    version: str
    description: str
    author: str
    enabled: bool
    loaded: bool
    file_path: str
    dependencies: List[str]
    metadata: Dict[str, Any]

class PlexiChatPlugin(ABC):
    """Base class for PlexiChat plugins."""
    
    def __init__(self):
        self.plugin_id = ""
        self.name = ""
        self.version = "1.0.0"
        self.description = ""
        self.author = ""
        self.dependencies = []
        self.enabled = False
        self.loaded = False
    
    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the plugin."""
        pass
    
    @abstractmethod
    async def shutdown(self) -> bool:
        """Shutdown the plugin."""
        pass
    
    async def on_message(self, message_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle message events."""
        return None
    
    async def on_user_join(self, user_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle user join events."""
        return None
    
    async def on_user_leave(self, user_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle user leave events."""
        return None
    
    def get_commands(self) -> Dict[str, Callable]:
        """Get plugin commands."""
        return {}
    
    def get_api_routes(self) -> List[Dict[str, Any]]:
        """Get plugin API routes."""
        return []

class PluginManager:
    """Plugin manager with threading support."""
    
    def __init__(self, plugins_dir: str = "plugins"):
        self.plugins_dir = Path(plugins_dir)
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.async_thread_manager = async_thread_manager
        
        # Plugin storage
        self.plugins: Dict[str, PlexiChatPlugin] = {}
        self.plugin_info: Dict[str, PluginInfo] = {}
        self.event_handlers: Dict[str, List[Callable]] = {}
        self.commands: Dict[str, Callable] = {}
        
        # Create plugins directory
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        
        # Statistics
        self.plugins_loaded = 0
        self.plugins_failed = 0
        self.events_processed = 0
    
    async def initialize(self):
        """Initialize plugin manager."""
        try:
            # Load plugin information from database
            await self._load_plugin_info()
            
            # Discover plugins
            await self.discover_plugins()
            
            # Load enabled plugins
            await self.load_enabled_plugins()
            
            logger.info("Plugin manager initialized")
            
        except Exception as e:
            logger.error(f"Error initializing plugin manager: {e}")
    
    async def discover_plugins(self):
        """Discover available plugins."""
        try:
            start_time = time.time()
            
            # Scan plugins directory
            plugin_files = list(self.plugins_dir.glob("*.py"))
            
            for plugin_file in plugin_files:
                if plugin_file.name.startswith("__"):
                    continue
                
                try:
                    # Load plugin info
                    plugin_info = await self._load_plugin_info_from_file(plugin_file)
                    if plugin_info:
                        self.plugin_info[plugin_info.plugin_id] = plugin_info
                        
                        # Store in database
                        await self._store_plugin_info(plugin_info)
                        
                except Exception as e:
                    logger.error(f"Error discovering plugin {plugin_file}: {e}")
            
            # Performance tracking
            if self.performance_logger:
                duration = time.time() - start_time
                self.performance_logger.record_metric("plugin_discovery_duration", duration, "seconds")
                self.performance_logger.record_metric("plugins_discovered", len(plugin_files), "count")
            
            logger.info(f"Discovered {len(self.plugin_info)} plugins")
            
        except Exception as e:
            logger.error(f"Error discovering plugins: {e}")
    
    async def _load_plugin_info_from_file(self, plugin_file: Path) -> Optional[PluginInfo]:
        """Load plugin info from file."""
        try:
            # Read plugin file
            with open(plugin_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract plugin metadata (simplified)
            plugin_id = plugin_file.stem
            name = plugin_id.replace("_", " ").title()
            version = "1.0.0"
            description = "PlexiChat plugin"
            author = "Unknown"
            dependencies = []
            
            # Look for metadata in comments or docstrings
            lines = content.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('# Name:'):
                    name = line.split(':', 1)[1].strip()
                elif line.startswith('# Version:'):
                    version = line.split(':', 1)[1].strip()
                elif line.startswith('# Description:'):
                    description = line.split(':', 1)[1].strip()
                elif line.startswith('# Author:'):
                    author = line.split(':', 1)[1].strip()
                elif line.startswith('# Dependencies:'):
                    deps = line.split(':', 1)[1].strip()
                    dependencies = [dep.strip() for dep in deps.split(',') if dep.strip()]
            
            return PluginInfo(
                plugin_id=plugin_id,
                name=name,
                version=version,
                description=description,
                author=author,
                enabled=False,
                loaded=False,
                file_path=str(plugin_file),
                dependencies=dependencies,
                metadata={}
            )
            
        except Exception as e:
            logger.error(f"Error loading plugin info from {plugin_file}: {e}")
            return None
    
    async def load_plugin(self, plugin_id: str) -> bool:
        """Load a specific plugin."""
        try:
            if plugin_id in self.plugins:
                logger.warning(f"Plugin already loaded: {plugin_id}")
                return True
            
            plugin_info = self.plugin_info.get(plugin_id)
            if not plugin_info:
                logger.error(f"Plugin not found: {plugin_id}")
                return False
            
            # Check dependencies
            for dep in plugin_info.dependencies:
                if dep not in self.plugins:
                    logger.error(f"Plugin dependency not loaded: {dep} (required by {plugin_id})")
                    return False
            
            # Load plugin module
            if self.async_thread_manager:
                plugin_instance = await self.async_thread_manager.run_in_thread(
                    self._load_plugin_sync, plugin_info
                )
            else:
                plugin_instance = await self._load_plugin_async(plugin_info)
            
            if not plugin_instance:
                return False
            
            # Initialize plugin
            try:
                success = await plugin_instance.initialize()
                if not success:
                    logger.error(f"Plugin initialization failed: {plugin_id}")
                    return False
            except Exception as e:
                logger.error(f"Plugin initialization error: {plugin_id} - {e}")
                return False
            
            # Store plugin
            self.plugins[plugin_id] = plugin_instance
            plugin_info.loaded = True
            
            # Register event handlers
            await self._register_plugin_handlers(plugin_id, plugin_instance)
            
            # Register commands
            commands = plugin_instance.get_commands()
            for cmd_name, cmd_func in commands.items():
                self.commands[cmd_name] = cmd_func
            
            self.plugins_loaded += 1
            
            # Performance tracking
            if self.performance_logger:
                self.performance_logger.record_metric("plugins_loaded", 1, "count")
            
            # Track analytics
            if track_event:
                await track_event(
                    "plugin_loaded",
                    properties={
                        "plugin_id": plugin_id,
                        "plugin_name": plugin_info.name,
                        "plugin_version": plugin_info.version
                    }
                )
            
            logger.info(f"Plugin loaded: {plugin_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading plugin {plugin_id}: {e}")
            self.plugins_failed += 1
            return False
    
    def _load_plugin_sync(self, plugin_info: PluginInfo) -> Optional[PlexiChatPlugin]:
        """Load plugin synchronously."""
        try:
            # Import plugin module
            spec = importlib.util.spec_from_file_location(plugin_info.plugin_id, plugin_info.file_path)
            if not spec or not spec.loader:
                return None
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin class
            plugin_class = None
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, PlexiChatPlugin) and 
                    obj != PlexiChatPlugin):
                    plugin_class = obj
                    break
            
            if not plugin_class:
                logger.error(f"No plugin class found in {plugin_info.file_path}")
                return None
            
            # Create plugin instance
            plugin_instance = plugin_class()
            plugin_instance.plugin_id = plugin_info.plugin_id
            plugin_instance.enabled = plugin_info.enabled
            
            return plugin_instance
            
        except Exception as e:
            logger.error(f"Error loading plugin module: {e}")
            return None
    
    async def _load_plugin_async(self, plugin_info: PluginInfo) -> Optional[PlexiChatPlugin]:
        """Load plugin asynchronously."""
        return self._load_plugin_sync(plugin_info)
    
    async def unload_plugin(self, plugin_id: str) -> bool:
        """Unload a plugin."""
        try:
            if plugin_id not in self.plugins:
                logger.warning(f"Plugin not loaded: {plugin_id}")
                return True
            
            plugin = self.plugins[plugin_id]
            
            # Shutdown plugin
            try:
                await plugin.shutdown()
            except Exception as e:
                logger.error(f"Plugin shutdown error: {plugin_id} - {e}")
            
            # Unregister handlers
            await self._unregister_plugin_handlers(plugin_id)
            
            # Remove commands
            commands = plugin.get_commands()
            for cmd_name in commands.keys():
                if cmd_name in self.commands:
                    del self.commands[cmd_name]
            
            # Remove plugin
            del self.plugins[plugin_id]
            
            # Update plugin info
            if plugin_id in self.plugin_info:
                self.plugin_info[plugin_id].loaded = False
            
            logger.info(f"Plugin unloaded: {plugin_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error unloading plugin {plugin_id}: {e}")
            return False
    
    async def enable_plugin(self, plugin_id: str) -> bool:
        """Enable a plugin."""
        try:
            if plugin_id not in self.plugin_info:
                logger.error(f"Plugin not found: {plugin_id}")
                return False
            
            plugin_info = self.plugin_info[plugin_id]
            plugin_info.enabled = True
            
            # Update database
            await self._update_plugin_enabled(plugin_id, True)
            
            # Load if not already loaded
            if not plugin_info.loaded:
                return await self.load_plugin(plugin_id)
            
            return True
            
        except Exception as e:
            logger.error(f"Error enabling plugin {plugin_id}: {e}")
            return False
    
    async def disable_plugin(self, plugin_id: str) -> bool:
        """Disable a plugin."""
        try:
            if plugin_id not in self.plugin_info:
                logger.error(f"Plugin not found: {plugin_id}")
                return False
            
            plugin_info = self.plugin_info[plugin_id]
            plugin_info.enabled = False
            
            # Update database
            await self._update_plugin_enabled(plugin_id, False)
            
            # Unload if loaded
            if plugin_info.loaded:
                return await self.unload_plugin(plugin_id)
            
            return True
            
        except Exception as e:
            logger.error(f"Error disabling plugin {plugin_id}: {e}")
            return False
    
    async def load_enabled_plugins(self):
        """Load all enabled plugins."""
        try:
            enabled_plugins = [
                plugin_id for plugin_id, info in self.plugin_info.items()
                if info.enabled and not info.loaded
            ]
            
            # Sort by dependencies
            sorted_plugins = self._sort_plugins_by_dependencies(enabled_plugins)
            
            for plugin_id in sorted_plugins:
                await self.load_plugin(plugin_id)
            
            logger.info(f"Loaded {len(sorted_plugins)} enabled plugins")
            
        except Exception as e:
            logger.error(f"Error loading enabled plugins: {e}")
    
    def _sort_plugins_by_dependencies(self, plugin_ids: List[str]) -> List[str]:
        """Sort plugins by dependencies."""
        try:
            sorted_plugins = []
            remaining_plugins = plugin_ids.copy()
            
            while remaining_plugins:
                # Find plugins with no unmet dependencies
                ready_plugins = []
                for plugin_id in remaining_plugins:
                    plugin_info = self.plugin_info[plugin_id]
                    unmet_deps = [
                        dep for dep in plugin_info.dependencies
                        if dep not in sorted_plugins
                    ]
                    if not unmet_deps:
                        ready_plugins.append(plugin_id)
                
                if not ready_plugins:
                    # Circular dependency or missing dependency
                    logger.warning(f"Circular or missing dependencies for plugins: {remaining_plugins}")
                    break
                
                # Add ready plugins to sorted list
                for plugin_id in ready_plugins:
                    sorted_plugins.append(plugin_id)
                    remaining_plugins.remove(plugin_id)
            
            return sorted_plugins
            
        except Exception as e:
            logger.error(f"Error sorting plugins by dependencies: {e}")
            return plugin_ids
    
    async def _register_plugin_handlers(self, plugin_id: str, plugin: PlexiChatPlugin):
        """Register plugin event handlers."""
        try:
            # Register message handler
            if hasattr(plugin, 'on_message'):
                if 'message' not in self.event_handlers:
                    self.event_handlers['message'] = []
                self.event_handlers['message'].append(plugin.on_message)
            
            # Register user join handler
            if hasattr(plugin, 'on_user_join'):
                if 'user_join' not in self.event_handlers:
                    self.event_handlers['user_join'] = []
                self.event_handlers['user_join'].append(plugin.on_user_join)
            
            # Register user leave handler
            if hasattr(plugin, 'on_user_leave'):
                if 'user_leave' not in self.event_handlers:
                    self.event_handlers['user_leave'] = []
                self.event_handlers['user_leave'].append(plugin.on_user_leave)
            
        except Exception as e:
            logger.error(f"Error registering plugin handlers: {e}")
    
    async def _unregister_plugin_handlers(self, plugin_id: str):
        """Unregister plugin event handlers."""
        try:
            plugin = self.plugins.get(plugin_id)
            if not plugin:
                return
            
            # Remove handlers
            for event_type, handlers in self.event_handlers.items():
                handlers_to_remove = []
                for handler in handlers:
                    if hasattr(handler, '__self__') and handler.__self__ == plugin:
                        handlers_to_remove.append(handler)
                
                for handler in handlers_to_remove:
                    handlers.remove(handler)
            
        except Exception as e:
            logger.error(f"Error unregistering plugin handlers: {e}")
    
    async def emit_event(self, event_type: str, event_data: Dict[str, Any]) -> List[Any]:
        """Emit event to plugins."""
        try:
            start_time = time.time()
            
            handlers = self.event_handlers.get(event_type, [])
            results = []
            
            for handler in handlers:
                try:
                    result = await handler(event_data)
                    if result is not None:
                        results.append(result)
                except Exception as e:
                    logger.error(f"Plugin event handler error: {e}")
            
            self.events_processed += 1
            
            # Performance tracking
            if self.performance_logger:
                duration = time.time() - start_time
                self.performance_logger.record_metric("plugin_event_duration", duration, "seconds")
                self.performance_logger.record_metric("plugin_events_processed", 1, "count")
            
            return results
            
        except Exception as e:
            logger.error(f"Error emitting event: {e}")
            return []
    
    async def execute_command(self, command: str, args: List[str], context: Dict[str, Any]) -> Any:
        """Execute plugin command."""
        try:
            if command not in self.commands:
                return None
            
            command_func = self.commands[command]
            
            # Execute command
            if asyncio.iscoroutinefunction(command_func):
                return await command_func(args, context)
            else:
                return command_func(args, context)
            
        except Exception as e:
            logger.error(f"Error executing command {command}: {e}")
            return None
    
    async def _load_plugin_info(self):
        """Load plugin info from database."""
        try:
            if self.db_manager:
                query = "SELECT * FROM plugins"
                result = await self.db_manager.execute_query(query)
                
                for row in result:
                    plugin_info = PluginInfo(
                        plugin_id=row[0],
                        name=row[1],
                        version=row[2],
                        description=row[3],
                        author=row[4],
                        enabled=row[5],
                        loaded=False,
                        file_path=row[6],
                        dependencies=row[7].split(',') if row[7] else [],
                        metadata={}
                    )
                    self.plugin_info[plugin_info.plugin_id] = plugin_info
                    
        except Exception as e:
            logger.error(f"Error loading plugin info from database: {e}")
    
    async def _store_plugin_info(self, plugin_info: PluginInfo):
        """Store plugin info in database."""
        try:
            if self.db_manager:
                query = """
                    INSERT OR REPLACE INTO plugins (
                        plugin_id, name, version, description, author,
                        enabled, file_path, dependencies
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """
                params = {
                    "plugin_id": plugin_info.plugin_id,
                    "name": plugin_info.name,
                    "version": plugin_info.version,
                    "description": plugin_info.description,
                    "author": plugin_info.author,
                    "enabled": plugin_info.enabled,
                    "file_path": plugin_info.file_path,
                    "dependencies": ','.join(plugin_info.dependencies)
                }
                await self.db_manager.execute_query(query, params)
        except Exception as e:
            logger.error(f"Error storing plugin info: {e}")
    
    async def _update_plugin_enabled(self, plugin_id: str, enabled: bool):
        """Update plugin enabled status in database."""
        try:
            if self.db_manager:
                query = "UPDATE plugins SET enabled = ? WHERE plugin_id = ?"
                params = {"enabled": enabled, "plugin_id": plugin_id}
                await self.db_manager.execute_query(query, params)
        except Exception as e:
            logger.error(f"Error updating plugin enabled status: {e}")
    
    def get_plugins(self) -> List[Dict[str, Any]]:
        """Get all plugins."""
        try:
            return [
                {
                    "plugin_id": info.plugin_id,
                    "name": info.name,
                    "version": info.version,
                    "description": info.description,
                    "author": info.author,
                    "enabled": info.enabled,
                    "loaded": info.loaded,
                    "dependencies": info.dependencies
                }
                for info in self.plugin_info.values()
            ]
        except Exception as e:
            logger.error(f"Error getting plugins: {e}")
            return []
    
    def get_stats(self) -> Dict[str, Any]:
        """Get plugin manager statistics."""
        return {
            "plugins_dir": str(self.plugins_dir),
            "total_plugins": len(self.plugin_info),
            "loaded_plugins": len(self.plugins),
            "enabled_plugins": sum(1 for info in self.plugin_info.values() if info.enabled),
            "plugins_loaded": self.plugins_loaded,
            "plugins_failed": self.plugins_failed,
            "events_processed": self.events_processed,
            "registered_commands": len(self.commands),
            "event_handlers": {
                event_type: len(handlers)
                for event_type, handlers in self.event_handlers.items()
            }
        }

# Global plugin manager
plugin_manager = PluginManager()

# Convenience functions
async def load_plugin(plugin_id: str) -> bool:
    """Load plugin."""
    return await plugin_manager.load_plugin(plugin_id)

async def unload_plugin(plugin_id: str) -> bool:
    """Unload plugin."""
    return await plugin_manager.unload_plugin(plugin_id)

async def enable_plugin(plugin_id: str) -> bool:
    """Enable plugin."""
    return await plugin_manager.enable_plugin(plugin_id)

async def disable_plugin(plugin_id: str) -> bool:
    """Disable plugin."""
    return await plugin_manager.disable_plugin(plugin_id)

async def emit_plugin_event(event_type: str, event_data: Dict[str, Any]) -> List[Any]:
    """Emit event to plugins."""
    return await plugin_manager.emit_event(event_type, event_data)

def get_plugins() -> List[Dict[str, Any]]:
    """Get all plugins."""
    return plugin_manager.get_plugins()
