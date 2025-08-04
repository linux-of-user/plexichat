"""
PlexiChat System Orchestrator
Simplified system orchestration and module management.
"""

import asyncio
import importlib
import logging
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class ModuleManager:
    """Manages module loading and initialization."""
    
    def __init__(self):
        self.loaded_modules: Set[str] = set()
        self.failed_modules: Set[str] = set()
        self.module_registry: Dict[str, Any] = {}
    
    def load_module(self, module_name: str) -> bool:
        """Load a single module."""
        try:
            module = importlib.import_module(module_name)
            self.loaded_modules.add(module_name)
            self.module_registry[module_name] = module
            logger.debug(f"Loaded module: {module_name}")
            return True
        except ImportError as e:
            self.failed_modules.add(module_name)
            logger.warning(f"Failed to load module {module_name}: {e}")
            return False
        except Exception as e:
            self.failed_modules.add(module_name)
            logger.error(f"Error loading module {module_name}: {e}")
            return False
    
    def load_modules(self, module_names: List[str]) -> Dict[str, Any]:
        """Load multiple modules and return results."""
        results = {
            "successful": [],
            "failed": []
        }
        
        for module_name in module_names:
            if self.load_module(module_name):
                results["successful"].append(module_name)
            else:
                results["failed"].append(module_name)
        
        return results
    
    def get_module(self, module_name: str) -> Optional[Any]:
        """Get a loaded module."""
        return self.module_registry.get(module_name)
    
    def is_loaded(self, module_name: str) -> bool:
        """Check if a module is loaded."""
        return module_name in self.loaded_modules
    
    def get_status(self) -> Dict[str, Any]:
        """Get module loading status."""
        return {}}
            "loaded_count": len(self.loaded_modules),
            "failed_count": len(self.failed_modules),
            "loaded_modules": list(self.loaded_modules),
            "failed_modules": list(self.failed_modules)
        }


class SystemOrchestrator:
    """Orchestrates system startup and shutdown."""
    
    def __init__(self):
        self.module_manager = ModuleManager()
        self.startup_hooks: List[callable] = []
        self.shutdown_hooks: List[callable] = []
        self.is_running = False
    
    def add_startup_hook(self, hook: callable):
        """Add a startup hook."""
        self.startup_hooks.append(hook)
    
    def add_shutdown_hook(self, hook: callable):
        """Add a shutdown hook."""
        self.shutdown_hooks.append(hook)
    
    async def startup(self) -> bool:
        """Start the system."""
        if self.is_running:
            logger.warning("System is already running")
            return True
        
        logger.info("Starting system orchestrator...")
        
        try:
            # Load core modules
            core_modules = [
                "plexichat.core.config",
                "plexichat.core.database.manager",
                "plexichat.core.auth.auth_manager",
                "plexichat.core.services"
            ]
            
            logger.info("Loading core modules...")
            results = self.module_manager.load_modules(core_modules)
            
            if results["failed"]:
                logger.warning(f"Some core modules failed to load: {results['failed']}")
            
            # Run startup hooks
            logger.info("Running startup hooks...")
            for hook in self.startup_hooks:
                try:
                    if asyncio.iscoroutinefunction(hook):
                        await hook()
                    else:
                        hook()
                except Exception as e:
                    logger.error(f"Startup hook failed: {e}")
            
            self.is_running = True
            logger.info("System orchestrator started successfully")
            return True
            
        except Exception as e:
            logger.error(f"System startup failed: {e}")
            return False
    
    async def shutdown(self) -> bool:
        """Shutdown the system."""
        if not self.is_running:
            logger.warning("System is not running")
            return True
        
        logger.info("Shutting down system orchestrator...")
        
        try:
            # Run shutdown hooks in reverse order
            logger.info("Running shutdown hooks...")
            for hook in reversed(self.shutdown_hooks):
                try:
                    if asyncio.iscoroutinefunction(hook):
                        await hook()
                    else:
                        hook()
                except Exception as e:
                    logger.error(f"Shutdown hook failed: {e}")
            
            self.is_running = False
            logger.info("System orchestrator shut down successfully")
            return True
            
        except Exception as e:
            logger.error(f"System shutdown failed: {e}")
            return False
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status."""
        return {}}
            "is_running": self.is_running,
            "startup_hooks_count": len(self.startup_hooks),
            "shutdown_hooks_count": len(self.shutdown_hooks),
            "module_status": self.module_manager.get_status()
        }


class ComponentRegistry:
    """Registry for system components."""
    
    def __init__(self):
        self.components: Dict[str, Any] = {}
        self.component_types: Dict[str, str] = {}
    
    def register(self, name: str, component: Any, component_type: str = "unknown"):
        """Register a component."""
        self.components[name] = component
        self.component_types[name] = component_type
        logger.debug(f"Registered component: {name} ({component_type})")
    
    def get(self, name: str) -> Optional[Any]:
        """Get a component by name."""
        return self.components.get(name)
    
    def get_by_type(self, component_type: str) -> Dict[str, Any]:
        """Get all components of a specific type."""
        return {}}
            name: component
            for name, component in self.components.items()
            if self.component_types.get(name) == component_type
        }
    
    def unregister(self, name: str) -> bool:
        """Unregister a component."""
        if name in self.components:
            del self.components[name]
            self.component_types.pop(name, None)
            logger.debug(f"Unregistered component: {name}")
            return True
        return False
    
    def list_components(self) -> Dict[str, str]:
        """List all registered components with their types."""
        return self.component_types.copy()


# Global instances
module_manager = ModuleManager()
system_orchestrator = SystemOrchestrator()
component_registry = ComponentRegistry()


# Convenience functions
def register_component(name: str, component: Any, component_type: str = "unknown"):
    """Register a component in the global registry."""
    component_registry.register(name, component, component_type)


def get_component(name: str) -> Optional[Any]:
    """Get a component from the global registry."""
    return component_registry.get(name)


def load_module(module_name: str) -> bool:
    """Load a module using the global module manager."""
    return module_manager.load_module(module_name)


async def startup_system() -> bool:
    """Start the system using the global orchestrator."""
    return await system_orchestrator.startup()


async def shutdown_system() -> bool:
    """Shutdown the system using the global orchestrator."""
    return await system_orchestrator.shutdown()


__all__ = [
    "ModuleManager", "SystemOrchestrator", "ComponentRegistry",
    "module_manager", "system_orchestrator", "component_registry",
    "register_component", "get_component", "load_module",
    "startup_system", "shutdown_system"
]
