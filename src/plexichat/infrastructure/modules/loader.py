"""
PlexiChat Module Loader

Dynamic module loading system with error isolation for plug-and-play architecture.
Enables safe loading, unloading, and management of feature modules.
"""

import importlib
import importlib.util
import logging
import sys
import traceback
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable, Type
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
import threading
import weakref

logger = logging.getLogger(__name__)


class ModuleStatus(Enum):
    """Module status enumeration."""
    UNLOADED = "unloaded"
    LOADING = "loading"
    LOADED = "loaded"
    ERROR = "error"
    DISABLED = "disabled"


@dataclass
class ModuleInfo:
    """Information about a module."""
    name: str
    path: str
    version: str = "1.0.0"
    description: str = ""
    dependencies: List[str] = field(default_factory=list)
    status: ModuleStatus = ModuleStatus.UNLOADED
    module_instance: Optional[Any] = None
    error_message: Optional[str] = None
    load_time: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ModuleInterface(ABC):
    """Base interface for all loadable modules."""
    
    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the module. Return True if successful."""
        pass
    
    @abstractmethod
    def shutdown(self) -> bool:
        """Shutdown the module. Return True if successful."""
        pass
    
    @abstractmethod
    def get_info(self) -> Dict[str, Any]:
        """Get module information."""
        pass
    
    def health_check(self) -> bool:
        """Check if module is healthy. Override if needed."""
        return True


class ModuleLoader:
    """
    Dynamic module loader with error isolation and dependency management.
    """
    
    def __init__(self):
        self.modules: Dict[str, ModuleInfo] = {}
        self.module_paths: List[Path] = []
        self.hooks: Dict[str, List[Callable]] = {
            'before_load': [],
            'after_load': [],
            'before_unload': [],
            'after_unload': [],
            'on_error': []
        }
        self._lock = threading.RLock()
        self._shutdown_handlers = weakref.WeakSet()
    
    def add_module_path(self, path: Path) -> None:
        """Add a path to search for modules."""
        if path.exists() and path.is_dir():
            self.module_paths.append(path)
            logger.info(f"Added module path: {path}")
        else:
            logger.warning(f"Module path does not exist: {path}")
    
    def register_hook(self, event: str, callback: Callable) -> None:
        """Register a hook for module events."""
        if event in self.hooks:
            self.hooks[event].append(callback)
            logger.debug(f"Registered hook for {event}")
        else:
            logger.warning(f"Unknown hook event: {event}")
    
    def discover_modules(self) -> List[str]:
        """Discover available modules in registered paths."""
        discovered = []
        
        for path in self.module_paths:
            try:
                for module_dir in path.iterdir():
                    if module_dir.is_dir() and not module_dir.name.startswith('_'):
                        # Look for __init__.py or main.py
                        init_file = module_dir / "__init__.py"
                        main_file = module_dir / "main.py"
                        
                        if init_file.exists() or main_file.exists():
                            discovered.append(module_dir.name)
                            logger.debug(f"Discovered module: {module_dir.name}")
            except Exception as e:
                logger.error(f"Error discovering modules in {path}: {e}")
        
        return discovered
    
    def load_module(self, module_name: str, module_path: Optional[str] = None) -> bool:
        """Load a module by name."""
        with self._lock:
            try:
                # Check if already loaded
                if module_name in self.modules:
                    if self.modules[module_name].status == ModuleStatus.LOADED:
                        logger.warning(f"Module {module_name} is already loaded")
                        return True
                
                # Create module info
                if module_name not in self.modules:
                    self.modules[module_name] = ModuleInfo(
                        name=module_name,
                        path=module_path or "",
                        status=ModuleStatus.LOADING
                    )
                
                module_info = self.modules[module_name]
                module_info.status = ModuleStatus.LOADING
                
                # Execute before_load hooks
                self._execute_hooks('before_load', module_name)
                
                # Find module path if not provided
                if not module_path:
                    module_path = self._find_module_path(module_name)
                    if not module_path:
                        raise ImportError(f"Module {module_name} not found in any registered path")
                
                # Load the module
                spec = importlib.util.spec_from_file_location(module_name, module_path)
                if spec is None or spec.loader is None:
                    raise ImportError(f"Could not load spec for module {module_name}")
                
                module = importlib.util.module_from_spec(spec)
                
                # Add to sys.modules before execution
                sys.modules[module_name] = module
                
                # Execute the module
                spec.loader.exec_module(module)
                
                # Look for module class or initialize function
                module_instance = None
                if hasattr(module, 'PlexiChatModule'):
                    # Instantiate module class
                    module_class = getattr(module, 'PlexiChatModule')
                    if issubclass(module_class, ModuleInterface):
                        module_instance = module_class()
                        if not module_instance.initialize():
                            raise RuntimeError(f"Module {module_name} failed to initialize")
                elif hasattr(module, 'initialize'):
                    # Call initialize function
                    initialize_func = getattr(module, 'initialize')
                    if not initialize_func():
                        raise RuntimeError(f"Module {module_name} failed to initialize")
                    module_instance = module
                else:
                    # Use module as-is
                    module_instance = module
                
                # Update module info
                module_info.module_instance = module_instance
                module_info.status = ModuleStatus.LOADED
                module_info.path = module_path
                module_info.error_message = None
                
                # Execute after_load hooks
                self._execute_hooks('after_load', module_name)
                
                logger.info(f"Successfully loaded module: {module_name}")
                return True
                
            except Exception as e:
                error_msg = f"Failed to load module {module_name}: {e}"
                logger.error(error_msg)
                logger.debug(traceback.format_exc())
                
                # Update module info with error
                if module_name in self.modules:
                    self.modules[module_name].status = ModuleStatus.ERROR
                    self.modules[module_name].error_message = str(e)
                
                # Execute error hooks
                self._execute_hooks('on_error', module_name, error=e)
                
                # Clean up sys.modules if we added it
                if module_name in sys.modules:
                    del sys.modules[module_name]
                
                return False
    
    def unload_module(self, module_name: str) -> bool:
        """Unload a module."""
        with self._lock:
            try:
                if module_name not in self.modules:
                    logger.warning(f"Module {module_name} is not loaded")
                    return True
                
                module_info = self.modules[module_name]
                
                if module_info.status != ModuleStatus.LOADED:
                    logger.warning(f"Module {module_name} is not in loaded state")
                    return True
                
                # Execute before_unload hooks
                self._execute_hooks('before_unload', module_name)
                
                # Shutdown module if it has the interface
                if (module_info.module_instance and 
                    isinstance(module_info.module_instance, ModuleInterface)):
                    try:
                        module_info.module_instance.shutdown()
                    except Exception as e:
                        logger.error(f"Error shutting down module {module_name}: {e}")
                
                # Remove from sys.modules
                if module_name in sys.modules:
                    del sys.modules[module_name]
                
                # Update module info
                module_info.status = ModuleStatus.UNLOADED
                module_info.module_instance = None
                module_info.error_message = None
                
                # Execute after_unload hooks
                self._execute_hooks('after_unload', module_name)
                
                logger.info(f"Successfully unloaded module: {module_name}")
                return True
                
            except Exception as e:
                error_msg = f"Failed to unload module {module_name}: {e}"
                logger.error(error_msg)
                logger.debug(traceback.format_exc())
                
                # Execute error hooks
                self._execute_hooks('on_error', module_name, error=e)
                
                return False
    
    def reload_module(self, module_name: str) -> bool:
        """Reload a module."""
        module_path = None
        if module_name in self.modules:
            module_path = self.modules[module_name].path
        
        if self.unload_module(module_name):
            return self.load_module(module_name, module_path)
        return False
    
    def get_module(self, module_name: str) -> Optional[Any]:
        """Get a loaded module instance."""
        if module_name in self.modules:
            module_info = self.modules[module_name]
            if module_info.status == ModuleStatus.LOADED:
                return module_info.module_instance
        return None
    
    def list_modules(self) -> Dict[str, ModuleInfo]:
        """List all modules and their status."""
        return self.modules.copy()
    
    def get_module_status(self, module_name: str) -> ModuleStatus:
        """Get the status of a specific module."""
        if module_name in self.modules:
            return self.modules[module_name].status
        return ModuleStatus.UNLOADED
    
    def _find_module_path(self, module_name: str) -> Optional[str]:
        """Find the path to a module."""
        for path in self.module_paths:
            module_dir = path / module_name
            if module_dir.exists() and module_dir.is_dir():
                # Look for __init__.py or main.py
                init_file = module_dir / "__init__.py"
                main_file = module_dir / "main.py"
                
                if init_file.exists():
                    return str(init_file)
                elif main_file.exists():
                    return str(main_file)
        
        return None
    
    def _execute_hooks(self, event: str, module_name: str, **kwargs):
        """Execute hooks for an event."""
        for hook in self.hooks.get(event, []):
            try:
                hook(module_name, **kwargs)
            except Exception as e:
                logger.error(f"Error executing {event} hook: {e}")
    
    def shutdown_all(self) -> None:
        """Shutdown all loaded modules."""
        logger.info("Shutting down all modules...")
        
        for module_name in list(self.modules.keys()):
            if self.modules[module_name].status == ModuleStatus.LOADED:
                self.unload_module(module_name)
        
        logger.info("All modules shut down")


# Global module loader instance
module_loader = ModuleLoader()

# Convenience functions
def load_module(name: str, path: Optional[str] = None) -> bool:
    """Load a module."""
    return module_loader.load_module(name, path)

def unload_module(name: str) -> bool:
    """Unload a module."""
    return module_loader.unload_module(name)

def get_module(name: str) -> Optional[Any]:
    """Get a loaded module."""
    return module_loader.get_module(name)

def list_modules() -> Dict[str, ModuleInfo]:
    """List all modules."""
    return module_loader.list_modules()
