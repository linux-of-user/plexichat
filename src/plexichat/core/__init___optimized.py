"""
PlexiChat Core

Enhanced core module with comprehensive functionality and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import logging
from typing import Any, Dict, Optional

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core_system.logging.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

class CoreManager:
    """Enhanced core manager using EXISTING systems."""
    
    def __init__(self):
        self.performance_logger = performance_logger
        self.components: Dict[str, bool] = {}
    
    def register_component(self, name: str, status: bool = True):
        """Register core component."""
        try:
            self.components[name] = status
            logger.info(f"Registered core component: {name} (status: {status})")
            
            if self.performance_logger:
                self.performance_logger.record_metric("core_components_registered", 1, "count")
                
        except Exception as e:
            logger.error(f"Error registering component {name}: {e}")
    
    def is_available(self, name: str) -> bool:
        """Check if component is available."""
        return self.components.get(name, False)
    
    def get_status(self) -> Dict[str, Any]:
        """Get core status."""
        return {
            "components": self.components.copy(),
            "total_components": len(self.components),
            "active_components": sum(1 for status in self.components.values() if status)
        }

# Global core manager
core_manager = CoreManager()

# Register core components
def register_core_components():
    """Register core components."""
    try:
        # Configuration
        try:
            from plexichat.core.config import settings, config_manager
            core_manager.register_component("config", True)
        except ImportError:
            core_manager.register_component("config", False)
        
        # Logging
        try:
            from plexichat.core.logging import logging_manager
            core_manager.register_component("logging", True)
        except ImportError:
            core_manager.register_component("logging", False)
        
        # Exceptions
        try:
            from plexichat.core.exceptions import exception_handler
            core_manager.register_component("exceptions", True)
        except ImportError:
            core_manager.register_component("exceptions", False)
        
        # Authentication
        try:
            from plexichat.core.auth.auth_core import auth_core
            from plexichat.core.auth.manager_auth import auth_manager
            core_manager.register_component("auth", True)
        except ImportError:
            core_manager.register_component("auth", False)
        
        # Database
        try:
            from plexichat.core.database import database_manager
            core_manager.register_component("database", database_manager is not None)
        except ImportError:
            core_manager.register_component("database", False)
        
        logger.info("Core components registered successfully")
        
    except Exception as e:
        logger.error(f"Error registering core components: {e}")

# Initialize core components
register_core_components()

# Component availability checks
def config_available() -> bool:
    """Check if config is available."""
    return core_manager.is_available("config")

def logging_available() -> bool:
    """Check if logging is available."""
    return core_manager.is_available("logging")

def exceptions_available() -> bool:
    """Check if exceptions are available."""
    return core_manager.is_available("exceptions")

def auth_available() -> bool:
    """Check if auth is available."""
    return core_manager.is_available("auth")

def database_available() -> bool:
    """Check if database is available."""
    return core_manager.is_available("database")

# Safe imports with error handling
def import_core_modules():
    """Import core modules with error handling."""
    try:
        # Config
        if config_available():
            try:
                from .config import settings, config_manager
                logger.info("Config imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import config: {e}")
        
        # Logging
        if logging_available():
            try:
                from .logging import logging_manager, get_logger
                logger.info("Logging imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import logging: {e}")
        
        # Exceptions
        if exceptions_available():
            try:
                from .exceptions import exception_handler, handle_exception
                logger.info("Exceptions imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import exceptions: {e}")
        
        # Auth
        if auth_available():
            try:
                from .auth import auth_core, auth_manager
                logger.info("Auth imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import auth: {e}")
        
        # Database
        if database_available():
            try:
                from .database import database_manager, initialize_database_system
                logger.info("Database imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import database: {e}")
        
    except Exception as e:
        logger.error(f"Error importing core modules: {e}")

# Import core modules
import_core_modules()

# Export commonly used items
__all__ = [
    "core_manager",
    "config_available",
    "logging_available",
    "exceptions_available",
    "auth_available",
    "database_available",
]

# Version info
__version__ = "1.0.0"
