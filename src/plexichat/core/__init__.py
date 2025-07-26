# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
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
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

from .logging import get_logger
logger = get_logger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

from .config import Settings
settings = Settings()

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

# Import new core modules
try:
    from .config import config_manager, get_config, set_config
    core_manager.register_component("config_new", True)
except ImportError:
    config_manager = None
    get_config = None
    set_config = None
    core_manager.register_component("config_new", False)

try:
    from .threading import thread_manager, async_thread_manager
    core_manager.register_component("threading", True)
except ImportError:
    thread_manager = None
    async_thread_manager = None
    core_manager.register_component("threading", False)

try:
    from .caching import cache_manager
    core_manager.register_component("caching", True)
except ImportError:
    cache_manager = None
    core_manager.register_component("caching", False)

try:
    from .analytics import analytics_manager, track_event
    core_manager.register_component("analytics", True)
except ImportError:
    analytics_manager = None
    track_event = None
    core_manager.register_component("analytics", False)

try:
    from .monitoring import system_monitor, start_monitoring
    core_manager.register_component("monitoring", True)
except ImportError:
    system_monitor = None
    start_monitoring = None
    core_manager.register_component("monitoring", False)

try:
    from .scheduler import task_scheduler
    core_manager.register_component("scheduler", True)
except ImportError:
    task_scheduler = None
    core_manager.register_component("scheduler", False)

try:
    from .backup import backup_manager
    core_manager.register_component("backup", True)
except ImportError:
    backup_manager = None
    core_manager.register_component("backup", False)

try:
    from .plugins import plugin_manager
    core_manager.register_component("plugins", True)
except ImportError:
    plugin_manager = None
    core_manager.register_component("plugins", False)

try:
    from .events import event_manager, emit_event
    core_manager.register_component("events", True)
except ImportError:
    event_manager = None
    emit_event = None
    core_manager.register_component("events", False)

try:
    from .middleware import middleware_manager
    core_manager.register_component("middleware", True)
except ImportError:
    middleware_manager = None
    core_manager.register_component("middleware", False)

try:
    from .validation import validator, validate_data
    core_manager.register_component("validation", True)
except ImportError:
    validator = None
    validate_data = None
    core_manager.register_component("validation", False)

try:
    from .utils import generate_id, current_timestamp
    core_manager.register_component("utils", True)
except ImportError:
    generate_id = None
    current_timestamp = None
    core_manager.register_component("utils", False)

# Load from config files instead of constants
try:
    import json
    from pathlib import Path

    # Load version from version.json
    version_file = Path(__file__).parent.parent.parent / "version.json"
    if version_file.exists():
        with open(version_file, 'r') as f:
            version_data = json.load(f)
            APP_NAME = "PlexiChat"
            APP_VERSION = version_data.get('current_version', 'a.1.1-144')
    else:
        APP_NAME = "PlexiChat"
        APP_VERSION = "a.1.1-144"

    # Load config from config file
    config_file = Path(__file__).parent.parent.parent / "config" / "plexichat.json"
    if config_file.exists():
        with open(config_file, 'r') as f:
            DEFAULT_CONFIG = json.load(f)
    else:
        DEFAULT_CONFIG = {}

    core_manager.register_component("constants", True)
except Exception:
    APP_NAME = "PlexiChat"
    APP_VERSION = "a.1.1-144"
    DEFAULT_CONFIG = {}
    core_manager.register_component("constants", False)

# Register core components
def register_core_components():
    """Register core components."""
    try:
        # Configuration
        try:
            from plexichat.core.config import config_manager
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
                from .config import config_manager
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
