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

from typing import Any, Dict
import importlib

# Import consolidated systems
try:
    from .logging import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

try:
    from .configuration import get_config
    config = get_config()
except ImportError:
    config = None
    logger.warning("Configuration system not available")

try:
    from .security import get_security_manager
    security_manager = get_security_manager()
except ImportError:
    security_manager = None
    logger.warning("Security system not available")

try:
    from .authentication import get_auth_manager
    auth_manager = get_auth_manager()
except ImportError:
    auth_manager = None
    logger.warning("Authentication system not available")

try:
    from .data import get_database_manager
    database_manager = get_database_manager()
except ImportError:
    database_manager = None
    logger.warning("Database system not available")

try:
    from .errors import get_error_manager
    error_manager = get_error_manager()
except ImportError:
    error_manager = None
    logger.warning("Error handling system not available")

try:
    from .services import get_service_manager
    service_manager = get_service_manager()
except ImportError:
    service_manager = None
    logger.warning("Service management system not available")

class CoreManager:
    """Enhanced core manager using consolidated systems."""

    def __init__(self):
        self.components: Dict[str, bool] = {}
        self.managers = {
            'config': config,
            'security': security_manager,
            'auth': auth_manager,
            'database': database_manager,
            'errors': error_manager,
            'services': service_manager
        }

    def register_component(self, name: str, status: bool = True):
        """Register core component."""
        try:
            self.components[name] = status
            logger.info(f"Registered core component: {name} (status: {status})")
        except Exception as e:
            logger.error(f"Error registering component {name}: {e}")

    def is_available(self, name: str) -> bool:
        """Check if component is available."""
        return self.components.get(name, False)

    def get_status(self) -> Dict[str, Any]:
        """Get core status."""
        return {
            "components": self.components.copy(),
            "managers": {name: manager is not None for name, manager in self.managers.items()},
            "total_components": len(self.components),
            "active_components": sum(1 for status in self.components.values() if status),
            "available_managers": sum(1 for manager in self.managers.values() if manager is not None)
        }

    def get_manager(self, name: str):
        """Get a specific manager."""
        return self.managers.get(name)

    def is_secure(self) -> bool:
        """Check if security systems are properly initialized."""
        return (self.managers['security'] is not None and
                self.managers['auth'] is not None and
                self.managers['errors'] is not None)

# Global core manager
core_manager = CoreManager()

# Import new core modules
try:
    importlib.import_module("plexichat.core.config")
    core_manager.register_component("config_new", True)
except ImportError:
    core_manager.register_component("config_new", False)

try:
    importlib.import_module("plexichat.core.threading")
    core_manager.register_component("threading", True)
except ImportError:
    core_manager.register_component("threading", False)

try:
    importlib.import_module("plexichat.core.caching")
    core_manager.register_component("caching", True)
except ImportError:
    core_manager.register_component("caching", False)

try:
    importlib.import_module("plexichat.core.analytics")
    core_manager.register_component("analytics", True)
except ImportError:
    core_manager.register_component("analytics", False)

try:
    importlib.import_module("plexichat.core.monitoring")
    core_manager.register_component("monitoring", True)
except ImportError:
    core_manager.register_component("monitoring", False)

try:
    importlib.import_module("plexichat.core.scheduler")
    core_manager.register_component("scheduler", True)
except ImportError:
    core_manager.register_component("scheduler", False)

try:
    importlib.import_module("plexichat.core.backup")
    core_manager.register_component("backup", True)
except ImportError:
    core_manager.register_component("backup", False)

try:
    importlib.import_module("plexichat.core.plugins")
    core_manager.register_component("plugins", True)
except ImportError:
    core_manager.register_component("plugins", False)

try:
    importlib.import_module("plexichat.core.events")
    core_manager.register_component("events", True)
except ImportError:
    core_manager.register_component("events", False)

try:
    importlib.import_module("plexichat.core.middleware")
    core_manager.register_component("middleware", True)
except ImportError:
    core_manager.register_component("middleware", False)

try:
    importlib.import_module("plexichat.core.validation")
    core_manager.register_component("validation", True)
except ImportError:
    core_manager.register_component("validation", False)

try:
    importlib.import_module("plexichat.core.utils")
    core_manager.register_component("utils", True)
except ImportError:
    core_manager.register_component("utils", False)

# Load from config files instead of constants
def _load_constants():
    """Load constants from config files."""
    try:
        import json
        from pathlib import Path

        # Load version from version.json
        version_file = Path(__file__).parent.parent.parent / "version.json"
        if version_file.exists():
            with open(version_file, 'r') as f:
                version_data = json.load(f)
                app_name = "PlexiChat"
                app_version = version_data.get('version', 'b.1.1-88')
        else:
            app_name = "PlexiChat"
            app_version = "b.1.1-88"

        # Load config from config file
        config_file = Path(__file__).parent.parent.parent / "config" / "plexichat.json"
        if config_file.exists():
            with open(config_file, 'r') as f:
                default_config = json.load(f)
        else:
            default_config = {}

        core_manager.register_component("constants", True)
        return app_name, app_version, default_config
    except Exception:
        core_manager.register_component("constants", False)
        return "PlexiChat", "a.1.1-144", {}

APP_NAME, APP_VERSION, DEFAULT_CONFIG = _load_constants()

# Register core components
def register_core_components():
    """Register core components."""
    try:
        # Configuration
        try:
            importlib.import_module("plexichat.core.config")
            core_manager.register_component("config", True)
        except ImportError:
            core_manager.register_component("config", False)

        # Logging
        try:
            importlib.import_module("plexichat.core.logging")
            core_manager.register_component("logging", True)
        except ImportError:
            core_manager.register_component("logging", False)

        # Exceptions
        try:
            importlib.import_module("plexichat.core.exceptions")
            core_manager.register_component("exceptions", True)
        except ImportError:
            core_manager.register_component("exceptions", False)

        # Authentication
        try:
            importlib.import_module("plexichat.core.auth.auth_core")
            importlib.import_module("plexichat.core.auth.auth_manager")
            core_manager.register_component("auth", True)
        except ImportError:
            core_manager.register_component("auth", False)

        # Database
        try:
            importlib.import_module("plexichat.core.database")
            core_manager.register_component("database", True)
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
                importlib.import_module("plexichat.core.config")
                logger.info("Config imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import config: {e}")

        # Logging
        if logging_available():
            try:
                importlib.import_module("plexichat.core.logging")
                logger.info("Logging imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import logging: {e}")

        # Exceptions
        if exceptions_available():
            try:
                importlib.import_module("plexichat.core.exceptions")
                logger.info("Exceptions imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import exceptions: {e}")

        # Auth
        if auth_available():
            try:
                importlib.import_module("plexichat.core.auth")
                logger.info("Auth imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import auth: {e}")

        # Database
        if database_available():
            try:
                importlib.import_module("plexichat.core.database")
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
