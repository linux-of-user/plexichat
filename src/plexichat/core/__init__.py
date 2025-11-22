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

import importlib
from typing import Any, Dict, Optional

# Import consolidated systems
from plexichat.core.logging.logger import get_logger

logger = get_logger(__name__)

try:
    from plexichat.core.config_manager import get_config

    config: Any | None = get_config()
except ImportError:
    config: Any | None = None
    logger.warning("Configuration system not available")

try:
    from plexichat.core.security import get_security_manager

    security_manager: Any | None = get_security_manager()
except ImportError:
    security_manager: Any | None = None
    logger.warning("Security system not available")

try:
    from plexichat.core.authentication import get_auth_manager

    auth_manager: Any | None = get_auth_manager()
except ImportError:
    auth_manager: Any | None = None
    logger.warning("Authentication system not available")

try:
    from plexichat.core.database import get_database_manager

    database_manager: Any | None = get_database_manager()
except ImportError:
    database_manager: Any | None = None
    logger.warning("Database system not available")

try:
    from plexichat.core.errors.manager import get_error_manager

    error_manager: Any | None = get_error_manager()
except ImportError:
    error_manager: Any | None = None
    logger.warning("Error handling system not available")

try:
    from plexichat.core.services import get_service_manager

    service_manager: Any | None = get_service_manager()
except ImportError:
    service_manager: Any | None = None
    logger.warning("Service management system not available")


class CoreManager:
    """Enhanced core manager using consolidated systems."""

    def __init__(self):
        self.components: dict[str, bool] = {}
        self.managers: dict[str, Any | None] = {
            "config": config,
            "security": security_manager,
            "auth": auth_manager,
            "database": database_manager,
            "errors": error_manager,
            "services": service_manager,
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

    def get_status(self) -> dict[str, Any]:
        """Get core status."""
        return {
            "components": self.components.copy(),
            "managers": {
                name: manager is not None for name, manager in self.managers.items()
            },
            "total_components": len(self.components),
            "active_components": sum(
                1 for status in self.components.values() if status
            ),
            "available_managers": sum(
                1 for manager in self.managers.values() if manager is not None
            ),
        }

    def get_manager(self, name: str) -> Any | None:
        """Get a specific manager."""
        return self.managers.get(name)

    def is_secure(self) -> bool:
        """Check if security systems are properly initialized."""
        return (
            self.managers["security"] is not None
            and self.managers["auth"] is not None
            and self.managers["errors"] is not None
        )


# Global core manager
core_manager: CoreManager = CoreManager()

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

        # Authentication (use unified authentication module)
        try:
            importlib.import_module("plexichat.core.authentication")
            # Ensure the unified auth manager is initialized
            try:
                from plexichat.core.authentication import (
                    get_auth_manager as _get_auth_manager,
                )

                global auth_manager
                if auth_manager is None:
                    try:
                        auth_manager = _get_auth_manager()
                        core_manager.managers["auth"] = auth_manager
                    except Exception as e:
                        logger.warning(f"Failed to initialize auth manager: {e}")
                        core_manager.register_component("auth", False)
                        raise
                core_manager.register_component("auth", True)
            except Exception as e:
                # If importing get_auth_manager fails, consider auth unavailable
                logger.warning(
                    f"Authentication module imported but failed to initialize: {e}"
                )
                core_manager.register_component("auth", False)
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
    """Check if exceptions is available."""
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
                importlib.import_module("plexichat.core.authentication")
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
    "auth_available",
    "config_available",
    "core_manager",
    "database_available",
    "exceptions_available",
    "logging_available",
]

# Version info
from plexichat.core.config import settings

__version__: str = settings.version
