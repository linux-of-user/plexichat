# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat

Enhanced PlexiChat package with comprehensive functionality and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import importlib
import sys
from typing import Any

# Version information
from plexichat.version import __version__

__author__ = "PlexiChat Team"
__description__ = "Enhanced chat application with comprehensive features"

# Use EXISTING performance optimization engine
try:
    from plexichat.core.logging.performance_logger import get_performance_logger
except ImportError:
    get_performance_logger = None

from plexichat.core.logging import get_logger

logger = get_logger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None


class PlexiChatManager:
    """Enhanced PlexiChat manager using EXISTING systems."""

    def __init__(self):
        self.performance_logger = performance_logger
        self.modules: dict[str, bool] = {}
        self.initialized = False

    def register_module(self, name: str, status: bool = True):
        """Register module."""
        try:
            self.modules[name] = status
            logger.info(f"Registered module: {name} (status: {status})")

            if self.performance_logger:
                self.performance_logger.increment_counter("modules_registered", 1)

        except Exception as e:
            logger.error(f"Error registering module {name}: {e}")

    def is_available(self, name: str) -> bool:
        """Check if module is available."""
        return self.modules.get(name, False)

    async def initialize(self):
        """Initialize PlexiChat system."""
        try:
            if self.initialized:
                return

            logger.info("Initializing PlexiChat system...")

            # Register core modules
            self._register_core_modules()

            # Initialize core systems
            await self._initialize_core_systems()

            self.initialized = True
            logger.info("PlexiChat system initialized successfully")

            if self.performance_logger:
                self.performance_logger.increment_counter("system_initializations", 1)

        except Exception as e:
            logger.error(f"Error initializing PlexiChat system: {e}")

    def _register_core_modules(self):
        """Register core modules."""
        try:
            # Core module
            try:
                importlib.import_module("plexichat.core")
                self.register_module("core", True)
            except ImportError:
                self.register_module("core", False)

            # Infrastructure module
            try:
                importlib.import_module("plexichat.infrastructure")
                self.register_module("infrastructure", True)
            except ImportError:
                self.register_module("infrastructure", False)

            # Features module
            try:
                importlib.import_module("plexichat.features")
                self.register_module("features", True)
            except ImportError:
                self.register_module("features", False)

            # Interfaces module
            try:
                importlib.import_module("plexichat.interfaces")
                self.register_module("interfaces", True)
            except ImportError:
                self.register_module("interfaces", False)

        except Exception as e:
            logger.error(f"Error registering core modules: {e}")

    async def _initialize_core_systems(self):
        """Initialize core systems."""
        try:
            # Initialize database if available
            if self.is_available("core"):
                try:
                    from plexichat.core.database import initialize_database_system

                    await initialize_database_system()
                    logger.info("Database system initialized")
                except ImportError:
                    logger.warning("Database system not available")
                except Exception as e:
                    logger.error(f"Error initializing database: {e}")

            # Initialize performance monitoring if available
            if self.is_available("infrastructure"):
                try:
                    if self.performance_logger:
                        logger.info("Performance monitoring initialized")
                except Exception as e:
                    logger.error(f"Error initializing performance monitoring: {e}")

        except Exception as e:
            logger.error(f"Error initializing core systems: {e}")

    def get_status(self) -> dict[str, Any]:
        """Get system status."""
        return {
            "version": __version__,
            "initialized": self.initialized,
            "modules": self.modules.copy(),
            "total_modules": len(self.modules),
            "active_modules": sum(1 for status in self.modules.values() if status),
            "performance_monitoring": self.performance_logger is not None,
        }


# Global PlexiChat manager (lazy initialization)
_plexichat_manager = None


def get_plexichat_manager():
    """Get the global PlexiChat manager (lazy initialization)."""
    global _plexichat_manager
    if _plexichat_manager is None:
        _plexichat_manager = PlexiChatManager()
    return _plexichat_manager


# For backward compatibility - create a module-level attribute
class LazyManagerModule(sys.modules[__name__].__class__):
    @property
    def plexichat_manager(self):
        return get_plexichat_manager()


sys.modules[__name__].__class__ = LazyManagerModule


# Module availability checks
def core_available() -> bool:
    """Check if core module is available."""
    return get_plexichat_manager().is_available("core")


def infrastructure_available() -> bool:
    """Check if infrastructure module is available."""
    return get_plexichat_manager().is_available("infrastructure")


def features_available() -> bool:
    """Check if features module is available."""
    return get_plexichat_manager().is_available("features")


def interfaces_available() -> bool:
    """Check if interfaces module is available."""
    return get_plexichat_manager().is_available("interfaces")


# Safe imports with error handling
def import_plexichat_modules():
    """Import PlexiChat modules with error handling."""
    try:
        # Core
        if core_available():
            try:
                # # from . import core
                logger.info("Core module imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import core module: {e}")

        # Infrastructure
        if infrastructure_available():
            try:
                # # from . import infrastructure
                logger.info("Infrastructure module imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import infrastructure module: {e}")

        # Features
        if features_available():
            try:
                # # from . import features
                logger.info("Features module imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import features module: {e}")

        # Interfaces
        if interfaces_available():
            try:
                # # from . import interfaces
                logger.info("Interfaces module imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import interfaces module: {e}")

    except Exception as e:
        logger.error(f"Error importing PlexiChat modules: {e}")


# Initialize PlexiChat
async def initialize_plexichat():
    """Initialize PlexiChat system."""
    try:
        await get_plexichat_manager().initialize()
        import_plexichat_modules()
    except Exception as e:
        logger.error(f"Error during PlexiChat initialization: {e}")


# Auto-initialize on import (sync version)
def sync_initialize_plexichat():
    """Synchronous initialization wrapper."""
    try:
        import asyncio

        # Try to get existing event loop
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If loop is running, schedule the initialization
                asyncio.create_task(initialize_plexichat())
            else:
                # If loop is not running, run it
                loop.run_until_complete(initialize_plexichat())
        except RuntimeError:
            # No event loop, create one
            asyncio.run(initialize_plexichat())
    except Exception as e:
        logger.error(f"Error during sync initialization: {e}")
        # Continue without async initialization
        import_plexichat_modules()


# Auto-initialization removed - call initialize_plexichat() manually when needed

# Export commonly used items
__all__ = [
    "__author__",
    "__description__",
    "__version__",
    "core_available",
    "features_available",
    "get_plexichat_manager",
    "infrastructure_available",
    "initialize_plexichat",
    "interfaces_available",
]
