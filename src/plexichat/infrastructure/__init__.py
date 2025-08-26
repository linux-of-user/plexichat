# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Infrastructure Services - MODERN ARCHITECTURE

Comprehensive infrastructure layer with:
- Service discovery and management
- Performance optimization engines
- Caching and message queuing
- Microservices architecture
- Event-driven communication
- Analytics and monitoring
- Containerization and orchestration
- Background task processing

Uses shared components for consistent error handling and type definitions.
"""

import logging
from typing import Any, Dict
import importlib

# Import shared components (NEW ARCHITECTURE)
from plexichat.shared.models import Event, Priority, Status
from plexichat.shared.types import JSON, ConfigDict
from plexichat.shared.exceptions import ServiceUnavailableError, ValidationError
# from ..shared.constants import *  # Removed due to invalid wildcard import

# Infrastructure imports

# Use EXISTING performance optimization engine
try:
    from plexichat.core.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

class InfrastructureManager:
    """Enhanced infrastructure manager using EXISTING systems."""

    def __init__(self):
        self.performance_logger = performance_logger
        self.optimization_engine = PerformanceOptimizationEngine() if PerformanceOptimizationEngine else None
        self.components: Dict[str, bool] = {}

    def register_component(self, name: str, status: bool = True):
        """Register infrastructure component."""
        try:
            self.components[name] = status
            logger.info(f"Registered infrastructure component: {name} (status: {status})")

            if self.performance_logger:
                self.performance_logger.record_metric("infrastructure_components_registered", 1, "count")

        except Exception as e:
            logger.error(f"Error registering component {name}: {e}")

    def is_available(self, name: str) -> bool:
        """Check if component is available."""
        return self.components.get(name, False)

    def get_status(self) -> Dict[str, Any]:
        """Get infrastructure status."""
        return {
            "components": self.components.copy(),
            "optimization_engine": self.optimization_engine is not None,
            "performance_logger": self.performance_logger is not None,
            "total_components": len(self.components),
            "active_components": sum(1 for status in self.components.values() if status)
        }

# Global infrastructure manager
infrastructure_manager = InfrastructureManager()

# Register core infrastructure components
def register_core_components():
    """Register core infrastructure components."""
    try:
        # Database components
        try:
            from plexichat.core.database.manager import database_manager
            infrastructure_manager.register_component("database_manager", database_manager is not None)
        except ImportError:
            infrastructure_manager.register_component("database_manager", False)

        # Performance components
        infrastructure_manager.register_component("performance_optimization", PerformanceOptimizationEngine is not None)
        infrastructure_manager.register_component("performance_logger", performance_logger is not None)

        # Utility components
        try:
            importlib.import_module("plexichat.infrastructure.utils")
            infrastructure_manager.register_component("auth_utils", True)
            infrastructure_manager.register_component("security_utils", True)
            infrastructure_manager.register_component("performance_utils", True)
            infrastructure_manager.register_component("validation_utils", True)
            infrastructure_manager.register_component("helper_utils", True)
        except ImportError as e:
            logger.warning(f"Some utility components not available: {e}")
            infrastructure_manager.register_component("auth_utils", False)
            infrastructure_manager.register_component("security_utils", False)
            infrastructure_manager.register_component("performance_utils", False)
            infrastructure_manager.register_component("validation_utils", False)
            infrastructure_manager.register_component("helper_utils", False)

        # Caching components
        try:
            importlib.import_module("plexichat.infrastructure.caching")
            infrastructure_manager.register_component("cache_manager", True)
        except ImportError:
            infrastructure_manager.register_component("cache_manager", False)

        # Monitoring components
        try:
            importlib.import_module("plexichat.infrastructure.monitoring")
            infrastructure_manager.register_component("monitoring", True)
        except ImportError:
            infrastructure_manager.register_component("monitoring", False)

        logger.info("Core infrastructure components registered successfully")

    except Exception as e:
        logger.error(f"Error registering core infrastructure components: {e}")

# Initialize core components
register_core_components()

# Component availability checks
def database_available() -> bool:
    """Check if database components are available."""
    return infrastructure_manager.is_available("database_manager")

def performance_available() -> bool:
    """Check if performance components are available."""
    return (
        infrastructure_manager.is_available("performance_optimization")
        and infrastructure_manager.is_available("performance_logger")
    )

def auth_available() -> bool:
    """Check if auth utilities are available."""
    return infrastructure_manager.is_available("auth_utils")

def security_available() -> bool:
    """Check if security utilities are available."""
    return infrastructure_manager.is_available("security_utils")

def validation_available() -> bool:
    """Check if validation utilities are available."""
    return infrastructure_manager.is_available("validation_utils")

def cache_available() -> bool:
    """Check if caching is available."""
    return infrastructure_manager.is_available("cache_manager")

def monitoring_available() -> bool:
    """Check if monitoring is available."""
    return infrastructure_manager.is_available("monitoring")

# Safe imports with error handling
def import_infrastructure_modules():
    """Import infrastructure modules with error handling."""
    try:
        # Utils modules
        # Import consolidated utils
        try:
            importlib.import_module("plexichat.infrastructure.utils")
            logger.info("Infrastructure utils imported successfully")
        except ImportError as e:
            logger.warning(f"Could not import infrastructure utils: {e}")

        if validation_available():
            try:
                importlib.import_module("plexichat.infrastructure.utils.validation")
                logger.info("Validation utils imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import validation utils: {e}")

        # Performance optimization
        if performance_available():
            try:
                importlib.import_module("plexichat.core.performance")
                logger.info("Performance optimization imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import performance optimization: {e}")

        # Caching
        if cache_available():
            try:
                importlib.import_module("plexichat.infrastructure.caching")
                logger.info("Cache manager imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import cache manager: {e}")

        # Monitoring
        if monitoring_available():
            try:
                importlib.import_module("plexichat.infrastructure.monitoring")
                logger.info("Monitoring imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import monitoring: {e}")

    except Exception as e:
        logger.error(f"Error importing infrastructure modules: {e}")

# Import infrastructure modules
import_infrastructure_modules()

# Export commonly used items
__all__ = [
    # Shared components re-exports
    "Event",
    "Priority",
    "Status",
    "JSON",
    "ConfigDict",
    "ServiceUnavailableError",
    "ValidationError",

    # Infrastructure components
    "infrastructure_manager",
    "database_available",
    "performance_available",
    "auth_available",
    "security_available",
    "validation_available",
    "cache_available",
    "monitoring_available",
]

# Version info
from plexichat.core.unified_config import get_config

__version__ = get_config("system.version", "0.0.0")
