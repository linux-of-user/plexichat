# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Interface Layer - MODERN ARCHITECTURE

Comprehensive interface layer with API versioning and multiple interface types:
- REST API with versioning (v1, v2, beta)
- GraphQL API for flexible queries
- WebSocket API for real-time communication
- CLI interfaces with unified command management
- GUI interfaces with admin tools and wizards
- Web interfaces with modern components
- Terminal interfaces with enhanced features

Uses shared components for consistent error handling and type definitions.
"""

import logging
from typing import Any, Dict, Optional

# Import shared components (NEW ARCHITECTURE)
from ..shared.models import User, Event, Priority, Status
from ..shared.types import JSON, ConfigDict, ApiRequest, ApiResponse
from ..shared.exceptions import ValidationError, AuthorizationError, APIError
from ..shared.constants import API_VERSION, API_PREFIX, MAX_REQUEST_SIZE

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

class InterfaceManager:
    """Enhanced interface manager using EXISTING systems."""

    def __init__(self):
        self.performance_logger = performance_logger
        self.interfaces: Dict[str, bool] = {}

    def register_interface(self, name: str, status: bool = True):
        """Register interface."""
        try:
            self.interfaces[name] = status
            logger.info(f"Registered interface: {name} (status: {status})")

            if self.performance_logger:
                self.performance_logger.record_metric("interfaces_registered", 1, "count")

        except Exception as e:
            logger.error(f"Error registering interface {name}: {e}")

    def is_available(self, name: str) -> bool:
        """Check if interface is available."""
        return self.interfaces.get(name, False)

    def get_status(self) -> Dict[str, Any]:
        """Get interface status."""
        return {
            "interfaces": self.interfaces.copy(),
            "total_interfaces": len(self.interfaces),
            "active_interfaces": sum(1 for status in self.interfaces.values() if status)
        }

# Global interface manager
interface_manager = InterfaceManager()

# Register interfaces
def register_interfaces():
    """Register available interfaces."""
    try:
        # Web interface
        try:
            from plexichat.interfaces.web import app
            interface_manager.register_interface("web", app is not None)
        except ImportError:
            interface_manager.register_interface("web", False)

        # CLI interface
        try:
            from plexichat.interfaces.cli import cli_app
            interface_manager.register_interface("cli", True)
        except ImportError:
            interface_manager.register_interface("cli", False)

        # API interface
        try:
            from plexichat.interfaces.api import api_app
            interface_manager.register_interface("api", True)
        except ImportError:
            interface_manager.register_interface("api", False)

        logger.info("Interfaces registered successfully")

    except Exception as e:
        logger.error(f"Error registering interfaces: {e}")

# Initialize interfaces
register_interfaces()

# Interface availability checks
def web_available() -> bool:
    """Check if web interface is available."""
    return interface_manager.is_available("web")

def cli_available() -> bool:
    """Check if CLI interface is available."""
    return interface_manager.is_available("cli")

def api_available() -> bool:
    """Check if API interface is available."""
    return interface_manager.is_available("api")

# Safe imports with error handling
def import_interface_modules():
    """Import interface modules with error handling."""
    try:
        # Web interface
        if web_available():
            try:
                from .web import app
                logger.info("Web interface imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import web interface: {e}")

        # CLI interface
        if cli_available():
            try:
                from .cli import cli_app
                logger.info("CLI interface imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import CLI interface: {e}")

        # API interface
        if api_available():
            try:
                from .api import api_app
                logger.info("API interface imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import API interface: {e}")

    except Exception as e:
        logger.error(f"Error importing interface modules: {e}")

# Import interface modules
import_interface_modules()

# Export commonly used items
__all__ = [
    # Shared components re-exports
    "User",
    "Event",
    "Priority",
    "Status",
    "JSON",
    "ConfigDict",
    "ApiRequest",
    "ApiResponse",
    "ValidationError",
    "AuthorizationError",
    "APIError",

    # Interface components
    "interface_manager",
    "web_available",
    "cli_available",
    "api_available",
]

# Version info
__version__ = "3.0.0"
