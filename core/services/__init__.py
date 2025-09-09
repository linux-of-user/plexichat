"""Core services module with fallback implementations."""

from plexichat.core.utils.fallbacks import (
    ServiceManager,
    get_module_version,
    get_service_manager,
)

__version__ = get_module_version()
__all__ = ["ServiceManager", "get_service_manager"]
