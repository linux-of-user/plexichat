"""Core services module with fallback implementations."""
try:
    from plexichat.core.utils.fallbacks import ServiceManager, get_service_manager, get_module_version
except ImportError:
    # Retain old fallbacks
    pass

__version__ = get_module_version()
__all__ = ["ServiceManager", "get_service_manager"]