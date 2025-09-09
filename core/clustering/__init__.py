"""Core clustering module with fallback implementations."""

from plexichat.core.utils.fallbacks import ClusterManager, get_module_version

__version__ = get_module_version()
__all__ = ["ClusterManager"]
