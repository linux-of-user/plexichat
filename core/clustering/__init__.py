"""Core clustering module with fallback implementations."""

try:
    from plexichat.core.utils.fallbacks import ClusterManager, get_module_version
except ImportError:
    # Retain old fallbacks
    pass

__version__ = get_module_version()
__all__ = ["ClusterManager"]
