"""Core threading module with fallback implementations."""

from plexichat.core.utils.fallbacks import ThreadingManager, get_module_version

__version__ = get_module_version()
__all__ = ["ThreadingManager"]
