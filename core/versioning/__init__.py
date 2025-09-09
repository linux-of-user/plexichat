"""Core versioning module with fallback implementations."""

from plexichat.core.utils.fallbacks import VersionManager, get_module_version

__version__ = get_module_version()
__all__ = ["VersionManager"]
