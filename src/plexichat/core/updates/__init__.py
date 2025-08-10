"""
PlexiChat Updates System

This package contains update-related functionality.
"""

from plexichat.core.unified_config import get_config

__version__ = get_config("system.version", "0.0.0")
__all__ = []
