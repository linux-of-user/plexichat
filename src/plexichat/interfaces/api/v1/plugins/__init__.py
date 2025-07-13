    from .enhanced_plugins import router as enhanced_plugins_router
    from .plugins import router as plugins_router

"""
PlexiChat API v1 - Plugins Module

Plugin management, marketplace, and extension features.
"""

try:
except ImportError:
    plugins_router = None

try:
except ImportError:
    enhanced_plugins_router = None

__all__ = [
    "plugins_router",
    "enhanced_plugins_router"
]
