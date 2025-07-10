"""
NetLink API v1 - Plugins Module

Plugin management, marketplace, and extension features.
"""

try:
    from .plugins import router as plugins_router
except ImportError:
    plugins_router = None

try:
    from .enhanced_plugins import router as enhanced_plugins_router
except ImportError:
    enhanced_plugins_router = None

__all__ = [
    "plugins_router",
    "enhanced_plugins_router"
]
