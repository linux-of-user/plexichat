"""
PlexiChat - Government-Level Secure Communication Platform
=========================================================

A comprehensive communication platform with enterprise-grade features.
"""

__version__ = "a.1.1-16"
__author__ = "PlexiChat Team"
__description__ = "Government-Level Secure Communication Platform"

# Version information
VERSION_INFO = {
    "version": "a.1.1-16",
    "version_type": "alpha",
    "major_version": 1,
    "minor_version": 1,
    "build_number": 16,
    "api_version": "v1"
}

# Export main components
try:
    from .main import app, create_app
except ImportError:
    app = None
    create_app = None

__all__ = [
    "__version__",
    "__author__", 
    "__description__",
    "VERSION_INFO",
    "app",
    "create_app"
]
