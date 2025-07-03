"""
NetLink - Modern Distributed Communication Platform
"""

__version__ = "1.0.0"
__author__ = "NetLink Team"
__description__ = "Modern distributed communication platform with real-time messaging, hot updates, and multi-server clustering"
__url__ = "https://github.com/linux-of-user/netlink"

# Version info
VERSION_INFO = {
    "major": 1,
    "minor": 0,
    "patch": 0,
    "pre_release": None,
    "build": None
}

def get_version():
    """Get version string."""
    version = f"{VERSION_INFO['major']}.{VERSION_INFO['minor']}.{VERSION_INFO['patch']}"
    if VERSION_INFO['pre_release']:
        version += f"-{VERSION_INFO['pre_release']}"
    if VERSION_INFO['build']:
        version += f"+{VERSION_INFO['build']}"
    return version

# Export main components (lazy imports to avoid circular dependencies)
def get_app():
    """Get the FastAPI app instance."""
    from .app.main import app
    return app

def get_launcher():
    """Get the NetLink launcher."""
    from .core.launcher import NetLinkLauncher
    return NetLinkLauncher

__all__ = [
    "get_app",
    "get_launcher",
    "get_version"
]
