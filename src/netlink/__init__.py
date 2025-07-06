"""
NetLink - Quantum-Secure Distributed Communication Platform

Enhanced with government-level security, quantum-proof encryption,
intelligent optimization, and advanced service architecture.
"""

__version__ = "2.0.0"
__build__ = "quantum-secure"
__author__ = "NetLink Team"
__description__ = "Quantum-secure distributed communication platform with government-level encryption, intelligent optimization, and advanced service architecture"
__url__ = "https://github.com/linux-of-user/netlink"

# Version info
VERSION_INFO = {
    "major": 2,
    "minor": 0,
    "patch": 0,
    "pre_release": None,
    "build": "quantum-secure"
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

def get_security_manager():
    """Get the security manager."""
    from .security import security_manager
    return security_manager

def get_optimization_manager():
    """Get the optimization manager."""
    from .optimization import optimization_manager
    return optimization_manager

def get_service_manager():
    """Get the service manager."""
    from .services.service_manager import service_manager
    return service_manager

def get_backup_system():
    """Get the quantum backup system."""
    from .backup import quantum_backup_system
    return quantum_backup_system

__all__ = [
    "get_app",
    "get_launcher",
    "get_version",
    "get_security_manager",
    "get_optimization_manager",
    "get_service_manager",
    "get_backup_system"
]
