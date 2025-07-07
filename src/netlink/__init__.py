"""
NetLink - Government-Level Secure Communication Platform

Enterprise architecture with comprehensive security and advanced features:
- Government-level security with quantum encryption
- Distributed backup system with intelligent sharding
- Multi-node clustering with load balancing
- AI-powered features with multiple provider support
- Real-time collaboration capabilities
- Plugin marketplace and extensibility
- Zero-knowledge security architecture

Enterprise Architecture:
- Core: Fundamental system components (auth, security, backup, config)
- Services: Business logic with dependency injection
- API: RESTful endpoints with versioning
- Web: Modern responsive user interface
- CLI: Advanced command-line administration
- AI: Multi-provider AI integration
- Plugins: Extensible functionality system
- Tests: Comprehensive testing framework
"""

__version__ = "3.0.0"
__build__ = "enterprise-quantum"
__author__ = "NetLink Development Team"
__description__ = "Government-level secure communication platform with enterprise architecture, quantum encryption, and advanced features"
__url__ = "https://github.com/linux-of-user/netlink"

# Version info
VERSION_INFO = {
    "major": 3,
    "minor": 0,
    "patch": 0,
    "pre_release": None,
    "build": "enterprise-quantum"
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

def get_api_manager():
    """Get the API manager."""
    try:
        from .api import get_api_manager as _get_api_manager
        return _get_api_manager()
    except ImportError:
        return None

def get_web_manager():
    """Get the web interface manager."""
    try:
        from .web import get_web_manager as _get_web_manager
        return _get_web_manager()
    except ImportError:
        return None

def get_cli():
    """Get the CLI interface."""
    try:
        from .cli import get_cli as _get_cli
        return _get_cli()
    except ImportError:
        return None

def get_ai_manager():
    """Get the AI manager."""
    try:
        from .ai import get_ai_manager
        return get_ai_manager()
    except ImportError:
        return None

def get_plugin_manager():
    """Get the plugin manager."""
    try:
        from .plugins import get_plugin_manager
        return get_plugin_manager()
    except ImportError:
        return None

# Application metadata
APPLICATION_INFO = {
    "name": "NetLink",
    "version": __version__,
    "description": "Government-Level Secure Communication Platform",
    "architecture": "Enterprise Microservices",
    "security_level": "Government",
    "features": [
        "Quantum-resistant encryption",
        "Distributed backup system",
        "Multi-node clustering",
        "AI integration",
        "Real-time collaboration",
        "Plugin marketplace",
        "Zero-knowledge security"
    ],
    "supported_deployments": [
        "Standalone",
        "Cluster",
        "Cloud",
        "Container",
        "Hybrid"
    ]
}

__all__ = [
    "get_app",
    "get_launcher",
    "get_version",
    "get_security_manager",
    "get_optimization_manager",
    "get_service_manager",
    "get_backup_system",
    "get_api_manager",
    "get_web_manager",
    "get_cli",
    "get_ai_manager",
    "get_plugin_manager",
    "APPLICATION_INFO"
]
