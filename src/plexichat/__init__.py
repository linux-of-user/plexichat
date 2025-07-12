"""
PlexiChat - Government-Level Secure Communication Platform

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

# Unified Version System - Single Source of Truth
__version__ = "a.1.1-1"
__version_info__ = ("a", 1, 1, 1)  # (letter, major, minor, build)
__build__ = "enterprise-quantum"
__author__ = "PlexiChat Development Team"
__description__ = "Government-level secure communication platform with enterprise architecture, quantum encryption, and advanced features"
__url__ = "https://github.com/linux-of-user/plexichat"

# Import version management system
try:
    from .core.versioning.version_manager import version_manager, Version, VersionType

    # Ensure version consistency
    version_manager.set_current_version(__version__)

except ImportError:
    # Version system not available - use fallback
    pass

def get_version():
    """Get version string using new versioning system."""
    try:
        from .core.versioning.version_manager import version_manager
        current_version = version_manager.get_current_version()
        return str(current_version) if current_version else __version__
    except ImportError:
        return __version__

def get_version_info():
    """Get detailed version information."""
    try:
        from .core_system.versioning.version_manager import version_manager
        current_version = version_manager.get_current_version()
        if current_version:
            version_info = version_manager.get_version_info(current_version)
            return {
                "version": str(current_version),
                "major": current_version.major,
                "type": current_version.type.value,
                "minor": current_version.minor,
                "build": current_version.build,
                "status": current_version.get_status().value,
                "release_date": version_info.release_date.isoformat() if version_info else None,
                "database_version": version_info.database_version if version_info else None,
                "config_version": version_info.config_version if version_info else None
            }
    except ImportError:
        pass

    # Fallback version info using new format
    version_parts = __version__.split('.')
    letter = version_parts[0][0] if version_parts else "a"
    major = int(version_parts[0][2:]) if len(version_parts[0]) > 2 else 1
    minor = int(version_parts[1]) if len(version_parts) > 1 else 0
    build_part = version_parts[2].split('-') if len(version_parts) > 2 else ["1"]
    build_num = int(build_part[1]) if len(build_part) > 1 else 1

    return {
        "version": __version__,
        "letter": letter,
        "major": major,
        "minor": minor,
        "build_number": build_num,
        "build": __build__,
        "api_version": f"v{major}",
        "status": "alpha" if letter == "a" else "beta" if letter == "b" else "release"
    }

# Export main components (lazy imports to avoid circular dependencies)
def get_app():
    """Get the FastAPI app instance."""
    from .main import app
    return app

def get_launcher():
    """Get the PlexiChat launcher."""
    from .core.launcher import PlexiChatLauncher
    return PlexiChatLauncher

def get_security_manager():
    """Get the security manager."""
    try:
        from .features.security import security_manager
        return security_manager
    except ImportError:
        return None

def get_optimization_manager():
    """Get the optimization manager."""
    try:
        from .infrastructure.performance import get_edge_computing_manager
        return get_edge_computing_manager()
    except ImportError:
        return None

def get_service_manager():
    """Get the service manager."""
    try:
        from .infrastructure.services.service_manager import service_manager
        return service_manager
    except ImportError:
        return None

def get_backup_system():
    """Get the quantum backup system."""
    try:
        from .features.backup import quantum_backup_system
        return quantum_backup_system
    except ImportError:
        return None

def get_api_manager():
    """Get the API manager."""
    try:
        # API functionality is integrated with the web interface
        from .interfaces.web import get_web_manager
        return get_web_manager()
    except ImportError:
        return None

def get_web_manager():
    """Get the web interface manager."""
    try:
        from .interfaces.web import get_web_manager
        return get_web_manager()
    except ImportError:
        return None

def get_cli():
    """Get the CLI interface."""
    try:
        from .cli.integrated_cli import PlexiChatCLI
        return PlexiChatCLI()
    except ImportError:
        return None

def get_ai_manager():
    """Get the AI manager."""
    try:
        from .features.ai.ai_coordinator import ai_coordinator
        return ai_coordinator
    except ImportError:
        return None

def get_plugin_manager():
    """Get the plugin manager."""
    try:
        from .infrastructure.modules.plugin_manager import get_plugin_manager
        return get_plugin_manager()
    except ImportError:
        return None

# Application metadata
APPLICATION_INFO = {
    "name": "PlexiChat",
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
