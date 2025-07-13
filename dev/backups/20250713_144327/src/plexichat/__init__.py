from .cli.integrated_cli import PlexiChatCLI
from .core.launcher import PlexiChatLauncher
from .core.versioning.version_manager import Version, VersionType
from .core_system.versioning.version_manager import version_manager  # type: ignore[reportAttributeAccessIssue]
from .features.ai.ai_coordinator import ai_coordinator  # type: ignore[reportAttributeAccessIssue]
from .features.backup import quantum_backup_system
from .features.security import security_manager
from .infrastructure.performance import get_edge_computing_manager  # type: ignore[reportAttributeAccessIssue]
from .infrastructure.services.service_manager import service_manager
from .interfaces.web import get_web_manager
from typing import Optional, Any, Dict

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

__version__ = "a.1.1-1"
__version_info__ = ("a", 1, 1, 1)  # (letter, major, minor, build)
__build__ = "enterprise-quantum"
__author__ = "PlexiChat Development Team"
__description__ = "Government-level secure communication platform with enterprise architecture, quantum encryption, and advanced features"
__url__ = "https://github.com/linux-of-user/plexichat"

# Version management utilities
def get_version() -> str:
    """Get version string using new versioning system."""
    try:
        # Pyright may not see get_current_version, but it exists at runtime
        current_version = version_manager.get_current_version()  # type: ignore[reportAttributeAccessIssue]
        return str(current_version) if current_version else __version__
    except Exception:
        return __version__

def get_version_info() -> Dict[str, Any]:
    """Get detailed version information."""
    try:
        current_version = version_manager.get_current_version()  # type: ignore[reportAttributeAccessIssue]
        if current_version:
            if hasattr(version_manager, 'get_version_info'):
                version_info = version_manager.get_version_info(current_version)  # type: ignore[reportAttributeAccessIssue]
                if version_info:
                    return {
                        "version": str(current_version),
                        "major": getattr(current_version, 'major', None),
                        "type": getattr(current_version, 'type', None),
                        "minor": getattr(current_version, 'minor', None),
                        "build": getattr(current_version, 'build', None),
                        "status": getattr(current_version, 'get_status', lambda: None)(),
                        "release_date": getattr(version_info, 'release_date', None),
                        "database_version": getattr(version_info, 'database_version', None),
                        "config_version": getattr(version_info, 'config_version', None)
                    }
            return {"version": str(current_version)}
    except Exception:
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

def get_app() -> Any:
    """Get the FastAPI app instance. (May raise ImportError if not available)"""
    # This function is no longer needed as app is removed from imports
    # Keeping it for now to avoid breaking existing calls, but it will always return None
    return None

def get_launcher() -> type:
    """Get the PlexiChat launcher class."""
    return PlexiChatLauncher

def get_security_manager() -> Any:
    """Get the security manager instance."""
    return security_manager

def get_optimization_manager() -> Any:
    """Get the optimization manager (edge computing manager) instance."""
    return get_edge_computing_manager()  # type: ignore[reportAttributeAccessIssue]

def get_service_manager() -> Any:
    """Get the service manager instance."""
    return service_manager

def get_backup_system() -> Any:
    """Get the quantum backup system instance."""
    return quantum_backup_system

def get_api_manager() -> Optional[Any]:
    """Get the API manager (web manager) instance. May return None if not initialized."""
    return get_web_manager()

def get_web_manager() -> Optional[Any]:
    """Get the web interface manager instance. May return None if not initialized."""
    return get_web_manager()

def get_cli() -> PlexiChatCLI:
    """Get the CLI interface instance."""
    return PlexiChatCLI()

def get_ai_manager() -> Any:
    """Get the AI manager (AI coordinator) instance."""
    return ai_coordinator  # type: ignore[reportAttributeAccessIssue]

def get_plugin_manager() -> None:
    """Get the plugin manager (not implemented). Returns None."""
    return None

APPLICATION_INFO: Dict[str, Any] = {
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
