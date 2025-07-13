"""
PlexiChat Core System - Unified Core Module
Refactored from src/plexichat/core_system/ following new naming convention

This module consolidates all core system functionality:
- Authentication and authorization
- Configuration management  
- Database abstraction and management
- Error handling and logging
- Security and resilience
- Runtime and maintenance
- Updates and versioning

New Structure:
src/plexichat/core/{domain}/{module_type}_{name}.py

Domains:
- auth: Authentication and authorization
- config: Configuration management
- database: Database abstraction and operations
- error: Error handling and management
- integration: System integration and orchestration
- logging: Logging and monitoring
- maintenance: System maintenance
- resilience: System resilience and recovery
- runtime: Runtime management
- security: Security systems
- updates: Update management
- versioning: Version control and deployment
"""

# Core authentication system
from .auth import *

# Core configuration system  
from .config import *

# Core database system
from .database import *

# Core error handling
from .error import *

# Core integration
from .integration import *

# Core logging
from .logging import *

# Core maintenance
from .maintenance import *

# Core resilience
from .resilience import *

# Core runtime
from .runtime import *

# Core security
from .security import *

# Core updates
from .updates import *

# Core versioning
from .versioning import *

__version__ = "3.0.0"
__all__ = [
    # Authentication exports
    "auth",
    
    # Configuration exports
    "config",
    
    # Database exports
    "database",
    
    # Error handling exports
    "error",
    
    # Integration exports
    "integration",
    
    # Logging exports
    "logging",
    
    # Maintenance exports
    "maintenance",
    
    # Resilience exports
    "resilience",
    
    # Runtime exports
    "runtime",
    
    # Security exports
    "security",
    
    # Updates exports
    "updates",
    
    # Versioning exports
    "versioning"
]

# Backward compatibility aliases
# These maintain compatibility with old import paths
import warnings


def _deprecated_import_warning(old_path, new_path):
    """Issue deprecation warning for old import paths."""
    warnings.warn(
        f"Importing from '{old_path}' is deprecated. "
        f"Use '{new_path}' instead. "
        f"Old import paths will be removed in version 4.0.0.",
        DeprecationWarning,
        stacklevel=3
    )

# Legacy import support
class _LegacyImportHelper:
    """Helper class to support legacy imports with deprecation warnings."""
    
    def __getattr__(self, name):
        if name == "core_system":
            _deprecated_import_warning(
                "plexichat.core_system", 
                "plexichat.core"
            )
            return self
        
        # Try to find the attribute in the new structure
        for module_name in __all__:
            try:
                module = globals()[module_name]
                if hasattr(module, name):
                    return getattr(module, name)
            except (KeyError, AttributeError):
                continue
        
        raise AttributeError(f"module 'plexichat.core' has no attribute '{name}'")

# Install legacy import helper
import sys

sys.modules['plexichat.core_system'] = _LegacyImportHelper()

# Core system information
CORE_SYSTEM_INFO = {
    "version": "3.0.0",
    "refactored_from": "src/plexichat/core_system/",
    "new_structure": "src/plexichat/core/",
    "naming_convention": "{domain}/{module_type}_{name}.py",
    "domains": [
        "auth", "config", "database", "error", "integration",
        "logging", "maintenance", "resilience", "runtime", 
        "security", "updates", "versioning"
    ],
    "backward_compatible": True,
    "deprecation_version": "4.0.0"
}
