"""
PlexiChat Core Module
=====================

Core system components for PlexiChat.
"""

# Core components
try:
    from .database import get_database_manager, database_manager
except ImportError:
    get_database_manager = None
    database_manager = None

try:
    from .config_manager import ConfigurationManager
except ImportError:
    ConfigurationManager = None

try:
    from .config_wizard import ConfigurationWizard
except ImportError:
    ConfigurationWizard = None

__all__ = [
    "get_database_manager",
    "database_manager",
    "ConfigurationManager",
    "ConfigurationWizard"
]
