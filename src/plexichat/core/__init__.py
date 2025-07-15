from typing import Optional
"""
PlexiChat Core Module
=====================

Core system components for PlexiChat.
"""

# Core components
try:
    from .database import get_database_manager, database_manager
except ImportError: Optional[get_database_manager] = None
    database_manager = None

try:
    from .config_manager import ConfigurationManager
except ImportError: Optional[ConfigurationManager] = None

try:
    from .config_wizard import ConfigurationWizard
except ImportError: Optional[ConfigurationWizard] = None

__all__ = [
    "get_database_manager",
    "database_manager",
    "ConfigurationManager",
    "ConfigurationWizard"
]
