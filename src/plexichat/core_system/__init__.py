"""
PlexiChat Core System

Core system components including configuration, database, authentication,
logging, error handling, and other foundational elements.
"""

from .config import get_config, get_setting, set_setting

__all__ = [
    'get_config',
    'get_setting', 
    'set_setting'
]
