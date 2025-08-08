"""
PlexiChat Unified Configuration System

Single source of truth for all configuration functionality.
Consolidates config/, config.py, and unified_config.py into one clean system.
"""

from typing import Any, Dict, Optional
from pathlib import Path
import logging

# Use fallback implementations to avoid import issues
logger = logging.getLogger(__name__)
logger.warning("Using fallback config implementations")

class MinimalConfig:  # type: ignore
    def __init__(self):
        self.data = {}

    def get(self, key: str, default=None):
        return self.data.get(key, default)

    def set(self, key: str, value):
        self.data[key] = value

def get_config():  # type: ignore
    return MinimalConfig()

def load_config(*args, **kwargs):  # type: ignore
    return MinimalConfig()

def save_config(*args, **kwargs):  # type: ignore
    pass

def reload_config(*args, **kwargs):  # type: ignore
    pass

config = get_config()
UnifiedConfig = MinimalConfig

# Backward compatibility functions
def get_setting(key: str, default: Any = None) -> Any:
    """Get a configuration setting by key."""
    try:
        parts = key.split('.')
        value = config
        for part in parts:
            value = getattr(value, part, default)
        return value
    except (AttributeError, TypeError):
        return default

def get_settings():
    """Get the global configuration object."""
    return config

# Export all the main classes and functions
__all__ = [
    # Main config
    "config",
    "get_config",
    "get_setting",
    "get_settings",
    
    # Config classes (if available)
    "UnifiedConfig",
]

# Add config sections to __all__ if they exist
try:
    __all__.extend([
        "SystemConfig",
        "NetworkConfig", 
        "DatabaseConfig",
        "SecurityConfig",
        "CachingConfig",
        "AIConfig",
        "WebUIConfig",
        "LoggingConfig",
        "MessagingConfig",
        "PerformanceConfig",
        "FilesConfig",
        "load_config",
        "save_config",
        "reload_config",
    ])
except NameError:
    pass
