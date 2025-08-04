"""
Legacy configuration compatibility layer.

This module provides backward compatibility for existing code that uses
the old configuration system while redirecting to the unified config system.
"""

from typing import Optional, List
import logging

# Check if unified config is available
try:
    import plexichat.core.unified_config
    UNIFIED_CONFIG_AVAILABLE = True
except ImportError:
    UNIFIED_CONFIG_AVAILABLE = False

logger = logging.getLogger(__name__)

class LoggingSettings:
    """Logging configuration settings (compatibility layer)."""

    def __init__(self):
        try:
            if UNIFIED_CONFIG_AVAILABLE:
                from .simple_config import get_config
                self._# # config = get_config()  # Disabled to prevent circular imports  # Disabled to prevent circular imports
            else:
                self._config = None
        except Exception:
            self._config = None

    @property
    def buffer_size(self) -> int:
        return 10000  # Static value for now

    @property
    def level(self) -> str:
        if self._config:
            return self._config.logging.level
        return "INFO"

    @property
    def format(self) -> str:
        if self._config:
            return self._config.logging.format
        return "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

class Settings:
    """Main settings class (compatibility layer)."""

    def __init__(self):
        try:
            if UNIFIED_CONFIG_AVAILABLE:
                from .simple_config import get_config
                self._# # config = get_config()  # Disabled to prevent circular imports  # Disabled to prevent circular imports
            else:
                self._config = None
        except Exception:
            self._config = None
        self.logging = LoggingSettings()

    @property
    def app_name(self) -> str:
        if self._config:
            return self._config.system.name
        return "PlexiChat"

    @property
    def admin_email(self) -> str:
        return "admin@localhost"  # Could be added to unified config

    @property
    def items_per_user(self) -> int:
        return 50  # Could be added to unified config

    @property
    def allowed_origins(self) -> List[str]:
        if self._config:
            return self._config.network.cors_origins
        return ["http://localhost:3000"]

    @property
    def rate_limit_default_requests_per_minute(self) -> int:
        if self._config:
            return self._config.network.rate_limit_requests_per_minute
        return 60

    @property
    def rate_limit_default_requests_per_hour(self) -> int:
        return 1000  # Could be added to unified config

    @property
    def rate_limit_default_burst_limit(self) -> int:
        if self._config:
            return self._config.network.rate_limit_burst_limit
        return 10

# Global settings instance for backward compatibility (disabled to prevent circular imports)
# # # settings = Settings()  # Disabled to prevent circular imports  # Disabled to prevent circular imports

def get_settings():
    """Get global settings instance."""
    return Settings()

# Backward compatibility functions
def get_setting(key: str, default=None):
    """Get a setting value (backward compatibility)."""
    if UNIFIED_CONFIG_AVAILABLE:
        # # config = get_config()  # Disabled to prevent circular imports  # Disabled to prevent circular imports
        return config.get_config_value(key) if config else default
    return default

def get_settings():
    """Get settings instance (backward compatibility)."""
    return settings

# # settings = Settings()  # Disabled to prevent circular imports  # Disabled to prevent circular imports

def get_config():
    """Get the global configuration settings."""
    return settings
