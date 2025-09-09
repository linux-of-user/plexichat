"""
PlexiChat Unified Configuration System

Single source of truth for all configuration functionality.
Consolidates config/, config.py, and unified_config.py into one clean system.
"""

import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Try to import the unified config system
try:
    from plexichat.core.config_manager import (
        AIConfig,
        BackupConfig,
        CachingConfig,
        CallingServiceConfig,
        ClusterConfig,
        DatabaseConfig,
        DDoSProtectionConfig,
        KeyboardShortcutsConfig,
        LoggingConfig,
        NetworkConfig,
        PluginSecurityConfig,
        SecurityConfig,
        SecurityEnhancedConfig,
        SystemConfig,
        TypingConfig,
        UnifiedConfig,
        UnifiedConfigManager,
        get_config_manager,
    )

    # Get the global config manager
    _config_manager = get_config_manager()
    config = _config_manager._config

    def get_unified_config():
        """Get the unified configuration object."""
        return config

    def load_unified_config(*args, **kwargs):
        """Load configuration from file."""
        return _config_manager.load()

    def save_unified_config(*args, **kwargs):
        """Save configuration to file."""
        return _config_manager.save()

    def reload_unified_config(*args, **kwargs):
        """Reload configuration from file."""
        return _config_manager.reload()

    logger.info("Unified configuration system loaded successfully")

except ImportError as e:
    logger.warning(f"Unified config not available, using fallback: {e}")

    # Fallback minimal config
    class MinimalConfig:
        def __init__(self):
            self.data = {}
            self.system = type(
                "SystemConfig",
                (),
                {"name": "PlexiChat", "version": "0.0.0", "environment": "production"},
            )()
            self.network = type(
                "NetworkConfig",
                (),
                {
                    "host": "0.0.0.0",
                    "port": 8080,
                    "api_port": 8000,
                    "cors_origins": ["*"],
                    "rate_limit_enabled": True,
                    "rate_limit_requests_per_minute": 60,
                    "rate_limit_burst_limit": 10,
                    "max_request_size_mb": 100,
                    "ssl_enabled": False,
                },
            )()
            self.caching = type(
                "CachingConfig",
                (),
                {
                    "enabled": True,
                    "l1_max_items": 1000,
                    "l1_memory_size_mb": 100,
                    "default_ttl_seconds": 300,
                    "compression_threshold_bytes": 1024,
                    "warming_enabled": True,
                    "l2_redis_enabled": False,
                    "l2_redis_host": "localhost",
                    "l2_redis_port": 6379,
                    "l2_redis_db": 0,
                    "l2_redis_password": "",
                    "l3_memcached_enabled": False,
                    "l3_memcached_host": "localhost",
                    "l3_memcached_port": 11211,
                },
            )()

        def get(self, key: str, default=None):
            return self.data.get(key, default)

        def set(self, key: str, value):
            self.data[key] = value

    def get_fallback_config():
        return MinimalConfig()

    def load_fallback_config(*args, **kwargs):
        return MinimalConfig()

    def save_fallback_config(*args, **kwargs):
        pass

    def reload_fallback_config(*args, **kwargs):
        pass

    config = get_fallback_config()
    UnifiedConfig = MinimalConfig


# Create a settings object for backward compatibility
class Settings:
    """Settings object for backward compatibility."""

    def __init__(self, config_obj):
        self._config = config_obj
        # Add common settings as properties
        self.app_name = getattr(config_obj.system, "name", "PlexiChat")
        self.version = getattr(config_obj.system, "version", "0.0.0")
        self.environment = getattr(config_obj.system, "environment", "production")
        self.debug = getattr(config_obj.system, "debug", False)

    def __getattr__(self, name):
        # Try to get from config object
        return getattr(self._config, name, None)


settings = Settings(config)


# Backward compatibility functions
def get_config():
    """Get the configuration object (backward compatibility)."""
    try:
        return get_unified_config()
    except NameError:
        return get_fallback_config()


def load_config(*args, **kwargs):
    """Load configuration (backward compatibility)."""
    try:
        return load_unified_config(*args, **kwargs)
    except NameError:
        return load_fallback_config(*args, **kwargs)


def save_config(*args, **kwargs):
    """Save configuration (backward compatibility)."""
    try:
        return save_unified_config(*args, **kwargs)
    except NameError:
        return save_fallback_config(*args, **kwargs)


def reload_config(*args, **kwargs):
    """Reload configuration (backward compatibility)."""
    try:
        return reload_unified_config(*args, **kwargs)
    except NameError:
        return reload_fallback_config(*args, **kwargs)


def get_setting(key: str, default: Any = None) -> Any:
    """Get a configuration setting by key."""
    try:
        parts = key.split(".")
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
    "settings",
    "get_config",
    "get_unified_config",
    "get_fallback_config",
    "get_setting",
    "get_settings",
    "load_config",
    "load_unified_config",
    "load_fallback_config",
    "save_config",
    "reload_config",
    # Config classes (if available)
    "UnifiedConfig",
]

# Add config sections to __all__ if they exist
try:
    __all__.extend(
        [
            "SystemConfig",
            "NetworkConfig",
            "DatabaseConfig",
            "SecurityConfig",
            "CachingConfig",
            "AIConfig",
            "LoggingConfig",
            "ClusterConfig",
            "SecurityEnhancedConfig",
            "DDoSProtectionConfig",
            "PluginSecurityConfig",
            "BackupConfig",
            "CallingServiceConfig",
            "TypingConfig",
            "KeyboardShortcutsConfig",
        ]
    )
except NameError:
    pass
