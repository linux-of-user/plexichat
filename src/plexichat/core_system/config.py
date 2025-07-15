"""
Core System Configuration Module
===============================

Provides centralized configuration management for the core system.
"""

from typing import Any, Dict, Optional
import json
import yaml
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# Global configuration instance
_config_instance: Optional[Dict[str, Any]] = None


def get_config() -> Dict[str, Any]:
    """Get the global configuration."""
    global _config_instance
    if _config_instance is None:
        _config_instance = load_config()
    return _config_instance


def get_setting(key: str, default: Optional[Any] = None) -> Any:
    """Get a configuration setting using dot notation."""
    config = get_config()
    keys = key.split('.')
    value = config
    
    for k in keys:
        if isinstance(value, dict) and k in value:
            value = value[k]
        else:
            return default
    
    return value


def set_setting(key: str, value: Any) -> bool:
    """Set a configuration setting using dot notation."""
    config = get_config()
    keys = key.split('.')
    
    # Navigate to the parent of the target key
    for k in keys[:-1]:
        if k not in config:
            config[k] = {}
        config = config[k]
    
    # Set the value
    config[keys[-1]] = value
    return True


def load_config() -> Dict[str, Any]:
    """Load configuration from file."""
    config_file = Path("config/plexichat.yaml")
    
    # Default configuration
    default_config = {
        "system": {
            "name": "PlexiChat",
            "version": "a.1.1-17",
            "environment": "production",
            "debug": False,
            "timezone": "UTC"
        },
        "server": {
            "host": "127.0.0.1",
            "port": 8000,
            "reload": False,
            "workers": 1
        },
        "database": {
            "type": "sqlite",
            "path": "data/plexichat.db",
            "pool_size": 10,
            "max_overflow": 20,
            "echo": False
        },
        "security": {
            "encryption": "aes-256-gcm",
            "key_rotation_days": 30,
            "session_timeout": 3600,
            "max_login_attempts": 5,
            "password_min_length": 8,
            "require_special_chars": True
        },
        "logging": {
            "level": "INFO",
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "file": "logs/plexichat.log",
            "max_size": "10MB",
            "backup_count": 5
        },
        "ai": {
            "enabled": True,
            "provider": "openai",
            "api_key": "",
            "model": "gpt-3.5-turbo",
            "max_tokens": 1000,
            "temperature": 0.7
        },
        "plugins": {}
    }
    
    if config_file.exists():
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                file_config = yaml.safe_load(f) or {}
                # Merge with defaults
                merged_config = _merge_configs(default_config, file_config)
                return merged_config
        except Exception as e:
            logger.error(f"Error loading config file: {e}")
            return default_config
    else:
        logger.info("Config file not found, using defaults")
        return default_config


def _merge_configs(default: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge configuration dictionaries."""
    result = default.copy()
    
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge_configs(result[key], value)
        else:
            result[key] = value
    
    return result


def reload_config() -> Dict[str, Any]:
    """Reload configuration from file."""
    global _config_instance
    _config_instance = None
    return get_config()


# Export main functions
__all__ = [
    "get_config",
    "get_setting", 
    "set_setting",
    "load_config",
    "reload_config"
]
