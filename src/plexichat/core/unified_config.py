"""
PlexiChat Unified Configuration System

Single source of truth for all configuration management.
Consolidates all config systems into one unified approach.
"""

import json
import logging
import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional, Union
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class ConfigDefaults:
    """Default configuration values."""
    
    # Server settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    
    # Database settings
    DATABASE_URL: str = "sqlite:///data/plexichat.db"
    DATABASE_ECHO: bool = False
    
    # Security settings
    JWT_SECRET: str = "change-this-secret-key-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Logging settings
    LOG_LEVEL: str = "INFO"
    LOG_DIRECTORY: str = "logs"
    LOG_FILE_ENABLED: bool = True
    LOG_CONSOLE_ENABLED: bool = True
    
    # File settings
    UPLOAD_DIRECTORY: str = "uploads"
    MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 100MB
    
    # Performance settings
    CACHE_TTL: int = 300
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60

class UnifiedConfig:
    """Unified configuration manager for PlexiChat."""
    
    def __init__(self, config_file: Optional[Path] = None):
        self.config_file = config_file or Path("config/plexichat.yaml")
        self.plugin_config_dir = Path("config/plugins")
        self.defaults = ConfigDefaults()
        self._config = {}
        self._plugin_configs = {}
        
        # Ensure config directory exists
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.plugin_config_dir.mkdir(parents=True, exist_ok=True)
        
        # Load configuration
        self.load()
    
    def load(self) -> None:
        """Load configuration from file."""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    if self.config_file.suffix.lower() == '.yaml':
                        self._config = yaml.safe_load(f) or {}
                    else:
                        self._config = json.load(f)
                logger.info(f"Configuration loaded from {self.config_file}")
            else:
                self._config = {}
                logger.info("No configuration file found, using defaults")
                
            # Load plugin configurations
            self._load_plugin_configs()
            
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            self._config = {}
    
    def _load_plugin_configs(self) -> None:
        """Load plugin-specific configurations."""
        self._plugin_configs = {}
        
        if not self.plugin_config_dir.exists():
            return
            
        for config_file in self.plugin_config_dir.glob("*.yaml"):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    plugin_name = config_file.stem
                    self._plugin_configs[plugin_name] = yaml.safe_load(f) or {}
                logger.debug(f"Loaded plugin config for {plugin_name}")
            except Exception as e:
                logger.error(f"Error loading plugin config {config_file}: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with fallback to defaults."""
        # Check environment variable first
        env_key = f"PLEXICHAT_{key.upper()}"
        env_value = os.getenv(env_key)
        if env_value is not None:
            return self._convert_env_value(env_value)
        
        # Check config file
        if key in self._config:
            return self._config[key]
        
        # Check defaults
        if hasattr(self.defaults, key):
            return getattr(self.defaults, key)
        
        return default
    
    def _convert_env_value(self, value: str) -> Union[str, int, bool, float]:
        """Convert environment variable string to appropriate type."""
        # Boolean conversion
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'
        
        # Integer conversion
        try:
            return int(value)
        except ValueError:
            pass
        
        # Float conversion
        try:
            return float(value)
        except ValueError:
            pass
        
        # Return as string
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
        self._config[key] = value
    
    def save(self) -> bool:
        """Save configuration to file."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                if self.config_file.suffix.lower() == '.yaml':
                    yaml.safe_dump(self._config, f, default_flow_style=False, indent=2)
                else:
                    json.dump(self._config, f, indent=2)
            logger.info(f"Configuration saved to {self.config_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False
    
    def get_plugin_config(self, plugin_name: str) -> Dict[str, Any]:
        """Get configuration for a specific plugin."""
        return self._plugin_configs.get(plugin_name, {})
    
    def set_plugin_config(self, plugin_name: str, config: Dict[str, Any]) -> bool:
        """Set configuration for a specific plugin."""
        try:
            self._plugin_configs[plugin_name] = config
            plugin_file = self.plugin_config_dir / f"{plugin_name}.yaml"
            
            with open(plugin_file, 'w', encoding='utf-8') as f:
                yaml.safe_dump(config, f, default_flow_style=False, indent=2)
            
            logger.info(f"Plugin configuration saved for {plugin_name}")
            return True
        except Exception as e:
            logger.error(f"Error saving plugin configuration for {plugin_name}: {e}")
            return False
    
    def create_default_config(self) -> bool:
        """Create default configuration file."""
        try:
            default_config = {
                "server": {
                    "host": self.defaults.HOST,
                    "port": self.defaults.PORT,
                    "debug": self.defaults.DEBUG
                },
                "database": {
                    "url": self.defaults.DATABASE_URL,
                    "echo": self.defaults.DATABASE_ECHO
                },
                "security": {
                    "jwt_secret": self.defaults.JWT_SECRET,
                    "jwt_algorithm": self.defaults.JWT_ALGORITHM,
                    "access_token_expire_minutes": self.defaults.ACCESS_TOKEN_EXPIRE_MINUTES
                },
                "logging": {
                    "level": self.defaults.LOG_LEVEL,
                    "directory": self.defaults.LOG_DIRECTORY,
                    "file_enabled": self.defaults.LOG_FILE_ENABLED,
                    "console_enabled": self.defaults.LOG_CONSOLE_ENABLED
                },
                "files": {
                    "upload_directory": self.defaults.UPLOAD_DIRECTORY,
                    "max_file_size": self.defaults.MAX_FILE_SIZE
                },
                "performance": {
                    "cache_ttl": self.defaults.CACHE_TTL,
                    "rate_limit_requests": self.defaults.RATE_LIMIT_REQUESTS,
                    "rate_limit_window": self.defaults.RATE_LIMIT_WINDOW
                }
            }
            
            self._config = default_config
            return self.save()
        except Exception as e:
            logger.error(f"Error creating default configuration: {e}")
            return False
    
    def validate(self) -> bool:
        """Validate configuration."""
        try:
            # Check required settings
            required_keys = ["server", "database", "security"]
            for key in required_keys:
                if key not in self._config:
                    logger.error(f"Missing required configuration section: {key}")
                    return False
            
            # Validate server settings
            server = self._config.get("server", {})
            if not isinstance(server.get("port"), int) or server.get("port") <= 0:
                logger.error("Invalid server port configuration")
                return False
            
            logger.info("Configuration validation passed")
            return True
        except Exception as e:
            logger.error(f"Configuration validation error: {e}")
            return False

# Global configuration instance
config = UnifiedConfig()

# Convenience functions
def get_config(key: str, default: Any = None) -> Any:
    """Get configuration value."""
    return config.get(key, default)

def set_config(key: str, value: Any) -> None:
    """Set configuration value."""
    config.set(key, value)

def save_config() -> bool:
    """Save configuration."""
    return config.save()

def get_plugin_config(plugin_name: str) -> Dict[str, Any]:
    """Get plugin configuration."""
    return config.get_plugin_config(plugin_name)

def set_plugin_config(plugin_name: str, plugin_config: Dict[str, Any]) -> bool:
    """Set plugin configuration."""
    return config.set_plugin_config(plugin_name, plugin_config)
