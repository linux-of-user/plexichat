"""
NetLink Unified Configuration Management

Consolidates configuration functionality from:
- src/netlink/config/ (config files)
- src/netlink/core/config/ (config management system)
- Root config/ directory

Uses Pydantic for modern configuration management with validation.
"""

import os
import yaml
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Type
from datetime import datetime
from pydantic import BaseSettings, Field, validator
from pydantic.env_settings import SettingsSourceCallable

logger = logging.getLogger(__name__)


class ServerConfig(BaseSettings):
    """Server configuration settings."""
    host: str = Field(default="0.0.0.0", description="Server host address")
    port: int = Field(default=8000, description="Server port")
    workers: int = Field(default=4, description="Number of worker processes")
    reload: bool = Field(default=False, description="Enable auto-reload in development")
    ssl_enabled: bool = Field(default=True, description="Enable SSL/TLS")
    ssl_cert_path: Optional[str] = Field(default=None, description="SSL certificate path")
    ssl_key_path: Optional[str] = Field(default=None, description="SSL private key path")
    
    class Config:
        env_prefix = "NETLINK_SERVER_"


class DatabaseConfig(BaseSettings):
    """Database configuration settings."""
    url: str = Field(default="sqlite:///./netlink.db", description="Database URL")
    pool_size: int = Field(default=10, description="Connection pool size")
    max_overflow: int = Field(default=20, description="Maximum pool overflow")
    pool_timeout: int = Field(default=30, description="Pool timeout in seconds")
    pool_recycle: int = Field(default=3600, description="Pool recycle time in seconds")
    echo: bool = Field(default=False, description="Enable SQL query logging")
    encryption_enabled: bool = Field(default=True, description="Enable database encryption")
    backup_enabled: bool = Field(default=True, description="Enable automatic backups")
    
    class Config:
        env_prefix = "NETLINK_DATABASE_"


class SecurityConfig(BaseSettings):
    """Security configuration settings."""
    secret_key: str = Field(default="", description="Application secret key")
    jwt_algorithm: str = Field(default="HS256", description="JWT signing algorithm")
    jwt_expiration_minutes: int = Field(default=30, description="JWT token expiration")
    password_min_length: int = Field(default=12, description="Minimum password length")
    max_login_attempts: int = Field(default=5, description="Maximum login attempts")
    lockout_duration_minutes: int = Field(default=30, description="Account lockout duration")
    mfa_enabled: bool = Field(default=True, description="Enable multi-factor authentication")
    rate_limit_enabled: bool = Field(default=True, description="Enable rate limiting")
    ddos_protection_enabled: bool = Field(default=True, description="Enable DDoS protection")
    
    class Config:
        env_prefix = "NETLINK_SECURITY_"
    
    @validator('secret_key')
    def validate_secret_key(cls, v):
        if not v:
            import secrets
            return secrets.token_urlsafe(64)
        return v


class BackupConfig(BaseSettings):
    """Backup system configuration."""
    enabled: bool = Field(default=True, description="Enable backup system")
    storage_path: str = Field(default="data/backups", description="Backup storage path")
    retention_days: int = Field(default=365, description="Backup retention period")
    compression_enabled: bool = Field(default=True, description="Enable backup compression")
    encryption_enabled: bool = Field(default=True, description="Enable backup encryption")
    redundancy_factor: int = Field(default=7, description="Backup redundancy factor")
    max_shard_size_mb: int = Field(default=25, description="Maximum shard size in MB")
    quantum_encryption: bool = Field(default=True, description="Enable quantum encryption")
    
    class Config:
        env_prefix = "NETLINK_BACKUP_"


class ClusterConfig(BaseSettings):
    """Clustering configuration."""
    enabled: bool = Field(default=False, description="Enable clustering")
    node_id: Optional[str] = Field(default=None, description="Unique node identifier")
    discovery_method: str = Field(default="static", description="Node discovery method")
    heartbeat_interval: int = Field(default=30, description="Heartbeat interval in seconds")
    election_timeout: int = Field(default=150, description="Leader election timeout")
    replication_factor: int = Field(default=3, description="Data replication factor")
    
    class Config:
        env_prefix = "NETLINK_CLUSTER_"


class LoggingConfig(BaseSettings):
    """Logging configuration."""
    level: str = Field(default="INFO", description="Log level")
    format: str = Field(default="%(asctime)s - %(name)s - %(levelname)s - %(message)s", description="Log format")
    file_enabled: bool = Field(default=True, description="Enable file logging")
    file_path: str = Field(default="logs/netlink.log", description="Log file path")
    max_file_size_mb: int = Field(default=100, description="Maximum log file size in MB")
    backup_count: int = Field(default=5, description="Number of log file backups")
    console_enabled: bool = Field(default=True, description="Enable console logging")
    
    class Config:
        env_prefix = "NETLINK_LOGGING_"


class AIConfig(BaseSettings):
    """AI system configuration."""
    enabled: bool = Field(default=True, description="Enable AI features")
    default_provider: str = Field(default="openai", description="Default AI provider")
    openai_api_key: Optional[str] = Field(default=None, description="OpenAI API key")
    anthropic_api_key: Optional[str] = Field(default=None, description="Anthropic API key")
    max_tokens: int = Field(default=4000, description="Maximum tokens per request")
    temperature: float = Field(default=0.7, description="AI temperature setting")
    
    class Config:
        env_prefix = "NETLINK_AI_"


class NetLinkConfig(BaseSettings):
    """Main NetLink configuration."""
    # Application info
    app_name: str = Field(default="NetLink", description="Application name")
    version: str = Field(default="3.0.0", description="Application version")
    environment: str = Field(default="development", description="Environment (development/staging/production)")
    debug: bool = Field(default=False, description="Enable debug mode")
    
    # Component configurations
    server: ServerConfig = Field(default_factory=ServerConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    backup: BackupConfig = Field(default_factory=BackupConfig)
    cluster: ClusterConfig = Field(default_factory=ClusterConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    
    # Feature flags
    features: Dict[str, bool] = Field(default_factory=lambda: {
        "web_ui": True,
        "api": True,
        "cli": True,
        "gui": True,
        "plugins": True,
        "clustering": False,
        "ai_features": True,
        "backup_system": True,
        "monitoring": True
    })
    
    class Config:
        env_prefix = "NETLINK_"
        case_sensitive = False
        
        @classmethod
        def customise_sources(
            cls,
            init_settings: SettingsSourceCallable,
            env_settings: SettingsSourceCallable,
            file_secret_settings: SettingsSourceCallable,
        ) -> tuple[SettingsSourceCallable, ...]:
            return (
                init_settings,
                yaml_config_settings_source,
                env_settings,
                file_secret_settings,
            )


def yaml_config_settings_source(settings: BaseSettings) -> Dict[str, Any]:
    """Load configuration from YAML files."""
    config_data = {}
    
    # Try multiple config file locations
    config_paths = [
        Path("config/netlink.yaml"),
        Path("src/netlink/config/netlink.yaml"),
        Path("netlink.yaml"),
    ]
    
    for config_path in config_paths:
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    file_data = yaml.safe_load(f)
                    if file_data:
                        config_data.update(file_data)
                        logger.info(f"Loaded configuration from {config_path}")
                        break
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")
    
    return config_data


class ConfigManager:
    """
    Unified Configuration Manager
    
    Provides centralized configuration management with Pydantic validation,
    environment variable support, and YAML file loading.
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path
        self._config: Optional[NetLinkConfig] = None
        self._config_hash: Optional[str] = None
    
    @property
    def config(self) -> NetLinkConfig:
        """Get the current configuration."""
        if self._config is None:
            self._config = self.load_config()
        return self._config
    
    def load_config(self) -> NetLinkConfig:
        """Load configuration from files and environment."""
        try:
            config = NetLinkConfig()
            
            # Calculate config hash for change detection
            config_str = config.json()
            self._config_hash = hash(config_str)
            
            logger.info("✅ Configuration loaded successfully")
            return config
            
        except Exception as e:
            logger.error(f"❌ Failed to load configuration: {e}")
            # Return default configuration on error
            return NetLinkConfig()
    
    def reload_config(self) -> bool:
        """Reload configuration and detect changes."""
        try:
            new_config = NetLinkConfig()
            new_hash = hash(new_config.json())
            
            if new_hash != self._config_hash:
                self._config = new_config
                self._config_hash = new_hash
                logger.info("🔄 Configuration reloaded with changes")
                return True
            else:
                logger.debug("Configuration unchanged")
                return False
                
        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")
            return False
    
    def save_config(self, config_path: Optional[Path] = None) -> bool:
        """Save current configuration to YAML file."""
        try:
            save_path = config_path or Path("config/netlink.yaml")
            save_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert config to dict and save as YAML
            config_dict = self.config.dict()
            
            with open(save_path, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            
            logger.info(f"💾 Configuration saved to {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False
    
    def get_config_value(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by dot notation key."""
        try:
            keys = key.split('.')
            value = self.config
            
            for k in keys:
                if hasattr(value, k):
                    value = getattr(value, k)
                else:
                    return default
            
            return value
            
        except Exception:
            return default
    
    def validate_config(self) -> List[str]:
        """Validate current configuration and return any errors."""
        errors = []
        
        try:
            # Pydantic validation happens automatically during instantiation
            NetLinkConfig()
        except Exception as e:
            errors.append(str(e))
        
        return errors


# Global configuration manager instance
config_manager = ConfigManager()

# Convenience function to get configuration
def get_config() -> NetLinkConfig:
    """Get the global configuration instance."""
    return config_manager.config

# Convenience function to get specific config values
def get_config_value(key: str, default: Any = None) -> Any:
    """Get a configuration value by key."""
    return config_manager.get_config_value(key, default)
