"""
NetLink Unified Configuration Management System

Comprehensive configuration system with YAML format, validation, environment variable support,
and centralized management for all NetLink components.

Features:
- YAML-based configuration with validation
- Environment variable override support
- Configuration templates and defaults
- Hot-reload capabilities
- Schema validation with detailed error reporting
- Multi-environment support (development, staging, production)
- Encrypted configuration values for sensitive data
- Configuration versioning and migration
- Real-time configuration monitoring
"""

import os
import sys
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Type
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

# Import configuration components
try:
    from .config_manager import ConfigManager, ConfigValidationError
    from .config_schema import (
        NetLinkConfig, ServerConfig, DatabaseConfig, SecurityConfig,
        BackupConfig, ClusterConfig, LoggingConfig, AIConfig,
        MonitoringConfig, FeaturesConfig, LimitsConfig, ApplicationConfig
    )
    from .config_validator import ConfigValidator, ValidationError
    from .environment_manager import EnvironmentManager
    from .config_templates import ConfigTemplateGenerator
    from .config_migration import ConfigMigrator, ConfigMigrationError

    # Configuration components successfully imported
    _COMPONENTS_AVAILABLE = True

except ImportError as e:
    logger.warning(f"Failed to import configuration components: {e}")
    # Fallback for basic functionality
    ConfigManager = None
    ConfigValidator = None
    EnvironmentManager = None
    ConfigTemplateGenerator = None
    ConfigMigrator = None
    _COMPONENTS_AVAILABLE = False

# Configure logging
logger = logging.getLogger(__name__)

# Configuration constants
DEFAULT_CONFIG_DIR = Path("config")
DEFAULT_CONFIG_FILE = "netlink.yaml"
DEFAULT_ENVIRONMENT = "development"

# Supported configuration formats
SUPPORTED_FORMATS = ["yaml", "yml", "json"]

# Configuration schema version
CONFIG_SCHEMA_VERSION = "1a1"

# Environment variable prefixes
ENV_PREFIX = "NETLINK_"
ENV_PREFIXES = {
    "server": "NETLINK_SERVER_",
    "database": "NETLINK_DB_",
    "security": "NETLINK_SECURITY_",
    "backup": "NETLINK_BACKUP_",
    "cluster": "NETLINK_CLUSTER_",
    "logging": "NETLINK_LOG_",
    "ai": "NETLINK_AI_"
}

# Default configuration structure
DEFAULT_CONFIG = {
    "version": CONFIG_SCHEMA_VERSION,
    "environment": DEFAULT_ENVIRONMENT,
    "server": {
        "host": "0.0.0.0",
        "port": 8000,
        "workers": 4,
        "debug": False,
        "auto_reload": False,
        "access_log": True,
        "ssl_enabled": False,
        "ssl_cert_file": None,
        "ssl_key_file": None
    },
    "database": {
        "type": "sqlite",
        "url": "sqlite:///./data/netlink.db",
        "pool_size": 10,
        "pool_timeout": 30,
        "echo": False,
        "backup_enabled": True,
        "backup_interval": 3600,
        "encryption_enabled": True
    },
    "security": {
        "secret_key": None,  # Auto-generated
        "jwt_algorithm": "RS256",
        "access_token_expire_minutes": 15,
        "refresh_token_expire_days": 30,
        "password_min_length": 12,
        "max_login_attempts": 5,
        "lockout_duration": 300,
        "mfa_enabled": True,
        "biometric_enabled": False,
        "rate_limiting": True,
        "cors_enabled": True,
        "cors_origins": ["*"]
    },
    "backup": {
        "enabled": True,
        "directory": "backups",
        "encryption_enabled": True,
        "compression_enabled": True,
        "distributed_enabled": True,
        "shard_size_mb": 10,
        "redundancy_level": 2,
        "retention_days": 30,
        "auto_backup_interval": 3600
    },
    "cluster": {
        "enabled": False,
        "node_id": None,
        "discovery_method": "static",
        "nodes": [],
        "heartbeat_interval": 30,
        "election_timeout": 5000
    },
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        "file": "logs/netlink.log",
        "max_size": "10MB",
        "backup_count": 5,
        "console_enabled": True,
        "file_enabled": True
    },
    "ai": {
        "enabled": False,
        "providers": [],
        "default_provider": None,
        "api_keys": {},
        "models": {},
        "features": {
            "chat_completion": False,
            "content_moderation": False,
            "translation": False,
            "summarization": False
        }
    },
    "features": {
        "backup_system": True,
        "clustering": False,
        "ai_integration": False,
        "web_ui": True,
        "api_docs": True,
        "metrics": True,
        "health_checks": True
    },
    "limits": {
        "max_message_length": 10000,
        "max_file_size_mb": 100,
        "max_users": 10000,
        "rate_limit_per_minute": 1000,
        "max_concurrent_connections": 1000
    }
}

# Global configuration manager instance
_config_manager: Optional[ConfigManager] = None

def get_config_manager() -> ConfigManager:
    """Get the global configuration manager instance."""
    global _config_manager
    if _config_manager is None:
        if not _COMPONENTS_AVAILABLE or ConfigManager is None:
            raise RuntimeError("Configuration components not available. Please check imports.")
        _config_manager = ConfigManager()
    return _config_manager

def initialize_config(
    config_dir: Optional[Path] = None,
    config_file: Optional[str] = None,
    environment: Optional[str] = None
) -> NetLinkConfig:
    """Initialize the configuration system."""
    manager = get_config_manager()
    return manager.initialize(
        config_dir=config_dir,
        config_file=config_file,
        environment=environment
    )

def get_config() -> NetLinkConfig:
    """Get the current configuration."""
    manager = get_config_manager()
    return manager.get_config()

def reload_config() -> NetLinkConfig:
    """Reload configuration from files."""
    manager = get_config_manager()
    return manager.reload_config()

def save_config(config: NetLinkConfig) -> bool:
    """Save configuration to file."""
    manager = get_config_manager()
    return manager.save_config(config)

def validate_config(config: Dict[str, Any]) -> List[str]:
    """Validate configuration and return any issues."""
    validator = ConfigValidator()
    return validator.validate(config)

def get_environment() -> str:
    """Get current environment."""
    return os.getenv("NETLINK_ENVIRONMENT", DEFAULT_ENVIRONMENT)

def set_environment(environment: str):
    """Set current environment."""
    os.environ["NETLINK_ENVIRONMENT"] = environment

def create_config_template(
    output_path: Path,
    template_type: str = "default",
    environment: str = "development"
) -> bool:
    """Create a configuration template file."""
    templates = ConfigTemplates()
    return templates.create_template(output_path, template_type, environment)

def migrate_config(
    old_config_path: Path,
    new_config_path: Path,
    from_version: str,
    to_version: str = CONFIG_SCHEMA_VERSION
) -> bool:
    """Migrate configuration from old version to new version."""
    migration = ConfigMigration()
    return migration.migrate(old_config_path, new_config_path, from_version, to_version)

# Configuration decorators
def config_required(config_key: str):
    """Decorator to ensure configuration key is available."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            config = get_config()
            if not hasattr(config, config_key.replace('.', '_')):
                raise ConfigValidationError(f"Required configuration key not found: {config_key}")
            return func(*args, **kwargs)
        return wrapper
    return decorator

def with_config(func):
    """Decorator to inject configuration as first argument."""
    def wrapper(*args, **kwargs):
        config = get_config()
        return func(config, *args, **kwargs)
    return wrapper

# Configuration utilities
def get_config_value(key: str, default: Any = None) -> Any:
    """Get a configuration value by dot-notation key."""
    config = get_config()
    keys = key.split('.')
    value = config
    
    try:
        for k in keys:
            if hasattr(value, k):
                value = getattr(value, k)
            elif isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    except (AttributeError, KeyError, TypeError):
        return default

def set_config_value(key: str, value: Any) -> bool:
    """Set a configuration value by dot-notation key."""
    try:
        config = get_config()
        keys = key.split('.')
        target = config
        
        # Navigate to parent
        for k in keys[:-1]:
            if hasattr(target, k):
                target = getattr(target, k)
            elif isinstance(target, dict):
                if k not in target:
                    target[k] = {}
                target = target[k]
            else:
                return False
        
        # Set final value
        final_key = keys[-1]
        if hasattr(target, final_key):
            setattr(target, final_key, value)
        elif isinstance(target, dict):
            target[final_key] = value
        else:
            return False
        
        return True
    except Exception as e:
        logger.error(f"Failed to set config value {key}: {e}")
        return False

def get_config_hash() -> str:
    """Get hash of current configuration for change detection."""
    config = get_config()
    config_str = json.dumps(config.__dict__, sort_keys=True, default=str)
    return hashlib.sha256(config_str.encode()).hexdigest()

# Export main components
__all__ = [
    # Main classes
    "ConfigManager",
    "NetLinkConfig",
    "ConfigValidationError",
    
    # Configuration schemas
    "ServerConfig",
    "DatabaseConfig", 
    "SecurityConfig",
    "BackupConfig",
    "ClusterConfig",
    "LoggingConfig",
    "AIConfig",
    
    # Utility classes
    "ConfigValidator",
    "ValidationError",
    "EnvironmentManager",
    "ConfigTemplateGenerator",
    "ConfigMigrator",
    "ConfigMigrationError",
    
    # Functions
    "initialize_config",
    "get_config",
    "reload_config",
    "save_config",
    "validate_config",
    "get_environment",
    "set_environment",
    "create_config_template",
    "migrate_config",
    "get_config_manager",
    "get_config_value",
    "set_config_value",
    "get_config_hash",
    
    # Decorators
    "config_required",
    "with_config",
    
    # Constants
    "DEFAULT_CONFIG",
    "CONFIG_SCHEMA_VERSION",
    "ENV_PREFIX",
    "ENV_PREFIXES"
]

# Initialize logging for configuration system
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger.info(f"NetLink Configuration System initialized (v{CONFIG_SCHEMA_VERSION})")
