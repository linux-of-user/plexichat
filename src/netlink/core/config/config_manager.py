"""
NetLink Configuration Manager

Unified configuration management system with YAML support, validation,
environment variable integration, and hot-reload capabilities.
"""

import os
import sys
import yaml
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Callable
from datetime import datetime
import threading
import time
import hashlib
from dataclasses import asdict

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

logger = logging.getLogger(__name__)

class ConfigValidationError(Exception):
    """Configuration validation error."""
    pass

class ConfigManager:
    """
    Unified configuration manager for NetLink.
    
    Features:
    - YAML-based configuration files
    - Environment variable override support
    - Configuration validation and schema checking
    - Hot-reload capabilities with file watching
    - Multi-environment support
    - Configuration templates and defaults
    - Encrypted sensitive values
    - Configuration versioning and migration
    """
    
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or Path("config")
        self.config_file = self.config_dir / "netlink.yaml"
        self.environment = os.getenv("NETLINK_ENVIRONMENT", "development")
        
        # Configuration state
        self._config: Optional[Dict[str, Any]] = None
        self._config_hash: Optional[str] = None
        self._last_modified: Optional[datetime] = None
        self._watchers: List[Callable] = []
        self._watch_thread: Optional[threading.Thread] = None
        self._watch_enabled = False
        
        # Environment-specific config files
        self.env_config_file = self.config_dir / f"netlink.{self.environment}.yaml"
        
        # Create directories
        self.config_dir.mkdir(parents=True, exist_ok=True)
        Path("data").mkdir(parents=True, exist_ok=True)
        Path("logs").mkdir(parents=True, exist_ok=True)
        Path("backups").mkdir(parents=True, exist_ok=True)
        
        logger.info(f"ConfigManager initialized for environment: {self.environment}")
    
    def initialize(
        self,
        config_dir: Optional[Path] = None,
        config_file: Optional[str] = None,
        environment: Optional[str] = None
    ) -> Dict[str, Any]:
        """Initialize configuration system."""
        if config_dir:
            self.config_dir = config_dir
            self.config_dir.mkdir(parents=True, exist_ok=True)
        
        if config_file:
            self.config_file = self.config_dir / config_file
        
        if environment:
            self.environment = environment
            os.environ["NETLINK_ENVIRONMENT"] = environment
            self.env_config_file = self.config_dir / f"netlink.{environment}.yaml"
        
        # Load configuration
        config = self.load_config()
        
        # Start file watching if enabled
        if os.getenv("NETLINK_CONFIG_WATCH", "false").lower() == "true":
            self.start_watching()
        
        return config
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration structure."""
        return {
            "version": "3.0.0",
            "environment": self.environment,
            "application": {
                "name": "NetLink",
                "version": "3.0.0",
                "description": "Government-Level Secure Communication Platform",
                "debug": self.environment == "development",
                "host": "0.0.0.0",
                "port": 8000,
                "workers": 4,
                "auto_reload": self.environment == "development"
            },
            "server": {
                "host": "0.0.0.0",
                "port": 8000,
                "workers": 4,
                "debug": self.environment == "development",
                "auto_reload": self.environment == "development",
                "access_log": True,
                "ssl_enabled": False,
                "ssl_cert_file": None,
                "ssl_key_file": None,
                "cors_enabled": True,
                "cors_origins": ["*"] if self.environment == "development" else []
            },
            "database": {
                "type": "sqlite",
                "url": "sqlite:///./data/netlink.db",
                "host": "localhost",
                "port": 5432,
                "name": "netlink",
                "username": None,
                "password": None,
                "pool_size": 10,
                "pool_timeout": 30,
                "echo": self.environment == "development",
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
                "password_require_uppercase": True,
                "password_require_lowercase": True,
                "password_require_numbers": True,
                "password_require_symbols": True,
                "max_login_attempts": 5,
                "lockout_duration": 300,
                "mfa_enabled": True,
                "mfa_methods": ["totp", "sms", "email"],
                "biometric_enabled": False,
                "rate_limiting": True,
                "rate_limit_requests": 1000,
                "rate_limit_window": 60,
                "encryption_algorithm": "AES-256-GCM",
                "hash_algorithm": "SHA-512"
            },
            "backup": {
                "enabled": True,
                "directory": "backups",
                "encryption_enabled": True,
                "compression_enabled": True,
                "compression_algorithm": "zstd",
                "distributed_enabled": True,
                "shard_size_mb": 10,
                "redundancy_level": 2,
                "retention_days": 30,
                "auto_backup_interval": 3600,
                "backup_types": ["database", "files", "config"],
                "verification_enabled": True,
                "quantum_encryption": True
            },
            "cluster": {
                "enabled": False,
                "node_id": None,
                "node_name": None,
                "discovery_method": "static",
                "nodes": [],
                "heartbeat_interval": 30,
                "election_timeout": 5000,
                "sync_interval": 300,
                "encryption_enabled": True
            },
            "logging": {
                "level": "DEBUG" if self.environment == "development" else "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "file": "logs/netlink.log",
                "max_size": "10MB",
                "backup_count": 5,
                "console_enabled": True,
                "file_enabled": True,
                "structured_logging": True,
                "log_requests": self.environment == "development"
            },
            "ai": {
                "enabled": False,
                "providers": [],
                "default_provider": None,
                "api_keys": {},
                "models": {},
                "timeout": 30,
                "max_retries": 3,
                "features": {
                    "chat_completion": False,
                    "content_moderation": False,
                    "translation": False,
                    "summarization": False,
                    "sentiment_analysis": False
                }
            },
            "features": {
                "backup_system": True,
                "clustering": False,
                "ai_integration": False,
                "web_ui": True,
                "api_docs": True,
                "metrics": True,
                "health_checks": True,
                "file_sharing": True,
                "voice_calling": False,
                "video_calling": False,
                "screen_sharing": False,
                "real_time_collaboration": False
            },
            "limits": {
                "max_message_length": 10000,
                "max_file_size_mb": 100,
                "max_users": 10000,
                "rate_limit_per_minute": 1000,
                "max_concurrent_connections": 1000,
                "max_upload_size_mb": 500,
                "max_backup_size_gb": 100
            },
            "monitoring": {
                "enabled": True,
                "metrics_enabled": True,
                "health_checks_enabled": True,
                "performance_monitoring": True,
                "error_tracking": True,
                "log_aggregation": True
            }
        }
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from files and environment variables."""
        try:
            # Start with default configuration
            config = self.get_default_config()
            
            # Load main configuration file
            if self.config_file.exists():
                logger.info(f"Loading configuration from {self.config_file}")
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    file_config = yaml.safe_load(f) or {}
                config = self._deep_merge(config, file_config)
            else:
                logger.info(f"Configuration file not found, creating default: {self.config_file}")
                self.save_config_to_file(config, self.config_file)
            
            # Load environment-specific configuration
            if self.env_config_file.exists():
                logger.info(f"Loading environment config from {self.env_config_file}")
                with open(self.env_config_file, 'r', encoding='utf-8') as f:
                    env_config = yaml.safe_load(f) or {}
                config = self._deep_merge(config, env_config)
            
            # Override with environment variables
            config = self._apply_environment_variables(config)
            
            # Generate missing secrets
            config = self._generate_secrets(config)
            
            # Validate configuration
            self._validate_config(config)
            
            # Update state
            self._config = config
            self._config_hash = self._calculate_hash(config)
            self._last_modified = datetime.now()
            
            logger.info("Configuration loaded successfully")
            return config
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise ConfigValidationError(f"Configuration loading failed: {e}")
    
    def save_config(self, config: Dict[str, Any]) -> bool:
        """Save configuration to file."""
        try:
            self.save_config_to_file(config, self.config_file)
            self._config = config
            self._config_hash = self._calculate_hash(config)
            self._last_modified = datetime.now()
            logger.info("Configuration saved successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False
    
    def save_config_to_file(self, config: Dict[str, Any], file_path: Path):
        """Save configuration to specific file."""
        # Remove sensitive data before saving
        safe_config = self._sanitize_config_for_save(config)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            yaml.dump(
                safe_config,
                f,
                default_flow_style=False,
                indent=2,
                sort_keys=False,
                allow_unicode=True
            )
    
    def get_config(self) -> Dict[str, Any]:
        """Get current configuration."""
        if self._config is None:
            self._config = self.load_config()
        return self._config
    
    def reload_config(self) -> Dict[str, Any]:
        """Reload configuration from files."""
        logger.info("Reloading configuration")
        old_hash = self._config_hash
        config = self.load_config()
        
        # Notify watchers if configuration changed
        if old_hash != self._config_hash:
            self._notify_watchers(config)
        
        return config

    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value

        return result

    def _apply_environment_variables(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply environment variable overrides to configuration."""
        env_mappings = {
            # Server configuration
            "NETLINK_HOST": ("server", "host"),
            "NETLINK_PORT": ("server", "port"),
            "NETLINK_DEBUG": ("server", "debug"),
            "NETLINK_WORKERS": ("server", "workers"),

            # Database configuration
            "NETLINK_DB_TYPE": ("database", "type"),
            "NETLINK_DB_URL": ("database", "url"),
            "NETLINK_DB_HOST": ("database", "host"),
            "NETLINK_DB_PORT": ("database", "port"),
            "NETLINK_DB_NAME": ("database", "name"),
            "NETLINK_DB_USERNAME": ("database", "username"),
            "NETLINK_DB_PASSWORD": ("database", "password"),

            # Security configuration
            "NETLINK_SECRET_KEY": ("security", "secret_key"),
            "NETLINK_JWT_ALGORITHM": ("security", "jwt_algorithm"),
            "NETLINK_ACCESS_TOKEN_EXPIRE": ("security", "access_token_expire_minutes"),
            "NETLINK_MFA_ENABLED": ("security", "mfa_enabled"),

            # Backup configuration
            "NETLINK_BACKUP_ENABLED": ("backup", "enabled"),
            "NETLINK_BACKUP_DIR": ("backup", "directory"),
            "NETLINK_BACKUP_ENCRYPTION": ("backup", "encryption_enabled"),

            # Logging configuration
            "NETLINK_LOG_LEVEL": ("logging", "level"),
            "NETLINK_LOG_FILE": ("logging", "file"),

            # AI configuration
            "NETLINK_AI_ENABLED": ("ai", "enabled"),
            "NETLINK_AI_DEFAULT_PROVIDER": ("ai", "default_provider"),
        }

        for env_var, (section, key) in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                # Type conversion
                if key in ["port", "workers", "access_token_expire_minutes", "pool_size", "pool_timeout"]:
                    try:
                        value = int(value)
                    except ValueError:
                        logger.warning(f"Invalid integer value for {env_var}: {value}")
                        continue
                elif key in ["debug", "enabled", "mfa_enabled", "encryption_enabled"]:
                    value = value.lower() in ("true", "1", "yes", "on")

                # Set value in config
                if section not in config:
                    config[section] = {}
                config[section][key] = value
                logger.debug(f"Applied environment override: {env_var} -> {section}.{key} = {value}")

        return config

    def _generate_secrets(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate missing secret keys and secure values."""
        import secrets
        import string

        # Generate secret key if missing
        if not config.get("security", {}).get("secret_key"):
            secret_key = secrets.token_urlsafe(64)
            if "security" not in config:
                config["security"] = {}
            config["security"]["secret_key"] = secret_key
            logger.info("Generated new secret key")

        # Generate node ID if clustering is enabled and ID is missing
        if config.get("cluster", {}).get("enabled") and not config.get("cluster", {}).get("node_id"):
            node_id = secrets.token_hex(16)
            config["cluster"]["node_id"] = node_id
            logger.info(f"Generated cluster node ID: {node_id}")

        return config

    def _validate_config(self, config: Dict[str, Any]):
        """Validate configuration structure and values."""
        errors = []

        # Validate server configuration
        server_config = config.get("server", {})
        port = server_config.get("port", 8000)
        if not isinstance(port, int) or not (1 <= port <= 65535):
            errors.append(f"Invalid server port: {port}")

        # Validate database configuration
        db_config = config.get("database", {})
        db_type = db_config.get("type", "sqlite")
        if db_type not in ["sqlite", "postgresql", "mysql", "mariadb"]:
            errors.append(f"Unsupported database type: {db_type}")

        # Validate security configuration
        security_config = config.get("security", {})
        if not security_config.get("secret_key"):
            errors.append("Security secret key is required")

        password_min_length = security_config.get("password_min_length", 8)
        if not isinstance(password_min_length, int) or password_min_length < 8:
            errors.append("Password minimum length must be at least 8 characters")

        # Validate backup configuration
        backup_config = config.get("backup", {})
        if backup_config.get("enabled"):
            backup_dir = backup_config.get("directory")
            if backup_dir:
                backup_path = Path(backup_dir)
                try:
                    backup_path.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    errors.append(f"Cannot create backup directory {backup_dir}: {e}")

        # Validate logging configuration
        logging_config = config.get("logging", {})
        log_level = logging_config.get("level", "INFO")
        if log_level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            errors.append(f"Invalid logging level: {log_level}")

        if errors:
            error_msg = "Configuration validation errors:\n" + "\n".join(f"  - {error}" for error in errors)
            raise ConfigValidationError(error_msg)

    def _sanitize_config_for_save(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive data before saving configuration."""
        safe_config = json.loads(json.dumps(config))  # Deep copy

        # Remove sensitive keys
        sensitive_keys = [
            ("security", "secret_key"),
            ("database", "password"),
            ("ai", "api_keys")
        ]

        for section, key in sensitive_keys:
            if section in safe_config and key in safe_config[section]:
                if safe_config[section][key]:
                    safe_config[section][key] = "***REDACTED***"

        return safe_config

    def _calculate_hash(self, config: Dict[str, Any]) -> str:
        """Calculate hash of configuration for change detection."""
        config_str = json.dumps(config, sort_keys=True, default=str)
        return hashlib.sha256(config_str.encode()).hexdigest()

    def add_watcher(self, callback: Callable[[Dict[str, Any]], None]):
        """Add configuration change watcher."""
        self._watchers.append(callback)

    def remove_watcher(self, callback: Callable[[Dict[str, Any]], None]):
        """Remove configuration change watcher."""
        if callback in self._watchers:
            self._watchers.remove(callback)

    def _notify_watchers(self, config: Dict[str, Any]):
        """Notify all watchers of configuration changes."""
        for watcher in self._watchers:
            try:
                watcher(config)
            except Exception as e:
                logger.error(f"Configuration watcher error: {e}")

    def start_watching(self):
        """Start watching configuration files for changes."""
        if self._watch_enabled:
            return

        self._watch_enabled = True
        self._watch_thread = threading.Thread(target=self._watch_files, daemon=True)
        self._watch_thread.start()
        logger.info("Configuration file watching started")

    def stop_watching(self):
        """Stop watching configuration files."""
        self._watch_enabled = False
        if self._watch_thread:
            self._watch_thread.join(timeout=1)
        logger.info("Configuration file watching stopped")

    def _watch_files(self):
        """Watch configuration files for changes."""
        files_to_watch = [self.config_file, self.env_config_file]
        last_modified = {}

        # Initialize last modified times
        for file_path in files_to_watch:
            if file_path.exists():
                last_modified[file_path] = file_path.stat().st_mtime

        while self._watch_enabled:
            try:
                changed = False

                for file_path in files_to_watch:
                    if file_path.exists():
                        current_mtime = file_path.stat().st_mtime
                        if file_path not in last_modified or current_mtime > last_modified[file_path]:
                            last_modified[file_path] = current_mtime
                            changed = True
                            logger.info(f"Configuration file changed: {file_path}")

                if changed:
                    # Reload configuration
                    try:
                        self.reload_config()
                    except Exception as e:
                        logger.error(f"Failed to reload configuration: {e}")

                time.sleep(1)  # Check every second

            except Exception as e:
                logger.error(f"Configuration watching error: {e}")
                time.sleep(5)  # Wait longer on error

    def get_config_value(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot notation key."""
        config = self.get_config()
        keys = key.split('.')
        value = config

        try:
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            return value
        except (KeyError, TypeError):
            return default

    def set_config_value(self, key: str, value: Any) -> bool:
        """Set configuration value by dot notation key."""
        try:
            config = self.get_config()
            keys = key.split('.')
            target = config

            # Navigate to parent
            for k in keys[:-1]:
                if k not in target:
                    target[k] = {}
                target = target[k]

            # Set final value
            target[keys[-1]] = value

            # Update state
            self._config = config
            self._config_hash = self._calculate_hash(config)

            return True
        except Exception as e:
            logger.error(f"Failed to set config value {key}: {e}")
            return False

    def export_config(self, format: str = "yaml") -> str:
        """Export configuration in specified format."""
        config = self.get_config()
        safe_config = self._sanitize_config_for_save(config)

        if format.lower() == "yaml":
            return yaml.dump(safe_config, default_flow_style=False, indent=2)
        elif format.lower() == "json":
            return json.dumps(safe_config, indent=2)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    def import_config(self, config_data: str, format: str = "yaml") -> bool:
        """Import configuration from string data."""
        try:
            if format.lower() == "yaml":
                config = yaml.safe_load(config_data)
            elif format.lower() == "json":
                config = json.loads(config_data)
            else:
                raise ValueError(f"Unsupported import format: {format}")

            # Validate imported configuration
            self._validate_config(config)

            # Save configuration
            return self.save_config(config)

        except Exception as e:
            logger.error(f"Failed to import configuration: {e}")
            return False
