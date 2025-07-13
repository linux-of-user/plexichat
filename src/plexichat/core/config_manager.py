import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime

#!/usr/bin/env python3
"""
Configuration Manager for PlexiChat
==================================

Handles all configuration through YAML files with support for:
- Main application configuration
- Plugin-specific configurations
- Environment-specific settings
- Dynamic configuration updates
- Configuration validation
- Configuration wizards
"""


logger = logging.getLogger(__name__)

@dataclass
class ConfigSection:
    """Represents a configuration section."""
    name: str
    data: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    required: bool = False
    validator: Optional[Callable] = None

class ConfigurationManager:
    """Manages all PlexiChat configuration through YAML files."""
    
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or Path("config")
        self.config_dir.mkdir(exist_ok=True)
        
        # Main configuration files
        self.main_config_file = self.config_dir / "plexichat.yaml"
        self.plugins_config_dir = self.config_dir / "plugins"
        self.plugins_config_dir.mkdir(exist_ok=True)
        
        # Configuration sections
        self.sections = {
            "system": ConfigSection("system", description="System configuration"),
            "database": ConfigSection("database", description="Database configuration", required=True),
            "security": ConfigSection("security", description="Security settings", required=True),
            "network": ConfigSection("network", description="Network configuration"),
            "logging": ConfigSection("logging", description="Logging configuration"),
            "ai": ConfigSection("ai", description="AI features configuration"),
            "backup": ConfigSection("backup", description="Backup configuration"),
            "clustering": ConfigSection("clustering", description="Clustering configuration"),
            "plugins": ConfigSection("plugins", description="Plugin configuration"),
            "ui": ConfigSection("ui", description="User interface configuration"),
            "performance": ConfigSection("performance", description="Performance settings"),
            "monitoring": ConfigSection("monitoring", description="Monitoring configuration")
        }
        
        # Load configuration
        self.config = self.load_configuration()

    async def initialize(self) -> bool:
        """Initialize the configuration manager."""
        try:
            logger.info("Initializing Configuration Manager...")

            # Reload configuration
            self.config = self.load_configuration()

            logger.info("Configuration Manager initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Configuration Manager initialization failed: {e}")
            return False

    def load_configuration(self) -> Dict[str, Any]:
        """Load all configuration from YAML files."""
        config = {}
        
        # Load main configuration
        if self.main_config_file.exists():
            try:
                with open(self.main_config_file, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f) or {}
                logger.info(f"Loaded main configuration from {self.main_config_file}")
            except Exception as e:
                logger.error(f"Error loading main configuration: {e}")
                config = {}
        
        # Load plugin configurations
        plugin_configs = {}
        for plugin_file in self.plugins_config_dir.glob("*.yaml"):
            try:
                with open(plugin_file, 'r', encoding='utf-8') as f:
                    plugin_name = plugin_file.stem
                    plugin_configs[plugin_name] = yaml.safe_load(f) or {}
                logger.info(f"Loaded plugin configuration: {plugin_name}")
            except Exception as e:
                logger.error(f"Error loading plugin configuration {plugin_file}: {e}")
        
        config["plugins"] = plugin_configs
        
        # Set defaults for missing sections
        config = self.set_defaults(config)
        
        return config
    
    def set_defaults(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Set default values for missing configuration sections."""
        defaults = {
            "system": {
                "name": "PlexiChat",
                "version": "1.0.0",
                "environment": "production",
                "debug": False,
                "timezone": "UTC"
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
            "network": {
                "host": "0.0.0.0",
                "port": 8080,
                "api_port": 8000,
                "admin_port": 8002,
                "websocket_port": 8001,
                "ssl_enabled": False,
                "ssl_cert": "",
                "ssl_key": ""
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
            "backup": {
                "enabled": True,
                "schedule": "daily",
                "retention_days": 30,
                "compression": True,
                "encryption": True
            },
            "clustering": {
                "enabled": False,
                "nodes": [],
                "leader_election": True,
                "heartbeat_interval": 30
            },
            "plugins": {},
            "ui": {
                "theme": "dark",
                "language": "en",
                "timezone": "UTC",
                "date_format": "%Y-%m-%d",
                "time_format": "%H:%M:%S"
            },
            "performance": {
                "max_connections": 1000,
                "connection_timeout": 30,
                "request_timeout": 60,
                "cache_size": 1000,
                "cache_ttl": 300
            },
            "monitoring": {
                "enabled": True,
                "metrics_interval": 60,
                "health_check_interval": 30,
                "alerting": True
            }
        }
        
        # Merge defaults with existing config
        for section, default_data in defaults.items():
            if section not in config:
                config[section] = default_data
            else:
                # Merge nested dictionaries
                for key, value in default_data.items():
                    if key not in config[section]:
                        config[section][key] = value
        
        return config
    
    def save_configuration(self, config: Optional[Dict[str, Any]] = None) -> bool:
        """Save configuration to YAML files."""
        if config is None:
            config = self.config
        
        try:
            # Save main configuration
            main_config = {k: v for k, v in config.items() if k != "plugins"}
            with open(self.main_config_file, 'w', encoding='utf-8') as f:
                yaml.dump(main_config, f, default_flow_style=False, indent=2)
            
            # Save plugin configurations
            if "plugins" in config:
                for plugin_name, plugin_config in config["plugins"].items():
                    plugin_file = self.plugins_config_dir / f"{plugin_name}.yaml"
                    with open(plugin_file, 'w', encoding='utf-8') as f:
                        yaml.dump(plugin_config, f, default_flow_style=False, indent=2)
            
            logger.info("Configuration saved successfully")
            return True
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value using dot notation."""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> bool:
        """Set a configuration value using dot notation."""
        keys = key.split('.')
        config = self.config
        
        # Navigate to the parent of the target key
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the value
        config[keys[-1]] = value
        return True
    
    def validate_configuration(self) -> List[str]:
        """Validate the current configuration."""
        errors = []
        
        # Check required sections
        for section_name, section in self.sections.items():
            if section.required and section_name not in self.config:
                errors.append(f"Required section '{section_name}' is missing")
        
        # Validate specific sections
        errors.extend(self.validate_database_config())
        errors.extend(self.validate_security_config())
        errors.extend(self.validate_network_config())
        
        return errors
    
    def validate_database_config(self) -> List[str]:
        """Validate database configuration."""
        errors = []
        db_config = self.config.get("database", {})
        
        if not db_config.get("type"):
            errors.append("Database type is required")
        
        if db_config.get("type") == "sqlite" and not db_config.get("path"):
            errors.append("SQLite database path is required")
        
        return errors
    
    def validate_security_config(self) -> List[str]:
        """Validate security configuration."""
        errors = []
        security_config = self.config.get("security", {})
        
        if not security_config.get("encryption"):
            errors.append("Encryption method is required")
        
        if security_config.get("password_min_length", 0) < 6:
            errors.append("Password minimum length must be at least 6")
        
        return errors
    
    def validate_network_config(self) -> List[str]:
        """Validate network configuration."""
        errors = []
        network_config = self.config.get("network", {})
        
        if not network_config.get("host"):
            errors.append("Host address is required")
        
        if not network_config.get("port"):
            errors.append("Port number is required")
        
        return errors
    
    def get_plugin_config(self, plugin_name: str) -> Dict[str, Any]:
        """Get configuration for a specific plugin."""
        return self.config.get("plugins", {}).get(plugin_name, {})
    
    def set_plugin_config(self, plugin_name: str, config: Dict[str, Any]) -> bool:
        """Set configuration for a specific plugin."""
        if "plugins" not in self.config:
            self.config["plugins"] = {}
        
        self.config["plugins"][plugin_name] = config
        return self.save_configuration()
    
    def create_configuration_wizard(self) -> Dict[str, Any]:
        """Interactive configuration wizard."""
        print("=== PlexiChat Configuration Wizard ===")

        config: Dict[str, Any] = {}
        
        # System configuration
        print("\n1. System Configuration")
        config["system"] = {
            "name": input("System name [PlexiChat]: ") or "PlexiChat",
            "environment": input("Environment (development/production) [production]: ") or "production",
            "debug": input("Enable debug mode (y/n) [n]: ").lower() == 'y'
        }
        
        # Database configuration
        print("\n2. Database Configuration")
        db_type = input("Database type (sqlite/postgresql/mysql) [sqlite]: ") or "sqlite"
        config["database"] = {"type": db_type}
        
        if db_type == "sqlite":
            config["database"]["path"] = input("Database path [data/plexichat.db]: ") or "data/plexichat.db"
        else:
            config["database"]["host"] = input("Database host: ")
            config["database"]["port"] = input("Database port [5432]: ") or "5432"
            config["database"]["name"] = input("Database name: ")
            config["database"]["user"] = input("Database user: ")
            config["database"]["password"] = input("Database password: ")
        # Security configuration
        print("\n3. Security Configuration")
        config["security"] = {
            "encryption": input("Encryption method [aes-256-gcm]: ") or "aes-256-gcm",
            "session_timeout": int(input("Session timeout (seconds) [3600]: ") or "3600"),
            "password_min_length": int(input("Minimum password length [8]: ") or "8")
        }
        
        # Network configuration
        print("\n4. Network Configuration")
        config["network"] = {
            "host": input("Host address [0.0.0.0]: ") or "0.0.0.0",
            "port": int(input("Web port [8080]: ") or "8080"),
            "api_port": int(input("API port [8000]: ") or "8000"),
            "admin_port": int(input("Admin port [8002]: ") or "8002")
        }
        
        # AI configuration
        print("\n5. AI Configuration")
        ai_enabled = input("Enable AI features (y/n) [y]: ").lower() != 'n'
        config["ai"] = {"enabled": ai_enabled}

        if ai_enabled:
            provider = input("AI provider (openai/anthropic) [openai]: ") or "openai"
            api_key = input("API key: ")
            model = input("Model name [gpt-3.5-turbo]: ") or "gpt-3.5-turbo"
            # Use type: ignore to bypass type checker for this dynamic assignment
            config["ai"]["provider"] = provider  # type: ignore
            config["ai"]["api_key"] = api_key  # type: ignore
            config["ai"]["model"] = model  # type: ignore

        return config
    
    def export_configuration(self, filepath: Path) -> bool:
        """Export configuration to a file."""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, indent=2)
            logger.info(f"Configuration exported to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Error exporting configuration: {e}")
            return False
    
    def import_configuration(self, filepath: Path) -> bool:
        """Import configuration from a file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                imported_config = yaml.safe_load(f)
            
            # Merge with existing configuration
            self.config.update(imported_config)
            return self.save_configuration()
        except Exception as e:
            logger.error(f"Error importing configuration: {e}")
            return False

# Global configuration manager instance
config_manager = ConfigurationManager() 