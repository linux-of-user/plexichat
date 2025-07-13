import os
import sys
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime

#!/usr/bin/env python3
"""
Configuration Wizard for PlexiChat
==================================

Interactive configuration wizard that guides users through
setting up PlexiChat with proper configuration files.
"""


logger = logging.getLogger(__name__)

class ConfigurationWizard:
    """Interactive configuration wizard."""
    
    def __init__(self):
        self.config_dir = Path("config")
        self.config_dir.mkdir(exist_ok=True)
        self.main_config_file = self.config_dir / "plexichat.yaml"
        self.plugins_config_dir = self.config_dir / "plugins"
        self.plugins_config_dir.mkdir(exist_ok=True)
        
        # Configuration templates
        self.templates = {
            "development": self.get_development_template(),
            "production": self.get_production_template(),
            "testing": self.get_testing_template()
        }
    
    def get_development_template(self) -> Dict[str, Any]:
        """Get development configuration template."""
        return {
            "system": {
                "name": "PlexiChat",
                "version": "1.0.0",
                "environment": "development",
                "debug": True,
                "timezone": "UTC"
            },
            "database": {
                "type": "sqlite",
                "path": "data/plexichat_dev.db",
                "pool_size": 5,
                "max_overflow": 10,
                "echo": True
            },
            "security": {
                "encryption": "aes-256-gcm",
                "key_rotation_days": 7,
                "session_timeout": 1800,
                "max_login_attempts": 10,
                "password_min_length": 6,
                "require_special_chars": False
            },
            "network": {
                "host": "127.0.0.1",
                "port": 8080,
                "api_port": 8000,
                "admin_port": 8002,
                "websocket_port": 8001,
                "ssl_enabled": False,
                "ssl_cert": "",
                "ssl_key": ""
            },
            "logging": {
                "level": "DEBUG",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "file": "logs/plexichat_dev.log",
                "max_size": "5MB",
                "backup_count": 3
            },
            "ai": {
                "enabled": True,
                "provider": "openai",
                "api_key": "",
                "model": "gpt-3.5-turbo",
                "max_tokens": 500,
                "temperature": 0.7
            },
            "backup": {
                "enabled": False,
                "schedule": "daily",
                "retention_days": 7,
                "compression": True,
                "encryption": False
            },
            "clustering": {
                "enabled": False,
                "nodes": [],
                "leader_election": False,
                "heartbeat_interval": 60
            },
            "plugins": {},
            "ui": {
                "theme": "light",
                "language": "en",
                "timezone": "UTC",
                "date_format": "%Y-%m-%d",
                "time_format": "%H:%M:%S"
            },
            "performance": {
                "max_connections": 100,
                "connection_timeout": 30,
                "request_timeout": 60,
                "cache_size": 100,
                "cache_ttl": 60
            },
            "monitoring": {
                "enabled": True,
                "metrics_interval": 30,
                "health_check_interval": 15,
                "alerting": False
            }
        }
    
    def get_production_template(self) -> Dict[str, Any]:
        """Get production configuration template."""
        return {
            "system": {
                "name": "PlexiChat",
                "version": "1.0.0",
                "environment": "production",
                "debug": False,
                "timezone": "UTC"
            },
            "database": {
                "type": "postgresql",
                "host": "localhost",
                "port": 5432,
                "name": "plexichat",
                "user": "plexichat",
                "password": "",
                "pool_size": 20,
                "max_overflow": 30,
                "echo": False
            },
            "security": {
                "encryption": "aes-256-gcm",
                "key_rotation_days": 30,
                "session_timeout": 3600,
                "max_login_attempts": 5,
                "password_min_length": 12,
                "require_special_chars": True
            },
            "network": {
                "host": "0.0.0.0",
                "port": 443,
                "api_port": 8443,
                "admin_port": 8444,
                "websocket_port": 8445,
                "ssl_enabled": True,
                "ssl_cert": "certs/server.crt",
                "ssl_key": "certs/server.key"
            },
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "file": "logs/plexichat.log",
                "max_size": "100MB",
                "backup_count": 10
            },
            "ai": {
                "enabled": True,
                "provider": "openai",
                "api_key": "",
                "model": "gpt-4",
                "max_tokens": 2000,
                "temperature": 0.7
            },
            "backup": {
                "enabled": True,
                "schedule": "daily",
                "retention_days": 90,
                "compression": True,
                "encryption": True
            },
            "clustering": {
                "enabled": True,
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
                "max_connections": 10000,
                "connection_timeout": 30,
                "request_timeout": 60,
                "cache_size": 10000,
                "cache_ttl": 300
            },
            "monitoring": {
                "enabled": True,
                "metrics_interval": 60,
                "health_check_interval": 30,
                "alerting": True
            }
        }
    
    def get_testing_template(self) -> Dict[str, Any]:
        """Get testing configuration template."""
        return {
            "system": {
                "name": "PlexiChat",
                "version": "1.0.0",
                "environment": "testing",
                "debug": True,
                "timezone": "UTC"
            },
            "database": {
                "type": "sqlite",
                "path": "data/plexichat_test.db",
                "pool_size": 1,
                "max_overflow": 1,
                "echo": True
            },
            "security": {
                "encryption": "aes-256-gcm",
                "key_rotation_days": 1,
                "session_timeout": 300,
                "max_login_attempts": 100,
                "password_min_length": 1,
                "require_special_chars": False
            },
            "network": {
                "host": "127.0.0.1",
                "port": 8081,
                "api_port": 8001,
                "admin_port": 8003,
                "websocket_port": 8002,
                "ssl_enabled": False,
                "ssl_cert": "",
                "ssl_key": ""
            },
            "logging": {
                "level": "DEBUG",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "file": "logs/plexichat_test.log",
                "max_size": "1MB",
                "backup_count": 1
            },
            "ai": {
                "enabled": False,
                "provider": "mock",
                "api_key": "",
                "model": "mock",
                "max_tokens": 100,
                "temperature": 0.5
            },
            "backup": {
                "enabled": False,
                "schedule": "never",
                "retention_days": 1,
                "compression": False,
                "encryption": False
            },
            "clustering": {
                "enabled": False,
                "nodes": [],
                "leader_election": False,
                "heartbeat_interval": 300
            },
            "plugins": {},
            "ui": {
                "theme": "light",
                "language": "en",
                "timezone": "UTC",
                "date_format": "%Y-%m-%d",
                "time_format": "%H:%M:%S"
            },
            "performance": {
                "max_connections": 10,
                "connection_timeout": 5,
                "request_timeout": 10,
                "cache_size": 10,
                "cache_ttl": 10
            },
            "monitoring": {
                "enabled": False,
                "metrics_interval": 300,
                "health_check_interval": 300,
                "alerting": False
            }
        }
    
    def run_wizard(self):
        """Run the interactive configuration wizard."""
        print("=== PlexiChat Configuration Wizard ===")
        print("This wizard will help you configure PlexiChat for your environment.")
        print()
        
        # Step 1: Choose environment
        environment = self.choose_environment()
        
        # Step 2: Choose template
        template = self.choose_template(environment)
        
        # Step 3: Customize configuration
        config = self.customize_configuration(template)
        
        # Step 4: Save configuration
        self.save_configuration(config)
        
        # Step 5: Setup plugins
        self.setup_plugins()
        
        print("\n=== Configuration Complete ===")
        print(f"Configuration saved to: {self.main_config_file}")
        print("You can now start PlexiChat with: python run.py")
        print()
    
    def choose_environment(self) -> str:
        """Let user choose the environment."""
        print("1. Development - For development and testing")
        print("2. Production - For production deployment")
        print("3. Testing - For automated testing")
        print()
        
        while True:
            choice = input("Choose environment (1-3): ").strip()
            if choice == "1":
                return "development"
            elif choice == "2":
                return "production"
            elif choice == "3":
                return "testing"
            else:
                print("Please enter 1, 2, or 3")
    
    def choose_template(self, environment: str) -> Dict[str, Any]:
        """Choose configuration template."""
        print(f"\nUsing {environment} template as base configuration.")
        
        if environment == "development":
            return self.templates["development"]
        elif environment == "production":
            return self.templates["production"]
        elif environment == "testing":
            return self.templates["testing"]
        else:
            return self.templates["development"]
    
    def customize_configuration(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """Customize the configuration template."""
        config = template.copy()
        
        print("\n=== Customize Configuration ===")
        print("Press Enter to use default values, or enter custom values.")
        print()
        
        # System configuration
        print("System Configuration:")
        config["system"]["name"] = input(f"System name [{config['system']['name']}]: ") or config["system"]["name"]
        config["system"]["environment"] = input(f"Environment [{config['system']['environment']}]: ") or config["system"]["environment"]
        
        # Database configuration
        print("\nDatabase Configuration:")
        db_type = input(f"Database type [{config['database']['type']}]: ") or config["database"]["type"]
        config["database"]["type"] = db_type
        
        if db_type == "sqlite":
            config["database"]["path"] = input(f"Database path [{config['database']['path']}]: ") or config["database"]["path"]
        else:
            config["database"]["host"] = input(f"Database host [{config['database']['host']}]: ") or config["database"]["host"]
            config["database"]["port"] = int(input(f"Database port [{config['database']['port']}]: ") or str(config["database"]["port"]))
            config["database"]["name"] = input(f"Database name [{config['database']['name']}]: ") or config["database"]["name"]
            config["database"]["user"] = input(f"Database user [{config['database']['user']}]: ") or config["database"]["user"]
            config["database"]["password"] = input("Database password: ") or config["database"]["password"]
        
        # Network configuration
        print("\nNetwork Configuration:")
        config["network"]["host"] = input(f"Host address [{config['network']['host']}]: ") or config["network"]["host"]
        config["network"]["port"] = int(input(f"Web port [{config['network']['port']}]: ") or str(config["network"]["port"]))
        config["network"]["api_port"] = int(input(f"API port [{config['network']['api_port']}]: ") or str(config["network"]["api_port"]))
        
        # Security configuration
        print("\nSecurity Configuration:")
        config["security"]["password_min_length"] = int(input(f"Minimum password length [{config['security']['password_min_length']}]: ") or str(config["security"]["password_min_length"]))
        config["security"]["session_timeout"] = int(input(f"Session timeout (seconds) [{config['security']['session_timeout']}]: ") or str(config["security"]["session_timeout"]))
        
        # AI configuration
        print("\nAI Configuration:")
        ai_enabled = input(f"Enable AI features (y/n) [{'y' if config['ai']['enabled'] else 'n'}]: ").lower()
        if ai_enabled in ['y', 'yes']:
            config["ai"]["enabled"] = True
            config["ai"]["provider"] = input(f"AI provider [{config['ai']['provider']}]: ") or config["ai"]["provider"]
            config["ai"]["api_key"] = input("AI API key: ") or config["ai"]["api_key"]
            config["ai"]["model"] = input(f"AI model [{config['ai']['model']}]: ") or config["ai"]["model"]
        else:
            config["ai"]["enabled"] = False
        
        return config
    
    def save_configuration(self, config: Dict[str, Any]):
        """Save configuration to file."""
        try:
            # Save main configuration
            main_config = {k: v for k, v in config.items() if k != "plugins"}
            with open(self.main_config_file, 'w', encoding='utf-8') as f:
                yaml.dump(main_config, f, default_flow_style=False, indent=2)
            
            print(f"Configuration saved to: {self.main_config_file}")
            
        except Exception as e:
            print(f"Error saving configuration: {e}")
            sys.exit(1)
    
    def setup_plugins(self):
        """Setup plugin configurations."""
        print("\n=== Plugin Configuration ===")
        
        plugins = [
            "archive_system",
            "antivirus",
            "backup",
            "clustering",
            "security",
            "ai_features"
        ]
        
        for plugin in plugins:
            enable = input(f"Enable {plugin} plugin? (y/n) [n]: ").lower()
            if enable in ['y', 'yes']:
                plugin_config = self.create_plugin_config(plugin)
                plugin_file = self.plugins_config_dir / f"{plugin}.yaml"
                
                try:
                    with open(plugin_file, 'w', encoding='utf-8') as f:
                        yaml.dump(plugin_config, f, default_flow_style=False, indent=2)
                    print(f"  {plugin} plugin configured")
                except Exception as e:
                    print(f"  Error configuring {plugin} plugin: {e}")
    
    def create_plugin_config(self, plugin_name: str) -> Dict[str, Any]:
        """Create configuration for a specific plugin."""
        configs = {
            "archive_system": {
                "enabled": True,
                "retention_days": 365,
                "compression": True,
                "encryption": True
            },
            "antivirus": {
                "enabled": True,
                "scan_on_upload": True,
                "scan_on_download": False,
                "quarantine_suspicious": True
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
            "security": {
                "enabled": True,
                "encryption": True,
                "certificate_management": True,
                "firewall": True
            },
            "ai_features": {
                "enabled": True,
                "provider": "openai",
                "api_key": "",
                "model": "gpt-3.5-turbo"
            }
        }
        
        return configs.get(plugin_name, {"enabled": True})

def main():
    """Main entry point for configuration wizard."""
    wizard = ConfigurationWizard()
    wizard.run_wizard()

if __name__ == '__main__':
    main() 