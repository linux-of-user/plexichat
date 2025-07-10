"""
NetLink Configuration Manager
Handles dynamic configuration through web UI.
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
import shutil

class ConfigurationManager:
    """Manages NetLink configuration with web UI integration."""
    
    def __init__(self):
        self.config_dir = Path("config")
        self.config_file = self.config_dir / "netlink.yaml"
        self.backup_dir = self.config_dir / "backups"
        self.schema_file = self.config_dir / "schema.json"
        
        # Ensure directories exist
        self.config_dir.mkdir(exist_ok=True)
        self.backup_dir.mkdir(exist_ok=True)
        
        # Load configuration
        self.config = self.load_config()
        self.schema = self.load_schema()
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "server": {
                "host": "0.0.0.0",
                "port": 8000,
                "workers": 4,
                "debug": False,
                "environment": "production",
                "auto_reload": False,
                "access_log": True
            },
            "database": {
                "type": "sqlite",
                "url": "sqlite:///./netlink.db",  # Moved to root
                "pool_size": 10,
                "pool_timeout": 30,
                "echo": False,
                "backup_enabled": True,
                "backup_interval": 3600
            },
            "security": {
                "secret_key": None,  # Auto-generated
                "jwt_expire_minutes": 30,
                "password_min_length": 8,
                "max_login_attempts": 5,
                "lockout_duration": 300,
                "https_enabled": False,
                "https_cert_file": None,
                "https_key_file": None,
                "cors_enabled": True,
                "cors_origins": ["*"],
                "rate_limiting": True
            },
            "features": {
                "clustering": True,
                "hot_updates": True,
                "file_uploads": True,
                "analytics": True,
                "websockets": True,
                "api_docs": True,
                "admin_panel": True
            },
            "limits": {
                "max_file_size": "10MB",
                "max_message_length": 2000,
                "max_users": 1000,
                "max_channels": 100,
                "rate_limit_requests": 100,
                "rate_limit_window": 60,
                "session_timeout": 1800
            },
            "logging": {
                "level": "INFO",
                "file_enabled": True,
                "file_path": "./logs/netlink.log",
                "file_max_size": "10MB",
                "file_backup_count": 5,
                "console_enabled": True,
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            },
            "clustering": {
                "enabled": True,
                "discovery_enabled": True,
                "discovery_ports": [8000, 8001, 8002, 8003, 8004],
                "heartbeat_interval": 10,
                "node_timeout": 30,
                "leader_election": True,
                "load_balancing": True
            },
            "analytics": {
                "enabled": True,
                "retention_days": 30,
                "detailed_logging": False,
                "performance_monitoring": True,
                "user_tracking": True,
                "export_enabled": True
            },
            "notifications": {
                "email_enabled": False,
                "email_smtp_host": None,
                "email_smtp_port": 587,
                "email_username": None,
                "email_password": None,
                "email_use_tls": True,
                "webhook_enabled": False,
                "webhook_url": None
            },
            "backup": {
                "enabled": True,
                "interval": 86400,  # 24 hours
                "retention_days": 7,
                "compression": True,
                "remote_backup": False,
                "remote_url": None,
                "encryption": False
            }
        }
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        if not self.config_file.exists():
            # Create default config
            config = self.get_default_config()
            self.save_config(config)
            return config
        
        try:
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            # Merge with defaults to ensure all keys exist
            default_config = self.get_default_config()
            return self.merge_configs(default_config, config)
            
        except Exception as e:
            print(f"Error loading config: {e}")
            return self.get_default_config()
    
    def save_config(self, config: Dict[str, Any]) -> bool:
        """Save configuration to file."""
        try:
            # Create backup first
            self.create_backup()
            
            # Save new config
            with open(self.config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
            
            self.config = config
            return True
            
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def merge_configs(self, default: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
        """Merge user config with defaults."""
        result = default.copy()
        
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self.merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def create_backup(self) -> str:
        """Create configuration backup."""
        if not self.config_file.exists():
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"netlink_config_{timestamp}.yaml"
        
        try:
            shutil.copy2(self.config_file, backup_file)
            return str(backup_file)
        except Exception as e:
            print(f"Error creating backup: {e}")
            return None
    
    def restore_backup(self, backup_file: str) -> bool:
        """Restore configuration from backup."""
        backup_path = Path(backup_file)
        
        if not backup_path.exists():
            return False
        
        try:
            shutil.copy2(backup_path, self.config_file)
            self.config = self.load_config()
            return True
        except Exception as e:
            print(f"Error restoring backup: {e}")
            return False
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List available configuration backups."""
        backups = []
        
        try:
            for backup_file in self.backup_dir.glob("netlink_config_*.yaml"):
                stat = backup_file.stat()
                backups.append({
                    "filename": backup_file.name,
                    "path": str(backup_file),
                    "size": stat.st_size,
                    "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
        except Exception as e:
            print(f"Error listing backups: {e}")
        
        return sorted(backups, key=lambda x: x["created"], reverse=True)
    
    def get_config_section(self, section: str) -> Dict[str, Any]:
        """Get specific configuration section."""
        return self.config.get(section, {})
    
    def update_config_section(self, section: str, updates: Dict[str, Any]) -> bool:
        """Update specific configuration section."""
        if section not in self.config:
            self.config[section] = {}
        
        self.config[section].update(updates)
        return self.save_config(self.config)
    
    def validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate configuration against schema."""
        errors = []
        warnings = []
        
        # Basic validation
        if not isinstance(config, dict):
            errors.append("Configuration must be a dictionary")
            return {"valid": False, "errors": errors, "warnings": warnings}
        
        # Validate server section
        server = config.get("server", {})
        if "port" in server:
            port = server["port"]
            if not isinstance(port, int) or port < 1 or port > 65535:
                errors.append("Server port must be between 1 and 65535")
        
        if "workers" in server:
            workers = server["workers"]
            if not isinstance(workers, int) or workers < 1:
                errors.append("Server workers must be a positive integer")
        
        # Validate security section
        security = config.get("security", {})
        if "jwt_expire_minutes" in security:
            expire = security["jwt_expire_minutes"]
            if not isinstance(expire, int) or expire < 1:
                errors.append("JWT expire minutes must be a positive integer")
        
        if "password_min_length" in security:
            min_len = security["password_min_length"]
            if not isinstance(min_len, int) or min_len < 4:
                errors.append("Password minimum length must be at least 4")
        
        # Validate limits section
        limits = config.get("limits", {})
        if "max_file_size" in limits:
            max_size = limits["max_file_size"]
            if isinstance(max_size, str):
                try:
                    self.parse_size(max_size)
                except ValueError:
                    errors.append("Invalid max_file_size format (use MB, GB, etc.)")
        
        # Check for deprecated settings
        if "old_setting" in config:
            warnings.append("old_setting is deprecated, use new_setting instead")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
        }
    
    def parse_size(self, size_str: str) -> int:
        """Parse size string (e.g., '10MB') to bytes."""
        size_str = size_str.upper().strip()
        
        units = {
            'B': 1,
            'KB': 1024,
            'MB': 1024 ** 2,
            'GB': 1024 ** 3,
            'TB': 1024 ** 4
        }
        
        for unit, multiplier in units.items():
            if size_str.endswith(unit):
                try:
                    value = float(size_str[:-len(unit)])
                    return int(value * multiplier)
                except ValueError:
                    raise ValueError(f"Invalid size format: {size_str}")
        
        # Try parsing as plain number (bytes)
        try:
            return int(size_str)
        except ValueError:
            raise ValueError(f"Invalid size format: {size_str}")
    
    def get_config_schema(self) -> Dict[str, Any]:
        """Get configuration schema for UI generation."""
        return {
            "server": {
                "title": "Server Configuration",
                "description": "Web server and networking settings",
                "fields": {
                    "host": {
                        "type": "string",
                        "title": "Host Address",
                        "description": "IP address to bind to (0.0.0.0 for all interfaces)",
                        "default": "0.0.0.0",
                        "examples": ["0.0.0.0", "127.0.0.1", "192.168.1.100"]
                    },
                    "port": {
                        "type": "integer",
                        "title": "Port Number",
                        "description": "TCP port to listen on",
                        "default": 8000,
                        "minimum": 1,
                        "maximum": 65535
                    },
                    "workers": {
                        "type": "integer",
                        "title": "Worker Processes",
                        "description": "Number of worker processes (0 = auto)",
                        "default": 4,
                        "minimum": 1,
                        "maximum": 32
                    },
                    "debug": {
                        "type": "boolean",
                        "title": "Debug Mode",
                        "description": "Enable debug mode (not for production)",
                        "default": False
                    }
                }
            },
            "security": {
                "title": "Security Settings",
                "description": "Authentication and security configuration",
                "fields": {
                    "jwt_expire_minutes": {
                        "type": "integer",
                        "title": "JWT Token Expiry (minutes)",
                        "description": "How long JWT tokens remain valid",
                        "default": 30,
                        "minimum": 5,
                        "maximum": 1440
                    },
                    "https_enabled": {
                        "type": "boolean",
                        "title": "Enable HTTPS",
                        "description": "Use HTTPS encryption (requires certificates)",
                        "default": False
                    },
                    "https_cert_file": {
                        "type": "string",
                        "title": "HTTPS Certificate File",
                        "description": "Path to SSL certificate file",
                        "condition": "https_enabled"
                    },
                    "https_key_file": {
                        "type": "string",
                        "title": "HTTPS Private Key File",
                        "description": "Path to SSL private key file",
                        "condition": "https_enabled"
                    }
                }
            },
            "features": {
                "title": "Feature Toggles",
                "description": "Enable or disable NetLink features",
                "fields": {
                    "clustering": {
                        "type": "boolean",
                        "title": "Multi-Server Clustering",
                        "description": "Enable automatic clustering with other NetLink instances",
                        "default": True
                    },
                    "hot_updates": {
                        "type": "boolean",
                        "title": "Hot Updates",
                        "description": "Enable zero-downtime updates",
                        "default": True
                    },
                    "file_uploads": {
                        "type": "boolean",
                        "title": "File Uploads",
                        "description": "Allow users to upload files",
                        "default": True
                    },
                    "analytics": {
                        "type": "boolean",
                        "title": "Analytics",
                        "description": "Collect usage analytics and metrics",
                        "default": True
                    }
                }
            }
        }
    
    def export_config(self, format: str = "yaml") -> str:
        """Export configuration in specified format."""
        if format.lower() == "json":
            return json.dumps(self.config, indent=2)
        elif format.lower() == "yaml":
            return yaml.dump(self.config, default_flow_style=False, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def import_config(self, config_data: str, format: str = "yaml") -> bool:
        """Import configuration from string."""
        try:
            if format.lower() == "json":
                config = json.loads(config_data)
            elif format.lower() == "yaml":
                config = yaml.safe_load(config_data)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            # Validate before saving
            validation = self.validate_config(config)
            if not validation["valid"]:
                return False
            
            return self.save_config(config)
            
        except Exception as e:
            print(f"Error importing config: {e}")
            return False

# Global configuration manager
config_manager = ConfigurationManager()
