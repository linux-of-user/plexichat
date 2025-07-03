"""
Comprehensive configuration management system for NetLink.
Auto-creates all necessary config files, directories, and handles missing components gracefully.
"""

import os
import json
import yaml
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import secrets
import hashlib

from netlink.app.logger_config import logger


class ConfigManager:
    """Manages all configuration files and directory structure for NetLink."""
    
    def __init__(self, base_path: Optional[Path] = None):
        self.base_path = base_path or Path.cwd()
        self.config_dir = self.base_path / "config"
        self.data_dir = self.base_path / "data"
        self.logs_dir = self.base_path / "logs"
        self.uploads_dir = self.base_path / "uploads"
        self.backups_dir = self.base_path / "secure_backups"
        self.temp_dir = self.base_path / "temp"
        
        # Configuration file paths
        self.main_config_file = self.config_dir / "netlink.yaml"
        self.database_config_file = self.config_dir / "database.yaml"
        self.security_config_file = self.config_dir / "security.yaml"
        self.backup_config_file = self.config_dir / "backup.yaml"
        self.node_config_file = self.config_dir / "nodes.yaml"
        
        # Default configurations
        self.default_configs = self._get_default_configurations()
        
    def initialize_application(self) -> Dict[str, Any]:
        """Initialize the entire application configuration and directory structure."""
        logger.info("🚀 Initializing NetLink application configuration...")
        
        initialization_report = {
            "success": True,
            "warnings": [],
            "errors": [],
            "created_directories": [],
            "created_configs": [],
            "database_status": "unknown",
            "security_status": "unknown"
        }
        
        try:
            # Create directory structure
            self._create_directory_structure(initialization_report)
            
            # Create configuration files
            self._create_configuration_files(initialization_report)
            
            # Validate database connection
            self._validate_database_connection(initialization_report)
            
            # Initialize security settings
            self._initialize_security_settings(initialization_report)
            
            # Create gitignore if needed
            self._create_gitignore(initialization_report)
            
            # Generate initial admin credentials if needed
            self._generate_initial_credentials(initialization_report)
            
            logger.info("✅ Application initialization completed successfully")
            
        except Exception as e:
            logger.error(f"❌ Critical error during initialization: {e}")
            initialization_report["success"] = False
            initialization_report["errors"].append(f"Critical initialization error: {str(e)}")
        
        return initialization_report
    
    def _create_directory_structure(self, report: Dict[str, Any]):
        """Create all necessary directories with proper permissions."""
        directories = [
            (self.config_dir, 0o755, "Configuration files"),
            (self.data_dir, 0o755, "Application data"),
            (self.logs_dir, 0o755, "Log files"),
            (self.uploads_dir, 0o700, "User uploads (secure)"),
            (self.uploads_dir / "profiles", 0o700, "Profile pictures"),
            (self.uploads_dir / "attachments", 0o700, "File attachments"),
            (self.backups_dir, 0o700, "Secure backups"),
            (self.backups_dir / "shards", 0o700, "Backup shards"),
            (self.backups_dir / "metadata", 0o700, "Backup metadata"),
            (self.backups_dir / "recovery", 0o700, "Recovery workspace"),
            (self.temp_dir, 0o700, "Temporary files"),
            (self.base_path / "web" / "static", 0o755, "Static web files"),
            (self.base_path / "web" / "templates", 0o755, "Web templates"),
            (self.base_path / "tests" / "reports", 0o755, "Test reports"),
            (self.base_path / "certificates", 0o700, "SSL certificates"),
            (self.base_path / "keys", 0o600, "Encryption keys")
        ]
        
        for directory, permissions, description in directories:
            if not directory.exists():
                try:
                    directory.mkdir(parents=True, exist_ok=True)
                    os.chmod(directory, permissions)
                    report["created_directories"].append(str(directory))
                    logger.info(f"📁 Created directory: {directory} ({description})")
                except Exception as e:
                    error_msg = f"Failed to create directory {directory}: {e}"
                    report["errors"].append(error_msg)
                    logger.error(f"❌ {error_msg}")
    
    def _create_configuration_files(self, report: Dict[str, Any]):
        """Create all configuration files with secure defaults."""
        config_files = [
            (self.main_config_file, self.default_configs["main"], "Main application configuration"),
            (self.database_config_file, self.default_configs["database"], "Database configuration"),
            (self.security_config_file, self.default_configs["security"], "Security configuration"),
            (self.backup_config_file, self.default_configs["backup"], "Backup system configuration"),
            (self.node_config_file, self.default_configs["nodes"], "Backup nodes configuration")
        ]
        
        for config_file, default_config, description in config_files:
            if not config_file.exists():
                try:
                    with open(config_file, 'w') as f:
                        yaml.dump(default_config, f, default_flow_style=False, indent=2)
                    
                    # Set secure permissions for config files
                    os.chmod(config_file, 0o600)
                    report["created_configs"].append(str(config_file))
                    logger.info(f"⚙️ Created configuration: {config_file} ({description})")
                    
                except Exception as e:
                    error_msg = f"Failed to create config file {config_file}: {e}"
                    report["errors"].append(error_msg)
                    logger.error(f"❌ {error_msg}")
    
    def _validate_database_connection(self, report: Dict[str, Any]):
        """Validate database connection and warn if missing."""
        try:
            # Try to import and test database connection
            from netlink.app.db import engine, get_session
            
            # Test connection
            with get_session() as session:
                session.execute("SELECT 1")
                report["database_status"] = "connected"
                logger.info("✅ Database connection successful")
                
        except ImportError as e:
            warning_msg = "Database modules not available - running in limited mode"
            report["warnings"].append(warning_msg)
            report["database_status"] = "modules_missing"
            logger.warning(f"⚠️ {warning_msg}: {e}")
            
        except Exception as e:
            warning_msg = f"Database connection failed - application will run with limited functionality: {e}"
            report["warnings"].append(warning_msg)
            report["database_status"] = "connection_failed"
            logger.warning(f"⚠️ {warning_msg}")
            
            # Create database initialization script
            self._create_database_init_script(report)
    
    def _create_database_init_script(self, report: Dict[str, Any]):
        """Create database initialization script for manual setup."""
        init_script_path = self.config_dir / "init_database.py"
        
        init_script_content = '''#!/usr/bin/env python3
"""
Database initialization script for NetLink.
Run this script to set up the database when it's available.
"""

import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
    from netlink.app.db import create_tables
    from netlink.app.logger_config import logger
    
    def main():
        logger.info("Initializing NetLink database...")
        create_tables()
        logger.info("Database initialization completed successfully!")
        
    if __name__ == "__main__":
        main()
        
except ImportError as e:
    print(f"Error: Required modules not available: {e}")
    print("Please ensure all dependencies are installed.")
    sys.exit(1)
'''
        
        try:
            with open(init_script_path, 'w') as f:
                f.write(init_script_content)
            os.chmod(init_script_path, 0o755)
            report["created_configs"].append(str(init_script_path))
            logger.info(f"📝 Created database initialization script: {init_script_path}")
        except Exception as e:
            logger.error(f"Failed to create database init script: {e}")
    
    def _initialize_security_settings(self, report: Dict[str, Any]):
        """Initialize security settings and generate keys if needed."""
        try:
            security_config = self.load_config("security")
            
            # Generate encryption keys if not present
            keys_dir = self.base_path / "keys"
            master_key_file = keys_dir / "master.key"
            
            if not master_key_file.exists():
                master_key = secrets.token_bytes(32)  # 256-bit key
                with open(master_key_file, 'wb') as f:
                    f.write(master_key)
                os.chmod(master_key_file, 0o600)
                logger.info("🔐 Generated master encryption key")
            
            # Generate API keys if not present
            if not security_config.get("api_keys", {}).get("admin"):
                admin_api_key = secrets.token_urlsafe(32)
                security_config.setdefault("api_keys", {})["admin"] = admin_api_key
                self.save_config("security", security_config)
                logger.info("🔑 Generated admin API key")
            
            report["security_status"] = "initialized"
            
        except Exception as e:
            error_msg = f"Security initialization failed: {e}"
            report["errors"].append(error_msg)
            report["security_status"] = "failed"
            logger.error(f"❌ {error_msg}")
    
    def _create_gitignore(self, report: Dict[str, Any]):
        """Create comprehensive .gitignore file."""
        gitignore_path = self.base_path / ".gitignore"
        
        gitignore_content = '''# NetLink - Government-Level Secure Communication Platform
# Auto-generated .gitignore - DO NOT EDIT MANUALLY

# Sensitive Data & Security
keys/
certificates/
*.key
*.pem
*.crt
*.p12
config/security.yaml
config/database.yaml

# User Data & Uploads
uploads/
data/
*.db
*.sqlite
*.sqlite3

# Backups & Temporary Files
secure_backups/
temp/
*.tmp
*.bak
recovery/

# Logs
logs/
*.log
*.log.*

# Environment & Runtime
.env
.env.*
*.pid
*.sock

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Virtual Environments
venv/
env/
ENV/
.venv/

# IDE & Editor Files
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store
Thumbs.db

# Testing
.coverage
.pytest_cache/
.tox/
htmlcov/
tests/reports/

# Node.js (if using frontend build tools)
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# OS Generated Files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db
'''
        
        try:
            with open(gitignore_path, 'w') as f:
                f.write(gitignore_content)
            logger.info("📝 Created comprehensive .gitignore file")
        except Exception as e:
            logger.error(f"Failed to create .gitignore: {e}")
    
    def _generate_initial_credentials(self, report: Dict[str, Any]):
        """Generate initial admin credentials."""
        credentials_file = self.config_dir / "initial_credentials.txt"
        
        if not credentials_file.exists():
            admin_username = "admin"
            admin_password = secrets.token_urlsafe(16)
            admin_api_key = secrets.token_urlsafe(32)
            
            credentials_content = f"""
NetLink Initial Administrator Credentials
Generated: {datetime.now().isoformat()}

⚠️  IMPORTANT: Change these credentials immediately after first login!

Username: {admin_username}
Password: {admin_password}
API Key: {admin_api_key}

Admin Dashboard: http://localhost:8000/api/v1/admin/dashboard
API Documentation: http://localhost:8000/docs

🔒 Security Notes:
- These credentials provide full system access
- Delete this file after changing the password
- Enable two-factor authentication
- Review all security settings

For support: https://github.com/your-org/netlink
"""
            
            try:
                with open(credentials_file, 'w') as f:
                    f.write(credentials_content)
                os.chmod(credentials_file, 0o600)
                logger.warning(f"🔐 Generated initial admin credentials: {credentials_file}")
                logger.warning("⚠️  CHANGE DEFAULT CREDENTIALS IMMEDIATELY!")
                report["warnings"].append(f"Initial admin credentials created: {credentials_file}")
            except Exception as e:
                logger.error(f"Failed to create credentials file: {e}")
    
    def _get_default_configurations(self) -> Dict[str, Dict[str, Any]]:
        """Get all default configuration templates."""
        return {
            "main": {
                "application": {
                    "name": "NetLink",
                    "version": "3.0.0",
                    "description": "Government-Level Secure Communication Platform",
                    "environment": "production",
                    "debug": False,
                    "host": "0.0.0.0",
                    "port": 8000,
                    "workers": 4
                },
                "features": {
                    "backup_system": True,
                    "moderation": True,
                    "file_sharing": True,
                    "encryption": True,
                    "clustering": False,
                    "auto_backup": True
                },
                "limits": {
                    "max_message_length": 10000,
                    "max_file_size_mb": 100,
                    "max_users": 10000,
                    "rate_limit_per_minute": 1000
                }
            },
            "database": {
                "type": "sqlite",
                "sqlite": {
                    "path": "data/netlink.db",
                    "timeout": 30,
                    "check_same_thread": False
                },
                "postgresql": {
                    "host": "localhost",
                    "port": 5432,
                    "database": "netlink",
                    "username": "netlink_user",
                    "password": "CHANGE_ME",
                    "pool_size": 10,
                    "max_overflow": 20
                },
                "backup": {
                    "auto_backup_interval_hours": 6,
                    "retention_days": 30,
                    "compression": True
                }
            },
            "security": {
                "encryption": {
                    "algorithm": "AES-256-GCM",
                    "key_derivation": "PBKDF2",
                    "iterations": 200000,
                    "salt_length": 32
                },
                "authentication": {
                    "session_timeout_minutes": 60,
                    "max_login_attempts": 5,
                    "lockout_duration_minutes": 15,
                    "require_2fa": False,
                    "password_min_length": 12
                },
                "api_keys": {},
                "ssl": {
                    "enabled": False,
                    "cert_file": "certificates/server.crt",
                    "key_file": "certificates/server.key"
                }
            },
            "backup": {
                "enabled": True,
                "redundancy_factor": 5,
                "max_shard_size_mb": 10,
                "auto_distribution": True,
                "verification_interval_hours": 6,
                "cleanup_interval_hours": 24,
                "storage": {
                    "local_path": "secure_backups",
                    "user_quota_gb": 1.0,
                    "max_user_shards": 1000
                },
                "recovery": {
                    "parallel_downloads": 10,
                    "timeout_seconds": 300,
                    "retry_attempts": 3
                }
            },
            "nodes": {
                "backup_nodes": [],
                "discovery": {
                    "enabled": True,
                    "port": 8100,
                    "heartbeat_interval_seconds": 30
                },
                "load_balancing": {
                    "algorithm": "round_robin",
                    "health_check_interval_seconds": 60
                }
            }
        }
    
    def load_config(self, config_name: str) -> Dict[str, Any]:
        """Load a specific configuration file."""
        config_files = {
            "main": self.main_config_file,
            "database": self.database_config_file,
            "security": self.security_config_file,
            "backup": self.backup_config_file,
            "nodes": self.node_config_file
        }
        
        config_file = config_files.get(config_name)
        if not config_file or not config_file.exists():
            logger.warning(f"Configuration file not found: {config_name}")
            return self.default_configs.get(config_name, {})
        
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.error(f"Failed to load config {config_name}: {e}")
            return self.default_configs.get(config_name, {})
    
    def save_config(self, config_name: str, config_data: Dict[str, Any]):
        """Save a specific configuration file."""
        config_files = {
            "main": self.main_config_file,
            "database": self.database_config_file,
            "security": self.security_config_file,
            "backup": self.backup_config_file,
            "nodes": self.node_config_file
        }
        
        config_file = config_files.get(config_name)
        if not config_file:
            raise ValueError(f"Unknown configuration: {config_name}")
        
        try:
            with open(config_file, 'w') as f:
                yaml.dump(config_data, f, default_flow_style=False, indent=2)
            logger.info(f"Saved configuration: {config_name}")
        except Exception as e:
            logger.error(f"Failed to save config {config_name}: {e}")
            raise


# Global configuration manager instance
config_manager = ConfigManager()
