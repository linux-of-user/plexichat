"""
NetLink Environment Manager

Handles environment variable loading, validation, and configuration override.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Tuple
import logging
from dotenv import load_dotenv

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

logger = logging.getLogger(__name__)

class EnvironmentManager:
    """
    Environment variable manager for NetLink configuration.
    
    Features:
    - .env file loading
    - Environment variable validation
    - Type conversion and casting
    - Configuration override mapping
    - Environment-specific settings
    - Secure environment variable handling
    """
    
    def __init__(self, env_file: Optional[Path] = None):
        self.env_file = env_file or Path(".env")
        self.loaded_vars: Dict[str, str] = {}
        
        # Environment variable mappings to configuration paths
        self.env_mappings = {
            # Application settings
            "NETLINK_ENVIRONMENT": ("environment",),
            "NETLINK_DEBUG": ("application", "debug"),
            "NETLINK_NAME": ("application", "name"),
            "NETLINK_VERSION": ("application", "version"),
            
            # Server configuration
            "NETLINK_HOST": ("server", "host"),
            "NETLINK_PORT": ("server", "port"),
            "NETLINK_WORKERS": ("server", "workers"),
            "NETLINK_SSL_ENABLED": ("server", "ssl_enabled"),
            "NETLINK_SSL_CERT": ("server", "ssl_cert_file"),
            "NETLINK_SSL_KEY": ("server", "ssl_key_file"),
            "NETLINK_CORS_ORIGINS": ("server", "cors_origins"),
            
            # Database configuration
            "NETLINK_DB_TYPE": ("database", "type"),
            "NETLINK_DB_URL": ("database", "url"),
            "NETLINK_DB_HOST": ("database", "host"),
            "NETLINK_DB_PORT": ("database", "port"),
            "NETLINK_DB_NAME": ("database", "name"),
            "NETLINK_DB_USERNAME": ("database", "username"),
            "NETLINK_DB_PASSWORD": ("database", "password"),
            "NETLINK_DB_POOL_SIZE": ("database", "pool_size"),
            "NETLINK_DB_POOL_TIMEOUT": ("database", "pool_timeout"),
            "NETLINK_DB_ECHO": ("database", "echo"),
            "NETLINK_DB_ENCRYPTION": ("database", "encryption_enabled"),
            
            # Security configuration
            "NETLINK_SECRET_KEY": ("security", "secret_key"),
            "NETLINK_JWT_ALGORITHM": ("security", "jwt_algorithm"),
            "NETLINK_ACCESS_TOKEN_EXPIRE": ("security", "access_token_expire_minutes"),
            "NETLINK_REFRESH_TOKEN_EXPIRE": ("security", "refresh_token_expire_days"),
            "NETLINK_PASSWORD_MIN_LENGTH": ("security", "password_min_length"),
            "NETLINK_MFA_ENABLED": ("security", "mfa_enabled"),
            "NETLINK_MFA_METHODS": ("security", "mfa_methods"),
            "NETLINK_RATE_LIMITING": ("security", "rate_limiting"),
            "NETLINK_RATE_LIMIT_REQUESTS": ("security", "rate_limit_requests"),
            "NETLINK_RATE_LIMIT_WINDOW": ("security", "rate_limit_window"),
            
            # Backup configuration
            "NETLINK_BACKUP_ENABLED": ("backup", "enabled"),
            "NETLINK_BACKUP_DIR": ("backup", "directory"),
            "NETLINK_BACKUP_ENCRYPTION": ("backup", "encryption_enabled"),
            "NETLINK_BACKUP_COMPRESSION": ("backup", "compression_enabled"),
            "NETLINK_BACKUP_DISTRIBUTED": ("backup", "distributed_enabled"),
            "NETLINK_BACKUP_SHARD_SIZE": ("backup", "shard_size_mb"),
            "NETLINK_BACKUP_REDUNDANCY": ("backup", "redundancy_level"),
            "NETLINK_BACKUP_RETENTION": ("backup", "retention_days"),
            "NETLINK_BACKUP_INTERVAL": ("backup", "auto_backup_interval"),
            
            # Cluster configuration
            "NETLINK_CLUSTER_ENABLED": ("cluster", "enabled"),
            "NETLINK_CLUSTER_NODE_ID": ("cluster", "node_id"),
            "NETLINK_CLUSTER_NODE_NAME": ("cluster", "node_name"),
            "NETLINK_CLUSTER_DISCOVERY": ("cluster", "discovery_method"),
            "NETLINK_CLUSTER_NODES": ("cluster", "nodes"),
            "NETLINK_CLUSTER_HEARTBEAT": ("cluster", "heartbeat_interval"),
            "NETLINK_CLUSTER_ELECTION_TIMEOUT": ("cluster", "election_timeout"),
            
            # Logging configuration
            "NETLINK_LOG_LEVEL": ("logging", "level"),
            "NETLINK_LOG_FILE": ("logging", "file"),
            "NETLINK_LOG_MAX_SIZE": ("logging", "max_size"),
            "NETLINK_LOG_BACKUP_COUNT": ("logging", "backup_count"),
            "NETLINK_LOG_CONSOLE": ("logging", "console_enabled"),
            "NETLINK_LOG_STRUCTURED": ("logging", "structured_logging"),
            
            # AI configuration
            "NETLINK_AI_ENABLED": ("ai", "enabled"),
            "NETLINK_AI_PROVIDERS": ("ai", "providers"),
            "NETLINK_AI_DEFAULT_PROVIDER": ("ai", "default_provider"),
            "NETLINK_AI_TIMEOUT": ("ai", "timeout"),
            "NETLINK_AI_MAX_RETRIES": ("ai", "max_retries"),
            
            # Monitoring configuration
            "NETLINK_MONITORING_ENABLED": ("monitoring", "enabled"),
            "NETLINK_METRICS_ENABLED": ("monitoring", "metrics_enabled"),
            "NETLINK_HEALTH_CHECKS": ("monitoring", "health_checks_enabled"),
            "NETLINK_PERFORMANCE_MONITORING": ("monitoring", "performance_monitoring"),
            
            # Feature flags
            "NETLINK_FEATURE_BACKUP": ("features", "backup_system"),
            "NETLINK_FEATURE_CLUSTERING": ("features", "clustering"),
            "NETLINK_FEATURE_AI": ("features", "ai_integration"),
            "NETLINK_FEATURE_WEB_UI": ("features", "web_ui"),
            "NETLINK_FEATURE_API_DOCS": ("features", "api_docs"),
            "NETLINK_FEATURE_FILE_SHARING": ("features", "file_sharing"),
            "NETLINK_FEATURE_VOICE_CALLING": ("features", "voice_calling"),
            "NETLINK_FEATURE_VIDEO_CALLING": ("features", "video_calling"),
            
            # Limits configuration
            "NETLINK_MAX_MESSAGE_LENGTH": ("limits", "max_message_length"),
            "NETLINK_MAX_FILE_SIZE": ("limits", "max_file_size_mb"),
            "NETLINK_MAX_USERS": ("limits", "max_users"),
            "NETLINK_MAX_CONNECTIONS": ("limits", "max_concurrent_connections"),
            "NETLINK_MAX_UPLOAD_SIZE": ("limits", "max_upload_size_mb"),
        }
        
        # Type conversion mappings
        self.type_converters = {
            # Boolean values
            ("application", "debug"): self._to_bool,
            ("server", "debug"): self._to_bool,
            ("server", "auto_reload"): self._to_bool,
            ("server", "ssl_enabled"): self._to_bool,
            ("server", "cors_enabled"): self._to_bool,
            ("database", "echo"): self._to_bool,
            ("database", "encryption_enabled"): self._to_bool,
            ("security", "mfa_enabled"): self._to_bool,
            ("security", "rate_limiting"): self._to_bool,
            ("backup", "enabled"): self._to_bool,
            ("backup", "encryption_enabled"): self._to_bool,
            ("backup", "compression_enabled"): self._to_bool,
            ("backup", "distributed_enabled"): self._to_bool,
            ("cluster", "enabled"): self._to_bool,
            ("logging", "console_enabled"): self._to_bool,
            ("logging", "structured_logging"): self._to_bool,
            ("ai", "enabled"): self._to_bool,
            ("monitoring", "enabled"): self._to_bool,
            ("monitoring", "metrics_enabled"): self._to_bool,
            ("monitoring", "health_checks_enabled"): self._to_bool,
            
            # Integer values
            ("server", "port"): int,
            ("server", "workers"): int,
            ("database", "port"): int,
            ("database", "pool_size"): int,
            ("database", "pool_timeout"): int,
            ("security", "access_token_expire_minutes"): int,
            ("security", "refresh_token_expire_days"): int,
            ("security", "password_min_length"): int,
            ("security", "rate_limit_requests"): int,
            ("security", "rate_limit_window"): int,
            ("backup", "shard_size_mb"): int,
            ("backup", "redundancy_level"): int,
            ("backup", "retention_days"): int,
            ("backup", "auto_backup_interval"): int,
            ("cluster", "heartbeat_interval"): int,
            ("cluster", "election_timeout"): int,
            ("logging", "backup_count"): int,
            ("ai", "timeout"): int,
            ("ai", "max_retries"): int,
            ("limits", "max_message_length"): int,
            ("limits", "max_file_size_mb"): int,
            ("limits", "max_users"): int,
            ("limits", "max_concurrent_connections"): int,
            ("limits", "max_upload_size_mb"): int,
            
            # List values
            ("server", "cors_origins"): self._to_list,
            ("security", "mfa_methods"): self._to_list,
            ("ai", "providers"): self._to_list,
            ("cluster", "nodes"): self._to_list,
        }
    
    def load_environment(self, env_file: Optional[Path] = None) -> Dict[str, str]:
        """Load environment variables from .env file and system environment."""
        env_file = env_file or self.env_file
        
        # Load from .env file if it exists
        if env_file.exists():
            logger.info(f"Loading environment from {env_file}")
            load_dotenv(env_file, override=True)
        else:
            logger.info("No .env file found, using system environment variables only")
        
        # Collect all NetLink-related environment variables
        netlink_vars = {}
        for key, value in os.environ.items():
            if key.startswith("NETLINK_"):
                netlink_vars[key] = value
        
        self.loaded_vars = netlink_vars
        logger.info(f"Loaded {len(netlink_vars)} NetLink environment variables")
        
        return netlink_vars
    
    def apply_to_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply environment variables to configuration."""
        if not self.loaded_vars:
            self.load_environment()
        
        modified_config = config.copy()
        applied_count = 0
        
        for env_var, config_path in self.env_mappings.items():
            if env_var in self.loaded_vars:
                value = self.loaded_vars[env_var]
                
                # Convert value to appropriate type
                if config_path in self.type_converters:
                    try:
                        converter = self.type_converters[config_path]
                        value = converter(value)
                    except (ValueError, TypeError) as e:
                        logger.warning(f"Failed to convert {env_var}={value}: {e}")
                        continue
                
                # Apply to configuration
                self._set_nested_value(modified_config, config_path, value)
                applied_count += 1
                logger.debug(f"Applied {env_var} -> {'.'.join(config_path)} = {value}")
        
        logger.info(f"Applied {applied_count} environment variable overrides")
        return modified_config
    
    def get_environment_info(self) -> Dict[str, Any]:
        """Get information about the current environment."""
        return {
            "environment": os.getenv("NETLINK_ENVIRONMENT", "development"),
            "loaded_vars_count": len(self.loaded_vars),
            "env_file_exists": self.env_file.exists(),
            "env_file_path": str(self.env_file),
            "system_vars": {k: "***" if "password" in k.lower() or "key" in k.lower() or "secret" in k.lower() else v 
                           for k, v in self.loaded_vars.items()},
        }
    
    def validate_environment(self) -> List[str]:
        """Validate environment variables and return any issues."""
        issues = []
        
        # Check for required environment variables in production
        environment = os.getenv("NETLINK_ENVIRONMENT", "development")
        if environment == "production":
            required_vars = [
                "NETLINK_SECRET_KEY",
                "NETLINK_DB_PASSWORD",
            ]
            
            for var in required_vars:
                if not os.getenv(var):
                    issues.append(f"Required environment variable missing in production: {var}")
        
        # Validate environment variable formats
        for env_var, value in self.loaded_vars.items():
            if env_var in self.env_mappings:
                config_path = self.env_mappings[env_var]
                
                # Validate based on expected type
                if config_path in self.type_converters:
                    converter = self.type_converters[config_path]
                    try:
                        converter(value)
                    except (ValueError, TypeError):
                        issues.append(f"Invalid format for {env_var}: {value}")
        
        return issues
    
    def create_env_template(self, environment: str = "development") -> str:
        """Create a .env template file content."""
        template_lines = [
            f"# NetLink Environment Configuration - {environment.upper()}",
            f"# Generated on {os.getenv('USER', 'unknown')}@{os.getenv('HOSTNAME', 'localhost')}",
            "",
            "# Application Settings",
            f"NETLINK_ENVIRONMENT={environment}",
            "NETLINK_DEBUG=true" if environment == "development" else "NETLINK_DEBUG=false",
            "# NETLINK_NAME=NetLink",
            "# NETLINK_VERSION=3.0.0",
            "",
            "# Server Configuration",
            "NETLINK_HOST=0.0.0.0",
            "NETLINK_PORT=8000",
            "NETLINK_WORKERS=4",
            "# NETLINK_SSL_ENABLED=false",
            "# NETLINK_SSL_CERT=/path/to/cert.pem",
            "# NETLINK_SSL_KEY=/path/to/key.pem",
            "",
            "# Database Configuration",
            "NETLINK_DB_TYPE=sqlite",
            "# NETLINK_DB_URL=sqlite:///./data/netlink.db",
            "# NETLINK_DB_HOST=localhost",
            "# NETLINK_DB_PORT=5432",
            "# NETLINK_DB_NAME=netlink",
            "# NETLINK_DB_USERNAME=netlink_user",
            "# NETLINK_DB_PASSWORD=secure_password_here",
            "",
            "# Security Configuration",
            "# NETLINK_SECRET_KEY=generate_a_secure_key_here",
            "NETLINK_JWT_ALGORITHM=RS256",
            "NETLINK_ACCESS_TOKEN_EXPIRE=15",
            "NETLINK_MFA_ENABLED=true",
            "NETLINK_RATE_LIMITING=true",
            "",
            "# Backup Configuration",
            "NETLINK_BACKUP_ENABLED=true",
            "NETLINK_BACKUP_DIR=backups",
            "NETLINK_BACKUP_ENCRYPTION=true",
            "NETLINK_BACKUP_DISTRIBUTED=true",
            "",
            "# Logging Configuration",
            "NETLINK_LOG_LEVEL=DEBUG" if environment == "development" else "NETLINK_LOG_LEVEL=INFO",
            "NETLINK_LOG_FILE=logs/netlink.log",
            "NETLINK_LOG_CONSOLE=true",
            "",
            "# Feature Flags",
            "NETLINK_FEATURE_BACKUP=true",
            "NETLINK_FEATURE_WEB_UI=true",
            "NETLINK_FEATURE_API_DOCS=true",
            "# NETLINK_FEATURE_CLUSTERING=false",
            "# NETLINK_FEATURE_AI=false",
            "",
            "# AI Configuration (if enabled)",
            "# NETLINK_AI_ENABLED=false",
            "# NETLINK_AI_PROVIDERS=openai,anthropic",
            "# NETLINK_AI_DEFAULT_PROVIDER=openai",
            "# OPENAI_API_KEY=your_openai_key_here",
            "# ANTHROPIC_API_KEY=your_anthropic_key_here",
            "",
            "# Monitoring Configuration",
            "NETLINK_MONITORING_ENABLED=true",
            "NETLINK_METRICS_ENABLED=true",
            "NETLINK_HEALTH_CHECKS=true",
            "",
            "# Limits Configuration",
            "NETLINK_MAX_MESSAGE_LENGTH=10000",
            "NETLINK_MAX_FILE_SIZE=100",
            "NETLINK_MAX_USERS=10000",
            "",
        ]
        
        return "\n".join(template_lines)
    
    def save_env_template(self, file_path: Optional[Path] = None, environment: str = "development") -> bool:
        """Save environment template to file."""
        file_path = file_path or Path(f".env.{environment}")
        
        try:
            template_content = self.create_env_template(environment)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(template_content)
            
            logger.info(f"Environment template saved to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save environment template: {e}")
            return False
    
    def _set_nested_value(self, config: Dict[str, Any], path: Tuple[str, ...], value: Any):
        """Set a nested configuration value."""
        current = config
        
        # Navigate to parent
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        # Set final value
        current[path[-1]] = value
    
    def _to_bool(self, value: str) -> bool:
        """Convert string to boolean."""
        return value.lower() in ("true", "1", "yes", "on", "enabled")
    
    def _to_list(self, value: str) -> List[str]:
        """Convert comma-separated string to list."""
        if not value:
            return []
        return [item.strip() for item in value.split(",") if item.strip()]
