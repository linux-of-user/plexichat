"""
Enhanced Configuration System for NetLink.
Comprehensive configuration management with validation, auto-creation, and hot-reloading.
"""

import os
import json
import yaml
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
from datetime import datetime
import shutil
from dataclasses import dataclass, asdict

from netlink.app.logger_config import logger


@dataclass
class ServerConfig:
    """Server configuration."""
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    reload: bool = False
    workers: int = 1
    ssl_enabled: bool = False
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    cors_enabled: bool = True
    cors_origins: List[str] = None
    
    def __post_init__(self):
        if self.cors_origins is None:
            self.cors_origins = ["*"]


@dataclass
class DatabaseConfig:
    """Database configuration."""
    type: str = "sqlite"
    host: Optional[str] = None
    port: Optional[int] = None
    database: str = "netlink"
    username: Optional[str] = None
    password: Optional[str] = None
    file_path: str = "data/netlink.db"
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 3600
    echo: bool = False
    ssl_mode: Optional[str] = None
    charset: str = "utf8mb4"


@dataclass
class SecurityConfig:
    """Security configuration."""
    enabled: bool = True
    file_scanning: bool = True
    link_checking: bool = True
    sql_injection_detection: bool = True
    rate_limiting: bool = True
    max_requests_per_minute: int = 60
    max_requests_per_hour: int = 1000
    block_duration_minutes: int = 30
    witty_responses: bool = True
    encryption_enabled: bool = True
    jwt_secret_key: str = "your-secret-key-change-this"
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 24


@dataclass
class BackupConfig:
    """Backup configuration."""
    enabled: bool = True
    auto_backup: bool = True
    backup_interval_hours: int = 6
    max_backups: int = 30
    backup_directory: str = "backups"
    compression_enabled: bool = True
    encryption_enabled: bool = False
    remote_backup: bool = False
    remote_backup_url: Optional[str] = None
    shard_distribution: bool = True
    redundancy_level: int = 3


@dataclass
class ClusterConfig:
    """Cluster configuration."""
    enabled: bool = False
    node_id: Optional[str] = None
    discovery_method: str = "static"  # static, dns, consul
    nodes: List[str] = None
    heartbeat_interval: int = 30
    election_timeout: int = 150
    log_replication: bool = True
    auto_scaling: bool = False
    load_balancing: bool = True
    
    def __post_init__(self):
        if self.nodes is None:
            self.nodes = []


@dataclass
class ModerationConfig:
    """Moderation configuration."""
    enabled: bool = True
    ai_moderation: bool = False
    ai_endpoint: Optional[str] = None
    ai_api_key: Optional[str] = None
    auto_moderation: bool = True
    human_review: bool = True
    appeal_system: bool = True
    role_based_permissions: bool = True
    witty_responses: bool = True


@dataclass
class SocialConfig:
    """Social features configuration."""
    enabled: bool = True
    friend_system: bool = True
    friend_requests: bool = True
    user_profiles: bool = True
    activity_feed: bool = True
    user_search: bool = True
    privacy_controls: bool = True
    status_system: bool = True


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    file_logging: bool = True
    console_logging: bool = True
    log_directory: str = "logs"
    max_file_size: str = "10MB"
    backup_count: int = 5
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    structured_logging: bool = False
    log_rotation: bool = True


@dataclass
class NetLinkConfig:
    """Main NetLink configuration."""
    server: ServerConfig
    database: DatabaseConfig
    security: SecurityConfig
    backup: BackupConfig
    cluster: ClusterConfig
    moderation: ModerationConfig
    social: SocialConfig
    logging: LoggingConfig
    
    # Additional settings
    environment: str = "development"
    debug_mode: bool = False
    feature_flags: Dict[str, bool] = None
    custom_settings: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.feature_flags is None:
            self.feature_flags = {
                "voice_calling": True,
                "video_calling": True,
                "file_sharing": True,
                "screen_sharing": False,
                "plugins": False,
                "themes": True,
                "analytics": False
            }
        
        if self.custom_settings is None:
            self.custom_settings = {}


class EnhancedConfigManager:
    """Enhanced configuration manager with comprehensive features."""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.config_file = self.config_dir / "netlink.yaml"
        self.backup_dir = self.config_dir / "backups"
        self.config: Optional[NetLinkConfig] = None
        
        # Ensure directories exist
        self.config_dir.mkdir(exist_ok=True)
        self.backup_dir.mkdir(exist_ok=True)
        
        logger.info(f"📁 Enhanced configuration manager initialized: {self.config_dir}")
    
    def load_config(self) -> NetLinkConfig:
        """Load configuration from file or create default."""
        try:
            if self.config_file.exists():
                logger.info(f"📖 Loading configuration from {self.config_file}")
                with open(self.config_file, 'r') as f:
                    config_data = yaml.safe_load(f)
                
                # Convert to config objects
                self.config = self._dict_to_config(config_data)
                
                # Validate configuration
                self._validate_config()
                
                logger.info("✅ Configuration loaded successfully")
                return self.config
            else:
                logger.info("📝 Creating default configuration")
                return self.create_default_config()
                
        except Exception as e:
            logger.error(f"❌ Failed to load configuration: {e}")
            logger.info("📝 Creating default configuration as fallback")
            return self.create_default_config()
    
    def create_default_config(self) -> NetLinkConfig:
        """Create default configuration."""
        try:
            self.config = NetLinkConfig(
                server=ServerConfig(),
                database=DatabaseConfig(),
                security=SecurityConfig(),
                backup=BackupConfig(),
                cluster=ClusterConfig(),
                moderation=ModerationConfig(),
                social=SocialConfig(),
                logging=LoggingConfig()
            )
            
            # Save default configuration
            self.save_config()
            
            logger.info("✅ Default configuration created")
            return self.config
            
        except Exception as e:
            logger.error(f"❌ Failed to create default configuration: {e}")
            raise
    
    def save_config(self, backup: bool = True) -> bool:
        """Save configuration to file."""
        try:
            if not self.config:
                raise ValueError("No configuration to save")
            
            # Create backup if requested
            if backup and self.config_file.exists():
                self._create_config_backup()
            
            # Convert config to dict
            config_dict = self._config_to_dict(self.config)
            
            # Add metadata
            config_dict["_metadata"] = {
                "version": "1.0.0",
                "created_at": datetime.now().isoformat(),
                "created_by": "NetLink Enhanced Configuration Manager"
            }
            
            # Save to file
            with open(self.config_file, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            
            logger.info(f"💾 Configuration saved to {self.config_file}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to save configuration: {e}")
            return False
    
    def _dict_to_config(self, config_data: Dict[str, Any]) -> NetLinkConfig:
        """Convert dictionary to configuration objects."""
        return NetLinkConfig(
            server=ServerConfig(**config_data.get("server", {})),
            database=DatabaseConfig(**config_data.get("database", {})),
            security=SecurityConfig(**config_data.get("security", {})),
            backup=BackupConfig(**config_data.get("backup", {})),
            cluster=ClusterConfig(**config_data.get("cluster", {})),
            moderation=ModerationConfig(**config_data.get("moderation", {})),
            social=SocialConfig(**config_data.get("social", {})),
            logging=LoggingConfig(**config_data.get("logging", {})),
            environment=config_data.get("environment", "development"),
            debug_mode=config_data.get("debug_mode", False),
            feature_flags=config_data.get("feature_flags", {}),
            custom_settings=config_data.get("custom_settings", {})
        )
    
    def _config_to_dict(self, config: NetLinkConfig) -> Dict[str, Any]:
        """Convert configuration objects to dictionary."""
        return {
            "server": asdict(config.server),
            "database": asdict(config.database),
            "security": asdict(config.security),
            "backup": asdict(config.backup),
            "cluster": asdict(config.cluster),
            "moderation": asdict(config.moderation),
            "social": asdict(config.social),
            "logging": asdict(config.logging),
            "environment": config.environment,
            "debug_mode": config.debug_mode,
            "feature_flags": config.feature_flags,
            "custom_settings": config.custom_settings
        }
    
    def _validate_config(self):
        """Validate configuration."""
        if not self.config:
            raise ValueError("No configuration to validate")
        
        # Validate server config
        if not (1 <= self.config.server.port <= 65535):
            raise ValueError(f"Invalid server port: {self.config.server.port}")
        
        # Validate database config
        if self.config.database.type not in ["sqlite", "postgresql", "mysql", "mariadb"]:
            raise ValueError(f"Unsupported database type: {self.config.database.type}")
        
        # Validate paths
        if self.config.database.type == "sqlite":
            db_dir = Path(self.config.database.file_path).parent
            db_dir.mkdir(parents=True, exist_ok=True)
        
        # Create required directories
        Path(self.config.backup.backup_directory).mkdir(parents=True, exist_ok=True)
        Path(self.config.logging.log_directory).mkdir(parents=True, exist_ok=True)
        
        logger.info("✅ Configuration validation passed")
    
    def _create_config_backup(self):
        """Create backup of current configuration."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.backup_dir / f"netlink_{timestamp}.yaml"
            
            shutil.copy2(self.config_file, backup_file)
            
            # Keep only last 10 backups
            backups = sorted(self.backup_dir.glob("netlink_*.yaml"))
            if len(backups) > 10:
                for old_backup in backups[:-10]:
                    old_backup.unlink()
            
            logger.info(f"📦 Configuration backup created: {backup_file}")
            
        except Exception as e:
            logger.warning(f"Failed to create configuration backup: {e}")
    
    def get_config(self) -> NetLinkConfig:
        """Get current configuration."""
        if not self.config:
            self.config = self.load_config()
        return self.config
    
    def reload_config(self) -> bool:
        """Reload configuration from file."""
        try:
            logger.info("🔄 Reloading configuration...")
            self.config = self.load_config()
            logger.info("✅ Configuration reloaded successfully")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to reload configuration: {e}")
            return False
    
    def export_config(self, format: str = "yaml") -> str:
        """Export configuration in specified format."""
        if not self.config:
            self.config = self.load_config()
        
        config_dict = self._config_to_dict(self.config)
        
        if format.lower() == "json":
            return json.dumps(config_dict, indent=2)
        elif format.lower() == "yaml":
            return yaml.dump(config_dict, default_flow_style=False, indent=2)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary."""
        if not self.config:
            self.config = self.load_config()
        
        return {
            "environment": self.config.environment,
            "debug_mode": self.config.debug_mode,
            "server": {
                "host": self.config.server.host,
                "port": self.config.server.port,
                "ssl_enabled": self.config.server.ssl_enabled
            },
            "database": {
                "type": self.config.database.type,
                "database": self.config.database.database
            },
            "features": {
                "security": self.config.security.enabled,
                "backup": self.config.backup.enabled,
                "cluster": self.config.cluster.enabled,
                "moderation": self.config.moderation.enabled,
                "social": self.config.social.enabled
            },
            "feature_flags": self.config.feature_flags
        }


# Global enhanced configuration manager instance
enhanced_config_manager = EnhancedConfigManager()


def get_enhanced_config() -> NetLinkConfig:
    """Get global enhanced configuration."""
    return enhanced_config_manager.get_config()


def reload_enhanced_config() -> bool:
    """Reload global enhanced configuration."""
    return enhanced_config_manager.reload_config()
