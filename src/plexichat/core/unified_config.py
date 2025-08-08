"""
PlexiChat Unified Configuration System

Comprehensive configuration management system that handles all aspects of
PlexiChat configuration including server, database, security, networking,
caching, AI, plugins, WebUI, and more.
"""

import json
import logging
import os
import yaml
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Union, List, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ConfigCategory(Enum):
    """Configuration categories for organization."""
    SYSTEM = "system"
    NETWORK = "network"
    DATABASE = "database"
    SECURITY = "security"
    LOGGING = "logging"
    CACHING = "caching"
    AI = "ai"
    PLUGINS = "plugins"
    WEBUI = "webui"
    MESSAGING = "messaging"
    FILES = "files"
    PERFORMANCE = "performance"
    MONITORING = "monitoring"
    BACKUP = "backup"


@dataclass
class ConfigField:
    """Configuration field definition with metadata."""
    name: str
    value: Any
    category: ConfigCategory
    description: str = ""
    data_type: str = "string"
    required: bool = False
    sensitive: bool = False
    restart_required: bool = False
    validation_func: Optional[Callable] = None
    options: Optional[List[Any]] = None
    min_value: Optional[Union[int, float]] = None
    max_value: Optional[Union[int, float]] = None
    webui_editable: bool = True
    webui_section: str = ""


@dataclass
class SystemConfig:
    """System configuration section."""
    name: str = "PlexiChat"
    version: str = "b.1.1-94"  # Will be loaded from version.json
    environment: str = "production"
    debug: bool = False
    timezone: str = "UTC"
    max_users: int = 10000
    maintenance_mode: bool = False
    auto_backup: bool = True
    backup_interval_hours: int = 24
    data_retention_days: int = 365
    version_file: str = "version.json"
    changelog_file: str = "changelog.json"


@dataclass
class NetworkConfig:
    """Network configuration section."""
    host: str = "0.0.0.0"
    port: int = 8080
    api_port: int = 8000
    admin_port: int = 8002
    websocket_port: int = 8001
    ssl_enabled: bool = False
    ssl_cert_path: str = ""
    ssl_key_path: str = ""
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    rate_limit_enabled: bool = True
    rate_limit_requests_per_minute: int = 60
    rate_limit_burst_limit: int = 10
    proxy_headers: bool = False
    max_request_size_mb: int = 100


@dataclass
class DatabaseConfig:
    """Database configuration section."""
    db_type: str = "sqlite"
    host: str = "localhost"
    port: int = 5432
    name: str = "plexichat"
    username: str = ""
    password: str = ""
    path: str = "data/plexichat.db"
    pool_size: int = 10
    max_overflow: int = 20
    echo: bool = False
    backup_enabled: bool = True
    backup_interval_hours: int = 6


@dataclass
class SecurityConfig:
    """Security configuration section."""
    secret_key: str = ""
    jwt_secret: str = ""
    jwt_expiry_hours: int = 24
    password_min_length: int = 8
    password_require_special: bool = True
    password_require_numbers: bool = True
    password_require_uppercase: bool = True
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30
    session_timeout_minutes: int = 60
    csrf_protection: bool = True
    secure_cookies: bool = True


@dataclass
class CachingConfig:
    """Caching configuration section."""
    enabled: bool = True
    backend: str = "memory"
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str = ""
    default_timeout: int = 300
    max_entries: int = 10000
    # Enhanced caching config for unified system
    l1_max_items: int = 1000
    l1_memory_size_mb: int = 100
    default_ttl_seconds: int = 300
    compression_threshold_bytes: int = 1024
    warming_enabled: bool = True
    l2_redis_enabled: bool = False
    l2_redis_host: str = "localhost"
    l2_redis_port: int = 6379
    l2_redis_db: int = 0
    l2_redis_password: str = ""
    l3_memcached_enabled: bool = False
    l3_memcached_host: str = "localhost"
    l3_memcached_port: int = 11211


@dataclass
class AIConfig:
    """AI configuration section."""
    enabled: bool = True
    provider: str = "openai"
    api_key: str = ""
    model: str = "gpt-3.5-turbo"
    max_tokens: int = 2048
    temperature: float = 0.7
    timeout_seconds: int = 30


@dataclass
class WebUIConfig:
    """WebUI configuration section."""
    enabled: bool = True
    theme: str = "default"
    language: str = "en"
    items_per_page: int = 20
    auto_refresh: bool = True
    refresh_interval_seconds: int = 30


@dataclass
class LoggingConfig:
    """Logging configuration section."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_enabled: bool = True
    file_path: str = "logs/plexichat.log"
    file_max_size_mb: int = 100
    file_backup_count: int = 5
    console_enabled: bool = True


@dataclass
class MessagingConfig:
    """Messaging configuration section."""
    max_message_length: int = 4096
    max_attachments: int = 10
    max_attachment_size_mb: int = 50
    allowed_file_types: List[str] = field(default_factory=lambda: [".txt", ".pdf", ".jpg", ".png"])
    message_retention_days: int = 365
    enable_encryption: bool = True


@dataclass
class PerformanceConfig:
    """Performance configuration section."""
    worker_processes: int = 4
    worker_threads: int = 8
    max_connections: int = 1000
    connection_timeout: int = 30
    request_timeout: int = 60
    enable_compression: bool = True


@dataclass
class FilesConfig:
    """Files configuration section."""
    upload_dir: str = "uploads"
    max_file_size_mb: int = 100
    allowed_extensions: List[str] = field(default_factory=lambda: [".txt", ".pdf", ".jpg", ".png", ".gif"])
    scan_for_viruses: bool = True
    auto_cleanup_days: int = 30


@dataclass
class UnifiedConfig:
    """Main unified configuration container."""
    system: SystemConfig = field(default_factory=SystemConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    caching: CachingConfig = field(default_factory=CachingConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    webui: WebUIConfig = field(default_factory=WebUIConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    messaging: MessagingConfig = field(default_factory=MessagingConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    files: FilesConfig = field(default_factory=FilesConfig)


class UnifiedConfigManager:
    """Unified configuration manager with thread safety and persistence."""

    def __init__(self, config_file: Optional[str] = None):
        self.config_file = Path(config_file or "config/plexichat.yaml")
        self.project_root = Path(__file__).parent.parent.parent.parent
        self.version_file = self.project_root / "version.json"
        self.changelog_file = self.project_root / "changelog.json"
        self._config = UnifiedConfig()
        self._lock = threading.RLock()
        self._change_callbacks: List[Callable] = []
        self.load()
        self._load_version_info()
        self._ensure_directories()
    
    def load(self) -> None:
        """Load configuration from file."""
        with self._lock:
            if self.config_file.exists():
                try:
                    with open(self.config_file, 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f)
                        if data:
                            self._update_config_from_dict(data)
                    logger.info(f"Configuration loaded from {self.config_file}")
                except Exception as e:
                    logger.error(f"Failed to load configuration: {e}")
            else:
                logger.info("Configuration file not found, using defaults")
    
    def save(self) -> None:
        """Save configuration to file."""
        with self._lock:
            try:
                self.config_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self.config_file, 'w', encoding='utf-8') as f:
                    yaml.dump(asdict(self._config), f, default_flow_style=False)
                logger.info(f"Configuration saved to {self.config_file}")
            except Exception as e:
                logger.error(f"Failed to save configuration: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot notation key."""
        with self._lock:
            try:
                parts = key.split('.')
                value = self._config
                for part in parts:
                    value = getattr(value, part)
                return value
            except (AttributeError, KeyError):
                return default
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value by dot notation key."""
        with self._lock:
            try:
                parts = key.split('.')
                config_obj = self._config
                for part in parts[:-1]:
                    config_obj = getattr(config_obj, part)
                setattr(config_obj, parts[-1], value)
                self._notify_change_callbacks(key, value)
            except (AttributeError, KeyError) as e:
                logger.error(f"Failed to set config key {key}: {e}")
    
    def _update_config_from_dict(self, data: Dict[str, Any]) -> None:
        """Update configuration from dictionary."""
        for section_name, section_data in data.items():
            if hasattr(self._config, section_name) and isinstance(section_data, dict):
                section = getattr(self._config, section_name)
                for key, value in section_data.items():
                    if hasattr(section, key):
                        setattr(section, key, value)
    
    def _notify_change_callbacks(self, key: str, value: Any) -> None:
        """Notify registered callbacks of configuration changes."""
        for callback in self._change_callbacks:
            try:
                callback(key, value)
            except Exception as e:
                logger.error(f"Error in config change callback: {e}")
    
    def add_change_callback(self, callback: Callable) -> None:
        """Add a callback to be notified of configuration changes."""
        self._change_callbacks.append(callback)
    
    def remove_change_callback(self, callback: Callable) -> None:
        """Remove a configuration change callback."""
        if callback in self._change_callbacks:
            self._change_callbacks.remove(callback)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        with self._lock:
            return asdict(self._config)
    
    def reload(self) -> None:
        """Reload configuration from file."""
        self.load()
        self._load_version_info()

    def _load_version_info(self) -> None:
        """Load version information from version.json."""
        try:
            if self.version_file.exists():
                with open(self.version_file, 'r', encoding='utf-8') as f:
                    version_data = json.load(f)
                    self._config.system.version = version_data.get('version', self._config.system.version)
                    logger.info(f"Version loaded from {self.version_file}: {self._config.system.version}")
            else:
                logger.warning(f"Version file not found: {self.version_file}")
        except Exception as e:
            logger.error(f"Failed to load version info: {e}")

    def get_version_info(self) -> Dict[str, Any]:
        """Get complete version information."""
        try:
            if self.version_file.exists():
                with open(self.version_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load version info: {e}")

        # Return fallback version info
        return {
            "version": self._config.system.version,
            "version_type": "beta",
            "major_version": 1,
            "minor_version": 1,
            "build_number": 94,
            "api_version": "v1",
            "release_date": "2025-08-08",
            "status": "beta"
        }

    def get_changelog_info(self) -> Dict[str, Any]:
        """Get changelog information."""
        try:
            if self.changelog_file.exists():
                with open(self.changelog_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load changelog info: {e}")

        # Return empty changelog
        return {
            "changelog": {"format_version": "1.0", "last_updated": "2025-08-08T00:00:00Z"},
            "releases": []
        }

    def _ensure_directories(self) -> None:
        """Ensure all necessary directories exist."""
        directories = [
            self.project_root / "config",
            self.project_root / "data" / "config",
            self.project_root / "data" / "logs",
            self.project_root / "data" / "uploads",
            self.project_root / "data" / "cache",
            self.project_root / "data" / "backups",
            self.project_root / "data" / "runtime",
            self.project_root / "data" / "storage",
            self.project_root / "logs",
            self.project_root / "temp",
            self.project_root / "certs"
        ]

        for directory in directories:
            try:
                directory.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                logger.warning(f"Failed to create directory {directory}: {e}")


# Global configuration manager instance
_config_manager: Optional[UnifiedConfigManager] = None


def get_config_manager() -> UnifiedConfigManager:
    """Get the global configuration manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = UnifiedConfigManager()
    return _config_manager


def get_config(key: str, default: Any = None) -> Any:
    """Get configuration value by key."""
    return get_config_manager().get(key, default)


def set_config(key: str, value: Any) -> None:
    """Set configuration value by key."""
    get_config_manager().set(key, value)


def reload_config() -> None:
    """Reload configuration from file."""
    get_config_manager().reload()


# Create global config instance
config = get_config_manager()._config
