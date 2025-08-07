"""
PlexiChat Unified Configuration System

Comprehensive configuration management system that handles all aspects of
PlexiChat configuration including server, database, security, networking,
caching, AI, plugins, WebUI, and more.


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
    version: str = "2.0.0"
    environment: str = "production"
    debug: bool = False
    timezone: str = "UTC"
    max_users: int = 10000
    maintenance_mode: bool = False
    auto_backup: bool = True
    backup_interval_hours: int = 24
    data_retention_days: int = 365

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
        type: str = "sqlite"
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
    encryption_enabled: bool = True
    connection_timeout: int = 30

@dataclass
class SecurityConfig:
    """Security configuration section."""
        encryption_algorithm: str = "aes-256-gcm"
    key_rotation_days: int = 30
    session_timeout_minutes: int = 60
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_numbers: bool = True
    password_require_special: bool = True
    two_factor_enabled: bool = False
    audit_logging: bool = True
    ip_whitelist: List[str] = field(default_factory=list)
    ip_blacklist: List[str] = field(default_factory=list)
    csrf_protection: bool = True
    content_security_policy: bool = True

@dataclass
class CachingConfig:
    """Caching configuration section."""
        enabled: bool = True
    type: str = "multi-tier"
    l1_memory_size_mb: int = 200
    l1_max_items: int = 5000
    l2_redis_enabled: bool = True
    l2_redis_host: str = "localhost"
    l2_redis_port: int = 6379
    l2_redis_db: int = 0
    l2_redis_password: str = ""
    l3_memcached_enabled: bool = False
    l3_memcached_host: str = "localhost"
    l3_memcached_port: int = 11211
    default_ttl_seconds: int = 1800
    compression_enabled: bool = True
    compression_threshold_bytes: int = 512
    warming_enabled: bool = True
    monitoring_enabled: bool = True

@dataclass
class AIConfig:
    """AI configuration section."""
        enabled: bool = True
    default_provider: str = "openai"
    max_tokens: int = 4096
    temperature: float = 0.7
    timeout_seconds: int = 30
    rate_limit_requests_per_minute: int = 60
    content_filtering: bool = True
    logging_enabled: bool = True
    cost_tracking: bool = True
    fallback_enabled: bool = True
    model_caching: bool = True
    providers: Dict[str, Dict[str, Any]] = field(default_factory=dict)

@dataclass
class WebUIConfig:
    """WebUI configuration section."""
        enabled: bool = True
    theme: str = "default"
    dark_mode_default: bool = False
    language: str = "en"
    items_per_page: int = 25
    auto_refresh_seconds: int = 30
    notifications_enabled: bool = True
    sound_enabled: bool = True
    keyboard_shortcuts: bool = True
    advanced_features: bool = False
    beta_features: bool = False
    custom_css_enabled: bool = False
    custom_js_enabled: bool = False
    mobile_optimized: bool = True
    accessibility_mode: bool = False
    config_editing_enabled: bool = True
    real_time_updates: bool = True

@dataclass
class LoggingConfig:
    """Logging configuration section."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: str = "logs/plexichat.log"
    max_size_mb: int = 10
    backup_count: int = 5
    structured_logging: bool = True
    json_format: bool = False
    console_output: bool = True
    file_output: bool = True
    syslog_enabled: bool = False
    syslog_host: str = "localhost"
    syslog_port: int = 514
    audit_logging: bool = True
    performance_logging: bool = True
    error_tracking: bool = True

@dataclass
class MessagingConfig:
    """Messaging configuration section.
        max_message_length: int = 10000
    file_attachments_enabled: bool = True
    max_attachment_size_mb: int = 50
    encryption_default: bool = True
    message_history_days: int = 365
    typing_indicators: bool = True
    read_receipts: bool = True
    message_reactions: bool = True
    thread_support: bool = True
    broadcast_messages: bool = True
    scheduled_messages: bool = True
    message_search: bool = True
    auto_delete_enabled: bool = False
    auto_delete_days: int = 30

@dataclass
class PerformanceConfig:
    """Performance configuration section."""
        worker_processes: int = 4
    worker_threads: int = 8
    max_concurrent_requests: int = 1000
    request_timeout_seconds: int = 30
    keepalive_timeout_seconds: int = 5
    memory_limit_mb: int = 1024
    cpu_limit_percent: int = 80
    disk_cache_size_mb: int = 500
    compression_enabled: bool = True
    gzip_compression: bool = True
    brotli_compression: bool = False
    static_file_caching: bool = True
    cdn_enabled: bool = False
    cdn_url: str = ""

@dataclass
class FilesConfig:
    """Files configuration section."""
        upload_enabled: bool = True
    upload_directory: str = "uploads"
    max_file_size_mb: int = 100
    allowed_extensions: List[str] = field(default_factory=lambda: [
        ".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp",
        ".mp3", ".wav", ".ogg", ".mp4", ".avi", ".mov", ".webm",
        ".zip", ".rar", ".7z", ".tar", ".gz"
    ])
    virus_scanning: bool = True
    auto_cleanup_days: int = 90
    thumbnail_generation: bool = True
    compression_enabled: bool = True
    encryption_enabled: bool = True
    backup_enabled: bool = True

class UnifiedConfigManager:
    """Unified configuration manager for all PlexiChat settings."""

    def __init__(self, config_file: Optional[Path] = None):
        # Ensure paths are relative to project root, not src
        project_root = Path(__file__).parent.parent.parent.parent
        self.config_file = config_file or (project_root / "config/plexichat.yaml")
        self.plugin_config_dir = project_root / "config/plugins"
        self.backup_dir = project_root / "config/backups"

        # Configuration sections
        self.system = SystemConfig()
        self.network = NetworkConfig()
        self.database = DatabaseConfig()
        self.security = SecurityConfig()
        self.caching = CachingConfig()
        self.ai = AIConfig()
        self.webui = WebUIConfig()
        self.logging = LoggingConfig()
        self.messaging = MessagingConfig()
        self.performance = PerformanceConfig()
        self.files = FilesConfig()

        # Plugin configurations
        self._plugin_configs: Dict[str, Dict[str, Any]] = {}

        # Main configuration data
        self._config: Dict[str, Any] = {}

        # Create a simple defaults object
        class Defaults:
            pass
        self.defaults = Defaults()

        # Configuration metadata
        self._config_fields: Dict[str, ConfigField] = {}
        self._change_callbacks: List[Callable] = []
        self._lock = threading.RLock()

        # Ensure directories exist
        self._ensure_directories()

        # Load configuration
        self.load()

        # Initialize configuration fields metadata
        self._initialize_config_fields()

        # Load configuration
        self.load()

    def _ensure_directories(self):
        """Ensure all required directories exist."""
        project_root = Path(__file__).parent.parent.parent.parent
        for directory in [
            self.config_file.parent,
            self.plugin_config_dir,
            self.backup_dir,
            project_root / "logs",
            project_root / "data",
            project_root / Path(self.files.upload_directory)
        ]:
            directory.mkdir(parents=True, exist_ok=True)
    
    def _initialize_config_fields(self):
        """Initialize configuration field metadata for WebUI."""
        # System fields
        self._add_config_field("system.name", self.system.name, ConfigCategory.SYSTEM,
                            "Application name", "string", webui_section="Basic")
        self._add_config_field("system.environment", self.system.environment, ConfigCategory.SYSTEM,
                            "Environment (development/staging/production)", "select",
                            options=["development", "staging", "production"], webui_section="Basic")
        self._add_config_field("system.debug", self.system.debug, ConfigCategory.SYSTEM,
                            "Enable debug mode", "boolean", restart_required=True, webui_section="Basic")
        self._add_config_field("system.max_users", self.system.max_users, ConfigCategory.SYSTEM,
                            "Maximum number of users", "integer", min_value=1, max_value=100000, webui_section="Limits")

        # Network fields
        self._add_config_field("network.host", self.network.host, ConfigCategory.NETWORK,
                            "Server host address", "string", restart_required=True, webui_section="Basic")
        self._add_config_field("network.port", self.network.port, ConfigCategory.NETWORK,
                            "Main server port", "integer", min_value=1, max_value=65535,
                            restart_required=True, webui_section="Basic")
        self._add_config_field("network.ssl_enabled", self.network.ssl_enabled, ConfigCategory.NETWORK,
                            "Enable SSL/TLS", "boolean", restart_required=True, webui_section="Security")

        # Database fields
        self._add_config_field("database.type", self.database.type, ConfigCategory.DATABASE,
                            "Database type", "select", options=["sqlite", "postgresql", "mysql"],
                            restart_required=True, webui_section="Basic")
        self._add_config_field("database.backup_enabled", self.database.backup_enabled, ConfigCategory.DATABASE,
                            "Enable automatic backups", "boolean", webui_section="Backup")

        # Security fields
        self._add_config_field("security.session_timeout_minutes", self.security.session_timeout_minutes,
                            ConfigCategory.SECURITY, "Session timeout in minutes", "integer",
                            min_value=5, max_value=1440, webui_section="Authentication")
        self._add_config_field("security.two_factor_enabled", self.security.two_factor_enabled,
                            ConfigCategory.SECURITY, "Enable two-factor authentication", "boolean",
                            webui_section="Authentication")

        # Caching fields
        self._add_config_field("caching.enabled", self.caching.enabled, ConfigCategory.CACHING,
                            "Enable caching system", "boolean", restart_required=True, webui_section="Basic")
        self._add_config_field("caching.l1_memory_size_mb", self.caching.l1_memory_size_mb,
                            ConfigCategory.CACHING, "L1 cache memory size (MB)", "integer",
                            min_value=50, max_value=2048, webui_section="Memory")

        # WebUI fields
        self._add_config_field("webui.theme", self.webui.theme, ConfigCategory.WEBUI,
                            "Default theme", "select", options=["default", "dark", "light", "auto"],
                            webui_section="Appearance")
        self._add_config_field("webui.config_editing_enabled", self.webui.config_editing_enabled,
                            ConfigCategory.WEBUI, "Allow config editing via WebUI", "boolean",
                            webui_section="Features")

    def _add_config_field(self, name: str, value: Any, category: ConfigCategory,
                        description: str, data_type: str, **kwargs):
        """Add a configuration field with metadata.
        self._config_fields[name] = ConfigField(
            name=name,
            value=value,
            category=category,
            description=description,
            data_type=data_type,
            **kwargs
        )

    def load(self) -> None:
        """Load configuration from file."""
        with self._lock:
            try:
                if self.config_file.exists():
                    with open(self.config_file, 'r', encoding='utf-8') as f:
                        if self.config_file.suffix.lower() == '.yaml':
                            config_data = yaml.safe_load(f) or {}
                        else:
                            config_data = json.load(f)

                    # Store the raw config data
                    self._config = config_data

                    # Update configuration sections
                    self._update_config_sections(config_data)
                    logger.info(f"Configuration loaded from {self.config_file}")
                else:
                    logger.info("No configuration file found, using defaults")
                    # Initialize with empty config
                    self._config = {}
                    self.save()  # Create default config file

                # Load plugin configurations
                self._load_plugin_configs()

            except Exception as e:
                logger.error(f"Error loading configuration: {e}")

    def _update_config_sections(self, config_data: Dict[str, Any]):
        """Update configuration sections from loaded data."""
        if "system" in config_data:
            self.system = SystemConfig(**{k: v for k, v in config_data["system"].items()
                                        if hasattr(SystemConfig, k)})
        if "network" in config_data:
            self.network = NetworkConfig(**{k: v for k, v in config_data["network"].items()
                                        if hasattr(NetworkConfig, k)})
        if "database" in config_data:
            self.database = DatabaseConfig(**{k: v for k, v in config_data["database"].items()
                                            if hasattr(DatabaseConfig, k)})
        if "security" in config_data:
            self.security = SecurityConfig(**{k: v for k, v in config_data["security"].items()
                                            if hasattr(SecurityConfig, k)})
        if "caching" in config_data:
            self.caching = CachingConfig(**{k: v for k, v in config_data["caching"].items()
                                        if hasattr(CachingConfig, k)})
        if "ai" in config_data:
            self.ai = AIConfig(**{k: v for k, v in config_data["ai"].items()
                                if hasattr(AIConfig, k)})
        if "webui" in config_data:
            self.webui = WebUIConfig(**{k: v for k, v in config_data["webui"].items()
                                    if hasattr(WebUIConfig, k)})
        if "logging" in config_data:
            self.logging = LoggingConfig(**{k: v for k, v in config_data["logging"].items()
                                        if hasattr(LoggingConfig, k)})
        if "messaging" in config_data:
            self.messaging = MessagingConfig(**{k: v for k, v in config_data["messaging"].items()
                                            if hasattr(MessagingConfig, k)})
        if "performance" in config_data:
            self.performance = PerformanceConfig(**{k: v for k, v in config_data["performance"].items()
                                                if hasattr(PerformanceConfig, k)})
        if "files" in config_data:
            self.files = FilesConfig(**{k: v for k, v in config_data["files"].items()
                                    if hasattr(FilesConfig, k)})

    def _load_plugin_configs(self) -> None:
        """Load plugin-specific configurations."""
        self._plugin_configs = {}
        
        if not self.plugin_config_dir.exists():
            return
            
        for config_file in self.plugin_config_dir.glob("*.yaml"):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    plugin_name = config_file.stem
                    self._plugin_configs[plugin_name] = yaml.safe_load(f) or {}
                logger.debug(f"Loaded plugin config for {plugin_name}")
            except Exception as e:
                logger.error(f"Error loading plugin config {config_file}: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with fallback to defaults."""
        # Check environment variable first
        env_key = f"PLEXICHAT_{key.upper()}"
        env_value = os.getenv(env_key)
        if env_value is not None:
            return self._convert_env_value(env_value)
        
        # Check config file
        if key in self._config:
            return self._config[key]
        
        # Check defaults
        if hasattr(self, 'defaults') and hasattr(self.defaults, key):
            return getattr(self.defaults, key)
        
        return default
    
    def _convert_env_value(self, value: str) -> Union[str, int, bool, float]:
        """Convert environment variable string to appropriate type.
        # Boolean conversion
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'
        
        # Integer conversion
        try:
            return int(value)
        except ValueError:
            pass
        
        # Float conversion
        try:
            return float(value)
        except ValueError:
            pass
        
        # Return as string
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
        self._config[key] = value
    
    def save(self) -> bool:
        Save configuration to file."""
        with self._lock:
            try:
                # Create backup first
                self._create_backup()

                # Prepare configuration data
                config_data = {
                    "system": asdict(self.system),
                    "network": asdict(self.network),
                    "database": asdict(self.database),
                    "security": asdict(self.security),
                    "caching": asdict(self.caching),
                    "ai": asdict(self.ai),
                    "webui": asdict(self.webui),
                    "logging": asdict(self.logging),
                    "messaging": asdict(self.messaging),
                    "performance": asdict(self.performance),
                    "files": asdict(self.files),
                    "plugins": self._plugin_configs,
                    "_metadata": {
                        "last_updated": datetime.now().isoformat(),
                        "version": "2.0.0"
                    }
                }

                with open(self.config_file, 'w', encoding='utf-8') as f:
                    yaml.safe_dump(config_data, f, default_flow_style=False, indent=2)

                logger.info(f"Configuration saved to {self.config_file}")

                # Notify change callbacks
                for callback in self._change_callbacks:
                    try:
                        callback()
                    except Exception as e:
                        logger.error(f"Error in config change callback: {e}")

                return True
            except Exception as e:
                logger.error(f"Error saving configuration: {e}")
                return False

    def _create_backup(self):
        """Create a backup of the current configuration."""
        if self.config_file.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.backup_dir / f"plexichat_{timestamp}.yaml"
            try:
                import shutil
                shutil.copy2(self.config_file, backup_file)
                logger.debug(f"Configuration backup created: {backup_file}")
            except Exception as e:
                logger.warning(f"Failed to create config backup: {e}")

    def get_config_fields(self, category: Optional[ConfigCategory] = None) -> Dict[str, ConfigField]:
        """Get configuration fields, optionally filtered by category.
        if category:
            return {k: v for k, v in self._config_fields.items() if v.category == category}
        return self._config_fields.copy()

    def get_webui_config_sections(self) -> Dict[str, List[ConfigField]]:
        """Get configuration fields organized by WebUI sections."""
        sections = {}
        for field in self._config_fields.values():
            if field.webui_editable:
                section = field.webui_section or "General"
                if section not in sections:
                    sections[section] = []
                sections[section].append(field)
        return sections

    def update_config_value(self, field_path: str, value: Any) -> bool:
        """Update a configuration value by field path (e.g., 'system.debug')."""
        with self._lock:
            try:
                parts = field_path.split('.')
                if len(parts) != 2:
                    return False

                section_name, field_name = parts
                section = getattr(self, section_name, None)
                if section is None:
                    return False

                if hasattr(section, field_name):
                    # Validate the value if validator exists
                    field_meta = self._config_fields.get(field_path)
                    if field_meta and field_meta.validation_func:
                        if not field_meta.validation_func(value):
                            return False

                    setattr(section, field_name, value)
                    return True

                return False
            except Exception as e:
                logger.error(f"Error updating config value {field_path}: {e}")
                return False

    def get_config_value(self, field_path: str) -> Any:
        """Get a configuration value by field path.
        try:
            parts = field_path.split('.')
            if len(parts) != 2:
                return None

            section_name, field_name = parts
            section = getattr(self, section_name, None)
            if section is None:
                return None

            return getattr(section, field_name, None)
        except Exception:
            return None

    def add_change_callback(self, callback: Callable):
        """Add a callback to be called when configuration changes."""
        self._change_callbacks.append(callback)

    def remove_change_callback(self, callback: Callable):
        Remove a configuration change callback."""
        if callback in self._change_callbacks:
            self._change_callbacks.remove(callback)

    def validate_config(self) -> Dict[str, List[str]]:
        """Validate the current configuration."""
        errors = []
        warnings = []

        # Network validation
        if self.network.port == self.network.api_port:
            warnings.append("Main port and API port are the same")

        # Database validation
        if self.database.type == "sqlite" and not self.database.path:
            errors.append("SQLite database path is required")

        # Security validation
        if not self.security.two_factor_enabled and self.system.environment == "production":
            warnings.append("Two-factor authentication is recommended for production")

        # Caching validation
        if self.caching.enabled and self.caching.l1_memory_size_mb < 50:
            warnings.append("L1 cache memory size is very low")

        return {"errors": errors, "warnings": warnings}

    def export_config(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Export configuration for backup or transfer."""
        config_data = {
            "system": asdict(self.system),
            "network": asdict(self.network),
            "database": asdict(self.database),
            "security": asdict(self.security),
            "caching": asdict(self.caching),
            "ai": asdict(self.ai),
            "webui": asdict(self.webui),
            "logging": asdict(self.logging),
            "messaging": asdict(self.messaging),
            "performance": asdict(self.performance),
            "files": asdict(self.files),
            "plugins": self._plugin_configs
        }

        if not include_sensitive:
            # Remove sensitive fields
            if "password" in config_data["database"]:
                config_data["database"]["password"] = "***REDACTED***"
            if "l2_redis_password" in config_data["caching"]:
                config_data["caching"]["l2_redis_password"] = "***REDACTED***"

        return config_data

# Global configuration manager instance
_config_manager: Optional[UnifiedConfigManager] = None

def get_config() -> UnifiedConfigManager:
    """Get the global configuration manager instance.
    global _config_manager
    if _config_manager is None:
        _config_manager = UnifiedConfigManager()
    return _config_manager

def reload_config():
    """Reload the global configuration."""
    global _config_manager
    if _config_manager:
        _config_manager.load()

# Backward compatibility functions
def get_setting(key: str, default: Any = None) -> Any:
    Get a configuration setting (backward compatibility)."""
    return get_config().get(key, default)

def set_setting(key: str, value: Any) -> None:
    """Set a configuration setting (backward compatibility).
    get_config().set(key, value)
    
    def get_plugin_config(self, plugin_name: str) -> Dict[str, Any]:
        """Get configuration for a specific plugin."""
        return self._plugin_configs.get(plugin_name, {})
    
    def set_plugin_config(self, plugin_name: str, config: Dict[str, Any]) -> bool:
        Set configuration for a specific plugin."""
        try:
            self._plugin_configs[plugin_name] = config
            plugin_file = self.plugin_config_dir / f"{plugin_name}.yaml"
            
            with open(plugin_file, 'w', encoding='utf-8') as f:
                yaml.safe_dump(config, f, default_flow_style=False, indent=2)
            
            logger.info(f"Plugin configuration saved for {plugin_name}")
            return True
        except Exception as e:
            logger.error(f"Error saving plugin configuration for {plugin_name}: {e}")
            return False
    
    def create_default_config(self) -> bool:
        """Create default configuration file."""
        try:
            default_config = {
                "server": {
                    "host": self.defaults.HOST,
                    "port": self.defaults.PORT,
                    "debug": self.defaults.DEBUG
                },
                "database": {
                    "url": self.defaults.DATABASE_URL,
                    "echo": self.defaults.DATABASE_ECHO
                },
                "security": {
                    "jwt_secret": self.defaults.JWT_SECRET,
                    "jwt_algorithm": self.defaults.JWT_ALGORITHM,
                    "access_token_expire_minutes": self.defaults.ACCESS_TOKEN_EXPIRE_MINUTES
                },
                "logging": {
                    "level": self.defaults.LOG_LEVEL,
                    "directory": self.defaults.LOG_DIRECTORY,
                    "file_enabled": self.defaults.LOG_FILE_ENABLED,
                    "console_enabled": self.defaults.LOG_CONSOLE_ENABLED
                },
                "files": {
                    "upload_directory": self.defaults.UPLOAD_DIRECTORY,
                    "max_file_size": self.defaults.MAX_FILE_SIZE
                },
                "performance": {
                    "cache_ttl": self.defaults.CACHE_TTL,
                    "rate_limit_requests": self.defaults.RATE_LIMIT_REQUESTS,
                    "rate_limit_window": self.defaults.RATE_LIMIT_WINDOW
                }
            }
            
            self._config = default_config
            return self.save()
        except Exception as e:
            logger.error(f"Error creating default configuration: {e}")
            return False
    
    def validate(self) -> bool:
        """Validate configuration."""
        try:
            # Check required settings
            required_keys = ["server", "database", "security"]
            for key in required_keys:
                if key not in self._config:
                    logger.error(f"Missing required configuration section: {key}")
                    return False
            
            # Validate server settings
            server = self._config.get("server", {})
            if not isinstance(server.get("port"), int) or server.get("port") <= 0:
                logger.error("Invalid server port configuration")
                return False
            
            logger.info("Configuration validation passed")
            return True
        except Exception as e:
            logger.error(f"Configuration validation error: {e}")
            return False

# Global configuration instance
config = UnifiedConfigManager()

# Convenience functions
def get_config(key: str, default: Any = None) -> Any:
    """Get configuration value.
    return config.get(key, default)

def set_config(key: str, value: Any) -> None:
    """Set configuration value."""
    config.set(key, value)

def save_config() -> bool:
    Save configuration."""
    return config.save()

def get_plugin_config(plugin_name: str) -> Dict[str, Any]:
    """Get plugin configuration.
    return config.get_plugin_config(plugin_name)

def set_plugin_config(plugin_name: str, plugin_config: Dict[str, Any]) -> bool:
    """Set plugin configuration."""
    return config.set_plugin_config(plugin_name, plugin_config)

def get_unified_config() -> UnifiedConfigManager:
    Get the unified configuration manager instance."""
    return config

# Constants access functions - All constants loaded from YAML config
def get_app_name() -> str:
    """Get application name from config."""
    return config.get("security.app_name", "PlexiChat")

def get_app_version() -> str:
    """Get application version from config."""
    return config.get("security.app_version", "2.0.0")

def get_default_secret_key() -> str:
    """Get default secret key from config."""
    return config.get("security.default_secret_key", "plexichat-default-secret-key-change-in-production")

def get_token_expiry_hours() -> int:
    """Get token expiry hours from config."""
    return config.get("security.token_expiry_hours", 24)

def get_password_min_length() -> int:
    """Get minimum password length from config."""
    return config.get("security.password_min_length", 8)

def get_max_login_attempts() -> int:
    """Get maximum login attempts from config."""
    return config.get("security.max_login_attempts", 5)

def get_lockout_duration_minutes() -> int:
    """Get lockout duration in minutes from config."""
    return config.get("security.lockout_duration_minutes", 15)

def get_logs_dir() -> str:
    """Get logs directory from config."""
    return config.get("security.logs_dir", "logs")

def get_plugin_timeout() -> int:
    """Get plugin timeout from config."""
    return config.get("security.plugin_timeout", 30)

def get_max_plugin_memory() -> int:
    """Get max plugin memory from config."""
    return config.get("security.max_plugin_memory", 512)

def get_plugin_sandbox_enabled() -> bool:
    """Get plugin sandbox enabled from config."""
    return config.get("security.plugin_sandbox_enabled", True)

def get_max_message_length() -> int:
    """Get maximum message length from config."""
    return config.get("security.max_message_length", 4096)

def get_max_attachment_count() -> int:
    """Get maximum attachment count from config."""
    return config.get("security.max_attachment_count", 10)

def get_message_history_limit() -> int:
    """Get message history limit from config."""
    return config.get("security.message_history_limit", 1000)

def get_max_channel_members() -> int:
    """Get maximum channel members from config."""
    return config.get("security.max_channel_members", 1000)

# Legacy constant names for backward compatibility - lazy loaded
def _get_legacy_constants():
    """Get legacy constants - lazy loaded to avoid circular imports.
    return {
        'APP_NAME': get_app_name(),
        'APP_VERSION': get_app_version(),
        'DEFAULT_SECRET_KEY': get_default_secret_key(),
        'TOKEN_EXPIRY_HOURS': get_token_expiry_hours(),
        'PASSWORD_MIN_LENGTH': get_password_min_length(),
        'MAX_LOGIN_ATTEMPTS': get_max_login_attempts(),
        'LOCKOUT_DURATION_MINUTES': get_lockout_duration_minutes(),
        'LOGS_DIR': get_logs_dir(),
        'PLUGIN_TIMEOUT': get_plugin_timeout(),
        'MAX_PLUGIN_MEMORY': get_max_plugin_memory(),
        'PLUGIN_SANDBOX_ENABLED': get_plugin_sandbox_enabled(),
        'MAX_MESSAGE_LENGTH': get_max_message_length(),
        'MAX_ATTACHMENT_COUNT': get_max_attachment_count(),
        'MESSAGE_HISTORY_LIMIT': get_message_history_limit(),
        'MAX_CHANNEL_MEMBERS': get_max_channel_members(),
    }

# Make constants available as module attributes
def __getattr__(name):
    """Lazy load constants when accessed."""
    constants = _get_legacy_constants()
    if name in constants:
        return constants[name]
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
