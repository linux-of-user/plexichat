"""
PlexiChat Logging Configuration

Centralized configuration for the comprehensive logging system.
Provides default settings, environment variable overrides, and validation.

Features:
- Environment variable configuration
- Default settings with validation
- Dynamic configuration updates
- Profile-based configurations
- Configuration validation
- Settings export/import
"""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class LoggingConfig:
    """Comprehensive logging configuration."""
    
    # General settings
    directory: str = "logs"
    level: str = "INFO"
    buffer_size: int = 10000
    
    # Console logging
    console_enabled: bool = True
    console_level: str = "INFO"
    console_colors: bool = True
    console_format: str = "[%(asctime)s] [%(levelname)-8s] %(name)s: %(message)s"
    
    # File logging
    file_enabled: bool = True
    file_level: str = "INFO"
    file_format: str = "[%(asctime)s] [%(levelname)-8s] [%(name)s:%(lineno)d] %(funcName)s() - %(message)s"
    max_file_size: str = "10MB"
    backup_count: int = 5
    
    # Structured logging
    structured_enabled: bool = True
    structured_format: str = "json"
    include_context: bool = True
    
    # Date formatting
    date_format: str = "%Y-%m-%d %H:%M:%S"
    
    # Performance monitoring
    performance_enabled: bool = True
    performance_interval: int = 30  # seconds
    performance_alerts: bool = True
    
    # Security logging
    security_enabled: bool = True
    security_tamper_resistant: bool = True
    security_encryption: bool = True
    
    # Audit logging
    audit_enabled: bool = True
    audit_retention_days: int = 365
    
    # Real-time streaming
    streaming_enabled: bool = True
    streaming_buffer_size: int = 1000
    
    # Alert settings
    alerts_enabled: bool = True
    alert_email: Optional[str] = None
    alert_webhook: Optional[str] = None
    alert_slack: Optional[str] = None
    
    # Compression and archival
    compression_enabled: bool = True
    compression_algorithm: str = "gzip"
    archive_enabled: bool = True
    archive_after_days: int = 30
    
    # Third-party logger settings
    silence_third_party: bool = True
    third_party_level: str = "WARNING"
    third_party_loggers: List[str] = field(default_factory=lambda: [
        "urllib3", "requests", "asyncio", "websockets", "sqlalchemy"
    ])
    
    # Advanced settings
    async_logging: bool = False
    queue_size: int = 1000
    flush_interval: float = 1.0
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate_config()
    
    def _validate_config(self):
        """Validate configuration values."""
        # Validate log levels
        valid_levels = ["TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.level.upper() not in valid_levels:
            raise ValueError(f"Invalid log level: {self.level}")
        if self.console_level.upper() not in valid_levels:
            raise ValueError(f"Invalid console log level: {self.console_level}")
        if self.file_level.upper() not in valid_levels:
            raise ValueError(f"Invalid file log level: {self.file_level}")
        if self.third_party_level.upper() not in valid_levels:
            raise ValueError(f"Invalid third-party log level: {self.third_party_level}")
        
        # Validate file size format
        if not self._is_valid_size_format(self.max_file_size):
            raise ValueError(f"Invalid file size format: {self.max_file_size}")
        
        # Validate buffer sizes
        if self.buffer_size <= 0:
            raise ValueError("Buffer size must be positive")
        if self.streaming_buffer_size <= 0:
            raise ValueError("Streaming buffer size must be positive")
        if self.queue_size <= 0:
            raise ValueError("Queue size must be positive")
        
        # Validate intervals
        if self.performance_interval <= 0:
            raise ValueError("Performance interval must be positive")
        if self.flush_interval <= 0:
            raise ValueError("Flush interval must be positive")
        
        # Validate retention settings
        if self.backup_count < 0:
            raise ValueError("Backup count cannot be negative")
        if self.audit_retention_days <= 0:
            raise ValueError("Audit retention days must be positive")
        if self.archive_after_days <= 0:
            raise ValueError("Archive after days must be positive")
    
    def _is_valid_size_format(self, size_str: str) -> bool:
        """Check if size string is valid."""
        try:
            size_str = size_str.upper()
            if size_str.endswith(('KB', 'MB', 'GB')):
                int(size_str[:-2])
                return True
            else:
                int(size_str)
                return True
        except ValueError:
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            field.name: getattr(self, field.name)
            for field in self.__dataclass_fields__.values()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LoggingConfig':
        """Create configuration from dictionary."""
        # Filter out unknown fields
        valid_fields = {field.name for field in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)
    
    def update(self, **kwargs):
        """Update configuration with new values."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self._validate_config()

class ConfigurationManager:
    """Manage logging configuration with environment overrides."""
    
    def __init__(self, config_file: Optional[Path] = None):
        self.config_file = config_file
        self._config = None
        self._load_config()
    
    def _load_config(self):
        """Load configuration from file and environment."""
        # Start with default configuration
        config_data = {}
        
        # Load from file if specified
        if self.config_file and self.config_file.exists():
            config_data = self._load_config_file()
        
        # Apply environment variable overrides
        env_overrides = self._get_env_overrides()
        config_data.update(env_overrides)
        
        # Create configuration object
        self._config = LoggingConfig.from_dict(config_data)
    
    def _load_config_file(self) -> Dict[str, Any]:
        """Load configuration from file."""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                if self.config_file.suffix.lower() in ['.yml', '.yaml']:
                    return yaml.safe_load(f) or {}
                elif self.config_file.suffix.lower() == '.json':
                    return json.load(f) or {}
                else:
                    # Try to parse as YAML first, then JSON
                    content = f.read()
                    try:
                        return yaml.safe_load(content) or {}
                    except yaml.YAMLError:
                        return json.loads(content) or {}
        except Exception as e:
            logging.warning(f"Failed to load logging config from {self.config_file}: {e}")
            return {}
    
    def _get_env_overrides(self) -> Dict[str, Any]:
        """Get configuration overrides from environment variables."""
        env_mapping = {
            'PLEXICHAT_LOG_DIRECTORY': 'directory',
            'PLEXICHAT_LOG_LEVEL': 'level',
            'PLEXICHAT_LOG_BUFFER_SIZE': ('buffer_size', int),
            'PLEXICHAT_LOG_CONSOLE_ENABLED': ('console_enabled', self._parse_bool),
            'PLEXICHAT_LOG_CONSOLE_LEVEL': 'console_level',
            'PLEXICHAT_LOG_CONSOLE_COLORS': ('console_colors', self._parse_bool),
            'PLEXICHAT_LOG_CONSOLE_FORMAT': 'console_format',
            'PLEXICHAT_LOG_FILE_ENABLED': ('file_enabled', self._parse_bool),
            'PLEXICHAT_LOG_FILE_LEVEL': 'file_level',
            'PLEXICHAT_LOG_FILE_FORMAT': 'file_format',
            'PLEXICHAT_LOG_MAX_FILE_SIZE': 'max_file_size',
            'PLEXICHAT_LOG_BACKUP_COUNT': ('backup_count', int),
            'PLEXICHAT_LOG_STRUCTURED_ENABLED': ('structured_enabled', self._parse_bool),
            'PLEXICHAT_LOG_INCLUDE_CONTEXT': ('include_context', self._parse_bool),
            'PLEXICHAT_LOG_DATE_FORMAT': 'date_format',
            'PLEXICHAT_LOG_PERFORMANCE_ENABLED': ('performance_enabled', self._parse_bool),
            'PLEXICHAT_LOG_PERFORMANCE_INTERVAL': ('performance_interval', int),
            'PLEXICHAT_LOG_SECURITY_ENABLED': ('security_enabled', self._parse_bool),
            'PLEXICHAT_LOG_AUDIT_ENABLED': ('audit_enabled', self._parse_bool),
            'PLEXICHAT_LOG_STREAMING_ENABLED': ('streaming_enabled', self._parse_bool),
            'PLEXICHAT_LOG_ALERTS_ENABLED': ('alerts_enabled', self._parse_bool),
            'PLEXICHAT_LOG_ALERT_EMAIL': 'alert_email',
            'PLEXICHAT_LOG_ALERT_WEBHOOK': 'alert_webhook',
            'PLEXICHAT_LOG_ALERT_SLACK': 'alert_slack',
            'PLEXICHAT_LOG_COMPRESSION_ENABLED': ('compression_enabled', self._parse_bool),
            'PLEXICHAT_LOG_ARCHIVE_ENABLED': ('archive_enabled', self._parse_bool),
            'PLEXICHAT_LOG_ARCHIVE_AFTER_DAYS': ('archive_after_days', int),
            'PLEXICHAT_LOG_SILENCE_THIRD_PARTY': ('silence_third_party', self._parse_bool),
            'PLEXICHAT_LOG_THIRD_PARTY_LEVEL': 'third_party_level',
            'PLEXICHAT_LOG_ASYNC_LOGGING': ('async_logging', self._parse_bool),
            'PLEXICHAT_LOG_QUEUE_SIZE': ('queue_size', int),
            'PLEXICHAT_LOG_FLUSH_INTERVAL': ('flush_interval', float),
        }
        
        overrides = {}
        for env_var, config_key in env_mapping.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                if isinstance(config_key, tuple):
                    key, converter = config_key
                    try:
                        overrides[key] = converter(env_value)
                    except (ValueError, TypeError) as e:
                        logging.warning(f"Invalid value for {env_var}: {env_value} ({e})")
                else:
                    overrides[config_key] = env_value
        
        return overrides
    
    def _parse_bool(self, value: str) -> bool:
        """Parse boolean value from string."""
        return value.lower() in ('true', '1', 'yes', 'on', 'enabled')
    
    @property
    def config(self) -> LoggingConfig:
        """Get current configuration."""
        return self._config
    
    def reload(self):
        """Reload configuration from file and environment."""
        self._load_config()
    
    def save_config(self, output_file: Path, format: str = "yaml"):
        """Save current configuration to file."""
        config_data = self._config.to_dict()
        
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            if format.lower() in ['yml', 'yaml']:
                yaml.dump(config_data, f, default_flow_style=False, indent=2)
            elif format.lower() == 'json':
                json.dump(config_data, f, indent=2, default=str)
            else:
                raise ValueError(f"Unsupported format: {format}")
    
    def get_profile_config(self, profile: str) -> LoggingConfig:
        """Get configuration for specific profile."""
        profile_configs = {
            'development': {
                'level': 'DEBUG',
                'console_enabled': True,
                'console_colors': True,
                'file_enabled': True,
                'performance_enabled': True,
                'security_enabled': False,
                'audit_enabled': False,
                'compression_enabled': False,
                'archive_enabled': False,
            },
            'testing': {
                'level': 'WARNING',
                'console_enabled': False,
                'file_enabled': True,
                'performance_enabled': False,
                'security_enabled': False,
                'audit_enabled': False,
                'compression_enabled': False,
                'archive_enabled': False,
                'buffer_size': 100,
            },
            'production': {
                'level': 'INFO',
                'console_enabled': False,
                'file_enabled': True,
                'performance_enabled': True,
                'security_enabled': True,
                'audit_enabled': True,
                'compression_enabled': True,
                'archive_enabled': True,
                'alerts_enabled': True,
                'silence_third_party': True,
            },
            'debug': {
                'level': 'TRACE',
                'console_enabled': True,
                'console_colors': True,
                'file_enabled': True,
                'performance_enabled': True,
                'security_enabled': True,
                'audit_enabled': True,
                'include_context': True,
                'silence_third_party': False,
            }
        }
        
        if profile not in profile_configs:
            raise ValueError(f"Unknown profile: {profile}")
        
        # Start with current config and apply profile overrides
        config_data = self._config.to_dict()
        config_data.update(profile_configs[profile])
        
        return LoggingConfig.from_dict(config_data)

# Global configuration manager
_config_manager = None

def get_logging_config(config_file: Optional[Path] = None) -> LoggingConfig:
    """Get the global logging configuration."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigurationManager(config_file)
    return _config_manager.config

def reload_logging_config():
    """Reload the global logging configuration."""
    global _config_manager
    if _config_manager:
        _config_manager.reload()

def set_logging_profile(profile: str):
    """Set logging configuration to a specific profile."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigurationManager()
    
    profile_config = _config_manager.get_profile_config(profile)
    _config_manager._config = profile_config

# Export main components
__all__ = [
    "LoggingConfig", "ConfigurationManager", "get_logging_config",
    "reload_logging_config", "set_logging_profile"
]
