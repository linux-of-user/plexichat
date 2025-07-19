# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Core Configuration

Enhanced configuration management with comprehensive settings and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import os
import logging
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

# Pydantic imports for settings validation
try:
    from pydantic import BaseSettings, Field, validator
except ImportError:
    class BaseSettings:
        def __init__(self):
            pass
        def dict(self):
            return {}
    def Field(default=None, **kwargs):
        return default
    validator = lambda *args, **kwargs: lambda f: f

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
except ImportError:
    PerformanceOptimizationEngine = None

try:
    from plexichat.infrastructure.utils.performance import async_track_performance
except ImportError:
    async_track_performance = None

try:
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    def get_performance_logger():
        return logging.getLogger(__name__)

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

class Settings(BaseSettings):
    """Application settings with comprehensive configuration."""

    # Application settings
    APP_NAME: str = Field(default="PlexiChat", description="Application name")
    APP_VERSION: str = Field(default="1.0.0", description="Application version")
    DEBUG: bool = Field(default=False, description="Debug mode")
    TESTING: bool = Field(default=False, description="Testing mode")

    # Server settings
    HOST: str = Field(default="0.0.0.0", description="Server host")
    PORT: int = Field(default=8000, description="Server port")
    WORKERS: int = Field(default=1, description="Number of worker processes")

    # Database settings
    DATABASE_URL: str = Field(default="sqlite:///plexichat.db", description="Database URL")
    DATABASE_ECHO: bool = Field(default=False, description="Database query logging")
    DATABASE_POOL_SIZE: int = Field(default=10, description="Database connection pool size")
    DATABASE_MAX_OVERFLOW: int = Field(default=20, description="Database max overflow connections")

    # Security settings
    JWT_SECRET: str = Field(default="your-secret-key-change-this", description="JWT secret key")
    JWT_ALGORITHM: str = Field(default="HS256", description="JWT algorithm")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, description="Access token expiration")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, description="Refresh token expiration")

    # Rate limiting settings
    RATE_LIMIT_REQUESTS: int = Field(default=100, description="Rate limit requests per window")
    RATE_LIMIT_WINDOW: int = Field(default=60, description="Rate limit window in seconds")
    RATE_LIMIT_BURST: int = Field(default=20, description="Rate limit burst allowance")

    # File upload settings
    MAX_FILE_SIZE: int = Field(default=100 * 1024 * 1024, description="Max file size in bytes")
    UPLOAD_DIR: str = Field(default="uploads", description="Upload directory")
    ALLOWED_FILE_TYPES: List[str] = Field(default=[".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt", ".doc", ".docx"], description="Allowed file extensions")

    # Logging settings
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    LOG_FILE: Optional[str] = Field(default=None, description="Log file path")
    LOG_MAX_SIZE: int = Field(default=10 * 1024 * 1024, description="Max log file size")
    LOG_BACKUP_COUNT: int = Field(default=5, description="Number of log backup files")
    LOG_DIRECTORY: str = Field(default="logs", description="Log directory")
    LOG_MAX_AGE_DAYS: int = Field(default=30, description="Maximum age of log files in days")
    LOG_MAX_TOTAL_SIZE_MB: int = Field(default=1000, description="Maximum total size of all logs in MB")
    LOG_COMPRESSION_ENABLED: bool = Field(default=True, description="Enable log file compression")
    LOG_CONSOLE_ENABLED: bool = Field(default=True, description="Enable console logging")
    LOG_FILE_ENABLED: bool = Field(default=True, description="Enable file logging")
    LOG_STRUCTURED_ENABLED: bool = Field(default=True, description="Enable structured JSON logging")

    # Performance settings
    ENABLE_PERFORMANCE_MONITORING: bool = Field(default=True, description="Enable performance monitoring")
    PERFORMANCE_LOG_INTERVAL: int = Field(default=60, description="Performance log interval in seconds")
    CACHE_TTL: int = Field(default=300, description="Cache TTL in seconds")

    # Security settings
    SECURITY_LEVEL: str = Field(default="STANDARD", description="Security level")
    ENABLE_AUDIT_LOGGING: bool = Field(default=True, description="Enable audit logging")
    SESSION_TIMEOUT: int = Field(default=3600, description="Session timeout in seconds")

    # Email settings (optional)
    SMTP_HOST: Optional[str] = Field(default=None, description="SMTP host")
    SMTP_PORT: int = Field(default=587, description="SMTP port")
    SMTP_USERNAME: Optional[str] = Field(default=None, description="SMTP username")
    SMTP_PASSWORD: Optional[str] = Field(default=None, description="SMTP password")
    SMTP_USE_TLS: bool = Field(default=True, description="SMTP use TLS")

    # External API settings
    EXTERNAL_API_TIMEOUT: int = Field(default=30, description="External API timeout in seconds")
    EXTERNAL_API_RETRIES: int = Field(default=3, description="External API retry attempts")

    # Clustering settings
    CLUSTER_ENABLED: bool = Field(default=False, description="Enable clustering")
    CLUSTER_NODE_ID: Optional[str] = Field(default=None, description="Cluster node ID")
    CLUSTER_DISCOVERY_URL: Optional[str] = Field(default=None, description="Cluster discovery URL")

    # Backup settings
    BACKUP_ENABLED: bool = Field(default=True, description="Enable automatic backups")
    BACKUP_INTERVAL: int = Field(default=86400, description="Backup interval in seconds")
    BACKUP_RETENTION_DAYS: int = Field(default=30, description="Backup retention in days")
    BACKUP_DIR: str = Field(default="backups", description="Backup directory")

    @validator('JWT_SECRET')
    def validate_jwt_secret(cls, v):
        if v == "your-secret-key-change-this":
            logger.warning("Using default JWT secret key - change this in production!")
        if len(v) < 32:
            raise ValueError("JWT secret key must be at least 32 characters long")
        return v

    @validator('LOG_LEVEL')
    def validate_log_level(cls, v):
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {valid_levels}")
        return v.upper()

    @validator('SECURITY_LEVEL')
    def validate_security_level(cls, v):
        valid_levels = ["BASIC", "STANDARD", "HIGH", "GOVERNMENT"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Security level must be one of: {valid_levels}")
        return v.upper()

    @validator('DATABASE_URL')
    def validate_database_url(cls, v):
        if not v:
            raise ValueError("Database URL cannot be empty")
        return v

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True

class ConfigurationManager:
    """Enhanced configuration manager with performance optimization."""

    def __init__(self):
        self.settings = Settings()
        self.performance_logger = performance_logger
        self._config_cache: Dict[str, Any] = {}
        self._cache_timestamp = 0
        self.cache_ttl = 300  # 5 minutes

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with caching."""
        try:
            # Check cache first
            import time
            current_time = time.time()
            if (current_time - self._cache_timestamp < self.cache_ttl and )
                key in self._config_cache):
                return self._config_cache[key]

            # Get from settings
            value = getattr(self.settings, key, default)

            # Update cache
            self._config_cache[key] = value
            self._cache_timestamp = current_time

            return value

        except Exception as e:
            logger.error(f"Error getting configuration value for {key}: {e}")
            return default

    def get_all(self) -> Dict[str, Any]:
        """Get all configuration values."""
        try:
            return self.settings.dict()
        except Exception as e:
            logger.error(f"Error getting all configuration values: {e}")
            return {}

    def validate_configuration(self) -> List[str]:
        """Validate configuration and return any errors."""
        errors = []

        try:
            # Validate required directories exist
            upload_dir = Path(self.settings.UPLOAD_DIR)
            if not upload_dir.exists():
                try:
                    upload_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    errors.append(f"Cannot create upload directory: {e}")

            backup_dir = Path(self.settings.BACKUP_DIR)
            if not backup_dir.exists():
                try:
                    backup_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    errors.append(f"Cannot create backup directory: {e}")

            # Validate database URL format
            if not self.settings.DATABASE_URL.startswith(('sqlite:', 'postgresql:', 'mysql:')):
                errors.append("Database URL must start with sqlite:, postgresql:, or mysql:")

            # Validate JWT secret in production
            if not self.settings.DEBUG and self.settings.JWT_SECRET == "your-secret-key-change-this":
                errors.append("JWT secret key must be changed in production")

            # Validate file size limits
            if self.settings.MAX_FILE_SIZE > 1024 * 1024 * 1024:  # 1GB
                errors.append("Max file size should not exceed 1GB")

            # Validate port range
            if not (1 <= self.settings.PORT <= 65535):
                errors.append("Port must be between 1 and 65535")

            # Validate worker count
            if self.settings.WORKERS < 1:
                errors.append("Worker count must be at least 1")

        except Exception as e:
            errors.append(f"Configuration validation error: {e}")

        return errors

    def get_database_config(self) -> Dict[str, Any]:
        """Get database configuration."""
        return {
            "url": self.settings.DATABASE_URL,
            "echo": self.settings.DATABASE_ECHO,
            "pool_size": self.settings.DATABASE_POOL_SIZE,
            "max_overflow": self.settings.DATABASE_MAX_OVERFLOW
        }

    def get_security_config(self) -> Dict[str, Any]:
        """Get security configuration."""
        return {
            "jwt_secret": self.settings.JWT_SECRET,
            "jwt_algorithm": self.settings.JWT_ALGORITHM,
            "access_token_expire": self.settings.ACCESS_TOKEN_EXPIRE_MINUTES,
            "refresh_token_expire": self.settings.REFRESH_TOKEN_EXPIRE_DAYS,
            "security_level": self.settings.SECURITY_LEVEL,
            "session_timeout": self.settings.SESSION_TIMEOUT
        }

    def get_performance_config(self) -> Dict[str, Any]:
        """Get performance configuration."""
        return {
            "enable_monitoring": self.settings.ENABLE_PERFORMANCE_MONITORING,
            "log_interval": self.settings.PERFORMANCE_LOG_INTERVAL,
            "cache_ttl": self.settings.CACHE_TTL,
            "rate_limit_requests": self.settings.RATE_LIMIT_REQUESTS,
            "rate_limit_window": self.settings.RATE_LIMIT_WINDOW
        }

    def reload_configuration(self):
        """Reload configuration from environment."""
        try:
            self.settings = Settings()
            self._config_cache.clear()
            self._cache_timestamp = 0
            logger.info("Configuration reloaded successfully")
        except Exception as e:
            logger.error(f"Error reloading configuration: {e}")

# Global configuration instances
settings = Settings()
config_manager = ConfigurationManager()

__all__ = [
    'Settings',
    'ConfigurationManager',
    'config_manager',
    'get_config',
    'set_config',
]
