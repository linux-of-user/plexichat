"""
PlexiChat - Real-time Communication Platform
Copyright (C) 2025 PlexiChat Contributors

Authentication Configuration Management
"""

import json
import os
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from plexichat.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class AuthSettings:
    """Main authentication settings configuration."""

    # Session settings
    session_timeout_minutes: int = 60
    elevated_session_timeout_minutes: int = 15
    max_concurrent_sessions_per_user: int = 5

    # Token settings
    access_token_expiry_minutes: int = 15
    refresh_token_expiry_days: int = 7
    token_issuer: str = "plexichat"
    token_audience: str = "plexichat-users"

    # Security settings
    enable_brute_force_protection: bool = True
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 30
    enable_rate_limiting: bool = True
    rate_limit_requests_per_minute: int = 60

    # MFA settings
    enable_mfa: bool = True
    mfa_challenge_timeout_minutes: int = 5
    max_mfa_attempts: int = 3
    require_mfa_for_admins: bool = True

    # Device tracking
    enable_device_tracking: bool = True
    trust_device_max_age_days: int = 30
    max_devices_per_user: int = 10

    # Password settings
    enable_password_history: bool = True
    password_history_count: int = 5
    password_min_age_hours: int = 24

    # OAuth2 settings
    enable_oauth2: bool = True
    oauth2_state_timeout_minutes: int = 10

    # Audit settings
    enable_audit_logging: bool = True
    audit_log_retention_days: int = 90

    # Cache settings
    enable_caching: bool = True
    cache_ttl_seconds: int = 300
    cache_max_size_mb: int = 100

    # Performance settings
    enable_performance_monitoring: bool = True
    performance_log_sample_rate: float = 0.1

    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate_configuration()

    def _validate_configuration(self):
        """Validate configuration values."""
        if self.session_timeout_minutes <= 0:
            raise ValueError("Session timeout must be positive")
        if self.access_token_expiry_minutes <= 0:
            raise ValueError("Access token expiry must be positive")
        if self.max_failed_attempts < 1:
            raise ValueError("Max failed attempts must be at least 1")
        if not 0 <= self.performance_log_sample_rate <= 1:
            raise ValueError("Performance log sample rate must be between 0 and 1")


class AuthConfig:
    """
    Centralized authentication configuration manager.
    Handles loading from environment variables, config files, and validation.
    """

    def __init__(self, config_file: Optional[str] = None):
        self.settings = AuthSettings()
        self._config_file = config_file or self._get_default_config_file()
        self._load_configuration()

    def _get_default_config_file(self) -> str:
        """Get default configuration file path."""
        return os.getenv("PLEXICHAT_AUTH_CONFIG", "config/auth.json")

    def _load_configuration(self):
        """Load configuration from multiple sources."""
        # Load from environment variables first
        self._load_from_environment()

        # Load from config file (overrides environment)
        self._load_from_file()

        # Validate final configuration
        self.settings._validate_configuration()

        logger.info("Authentication configuration loaded successfully")

    def _load_from_environment(self):
        """Load configuration from environment variables."""
        env_mappings = {
            "PLEXICHAT_SESSION_TIMEOUT_MINUTES": "session_timeout_minutes",
            "PLEXICHAT_ACCESS_TOKEN_EXPIRY_MINUTES": "access_token_expiry_minutes",
            "PLEXICHAT_REFRESH_TOKEN_EXPIRY_DAYS": "refresh_token_expiry_days",
            "PLEXICHAT_MAX_FAILED_ATTEMPTS": "max_failed_attempts",
            "PLEXICHAT_LOCKOUT_DURATION_MINUTES": "lockout_duration_minutes",
            "PLEXICHAT_RATE_LIMIT_REQUESTS_PER_MINUTE": "rate_limit_requests_per_minute",
            "PLEXICHAT_MAX_CONCURRENT_SESSIONS": "max_concurrent_sessions_per_user",
            "PLEXICHAT_MAX_DEVICES_PER_USER": "max_devices_per_user",
            "PLEXICHAT_PASSWORD_HISTORY_COUNT": "password_history_count",
            "PLEXICHAT_CACHE_TTL_SECONDS": "cache_ttl_seconds",
            "PLEXICHAT_CACHE_MAX_SIZE_MB": "cache_max_size_mb",
        }

        for env_var, setting_name in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                try:
                    # Convert string values to appropriate types
                    if setting_name in [
                        "session_timeout_minutes",
                        "access_token_expiry_minutes",
                        "refresh_token_expiry_days",
                        "max_failed_attempts",
                        "lockout_duration_minutes",
                        "rate_limit_requests_per_minute",
                        "max_concurrent_sessions_per_user",
                        "max_devices_per_user",
                        "password_history_count",
                        "cache_ttl_seconds",
                        "cache_max_size_mb",
                    ]:
                        value = int(value)
                    elif setting_name in ["performance_log_sample_rate"]:
                        value = float(value)
                    elif setting_name in [
                        "enable_brute_force_protection",
                        "enable_rate_limiting",
                        "enable_mfa",
                        "require_mfa_for_admins",
                        "enable_device_tracking",
                        "enable_password_history",
                        "enable_oauth2",
                        "enable_audit_logging",
                        "enable_caching",
                        "enable_performance_monitoring",
                    ]:
                        value = value.lower() in ("true", "1", "yes", "on")

                    setattr(self.settings, setting_name, value)
                    logger.debug(f"Loaded {setting_name} from environment: {value}")

                except (ValueError, TypeError) as e:
                    logger.warning(f"Invalid value for {env_var}: {value} ({e})")

    def _load_from_file(self):
        """Load configuration from JSON file."""
        if not os.path.exists(self._config_file):
            logger.debug(f"Configuration file not found: {self._config_file}")
            return

        try:
            with open(self._config_file, "r") as f:
                config_data = json.load(f)

            # Load auth settings
            if "auth" in config_data:
                auth_config = config_data["auth"]
                for key, value in auth_config.items():
                    if hasattr(self.settings, key):
                        setattr(self.settings, key, value)
                        logger.debug(f"Loaded {key} from config file: {value}")

        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading configuration file {self._config_file}: {e}")

    def save_configuration(self, file_path: Optional[str] = None):
        """Save current configuration to file."""
        save_path = file_path or self._config_file

        # Ensure directory exists
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)

        config_data = {
            "auth": {
                key: getattr(self.settings, key)
                for key in dir(self.settings)
                if not key.startswith("_") and not callable(getattr(self.settings, key))
            }
        }

        try:
            with open(save_path, "w") as f:
                json.dump(config_data, f, indent=2)
            logger.info(f"Configuration saved to {save_path}")
        except IOError as e:
            logger.error(f"Error saving configuration to {save_path}: {e}")
            raise

    def get_session_timeout(self) -> timedelta:
        """Get session timeout as timedelta."""
        return timedelta(minutes=self.settings.session_timeout_minutes)

    def get_elevated_session_timeout(self) -> timedelta:
        """Get elevated session timeout as timedelta."""
        return timedelta(minutes=self.settings.elevated_session_timeout_minutes)

    def get_access_token_expiry(self) -> timedelta:
        """Get access token expiry as timedelta."""
        return timedelta(minutes=self.settings.access_token_expiry_minutes)

    def get_refresh_token_expiry(self) -> timedelta:
        """Get refresh token expiry as timedelta."""
        return timedelta(days=self.settings.refresh_token_expiry_days)

    def get_lockout_duration(self) -> timedelta:
        """Get lockout duration as timedelta."""
        return timedelta(minutes=self.settings.lockout_duration_minutes)

    def is_feature_enabled(self, feature: str) -> bool:
        """Check if a feature is enabled."""
        feature_attr = f"enable_{feature.replace('-', '_')}"
        return getattr(self.settings, feature_attr, False)

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a configuration setting."""
        return getattr(self.settings, key, default)

    def set_setting(self, key: str, value: Any):
        """Set a configuration setting."""
        if hasattr(self.settings, key):
            setattr(self.settings, key, value)
            logger.debug(f"Setting updated: {key} = {value}")
        else:
            raise ValueError(f"Unknown configuration setting: {key}")

    def get_all_settings(self) -> Dict[str, Any]:
        """Get all configuration settings as dictionary."""
        return {
            key: getattr(self.settings, key)
            for key in dir(self.settings)
            if not key.startswith("_") and not callable(getattr(self.settings, key))
        }

    def validate_configuration(self) -> List[str]:
        """Validate current configuration and return list of issues."""
        issues = []

        try:
            self.settings._validate_configuration()
        except ValueError as e:
            issues.append(str(e))

        # Additional validation rules
        if self.settings.session_timeout_minutes > 1440:  # 24 hours
            issues.append("Session timeout should not exceed 24 hours")

        if self.settings.access_token_expiry_minutes > 60:  # 1 hour
            issues.append("Access token expiry should not exceed 1 hour for security")

        if self.settings.max_failed_attempts > 10:
            issues.append("Max failed attempts should not exceed 10")

        return issues


# Global configuration instance
_config_instance: Optional[AuthConfig] = None


def get_auth_config() -> AuthConfig:
    """Get the global authentication configuration instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = AuthConfig()
    return _config_instance


def reload_auth_config() -> AuthConfig:
    """Reload the authentication configuration."""
    global _config_instance
    _config_instance = AuthConfig()
    return _config_instance


__all__ = ["AuthSettings", "AuthConfig", "get_auth_config", "reload_auth_config"]
