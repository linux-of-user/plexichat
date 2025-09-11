from dataclasses import dataclass, field
import json
import logging
from pathlib import Path
from typing import Any

try:
    from plexichat.core.middleware.rate_limiting import (  # type: ignore
        RateLimitAlgorithm,
        RateLimitConfig,
    )
except ImportError:
    # Fallback implementations
    @dataclass
    class RateLimitConfig:  # type: ignore
        enabled: bool = True
        default_algorithm: str = "sliding_window"
        per_ip_requests_per_minute: int = 60
        per_ip_burst_limit: int = 10
        per_ip_block_duration: int = 300
        per_user_requests_per_minute: int = 120
        per_user_burst_limit: int = 20
        per_user_block_duration: int = 180
        per_route_requests_per_minute: int = 100
        per_route_burst_limit: int = 15
        get_requests_per_minute: int = 200
        post_requests_per_minute: int = 60
        put_requests_per_minute: int = 30
        delete_requests_per_minute: int = 20
        patch_requests_per_minute: int = 40
        global_requests_per_minute: int = 10000
        global_burst_limit: int = 500
        endpoint_overrides: dict[str, Any] = field(default_factory=dict)
        user_tier_multipliers: dict[str, float] = field(
            default_factory=lambda: {
                "guest": 0.5,
                "user": 1.0,
                "premium": 2.0,
                "moderator": 3.0,
                "admin": 10.0,
                "system": 100.0,
            }
        )

    class RateLimitAlgorithm:  # type: ignore
        TOKEN_BUCKET = "token_bucket"
        SLIDING_WINDOW = "sliding_window"
        FIXED_WINDOW = "fixed_window"


"""
Rate Limiting Configuration for PlexiChat

Provides comprehensive configuration for the unified rate limiting system.
Supports different user tiers, endpoint-specific overrides, and dynamic adjustments.
"""

logger = logging.getLogger(__name__)


@dataclass
class IPBlacklistConfig:
    """Configuration for IP blacklisting."""
    enabled: bool = True
    permanent_blacklist: list[str] = field(default_factory=list)
    temporary_blacklist: dict[str, int] = field(default_factory=dict)
    whitelist: list[str] = field(default_factory=list)
    geo_blocking_enabled: bool = False
    blocked_countries: list[str] = field(default_factory=list)
    auto_blacklist_enabled: bool = True
    auto_blacklist_threshold: int = 100
    auto_blacklist_duration: int = 3600

@dataclass
class EndpointRateLimit:
    """Rate limit configuration for a specific endpoint."""

    path: str
    user: str | None = None
    per_ip_requests_per_minute: int | None = None
    per_user_requests_per_minute: int | None = None
    per_route_requests_per_minute: int | None = None
    burst_limit: int | None = None
    algorithm: str | None = None
    enabled: bool = True


class RateLimitConfigManager:
    """Manages rate limiting configuration with persistence and dynamic updates."""

    def __init__(self, config_file: str = "config/rate_limit_config.json"):
        """Initialize rate limit config manager."""
        self.config_file = Path(config_file)
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self._config = self._load_default_config()
        self.load_config()

    def _load_default_config(self) -> RateLimitConfig:
        """Load default rate limiting configuration."""
        return RateLimitConfig(
            enabled=True,
            default_algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            # Per-IP limits (for unauthenticated users)
            per_ip_requests_per_minute=60,
            per_ip_burst_limit=10,
            per_ip_block_duration=300,  # 5 minutes
            # Per-user limits (for authenticated users)
            per_user_requests_per_minute=120,
            per_user_burst_limit=20,
            per_user_block_duration=180,  # 3 minutes
            # Per-route limits
            per_route_requests_per_minute=100,
            per_route_burst_limit=15,
            # Per-method limits
            get_requests_per_minute=200,
            post_requests_per_minute=60,
            put_requests_per_minute=30,
            delete_requests_per_minute=20,
            patch_requests_per_minute=40,
            # Global limits
            global_requests_per_minute=10000,
            global_burst_limit=500,
            # Endpoint-specific overrides
            endpoint_overrides={
                # Authentication endpoints (stricter limits)
                "/api/v1/auth/login": {
                    "per_ip": 5,  # 5 login attempts per minute per IP
                    "per_user": 10,
                    "burst_limit": 2,
                },
                "/api/v1/auth/register": {
                    "per_ip": 3,  # 3 registrations per minute per IP
                    "per_user": 5,
                    "burst_limit": 1,
                },
                "/api/v1/auth/reset-password": {
                    "per_ip": 2,  # 2 password resets per minute per IP
                    "per_user": 3,
                    "burst_limit": 1,
                },
                # Messaging endpoints
                "/api/v1/messages/send": {
                    "per_user": 30,  # 30 messages per minute per user
                    "burst_limit": 5,
                },
                "/api/v1/messages/upload": {
                    "per_user": 10,  # 10 file uploads per minute per user
                    "burst_limit": 2,
                },
                # Admin endpoints (more permissive for admins)
                "/api/v1/admin/*": {"per_user": 300, "burst_limit": 50},
                # Health check (very permissive)
                "/health": {
                    "per_ip": 600,  # 10 per second
                    "per_user": 600,
                    "burst_limit": 100,
                },
                "/api/health": {"per_ip": 600, "per_user": 600, "burst_limit": 100},
                # Documentation (permissive)
                "/docs": {"per_ip": 300, "per_user": 300, "burst_limit": 30},
                "/api/docs": {"per_ip": 300, "per_user": 300, "burst_limit": 30},
            },
            # User tier multipliers
            user_tier_multipliers={
                "guest": 0.5,  # Guests get 50% of base limits
                "user": 1.0,  # Regular users get 100% of base limits
                "premium": 2.0,  # Premium users get 200% of base limits
                "moderator": 3.0,  # Moderators get 300% of base limits
                "admin": 10.0,  # Admins get 1000% of base limits
                "system": 100.0,  # System accounts get 10000% of base limits
            },
        )

    def load_config(self) -> RateLimitConfig:
        """Load configuration from file."""
        try:
            if self.config_file.exists():
                with open(self.config_file) as f:
                    data = json.load(f)

                # Update config with loaded data
                for key, value in data.items():
                    if hasattr(self._config, key):
                        if key == "default_algorithm":
                            # Set string value directly
                            self._config.default_algorithm = value
                        else:
                            setattr(self._config, key, value)

                logger.info(f"Loaded rate limiting config from {self.config_file}")
            else:
                # Save default config
                self.save_config()
                logger.info("Created default rate limiting config")

        except Exception as e:
            logger.error(f"Failed to load rate limiting config: {e}")
            logger.info("Using default configuration")

        return self._config

    def save_config(self):
        """Save current configuration to file."""
        try:
            # Convert config to dict
            config_dict = self._config.__dict__.copy()

            # Convert enum to string
            config_dict["default_algorithm"] = str(self._config.default_algorithm)

            with open(self.config_file, "w") as f:
                json.dump(config_dict, f, indent=2)

            logger.info(f"Saved rate limiting config to {self.config_file}")

        except Exception as e:
            logger.error(f"Failed to save rate limiting config: {e}")

    def get_config(self) -> RateLimitConfig:
        """Get current configuration."""
        return self._config

    def update_config(self, **kwargs):
        """Update configuration parameters."""
        for key, value in kwargs.items():
            if hasattr(self._config, key):
                setattr(self._config, key, value)
                logger.info(f"Updated rate limit config: {key} = {value}")

        self.save_config()

    def add_endpoint_override(self, path: str, limits: dict):
        """Add or update endpoint-specific rate limits."""
        self._config.endpoint_overrides[path] = limits
        self.save_config()
        logger.info(f"Added endpoint override for {path}: {limits}")

    def remove_endpoint_override(self, path: str):
        """Remove endpoint-specific rate limits."""
        if path in self._config.endpoint_overrides:
            del self._config.endpoint_overrides[path]
            self.save_config()
            logger.info(f"Removed endpoint override for {path}")

    def update_user_tier_multiplier(self, tier: str, multiplier: float):
        """Update rate limit multiplier for a user tier."""
        self._config.user_tier_multipliers[tier] = multiplier
        self.save_config()
        logger.info(f"Updated user tier multiplier: {tier} = {multiplier}")

    def get_effective_limits_for_user(self, user_tier: str = "guest") -> dict[str, int]:
        """Get effective rate limits for a user tier."""
        multiplier = self._config.user_tier_multipliers.get(user_tier, 1.0)

        return {
            "per_ip_requests_per_minute": int(
                self._config.per_ip_requests_per_minute * multiplier
            ),
            "per_user_requests_per_minute": int(
                self._config.per_user_requests_per_minute * multiplier
            ),
            "per_route_requests_per_minute": int(
                self._config.per_route_requests_per_minute * multiplier
            ),
            "get_requests_per_minute": int(
                self._config.get_requests_per_minute * multiplier
            ),
            "post_requests_per_minute": int(
                self._config.post_requests_per_minute * multiplier
            ),
            "put_requests_per_minute": int(
                self._config.put_requests_per_minute * multiplier
            ),
            "delete_requests_per_minute": int(
                self._config.delete_requests_per_minute * multiplier
            ),
            "patch_requests_per_minute": int(
                self._config.patch_requests_per_minute * multiplier
            ),
        }


# Global configuration manager
_config_manager: RateLimitConfigManager | None = None


def get_rate_limit_config_manager() -> RateLimitConfigManager:
    """Get the global rate limit configuration manager."""
    global _config_manager
    if _config_manager is None:
        _config_manager = RateLimitConfigManager()
    return _config_manager


def get_rate_limit_config() -> RateLimitConfig:
    """Get the current rate limiting configuration."""
    return get_rate_limit_config_manager().get_config()

__all__ = [
    "EndpointRateLimit",
    "IPBlacklistConfig",
    "RateLimitConfig",
    "RateLimitConfigManager",
    "get_rate_limit_config",
    "get_rate_limit_config_manager",
]
