"""
PlexiChat Features

Enhanced features module with comprehensive functionality and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Performance logger placeholder (will be implemented when performance_logger.py is fixed)
performance_logger = None


class FeatureManager:
    """Enhanced feature manager using EXISTING systems."""

    def __init__(self):
        self.performance_logger = performance_logger
        self.enabled_features: dict[str, bool] = {}
        self.feature_configs: dict[str, dict[str, Any]] = {}

    def register_feature(self, name: str, enabled: bool = True, config: dict[str, Any] | None = None):
        """Register a feature."""
        try:
            self.enabled_features[name] = enabled
            self.feature_configs[name] = config or {}
            logger.info(f"Registered feature: {name} (enabled: {enabled})")
            if self.performance_logger:
                self.performance_logger.increment_counter("features_registered", 1)
        except Exception as e:
            logger.error(f"Error registering feature {name}: {e}")

    def is_enabled(self, name: str) -> bool:
        """Check if feature is enabled."""
        return self.enabled_features.get(name, False)

    def get_config(self, name: str) -> dict[str, Any]:
        """Get feature configuration."""
        return self.feature_configs.get(name, {})

    def enable_feature(self, name: str):
        """Enable a feature."""
        if name in self.enabled_features:
            self.enabled_features[name] = True
            logger.info(f"Enabled feature: {name}")

    def disable_feature(self, name: str):
        """Disable a feature."""
        if name in self.enabled_features:
            self.enabled_features[name] = False
            logger.info(f"Disabled feature: {name}")

    def get_enabled_features(self) -> list[str]:
        """Get list of enabled features."""
        return [name for name, enabled in self.enabled_features.items() if enabled]

# Global feature manager
feature_manager = FeatureManager()


# Register core features
def register_core_features():
    """Register core PlexiChat features."""
    try:
        # Backup features
        feature_manager.register_feature("backup", True, {
            "automatic_backup": True,
            "backup_interval": 86400,  # 24 hours
            "retention_days": 30
        })
        logger.info("Core features registered successfully")
    except Exception as e:
        logger.error(f"Error registering core features: {e}")


# Initialize core features
register_core_features()


# Feature availability checks
def backup_enabled() -> bool:
    """Check if backup features are enabled."""
    return feature_manager.is_enabled("backup")

# Feature imports (with error handling)
def import_feature_modules():
    """Import feature modules with error handling."""
    try:
        # Backup features
        if backup_enabled():
            try:
                from . import backup
                logger.info("Backup module imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import backup module: {e}")
    except Exception as e:
        logger.error(f"Error importing feature modules: {e}")


# Import feature modules
import_feature_modules()

# Export commonly used items
__all__ = [
    "backup_enabled",
    "feature_manager",
]

# Version info
from plexichat.core.config_manager import get_config

__version__ = get_config("system.version", "0.0.0")
