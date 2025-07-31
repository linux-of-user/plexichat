# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Features

Enhanced features module with comprehensive functionality and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import logging
from typing import Any, Dict, List, Optional
from plexichat.infrastructure.modules.interfaces import ModulePriority

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

class FeatureManager:
    """Enhanced feature manager using EXISTING systems."""
    def __init__(self):
        self.performance_logger = performance_logger
        self.enabled_features: Dict[str, bool] = {}
        self.feature_configs: Dict[str, Dict[str, Any]] = {}
    def register_feature(self, name: str, enabled: bool = True, config: Optional[Dict[str, Any]] = None):
        """Register a feature."""
        try:
            self.enabled_features[name] = enabled
            self.feature_configs[name] = config or {}
            logger.info(f"Registered feature: {name} (enabled: {enabled})")
            if self.performance_logger:
                self.performance_logger.record_metric("features_registered", 1, "count")
        except Exception as e:
            logger.error(f"Error registering feature {name}: {e}")
    def is_enabled(self, name: str) -> bool:
        """Check if feature is enabled."""
        return self.enabled_features.get(name, False)
    def get_config(self, name: str) -> Dict[str, Any]:
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
    def get_enabled_features(self) -> List[str]:
        """Get list of enabled features."""
        return [name for name, enabled in self.enabled_features.items() if enabled]

# Global feature manager
feature_manager = FeatureManager()

# Register core features
def register_core_features():
    """Register core PlexiChat features."""
    try:
        # User management features
        feature_manager.register_feature("users", True, {
            "max_users": 10000,
            "registration_enabled": True,
            "email_verification": True
        })
        # Messaging features
        feature_manager.register_feature("messaging", True, {
            "max_message_length": 2000,
            "file_attachments": True,
            "message_editing": True,
            "message_threading": True
        })
        # File management features
        feature_manager.register_feature("files", True, {
            "max_file_size": 100 * 1024 * 1024,  # 100MB
            "allowed_types": [".jpg", ".png", ".pdf", ".txt"],
            "virus_scanning": False
        })
        # Security features
        feature_manager.register_feature("security", True, {
            "rate_limiting": True,
            "ddos_protection": True,
            "input_validation": True,
            "audit_logging": True
        })
        # AI features
        feature_manager.register_feature("ai", False, {
            "chatbot": False,
            "content_moderation": False,
            "sentiment_analysis": False
        })
        # Backup features
        feature_manager.register_feature("backup", True, {
            "automatic_backup": True,
            "backup_interval": 86400,  # 24 hours
            "retention_days": 30
        })
        # Clustering features
        feature_manager.register_feature("clustering", False, {
            "auto_scaling": False,
            "load_balancing": False,
            "failover": False
        })
        # Monitoring features
        feature_manager.register_feature("monitoring", True, {
            "performance_tracking": True,
            "error_tracking": True,
            "health_checks": True
        })
        logger.info("Core features registered successfully")
    except Exception as e:
        logger.error(f"Error registering core features: {e}")

# Initialize core features
register_core_features()

# Feature availability checks
def users_enabled() -> bool:
    """Check if user features are enabled."""
    return feature_manager.is_enabled("users")
def messaging_enabled() -> bool:
    """Check if messaging features are enabled."""
    return feature_manager.is_enabled("messaging")
def files_enabled() -> bool:
    """Check if file features are enabled."""
    return feature_manager.is_enabled("files")
def security_enabled() -> bool:
    """Check if security features are enabled."""
    return feature_manager.is_enabled("security")
def ai_enabled() -> bool:
    """Check if AI features are enabled."""
    return feature_manager.is_enabled("ai")
def backup_enabled() -> bool:
    """Check if backup features are enabled."""
    return feature_manager.is_enabled("backup")
def clustering_enabled() -> bool:
    """Check if clustering features are enabled."""
    return feature_manager.is_enabled("clustering")
def monitoring_enabled() -> bool:
    """Check if monitoring features are enabled."""
    return feature_manager.is_enabled("monitoring")

# Feature imports (with error handling)
def import_feature_modules():
    """Import feature modules with error handling."""
    try:
        # User features
        if users_enabled():
            try:
                from . import users
                logger.info("Users module imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import users module: {e}")
        # Messaging features
        if messaging_enabled():
            try:
                from . import messaging
                logger.info("Messaging module imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import messaging module: {e}")
        # Security features
        if security_enabled():
            try:
                import platform
                if platform.system() != "Windows":
                    from . import security
                    logger.info("Security module imported successfully")
                else:
                    logger.warning("Security module not loaded on Windows due to syslog dependency.")
            except ImportError as e:
                logger.warning(f"Could not import security module: {e}")
        # AI features
        if ai_enabled():
            try:
                from . import ai
                logger.info("AI module imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import AI module: {e}")
        # Backup features
        if backup_enabled():
            try:
                from . import backup
                logger.info("Backup module imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import backup module: {e}")
        # Clustering features
        if clustering_enabled():
            try:
                from . import clustering
                logger.info("Clustering module imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import clustering module: {e}")
        # Monitoring features
        if monitoring_enabled():
            try:
                from . import monitoring
                logger.info("Monitoring module imported successfully")
            except ImportError as e:
                logger.warning(f"Could not import monitoring module: {e}")
    except Exception as e:
        logger.error(f"Error importing feature modules: {e}")

# Import feature modules
import_feature_modules()

# Export commonly used items
__all__ = [
    "feature_manager",
    "users_enabled",
    "messaging_enabled",
    "files_enabled",
    "security_enabled",
    "ai_enabled",
    "backup_enabled",
    "clustering_enabled",
    "monitoring_enabled",
]

# Version info
__version__ = "1.0.0" 