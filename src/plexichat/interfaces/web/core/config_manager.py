# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from cryptography.fernet import Fernet

"""
import secrets
import time
PlexiChat WebUI Configuration Manager

Enhanced configuration system for WebUI with configurable ports,
distributed authentication storage, and advanced security features.
"""

logger = logging.getLogger(__name__)

@dataclass
class WebUIPortConfig:
    """WebUI port configuration."""
    primary_port: int = 8000
    admin_port: Optional[int] = None  # If None, uses primary_port
    api_port: Optional[int] = None    # If None, uses primary_port
    docs_port: Optional[int] = None   # If None, uses primary_port
    websocket_port: Optional[int] = None  # If None, uses primary_port
    ssl_enabled: bool = False
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    auto_redirect_http: bool = True

@dataclass
class MFAConfig:
    """Multi-Factor Authentication configuration."""
    enabled: bool = True
    methods: Optional[List[str]] = None  # ['totp', 'sms', 'email', 'backup_codes']
    totp_issuer: str = "PlexiChat"
    backup_codes_count: int = 10
    recovery_email_required: bool = True
    session_timeout_with_mfa: int = 3600  # 1 hour
    session_timeout_without_mfa: int = 900  # 15 minutes
    require_mfa_for_admin: bool = True
    require_mfa_for_api: bool = False

    def __post_init__(self):
        if self.methods is None:
            self.methods = ['totp', 'backup_codes']

@dataclass
class AuthStorageConfig:
    """Distributed authentication storage configuration."""
    storage_type: str = "distributed"  # 'single', 'distributed', 'external'
    primary_storage: str = "database"  # 'database', 'file', 'redis', 'external'
    backup_storages: Optional[List[str]] = None  # ['file', 'redis']
    sync_interval: int = 300  # 5 minutes
    encryption_enabled: bool = True
    encryption_key_rotation: int = 86400  # 24 hours
    session_replication: bool = True
    failover_enabled: bool = True

    def __post_init__(self):
        if self.backup_storages is None:
            self.backup_storages = ['file']

@dataclass
class SelfTestConfig:
    """Self-test configuration for WebUI."""
    enabled: bool = True
    auto_run_on_startup: bool = False
    scheduled_runs: Optional[List[str]] = None  # Cron-like schedule
    test_categories: Optional[List[str]] = None
    notification_on_failure: bool = True
    detailed_reporting: bool = True
    export_results: bool = True

    def __post_init__(self):
        if self.scheduled_runs is None:
            self.scheduled_runs = ['0 2 * * *']  # Daily at 2 AM
        if self.test_categories is None:
            self.test_categories = [
                'security', 'performance', 'connectivity', 'database', 'api',
                'ai', 'monitoring', 'backup', 'plugins'
            ]

@dataclass
class FeatureToggleConfig:
    """Feature toggle configuration."""
    enabled_features: Optional[List[str]] = None
    disabled_features: Optional[List[str]] = None
    beta_features: Optional[List[str]] = None
    admin_only_features: Optional[List[str]] = None
    feature_permissions: Dict[str, List[str]] = None

    def __post_init__(self):
        if self.enabled_features is None:
            self.enabled_features = ['dashboard', 'user_management', 'system_monitoring', 'api_access']
        if self.disabled_features is None:
            self.disabled_features = []
        if self.beta_features is None:
            self.beta_features = ['ai_features', 'advanced_collaboration']
        if self.admin_only_features is None:
            self.admin_only_features = ['system_configuration', 'user_permissions', 'security_settings']
        if self.feature_permissions is None:
            self.feature_permissions = {}

class WebUIConfigManager:
    """Enhanced WebUI configuration manager."""

    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)

        self.config_file = self.config_dir / "webui_config.yaml"
        self.auth_config_file = self.config_dir / "webui_auth.yaml"
        self.secrets_file = self.config_dir / "webui_secrets.json"

        # Encryption for sensitive data
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher = Fernet(self.encryption_key)

        # Configuration objects
        self.port_config = WebUIPortConfig()
        self.mfa_config = MFAConfig()
        self.auth_storage_config = AuthStorageConfig()
        self.self_test_config = SelfTestConfig()
        self.feature_toggle_config = FeatureToggleConfig()

        # Load existing configuration
        self.load_configuration()

        logger.info("WebUI Configuration Manager initialized")

    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for sensitive data."""
        key_file = self.config_dir / ".webui_key"

        if key_file.exists():
            try:
                with open(key_file, 'rb') as f:
                    return f.read()
            except Exception as e:
                logger.warning(f"Failed to read encryption key: {e}")

        # Generate new key
        key = Fernet.generate_key()
        try:
            with open(key_file, 'wb') as f:
                f.write(key)
            # Set restrictive permissions
            os.chmod(key_file, 0o600)
        except Exception as e:
            logger.error(f"Failed to save encryption key: {e}")

        return key

    def load_configuration(self):
        """Load configuration from files."""
        try:
            # Load main configuration
            if self.config_file and self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config_data = yaml.safe_load(f)

                if config_data:
                    self._update_config_objects(config_data)

            # Load authentication configuration
            if self.auth_config_file and self.auth_config_file.exists():
                with open(self.auth_config_file, 'r') as f:
                    auth_data = yaml.safe_load(f)

                if auth_data:
                    self._update_auth_config(auth_data)

            logger.info("WebUI configuration loaded successfully")

        except Exception as e:
            logger.error(f"Failed to load WebUI configuration: {e}")
            self._create_default_configuration()

    def _update_config_objects(self, config_data: Dict[str, Any]):
        """Update configuration objects from loaded data."""
        if 'ports' in config_data:
            self.port_config = WebUIPortConfig(**config_data['ports'])

        if 'mfa' in config_data:
            self.mfa_config = MFAConfig(**config_data['mfa'])

        if 'auth_storage' in config_data:
            self.auth_storage_config = AuthStorageConfig(**config_data['auth_storage'])

        if 'self_tests' in config_data:
            self.self_test_config = SelfTestConfig(**config_data['self_tests'])

        if 'feature_toggles' in config_data:
            self.feature_toggle_config = FeatureToggleConfig(**config_data['feature_toggles'])

    def _update_auth_config(self, auth_data: Dict[str, Any]):
        """Update authentication configuration from loaded data."""
        # Handle encrypted authentication data
        if 'encrypted_data' in auth_data:
            try:
                decrypted_data = self.cipher.decrypt(auth_data['encrypted_data'].encode())
                json.loads(decrypted_data.decode())
                # Process decrypted authentication configuration
                logger.info("Encrypted authentication configuration loaded")
            except Exception as e:
                logger.error(f"Failed to decrypt authentication configuration: {e}")

    def save_configuration(self):
        """Save configuration to files."""
        try:
            # Prepare main configuration data
            config_data = {
                'version': '1.0.0',
                'last_updated': datetime.now(datetime.timezone.utc).isoformat(),
                'ports': asdict(self.port_config),
                'mfa': asdict(self.mfa_config),
                'auth_storage': asdict(self.auth_storage_config),
                'self_tests': asdict(self.self_test_config),
                'feature_toggles': asdict(self.feature_toggle_config)
            }

            # Save main configuration
            with open(self.config_file, 'w') as f:
                yaml.dump(config_data, f, default_flow_style=False, indent=2)

            # Save authentication configuration (encrypted)
            auth_data = {
                'version': '1.0.0',
                'last_updated': datetime.now(datetime.timezone.utc).isoformat(),
                'storage_config': asdict(self.auth_storage_config)
            }

            # Encrypt sensitive authentication data
            encrypted_data = self.cipher.encrypt(json.dumps(auth_data).encode())

            with open(self.auth_config_file, 'w') as f:
                yaml.dump({)
                    'encrypted_data': encrypted_data.decode(),
                    'encryption_version': '1.0.0'
                }, f)

            logger.info("WebUI configuration saved successfully")

        except Exception as e:
            logger.error(f"Failed to save WebUI configuration: {e}")

    def _create_default_configuration(self):
        """Create default configuration."""
        logger.info("Creating default WebUI configuration")

        # Set default values (already set in dataclass defaults)
        self.save_configuration()

    def get_port_for_service(self, service: str) -> int:
        """Get port for a specific service."""
        service_port_map = {
            'admin': self.port_config.admin_port,
            'api': self.port_config.api_port,
            'docs': self.port_config.docs_port,
            'websocket': self.port_config.websocket_port
        }

        return service_port_map.get(service) or self.port_config.primary_port

    def is_feature_enabled(self, feature: str, user_role: str = "user") -> bool:
        """Check if a feature is enabled for a user role."""
        # Check if feature is explicitly disabled
        if self.feature_toggle_config.disabled_features and feature in self.feature_toggle_config.disabled_features:
            return False

        # Check if feature requires admin role
        if self.feature_toggle_config.admin_only_features and feature in self.feature_toggle_config.admin_only_features and user_role != "admin":
            return False

        # Check if feature is enabled
        if self.feature_toggle_config.enabled_features and feature in self.feature_toggle_config.enabled_features:
            return True

        # Check beta features
        if self.feature_toggle_config.beta_features and feature in self.feature_toggle_config.beta_features:
            return user_role in ["admin", "beta_tester"]

        # Check feature permissions
        if self.feature_toggle_config.feature_permissions and feature in self.feature_toggle_config.feature_permissions:
            return user_role in self.feature_toggle_config.feature_permissions[feature]

        return False

    def get_mfa_methods_for_user(self, user_role: str = "user") -> List[str]:
        """Get available MFA methods for a user."""
        if not self.mfa_config:
            return []

        methods = self.mfa_config.methods.copy() if self.mfa_config.methods else []

        # Admin users might have additional methods
        if user_role == "admin" and self.mfa_config.require_mfa_for_admin:
            if 'totp' not in methods:
                methods.append('totp')

        return methods

    def get_session_timeout(self, has_mfa: bool = False) -> int:
        """Get session timeout based on MFA status."""
        if has_mfa:
            return self.mfa_config.session_timeout_with_mfa
        else:
            return self.mfa_config.session_timeout_without_mfa

    def update_port_config(self, **kwargs):
        """Update port configuration."""
        for key, value in kwargs.items():
            if hasattr(self.port_config, key):
                setattr(self.port_config, key, value)
        self.save_configuration()

    def update_mfa_config(self, **kwargs):
        """Update MFA configuration."""
        for key, value in kwargs.items():
            if hasattr(self.mfa_config, key):
                setattr(self.mfa_config, key, value)
        self.save_configuration()

    def toggle_feature(self, feature: str, enabled: bool):
        """Toggle a feature on or off."""
        if enabled:
            if self.feature_toggle_config.disabled_features is not None and feature not in self.feature_toggle_config.disabled_features:
                self.feature_toggle_config.disabled_features.remove(feature)
            if self.feature_toggle_config.enabled_features is not None and feature not in self.feature_toggle_config.enabled_features:
                self.feature_toggle_config.enabled_features.append(feature)
        else:
            if self.feature_toggle_config.enabled_features is not None and feature in self.feature_toggle_config.enabled_features:
                self.feature_toggle_config.enabled_features.remove(feature)
            if self.feature_toggle_config.disabled_features is not None and feature not in self.feature_toggle_config.disabled_features:
                self.feature_toggle_config.disabled_features.append(feature)

        self.save_configuration()

    def get_self_test_schedule(self) -> List[str]:
        """Get self-test schedule."""
        return self.self_test_config.scheduled_runs

    def is_self_test_enabled(self) -> bool:
        """Check if self-tests are enabled."""
        return self.self_test_config.enabled

    def get_auth_storage_config(self) -> AuthStorageConfig:
        """Get authentication storage configuration."""
        return self.auth_storage_config

    def validate_configuration(self) -> Dict[str, Any]:
        """Validate current configuration and return status."""
        validation_results = {
            'valid': True,
            'warnings': [],
            'errors': [],
            'recommendations': []
        }

        # Validate port configuration
        if self.port_config.primary_port < 1024 and os.getuid() != 0:
            validation_results['warnings'].append("Primary port < 1024 requires root privileges")

        # Validate SSL configuration
        if self.port_config.ssl_enabled:
            if not self.port_config.ssl_cert_path or not self.port_config.ssl_key_path:
                validation_results['errors'].append("SSL enabled but certificate/key paths not specified")
                validation_results['valid'] = False

        # Validate MFA configuration
        if self.mfa_config.enabled and not self.mfa_config.methods:
            validation_results['errors'].append("MFA enabled but no methods configured")
            validation_results['valid'] = False

        # Validate authentication storage
        if self.auth_storage_config.storage_type == "distributed" and not self.auth_storage_config.backup_storages:
            validation_results['warnings'].append("Distributed storage configured but no backup storages specified")

        return validation_results

# Global configuration manager instance
webui_config_manager = WebUIConfigManager()

def get_webui_config() -> WebUIConfigManager:
    """Get the global WebUI configuration manager."""
    return webui_config_manager
