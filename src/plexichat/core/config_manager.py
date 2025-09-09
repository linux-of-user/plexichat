"""
PlexiChat Unified Configuration System with Secure Key Vault Integration
"""

import base64
import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime
from enum import Enum
from functools import reduce
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import yaml

# Crypto imports (PyCryptodome)
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Try to import package version and key vault integration; if not available, continue with defaults
try:
    from plexichat.version import __version__
except Exception:
    __version__ = "0.0.0"

try:
    from plexichat.core.security.key_vault import DistributedKeyManager
except Exception:
    DistributedKeyManager = None

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


@dataclass
class SystemConfig:
    """System configuration section."""

    name: str = "PlexiChat"
    version: str = __version__
    environment: str = "production"
    debug: bool = False
    timezone: str = "UTC"


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""

    enabled: bool = True
    requests_per_minute: int = 60
    burst_limit: int = 10
    window_size_seconds: int = 60
    ban_duration_seconds: int = 3600
    ban_threshold: int = 10


@dataclass
class NetworkConfig:
    """Network configuration section."""

    host: str = "0.0.0.0"
    port: int = 8080
    ssl_enabled: bool = False
    ssl_cert_path: str = ""
    ssl_key_path: str = ""
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    proxy_headers: bool = False
    max_request_size_mb: int = 100
    timeout_keep_alive: int = 5
    rate_limiting: RateLimitConfig = field(default_factory=RateLimitConfig)


@dataclass
class SecurityConfig:
    """Security configuration section."""

    secret_key: str = "change-me"
    jwt_secret: str = "change-me-too"
    session_timeout_seconds: int = 3600
    password_hash_algorithm: str = "bcrypt"
    # Expanded security policy
    mfa_enabled: bool = True
    mfa_required_for_admin: bool = True
    totp_issuer: str = "PlexiChat"
    backup_codes_count: int = 10
    sanitation_enabled: bool = True
    sanitizer_strict: bool = True
    plugin_sandbox_strict: bool = True


@dataclass
class DatabaseConfig:
    """Database configuration section."""

    type: str = "sqlite"
    path: str = "data/plexichat.db"
    host: str = "localhost"
    port: int = 5432
    username: str = "user"
    password: str = "password"
    db_name: str = "plexichat"
    pool_min: int = 1
    pool_max: int = 10


@dataclass
class CachingConfig:
    """Caching configuration section."""

    enabled: bool = True
    l1_max_items: int = 1000
    l1_memory_size_mb: int = 64
    default_ttl_seconds: int = 300
    compression_threshold_bytes: int = 1024
    warming_enabled: bool = False
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
    """AI provider configuration section."""

    default_provider: str = "openai"
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    google_api_key: str = ""


@dataclass
class LoggingConfig:
    """Logging configuration section."""

    level: str = "INFO"
    format: str = "text"  # text|json
    log_to_file: bool = True
    file_main: str = "logs/latest.txt"
    retention_days: int = 14
    rotation_on_startup: bool = True
    rotation_compress: bool = True
    plugins_enabled: bool = True
    plugins_level: str = "INFO"
    debug_stacktraces: bool = False


@dataclass
class PluginSettings:
    """Plugin system configuration section."""

    timeout_seconds: int = 30
    max_memory_mb: int = 128
    sandboxing_enabled: bool = True
    allow_network_by_default: bool = False
    default_permissions: List[str] = field(default_factory=lambda: ["file_read"])


# --- New enhanced configuration sections ---


@dataclass
class ClusterConfig:
    """Cluster configuration section."""

    cluster_id: str = "cluster-local"
    cluster_name: str = "PlexiChat Cluster"
    node_type: str = "general"
    auth_token: str = ""  # Sensitive
    auto_join: bool = True
    discovery_enabled: bool = True
    min_nodes: int = 1
    max_nodes: int = 100
    replication_factor: int = 2
    health_check_interval: int = 30
    heartbeat_timeout: int = 60
    failover_enabled: bool = True
    backup_enabled: bool = True


@dataclass
class SecurityEnhancedConfig:
    """Enhanced security configuration for advanced features."""

    enable_quantum_crypto: bool = False
    pq_algorithm: str = "kyber-768"
    encryption_key_rotation_days: int = 90
    master_encryption_key: str = ""  # Sensitive - used for advanced encryption layers
    admin_contact: str = ""


@dataclass
class DDoSProtectionConfig:
    """DDoS protection and adaptive rate limiting."""

    enabled: bool = True
    dynamic_rate_limiting: bool = True
    base_request_limit: int = 100
    burst_limit: int = 50
    ip_block_threshold: int = 1000
    ip_block_duration_seconds: int = 3600
    user_tiers: Dict[str, int] = field(
        default_factory=lambda: {"free": 60, "pro": 600, "admin": 10000}
    )
    enable_intelligent_blocking: bool = True
    alert_threshold: int = 10000


@dataclass
class PluginSecurityConfig:
    """Plugin security and sandboxing configuration."""

    permission_request_flow_enabled: bool = True
    admin_approval_required: bool = True
    allowed_builtins: List[str] = field(
        default_factory=lambda: [
            "len",
            "range",
            "min",
            "max",
            "sum",
            "sorted",
            "abs",
            "all",
            "any",
            "enumerate",
            "zip",
            "map",
            "filter",
        ]
    )
    whitelist_modules: List[str] = field(default_factory=lambda: ["json", "math", "re"])
    max_cpu_seconds: float = 5.0
    max_memory_mb: int = 64
    audit_logging_enabled: bool = True


@dataclass
class BackupConfig:
    """Backup and disaster recovery configuration."""

    enabled: bool = True
    schedule_cron: str = "0 2 * * *"  # Default: daily at 02:00
    encryption_key: str = ""  # Sensitive: backup encryption root key
    storage_backend: str = "local"  # local, s3, distributed
    local_path: str = "backups/"
    distributed_shards: int = 3
    retention_days: int = 30
    verify_after_backup: bool = True
    backup_compression: bool = True


@dataclass
class CallingServiceConfig:
    """Calling service configuration section (encryption/quality)."""

    e2e_encryption_enabled: bool = True
    quantum_ready: bool = False
    key_rotation_interval_seconds: int = 3600
    default_audio_bitrate_kbps: int = 64
    default_video_bitrate_kbps: int = 512
    max_participants: int = 10


@dataclass
class TypingConfig:
    """Typing indicators configuration section."""

    enabled: bool = True
    timeout_seconds: int = 3
    cleanup_interval_seconds: int = 30
    max_concurrent_typing_users: int = 100
    debounce_delay_seconds: float = 0.5
    cache_ttl_seconds: int = 60
    broadcast_batch_size: int = 10
    broadcast_interval_seconds: float = 0.1
    enable_persistence: bool = True
    max_typing_history_days: int = 7
    enable_metrics: bool = True
    enable_debug_logging: bool = False


@dataclass
class KeyboardShortcutsConfig:
    """Keyboard shortcuts configuration section."""

    enabled: bool = True
    allow_custom_shortcuts: bool = True
    max_custom_shortcuts_per_user: int = 50
    conflict_detection_enabled: bool = True
    platform_mappings: Dict[str, Dict[str, str]] = field(
        default_factory=lambda: {
            "windows": {
                "ctrl": "Control",
                "alt": "Alt",
                "shift": "Shift",
                "meta": "Windows",
            },
            "mac": {
                "ctrl": "Control",
                "alt": "Option",
                "shift": "Shift",
                "meta": "Command",
            },
            "linux": {
                "ctrl": "Control",
                "alt": "Alt",
                "shift": "Shift",
                "meta": "Super",
            },
        }
    )
    accessibility_enabled: bool = True
    accessibility_modifiers: List[str] = field(default_factory=lambda: ["alt", "shift"])
    default_shortcuts_enabled: bool = True
    shortcut_validation_enabled: bool = True
    max_shortcut_length: int = 3
    reserved_shortcuts: List[str] = field(
        default_factory=lambda: [
            "Ctrl+C",
            "Ctrl+V",
            "Ctrl+X",
            "Ctrl+A",
            "Ctrl+Z",
            "Ctrl+Y",
            "Ctrl+S",
            "Ctrl+O",
            "Ctrl+N",
            "Ctrl+W",
            "Ctrl+Q",
            "Ctrl+R",
            "F1",
            "F2",
            "F3",
            "F4",
            "F5",
            "F6",
            "F7",
            "F8",
            "F9",
            "F10",
            "F11",
            "F12",
        ]
    )


@dataclass
class SupervisorConfig:
    """Supervisor configuration."""

    enabled: bool = True
    interval_seconds: int = 30
    backoff_initial_seconds: float = 5.0
    backoff_max_seconds: float = 300.0


@dataclass
class RateLimitEngineConfig:
    """Unified rate limit engine configuration."""

    enabled: bool = True
    per_ip_requests_per_minute: int = 60
    per_user_requests_per_minute: int = 120
    per_route_requests_per_minute: int = 100
    global_requests_per_minute: int = 10000
    per_ip_block_duration: int = 300
    per_user_block_duration: int = 180
    endpoint_overrides: Dict[str, Dict[str, int]] = field(default_factory=dict)
    user_tier_multipliers: Dict[str, float] = field(
        default_factory=lambda: {
            "guest": 0.5,
            "user": 1.0,
            "premium": 2.0,
            "admin": 10.0,
            "system": 100.0,
        }
    )


@dataclass
class UnifiedConfig:
    """Main unified configuration container."""

    system: SystemConfig = field(default_factory=SystemConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    caching: CachingConfig = field(default_factory=CachingConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    supervisor: SupervisorConfig = field(default_factory=SupervisorConfig)
    rate_limit: RateLimitEngineConfig = field(default_factory=RateLimitEngineConfig)
    plugins: PluginSettings = field(default_factory=PluginSettings)

    # New sections
    cluster: ClusterConfig = field(default_factory=ClusterConfig)
    security_enhanced: SecurityEnhancedConfig = field(
        default_factory=SecurityEnhancedConfig
    )
    ddos: DDoSProtectionConfig = field(default_factory=DDoSProtectionConfig)
    plugin_security: PluginSecurityConfig = field(default_factory=PluginSecurityConfig)
    backup: BackupConfig = field(default_factory=BackupConfig)
    calling: CallingServiceConfig = field(default_factory=CallingServiceConfig)
    typing: TypingConfig = field(default_factory=TypingConfig)
    keyboard: KeyboardShortcutsConfig = field(default_factory=KeyboardShortcutsConfig)


class UnifiedConfigManager:
    """Unified configuration manager with Key Vault integration."""

    def __init__(self, config_file: Optional[str] = None):
        self.config_file = Path(config_file or "data/config/plexichat.yaml")
        self._config = UnifiedConfig()
        self._lock = threading.RLock()
        self.sensitive_keys = {
            "security.secret_key",
            "security.jwt_secret",
            "database.password",
            "ai.openai_api_key",
            "ai.anthropic_api_key",
            "ai.google_api_key",
            "caching.l2_redis_password",
            # New sensitive fields
            "cluster.auth_token",
            "security_enhanced.master_encryption_key",
            "backup.encryption_key",
        }

        # Keys considered critical and not hot-reloadable
        self._critical_keys = set(self.sensitive_keys) | {
            "database.type",
            "database.path",
            "cluster.auth_token",
            "security.secret_key",
            "database.password",
        }

        # Try to initialize key manager if available
        self.key_manager = None
        self.master_key = None
        if DistributedKeyManager:
            try:
                vaults_dir = Path("vaults")
                self.key_manager = DistributedKeyManager(vaults_dir, 5, 3)
                self.master_key = self.key_manager.reconstruct_master_key()
                logger.info("Master key reconstructed successfully from key vaults.")
            except Exception as e:
                logger.error(
                    f"Failed to reconstruct master key: {e}. Secrets will not be available."
                )
                self.master_key = None
        else:
            logger.debug(
                "DistributedKeyManager not available; skipping key vault initialization."
            )

        # Hot reload control
        self._hot_reload_enabled = os.environ.get("PLEXI_CONFIG_HOT_RELOAD", "0") in (
            "1",
            "true",
            "True",
        )
        self._hot_reload_interval = int(
            os.environ.get("PLEXI_CONFIG_HOT_RELOAD_INTERVAL", "5")
        )
        self._file_mtime: Optional[float] = None
        self._hot_reload_thread: Optional[threading.Thread] = None
        self._stop_hot_reload = threading.Event()

        # Load configuration (includes env overrides)
        self.load()

        # Start hot reload thread if enabled
        if self._hot_reload_enabled:
            self._start_hot_reload()

    def _encrypt_secret(self, plaintext: str) -> str:
        """Encrypts a secret using AES-GCM."""
        if not self.master_key:
            return plaintext  # Cannot encrypt without a master key

        try:
            cipher = AES.new(self.master_key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))

            encrypted_data = {
                "nonce": base64.b64encode(cipher.nonce).decode("utf-8"),
                "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
                "tag": base64.b64encode(tag).decode("utf-8"),
            }
            return "enc_v1:" + base64.b64encode(
                json.dumps(encrypted_data).encode("utf-8")
            ).decode("utf-8")
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return plaintext

    def _decrypt_secret(self, encrypted_value: str) -> str:
        """Decrypts a secret encrypted with AES-GCM."""
        if (
            not self.master_key
            or not isinstance(encrypted_value, str)
            or not encrypted_value.startswith("enc_v1:")
        ):
            return encrypted_value

        try:
            encrypted_data_b64 = encrypted_value.split("enc_v1:")[1]
            encrypted_data_json = base64.b64decode(encrypted_data_b64).decode("utf-8")
            encrypted_data = json.loads(encrypted_data_json)

            nonce = base64.b64decode(encrypted_data["nonce"])
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            tag = base64.b64decode(encrypted_data["tag"])

            cipher = AES.new(self.master_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode("utf-8")
        except Exception as e:
            logger.error(f"Failed to decrypt secret: {e}")
            return ""  # Return empty string on decryption failure

    # ----------------------
    # Loading & Saving
    # ----------------------
    def load(self) -> None:
        """Load configuration from file and apply environment overrides and validation."""
        with self._lock:
            if self.config_file.exists():
                try:
                    mtime = self.config_file.stat().st_mtime
                    self._file_mtime = mtime
                    with open(self.config_file, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f) or {}
                        self._update_config_from_dict(
                            data, apply_env=False, validate=False
                        )
                    logger.info(f"Configuration loaded from {self.config_file}")
                except Exception as e:
                    logger.error(f"Failed to load configuration: {e}")
            else:
                logger.info("Configuration file not found, using defaults")

            # Always apply environment overrides after load
            self._apply_env_overrides()
            # Validate config after applying env overrides
            try:
                self._validate_config()
            except Exception as e:
                logger.error(f"Configuration validation failed: {e}")

    def save(self) -> None:
        """Save configuration to file, encrypting sensitive values."""
        with self._lock:
            try:
                self.config_file.parent.mkdir(parents=True, exist_ok=True)
                config_dict = self.to_dict(sanitize=False)

                # Encrypt sensitive fields in the nested config dict, but avoid double-encrypting
                for full_key in self.sensitive_keys:
                    parts = full_key.split(".")
                    node = config_dict
                    skip = False
                    for p in parts[:-1]:
                        if isinstance(node, dict) and p in node:
                            node = node[p]
                        else:
                            skip = True
                            break
                    if skip:
                        continue
                    last = parts[-1]
                    if isinstance(node, dict) and last in node:
                        val = node[last]
                        if isinstance(val, str) and not val.startswith("enc_v1:"):
                            node[last] = self._encrypt_secret(val)

                with open(self.config_file, "w", encoding="utf-8") as f:
                    yaml.dump(config_dict, f, default_flow_style=False)
                logger.info(f"Configuration saved to {self.config_file}")
            except Exception as e:
                logger.error(f"Failed to save configuration: {e}")

    def to_dict(self, sanitize: bool = True) -> Dict[str, Any]:
        """Return configuration as a nested dict. If sanitize=True, mask sensitive values."""

        def dataclass_to_dict(obj):
            if is_dataclass(obj):
                result = {}
                for field_name, value in asdict(obj).items():
                    # asdict returns nested dicts already
                    result[field_name] = value
                return result
            if isinstance(obj, dict):
                return {k: dataclass_to_dict(v) for k, v in obj.items()}
            return obj

        config_dict = dataclass_to_dict(self._config)
        if sanitize:
            for full_key in self.sensitive_keys:
                parts = full_key.split(".")
                node = config_dict
                try:
                    for p in parts[:-1]:
                        node = node.get(p, {})
                    last = parts[-1]
                    if isinstance(node, dict) and last in node:
                        node[last] = "***REDACTED***"
                except Exception:
                    continue
        return config_dict

    # ----------------------
    # Get/Set interface
    # ----------------------
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot notation key. Decrypt sensitive values."""
        with self._lock:
            try:
                parts = key.split(".")
                value = self._config
                for part in parts:
                    value = getattr(value, part)
                # If value is sensitive and encrypted, decrypt it before returning.
                if key in self.sensitive_keys and isinstance(value, str):
                    return self._decrypt_secret(value)
                return value
            except (AttributeError, KeyError):
                return default

    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value by dot notation key. Stores plaintext in memory;
        encryption is applied on save. Performs basic type coercion and validation.
        """
        with self._lock:
            try:
                parts = key.split(".")
                config_obj = self._config
                for part in parts[:-1]:
                    config_obj = getattr(config_obj, part)
                last_attr = parts[-1]
                if hasattr(config_obj, last_attr):
                    current_val = getattr(config_obj, last_attr)
                    coerced = self._coerce_to_type(current_val, value)
                    setattr(config_obj, last_attr, coerced)
                    # Run validation for the specific key
                    try:
                        self._validate_single_key(key, coerced)
                    except Exception as e:
                        logger.error(f"Validation failed when setting {key}: {e}")
                        # Still set value in memory but log error
                else:
                    logger.error(f"Config attribute not found: {key}")
            except (AttributeError, KeyError) as e:
                logger.error(f"Failed to set config key {key}: {e}")

    # ----------------------
    # Internal helpers
    # ----------------------
    def _update_config_from_dict(
        self, data: Dict[str, Any], apply_env: bool = True, validate: bool = True
    ) -> None:
        """Update configuration from dictionary, decrypting sensitive values."""
        for section_name, section_data in data.items():
            if hasattr(self._config, section_name) and isinstance(section_data, dict):
                section = getattr(self._config, section_name)
                for key, value in section_data.items():
                    full_key = f"{section_name}.{key}"
                    if full_key in self.sensitive_keys and isinstance(value, str):
                        # Decrypt if necessary
                        value = self._decrypt_secret(value)
                    if hasattr(section, key):
                        try:
                            current_val = getattr(section, key)
                            coerced = self._coerce_to_type(current_val, value)
                            setattr(section, key, coerced)
                        except Exception as e:
                            logger.error(f"Failed to set config value {full_key}: {e}")
                    else:
                        logger.debug(f"Ignoring unknown config key {full_key}")
            else:
                logger.debug(f"Ignoring unknown config section {section_name}")

        if apply_env:
            self._apply_env_overrides()

        if validate:
            self._validate_config()

    def _coerce_to_type(self, current_val: Any, new_val: Any) -> Any:
        """
        Coerce new_val to the type of current_val when reasonable.
        Handles basic types and lists/dicts; does not attempt to deeply validate complex nested structures.
        """
        try:
            if new_val is None:
                return None
            # If same type already, return new_val
            if isinstance(new_val, type(current_val)) or current_val is None:
                # If current_val is dataclass or dict-like, try to keep structure
                if is_dataclass(current_val) and isinstance(new_val, dict):
                    # merge into dataclass fields
                    for k, v in new_val.items():
                        if hasattr(current_val, k):
                            setattr(
                                current_val,
                                k,
                                self._coerce_to_type(getattr(current_val, k), v),
                            )
                    return current_val
                return new_val
            # Strings to basic types
            if isinstance(current_val, bool):
                if isinstance(new_val, str):
                    return new_val.lower() in ("1", "true", "yes", "on")
                return bool(new_val)
            if isinstance(current_val, int):
                return int(new_val)
            if isinstance(current_val, float):
                return float(new_val)
            if isinstance(current_val, str):
                return str(new_val)
            if isinstance(current_val, list):
                if isinstance(new_val, list):
                    return new_val
                if isinstance(new_val, str):
                    # Try to parse JSON list or comma-separated
                    try:
                        parsed = json.loads(new_val)
                        if isinstance(parsed, list):
                            return parsed
                    except Exception:
                        return [s.strip() for s in new_val.split(",") if s.strip()]
                return [new_val]
            if isinstance(current_val, dict):
                if isinstance(new_val, dict):
                    return new_val
                if isinstance(new_val, str):
                    try:
                        parsed = json.loads(new_val)
                        if isinstance(parsed, dict):
                            return parsed
                    except Exception:
                        return current_val
            # Fallback: attempt direct cast
            return new_val
        except Exception as e:
            logger.debug(f"Type coercion failed ({e}), returning original new_val")
            return new_val

    # ----------------------
    # Environment overrides
    # ----------------------
    def _apply_env_overrides(self) -> None:
        """
        Apply environment variable overrides. Supported formats:
         - PLEXI_<SECTION>_<FIELD> => section.field
         - PLEXI_<SECTION>__<SUBSECTION>__<FIELD> => section.subsection.field
        Example: PLEXI_NETWORK_HOST -> network.host
                 PLEXI_SECURITY_ENHANCED__MASTER_ENCRYPTION_KEY -> security_enhanced.master_encryption_key
        """
        prefix = "PLEXI_"
        env_items = {k: v for k, v in os.environ.items() if k.startswith(prefix)}
        if not env_items:
            return

        for raw_key, raw_val in env_items.items():
            key_part = raw_key[len(prefix) :]
            if "__" in key_part:
                dotted = key_part.replace("__", ".").lower()
            else:
                parts = key_part.split("_", 1)
                if len(parts) == 2:
                    dotted = f"{parts[0].lower()}.{parts[1].lower()}"
                else:
                    dotted = parts[0].lower()
            # Normalize multiple dots and underscores
            dotted = dotted.replace("__", ".")
            dotted = dotted.strip(".")
            try:
                # Coerce value into target type if possible
                # Resolve current value to determine expected type
                try:
                    current_val = self.get(dotted, None)
                except Exception:
                    current_val = None
                coerced = self._coerce_to_type(current_val, raw_val)
                self.set(dotted, coerced)
                logger.debug(f"Applied env override {raw_key} -> {dotted} = {coerced}")
            except Exception as e:
                logger.warning(f"Failed to apply env override {raw_key}: {e}")

    # ----------------------
    # Validation
    # ----------------------
    def _validate_config(self) -> None:
        """Validate the entire configuration for basic consistency and types."""
        # Basic sanity checks and ranges for critical numeric values
        errors = []

        # Validate network
        try:
            port = self.get("network.port")
            if not (1 <= int(port) <= 65535):
                errors.append("network.port must be between 1 and 65535")
        except Exception:
            errors.append("network.port invalid or missing")

        # Validate rate limits
        try:
            rpm = self.get("network.rate_limiting.requests_per_minute")
            if int(rpm) < 0:
                errors.append("network.rate_limiting.requests_per_minute must be >= 0")
        except Exception:
            errors.append(
                "network.rate_limiting.requests_per_minute invalid or missing"
            )

        # Validate plugin sandbox limits
        try:
            max_mem = self.get("plugin_security.max_memory_mb")
            if int(max_mem) <= 0:
                errors.append("plugin_security.max_memory_mb must be > 0")
        except Exception:
            errors.append("plugin_security.max_memory_mb invalid or missing")

        # Validate backup retention
        try:
            retention = self.get("backup.retention_days")
            if int(retention) < 0:
                errors.append("backup.retention_days must be >= 0")
        except Exception:
            errors.append("backup.retention_days invalid or missing")

        # Validate DDoS thresholds
        try:
            base_limit = self.get("ddos.base_request_limit")
            if int(base_limit) < 0:
                errors.append("ddos.base_request_limit must be >= 0")
        except Exception:
            errors.append("ddos.base_request_limit invalid or missing")

        # Add more checks as needed...

        if errors:
            raise ValueError("Configuration validation errors: " + "; ".join(errors))

    def _validate_single_key(self, dotted_key: str, value: Any) -> None:
        """Validate a single key based on simple rules."""
        # Protect critical keys from trivial modification via hot reload
        if dotted_key in self._critical_keys and self._hot_reload_enabled:
            # If hot reload thread attempted to set a critical key, log warning
            logger.warning(
                f"Attempted to modify critical config key at runtime: {dotted_key}"
            )

        # Example per-key validations
        if dotted_key == "network.port":
            if not (1 <= int(value) <= 65535):
                raise ValueError("network.port must be between 1 and 65535")
        if dotted_key == "plugin_security.max_cpu_seconds":
            if float(value) <= 0:
                raise ValueError("plugin_security.max_cpu_seconds must be > 0")

    # ----------------------
    # Hot reload support
    # ----------------------
    def _start_hot_reload(self):
        """Start background thread that monitors the config file for changes and applies non-critical updates."""
        if self._hot_reload_thread and self._hot_reload_thread.is_alive():
            return

        def hot_reload_loop():
            logger.info("Starting config hot-reload thread")
            while not self._stop_hot_reload.is_set():
                try:
                    if self.config_file.exists():
                        mtime = self.config_file.stat().st_mtime
                        if self._file_mtime is None:
                            self._file_mtime = mtime
                        elif mtime != self._file_mtime:
                            logger.info(
                                "Configuration file change detected; performing hot-reload"
                            )
                            try:
                                with open(self.config_file, "r", encoding="utf-8") as f:
                                    data = yaml.safe_load(f) or {}
                                # Flatten incoming dict to dotted keys
                                flat = self._flatten_dict(data)
                                with self._lock:
                                    for k, v in flat.items():
                                        # Only apply non-critical keys
                                        if k in self._critical_keys:
                                            logger.warning(
                                                f"Skipping hot-reload of critical key: {k}"
                                            )
                                            continue
                                        try:
                                            # Coerce based on existing value
                                            current_val = self.get(k, None)
                                            coerced = self._coerce_to_type(
                                                current_val, v
                                            )
                                            self.set(k, coerced)
                                            logger.info(
                                                f"Hot-reloaded config {k} -> {coerced}"
                                            )
                                        except Exception as e:
                                            logger.error(
                                                f"Failed to hot-reload key {k}: {e}"
                                            )
                                self._file_mtime = mtime
                            except Exception as e:
                                logger.error(f"Error during config hot-reload: {e}")
                    # Also apply any environment variable overrides that might have changed
                    self._apply_env_overrides()
                except Exception as e:
                    logger.error(f"Unexpected error in hot-reload loop: {e}")
                # Sleep for configured interval
                self._stop_hot_reload.wait(self._hot_reload_interval)
            logger.info("Config hot-reload thread stopped")

        self._hot_reload_thread = threading.Thread(
            target=hot_reload_loop, name="ConfigHotReload", daemon=True
        )
        self._hot_reload_thread.start()

    def stop_hot_reload(self):
        """Stop the hot-reload thread gracefully."""
        self._stop_hot_reload.set()
        if self._hot_reload_thread:
            self._hot_reload_thread.join(timeout=2.0)
            self._hot_reload_thread = None

    def _flatten_dict(self, d: Dict[str, Any], parent: str = "") -> Dict[str, Any]:
        """Flatten a nested dict to dotted keys."""
        items: Dict[str, Any] = {}
        for k, v in d.items() if isinstance(d, dict) else []:
            new_key = f"{parent}.{k}" if parent else k
            if isinstance(v, dict):
                items.update(self._flatten_dict(v, new_key))
            else:
                items[new_key] = v
        return items

    # ----------------------
    # Utility & convenience functions
    # ----------------------
    def get_plugin_timeout(self) -> int:
        """Convenience accessor for plugin timeout in seconds."""
        return int(self.get("plugins.timeout_seconds", 30))

    def get_max_plugin_memory(self) -> int:
        """Convenience accessor for plugin max memory in bytes."""
        mb = int(self.get("plugins.max_memory_mb", 128))
        return mb * 1024 * 1024

    def get_plugin_sandbox_enabled(self) -> bool:
        """Convenience accessor for whether plugin sandboxing is enabled."""
        return bool(self.get("plugins.sandboxing_enabled", True))

    def list_sensitive_keys(self) -> List[str]:
        """Return a list of configured sensitive keys."""
        return list(self.sensitive_keys)

    def reload(self) -> None:
        """Public API to force reload config from disk."""
        logger.info("Manual config reload triggered")
        self.load()

    # ----------------------
    # Clean up
    # ----------------------
    def __del__(self):
        try:
            self.stop_hot_reload()
        except Exception:
            pass


# ----------------------
# Module-level helpers and singletons
# ----------------------
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


# Convenience top-level functions used by other modules
def get_plugin_timeout() -> int:
    return get_config_manager().get_plugin_timeout()


def get_max_plugin_memory() -> int:
    return get_config_manager().get_max_plugin_memory()


def get_plugin_sandbox_enabled() -> bool:
    return get_config_manager().get_plugin_sandbox_enabled()


# Expose a current config snapshot for modules that import it directly
config = get_config_manager()._config
