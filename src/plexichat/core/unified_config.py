"""
PlexiChat Unified Configuration System with Secure Key Vault Integration
"""

import json
import logging
import os
import yaml
import threading
import base64
from pathlib import Path
from typing import Any, Dict, Optional, Union, List, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from .security.key_vault import DistributedKeyManager

logger = logging.getLogger(__name__)


@dataclass
class SystemConfig:
    """System configuration section."""
    name: str = "PlexiChat"
    version: str = "0.0.0"
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
    # ... other security settings

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
    log_to_file: bool = True
    log_file_path: str = "logs/plexichat.log"

@dataclass
class PluginSettings:
    """Plugin system configuration section."""
    timeout_seconds: int = 30
    max_memory_mb: int = 128
    sandboxing_enabled: bool = True

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
    plugins: PluginSettings = field(default_factory=PluginSettings)


class UnifiedConfigManager:
    """Unified configuration manager with Key Vault integration."""

    def __init__(self, config_file: Optional[str] = None):
        self.config_file = Path(config_file or "config/plexichat.yaml")
        self._config = UnifiedConfig()
        self._lock = threading.RLock()
        self.sensitive_keys = {
            "security.secret_key",
            "security.jwt_secret",
            "database.password",
            "ai.openai_api_key",
            "ai.anthropic_api_key",
            "ai.google_api_key",
            "caching.l2_redis_password"
        }

        try:
            vaults_dir = Path("vaults")
            self.key_manager = DistributedKeyManager(vaults_dir, 5, 3)
            self.master_key = self.key_manager.reconstruct_master_key()
            logger.info("Master key reconstructed successfully from key vaults.")
        except Exception as e:
            logger.error(f"Failed to reconstruct master key: {e}. Secrets will not be available.")
            self.master_key = None

        self.load()

    def _encrypt_secret(self, plaintext: str) -> str:
        """Encrypts a secret using AES-GCM."""
        if not self.master_key:
            return plaintext # Cannot encrypt without a master key

        cipher = AES.new(self.master_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))

        encrypted_data = {
            'nonce': base64.b64encode(cipher.nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')
        }
        return "enc_v1:" + base64.b64encode(json.dumps(encrypted_data).encode('utf-8')).decode('utf-8')

    def _decrypt_secret(self, encrypted_value: str) -> str:
        """Decrypts a secret encrypted with AES-GCM."""
        if not self.master_key or not encrypted_value.startswith("enc_v1:"):
            return encrypted_value

        try:
            encrypted_data_b64 = encrypted_value.split("enc_v1:")[1]
            encrypted_data_json = base64.b64decode(encrypted_data_b64).decode('utf-8')
            encrypted_data = json.loads(encrypted_data_json)

            nonce = base64.b64decode(encrypted_data['nonce'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            tag = base64.b64decode(encrypted_data['tag'])

            cipher = AES.new(self.master_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to decrypt secret: {e}")
            return "" # Return empty string on decryption failure

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
        """Save configuration to file, encrypting sensitive values."""
        with self._lock:
            try:
                self.config_file.parent.mkdir(parents=True, exist_ok=True)
                config_dict = asdict(self._config)

                for key in self.sensitive_keys:
                    section, setting = key.split('.')
                    if section in config_dict and setting in config_dict[section]:
                        config_dict[section][setting] = self._encrypt_secret(config_dict[section][setting])

                with open(self.config_file, 'w', encoding='utf-8') as f:
                    yaml.dump(config_dict, f, default_flow_style=False)
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

                if key in self.sensitive_keys:
                    return self._decrypt_secret(value)
                return value
            except (AttributeError, KeyError):
                return default
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value by dot notation key."""
        with self._lock:
            try:
                if key in self.sensitive_keys:
                    value = self._encrypt_secret(value)

                parts = key.split('.')
                config_obj = self._config
                for part in parts[:-1]:
                    config_obj = getattr(config_obj, part)
                setattr(config_obj, parts[-1], value)
            except (AttributeError, KeyError) as e:
                logger.error(f"Failed to set config key {key}: {e}")

    def _update_config_from_dict(self, data: Dict[str, Any]) -> None:
        """Update configuration from dictionary, decrypting sensitive values."""
        for section_name, section_data in data.items():
            if hasattr(self._config, section_name) and isinstance(section_data, dict):
                section = getattr(self._config, section_name)
                for key, value in section_data.items():
                    full_key = f"{section_name}.{key}"
                    if full_key in self.sensitive_keys:
                        value = self._decrypt_secret(value)

                    if hasattr(section, key):
                        setattr(section, key, value)

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

config = get_config_manager()._config
