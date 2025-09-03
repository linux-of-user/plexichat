"""
PlexiChat Client Settings Service

A comprehensive database-backed service for managing user client settings with
support for key-value pairs, image storage, validation, rate limiting, and security controls.
Enhanced with security system integration, encryption, audit logging, and configurable limits.
"""

import asyncio
import base64
import hashlib
import json
import logging
import mimetypes
import os
import time
import secrets
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union, Tuple
from dataclasses import dataclass, field
from functools import wraps

# Core imports
try:
    from plexichat.core.database.manager import database_manager, get_session
    from plexichat.core.config_manager import get_config_manager, get_config
    from plexichat.core.security.security_manager import get_security_system
    from plexichat.core.security.security_context import SecurityContext, SecurityLevel
    from plexichat.core.middleware.dynamic_rate_limiting_middleware import get_rate_limiter
except ImportError:
    # Fallback for standalone execution
    database_manager = None
    get_session = None
    get_config_manager = None
    get_config = lambda x: None
    get_security_system = None
    get_rate_limiter = None
    SecurityContext = None
    SecurityLevel = None

# Crypto imports for encryption
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

logger = logging.getLogger(__name__)


class SettingType(Enum):
    """Supported setting data types."""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    JSON = "json"
    IMAGE = "image"
    BINARY = "binary"


class ValidationError(Exception):
    """Raised when setting validation fails."""
    pass


class RateLimitError(Exception):
    """Raised when rate limit is exceeded."""
    pass


class StorageLimitError(Exception):
    """Raised when storage limit is exceeded."""
    pass


class SecurityError(Exception):
    """Raised when security validation fails."""
    pass


class EncryptionError(Exception):
    """Raised when encryption/decryption fails."""
    pass


@dataclass
class SettingLimits:
    """Configuration for setting limits."""
    max_key_length: int = 255
    max_string_value_length: int = 10000
    max_json_size: int = 100000  # 100KB
    max_image_size: int = 5242880  # 5MB
    max_binary_size: int = 1048576  # 1MB
    max_settings_per_user: int = 1000
    max_total_storage_per_user: int = 52428800  # 50MB
    allowed_image_types: Set[str] = field(default_factory=lambda: {
        'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml'
    })
    # Admin override limits
    admin_max_settings_per_user: int = 10000
    admin_max_total_storage_per_user: int = 524288000  # 500MB
    # Sensitive setting patterns (will be encrypted)
    sensitive_key_patterns: Set[str] = field(default_factory=lambda: {
        'password', 'token', 'secret', 'key', 'credential', 'auth'
    })


@dataclass
class SecurityConfig:
    """Security configuration for client settings."""
    require_authentication: bool = True
    enable_encryption: bool = True
    enable_audit_logging: bool = True
    max_failed_auth_attempts: int = 5
    auth_lockout_duration_minutes: int = 30
    encryption_key_rotation_days: int = 90
    audit_retention_days: int = 365


@dataclass
class MetricsData:
    """Metrics tracking for client settings service."""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    rate_limited_requests: int = 0
    security_violations: int = 0
    encryption_operations: int = 0
    audit_events: int = 0
    storage_bytes_used: int = 0
    settings_count: int = 0


class EncryptionManager:
    """Handles encryption and decryption of sensitive setting values."""
    
    def __init__(self, encryption_key: Optional[bytes] = None):
        self.encryption_key = encryption_key or self._generate_key()
        self.logger = logging.getLogger(__name__)
    
    def _generate_key(self) -> bytes:
        """Generate a new encryption key."""
        if CRYPTO_AVAILABLE:
            return get_random_bytes(32)  # 256-bit key
        else:
            # Fallback to a simple key if crypto not available
            return secrets.token_bytes(32)
    
    def encrypt_value(self, value: str) -> str:
        """Encrypt a sensitive value."""
        if not CRYPTO_AVAILABLE or not value:
            return value
        
        try:
            cipher = AES.new(self.encryption_key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(value.encode('utf-8'))
            
            # Combine nonce, tag, and ciphertext
            encrypted_data = cipher.nonce + tag + ciphertext
            return "enc:" + base64.b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt value: {e}")
    
    def decrypt_value(self, encrypted_value: str) -> str:
        """Decrypt a sensitive value."""
        if not CRYPTO_AVAILABLE or not encrypted_value or not encrypted_value.startswith("enc:"):
            return encrypted_value
        
        try:
            encrypted_data = base64.b64decode(encrypted_value[4:])  # Remove "enc:" prefix
            
            # Extract nonce, tag, and ciphertext
            nonce = encrypted_data[:16]
            tag = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            
            cipher = AES.new(self.encryption_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode('utf-8')
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise EncryptionError(f"Failed to decrypt value: {e}")
    
    def is_encrypted(self, value: str) -> bool:
        """Check if a value is encrypted."""
        return isinstance(value, str) and value.startswith("enc:")


class AuditLogger:
    """Handles audit logging for client settings operations."""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.audit")
        self.metrics = MetricsData()
    
    async def log_operation(self, 
                           operation: str, 
                           user_id: str, 
                           setting_key: Optional[str] = None,
                           success: bool = True,
                           error: Optional[str] = None,
                           metadata: Optional[Dict[str, Any]] = None) -> None:
        """Log an audit event."""
        try:
            audit_event = {
                "timestamp": datetime.utcnow().isoformat(),
                "operation": operation,
                "user_id": user_id,
                "setting_key": setting_key,
                "success": success,
                "error": error,
                "metadata": metadata or {},
                "ip_address": metadata.get("ip_address") if metadata else None,
                "user_agent": metadata.get("user_agent") if metadata else None
            }
            
            # Log to audit logger
            if success:
                self.logger.info(f"AUDIT: {operation} by {user_id}", extra=audit_event)
            else:
                self.logger.warning(f"AUDIT: Failed {operation} by {user_id}: {error}", extra=audit_event)
            
            # Store in database if available
            if database_manager:
                await self._store_audit_event(audit_event)
            
            # Update metrics
            self.metrics.audit_events += 1
            
        except Exception as e:
            self.logger.error(f"Failed to log audit event: {e}")
    
    async def _store_audit_event(self, event: Dict[str, Any]) -> None:
        """Store audit event in database."""
        try:
            async with get_session() as session:
                await session.insert(
                    "client_settings_audit",
                    {
                        "timestamp": event["timestamp"],
                        "operation": event["operation"],
                        "user_id": event["user_id"],
                        "setting_key": event.get("setting_key"),
                        "success": event["success"],
                        "error": event.get("error"),
                        "metadata": json.dumps(event.get("metadata", {})),
                        "ip_address": event.get("ip_address"),
                        "user_agent": event.get("user_agent")
                    }
                )
                await session.commit()
        except Exception as e:
            self.logger.error(f"Failed to store audit event in database: {e}")


def security_required(security_level: SecurityLevel = SecurityLevel.AUTHENTICATED):
    """Decorator to require security authentication for methods."""
    def decorator(func):
        @wraps(func)
        async def wrapper(self, user_id: str, *args, **kwargs):
            # Extract security context from kwargs if provided
            security_context = kwargs.get('security_context')
            
            if self.security_config.require_authentication and get_security_system:
                security_system = get_security_system()
                
                if not security_context:
                    await self.audit_logger.log_operation(
                        "security_violation", user_id, 
                        success=False, error="No security context provided"
                    )
                    raise SecurityError("Authentication required")
                
                if not security_context.authenticated:
                    await self.audit_logger.log_operation(
                        "security_violation", user_id,
                        success=False, error="User not authenticated"
                    )
                    raise SecurityError("User not authenticated")
                
                if security_context.security_level.value < security_level.value:
                    await self.audit_logger.log_operation(
                        "security_violation", user_id,
                        success=False, error=f"Insufficient security level: {security_context.security_level}"
                    )
                    raise SecurityError(f"Insufficient security level")
            
            return await func(self, user_id, *args, **kwargs)
        return wrapper
    return decorator


def rate_limited_with_global():
    """Decorator to apply global rate limiting to methods."""
    def decorator(func):
        @wraps(func)
        async def wrapper(self, user_id: str, *args, **kwargs):
            # Use global rate limiter if available
            if get_rate_limiter:
                rate_limiter = get_rate_limiter()
                if not await rate_limiter.check_rate_limit(user_id, "client_settings"):
                    self.metrics.rate_limited_requests += 1
                    await self.audit_logger.log_operation(
                        "rate_limit_exceeded", user_id,
                        success=False, error="Rate limit exceeded"
                    )
                    raise RateLimitError("Rate limit exceeded")
            
            return await func(self, user_id, *args, **kwargs)
        return wrapper
    return decorator


class SettingValidator:
    """Validates setting keys, values, and types with enhanced security."""
    
    def __init__(self, limits: SettingLimits, security_config: SecurityConfig):
        self.limits = limits
        self.security_config = security_config
        self.logger = logging.getLogger(__name__)
    
    def validate_key(self, key: str) -> None:
        """Validate setting key with security checks."""
        if not key:
            raise ValidationError("Setting key cannot be empty")
        
        if len(key) > self.limits.max_key_length:
            raise ValidationError(f"Setting key too long (max {self.limits.max_key_length} characters)")
        
        # Key should contain only alphanumeric characters, underscores, dots, and hyphens
        if not all(c.isalnum() or c in '._-' for c in key):
            raise ValidationError("Setting key contains invalid characters")
        
        # Check for potentially dangerous key patterns
        dangerous_patterns = ['__', 'admin', 'system', 'root', 'config']
        key_lower = key.lower()
        for pattern in dangerous_patterns:
            if pattern in key_lower:
                self.logger.warning(f"Potentially dangerous key pattern detected: {key}")
    
    def is_sensitive_key(self, key: str) -> bool:
        """Check if a setting key should be treated as sensitive."""
        key_lower = key.lower()
        return any(pattern in key_lower for pattern in self.limits.sensitive_key_patterns)
    
    def validate_value(self, value: Any, setting_type: SettingType) -> Any:
        """Validate and convert setting value based on type."""
        if value is None:
            return None
        
        if setting_type == SettingType.STRING:
            str_value = str(value)
            if len(str_value) > self.limits.max_string_value_length:
                raise ValidationError(f"String value too long (max {self.limits.max_string_value_length} characters)")
            return str_value
        
        elif setting_type == SettingType.INTEGER:
            try:
                return int(value)
            except (ValueError, TypeError):
                raise ValidationError("Invalid integer value")
        
        elif setting_type == SettingType.FLOAT:
            try:
                return float(value)
            except (ValueError, TypeError):
                raise ValidationError("Invalid float value")
        
        elif setting_type == SettingType.BOOLEAN:
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.lower() in ('true', '1', 'yes', 'on')
            return bool(value)
        
        elif setting_type == SettingType.JSON:
            if isinstance(value, (dict, list)):
                json_str = json.dumps(value)
            else:
                json_str = str(value)
            
            if len(json_str) > self.limits.max_json_size:
                raise ValidationError(f"JSON value too large (max {self.limits.max_json_size} bytes)")
            
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                raise ValidationError("Invalid JSON value")
        
        elif setting_type == SettingType.IMAGE:
            return self._validate_image(value)
        
        elif setting_type == SettingType.BINARY:
            return self._validate_binary(value)
        
        else:
            raise ValidationError(f"Unsupported setting type: {setting_type}")
    
    def _validate_image(self, value: Any) -> Dict[str, Any]:
        """Validate image data."""
        if isinstance(value, dict) and 'data' in value:
            image_data = value['data']
            content_type = value.get('content_type', 'image/jpeg')
        elif isinstance(value, str):
            # Assume base64 encoded image
            try:
                image_data = base64.b64decode(value)
                content_type = 'image/jpeg'  # Default
            except Exception:
                raise ValidationError("Invalid base64 image data")
        else:
            raise ValidationError("Invalid image format")
        
        if isinstance(image_data, str):
            image_data = image_data.encode('utf-8')
        
        if len(image_data) > self.limits.max_image_size:
            raise ValidationError(f"Image too large (max {self.limits.max_image_size} bytes)")
        
        if content_type not in self.limits.allowed_image_types:
            raise ValidationError(f"Unsupported image type: {content_type}")
        
        return {
            'data': base64.b64encode(image_data).decode('utf-8'),
            'content_type': content_type,
            'size': len(image_data),
            'hash': hashlib.sha256(image_data).hexdigest()
        }
    
    def _validate_binary(self, value: Any) -> Dict[str, Any]:
        """Validate binary data."""
        if isinstance(value, dict) and 'data' in value:
            binary_data = value['data']
        elif isinstance(value, str):
            try:
                binary_data = base64.b64decode(value)
            except Exception:
                raise ValidationError("Invalid base64 binary data")
        elif isinstance(value, bytes):
            binary_data = value
        else:
            raise ValidationError("Invalid binary format")
        
        if isinstance(binary_data, str):
            binary_data = binary_data.encode('utf-8')
        
        if len(binary_data) > self.limits.max_binary_size:
            raise ValidationError(f"Binary data too large (max {self.limits.max_binary_size} bytes)")
        
        return {
            'data': base64.b64encode(binary_data).decode('utf-8'),
            'size': len(binary_data),
            'hash': hashlib.sha256(binary_data).hexdigest()
        }


class ClientSettingsService:
    """
    Comprehensive client settings service with database backend, validation,
    rate limiting, security controls, encryption, and audit logging.
    """
    
    def __init__(self, 
                 limits: Optional[SettingLimits] = None,
                 security_config: Optional[SecurityConfig] = None):
        # Load configuration from config manager
        self._load_configuration()
        
        # Initialize components
        self.limits = limits or self._create_limits_from_config()
        self.security_config = security_config or self._create_security_config_from_config()
        self.validator = SettingValidator(self.limits, self.security_config)
        self.encryption_manager = EncryptionManager()
        self.audit_logger = AuditLogger()
        self.metrics = MetricsData()
        self.logger = logging.getLogger(__name__)
        self._initialized = False
        
        # Cache for user permissions and limits
        self._user_cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl = 300  # 5 minutes
    
    def _load_configuration(self) -> None:
        """Load configuration from the config manager."""
        if get_config_manager:
            self.config_manager = get_config_manager()
        else:
            self.config_manager = None
    
    def _create_limits_from_config(self) -> SettingLimits:
        """Create setting limits from configuration."""
        if not self.config_manager:
            return SettingLimits()
        
        return SettingLimits(
            max_key_length=self.config_manager.get("client_settings.max_key_length", 255),
            max_string_value_length=self.config_manager.get("client_settings.max_string_value_length", 10000),
            max_json_size=self.config_manager.get("client_settings.max_json_size", 100000),
            max_image_size=self.config_manager.get("client_settings.max_image_size", 5242880),
            max_binary_size=self.config_manager.get("client_settings.max_binary_size", 1048576),
            max_settings_per_user=self.config_manager.get("client_settings.max_settings_per_user", 1000),
            max_total_storage_per_user=self.config_manager.get("client_settings.max_total_storage_per_user", 52428800),
            admin_max_settings_per_user=self.config_manager.get("client_settings.admin_max_settings_per_user", 10000),
            admin_max_total_storage_per_user=self.config_manager.get("client_settings.admin_max_total_storage_per_user", 524288000),
        )
    
    def _create_security_config_from_config(self) -> SecurityConfig:
        """Create security configuration from config manager."""
        if not self.config_manager:
            return SecurityConfig()
        
        return SecurityConfig(
            require_authentication=self.config_manager.get("client_settings.require_authentication", True),
            enable_encryption=self.config_manager.get("client_settings.enable_encryption", True),
            enable_audit_logging=self.config_manager.get("client_settings.enable_audit_logging", True),
            max_failed_auth_attempts=self.config_manager.get("client_settings.max_failed_auth_attempts", 5),
            auth_lockout_duration_minutes=self.config_manager.get("client_settings.auth_lockout_duration_minutes", 30),
            encryption_key_rotation_days=self.config_manager.get("client_settings.encryption_key_rotation_days", 90),
            audit_retention_days=self.config_manager.get("client_settings.audit_retention_days", 365),
        )
    
    def _is_admin_user(self, security_context: Optional[SecurityContext]) -> bool:
        """Check if user has admin privileges."""
        if not security_context:
            return False
        return (security_context.security_level == SecurityLevel.ADMIN or 
                security_context.security_level == SecurityLevel.SYSTEM or
                'admin' in security_context.permissions)
    
    def _get_effective_limits(self, security_context: Optional[SecurityContext]) -> SettingLimits:
        """Get effective limits based on user privileges."""
        if self._is_admin_user(security_context):
            # Return admin limits
            admin_limits = SettingLimits(
                max_key_length=self.limits.max_key_length,
                max_string_value_length=self.limits.max_string_value_length,
                max_json_size=self.limits.max_json_size,
                max_image_size=self.limits.max_image_size,
                max_binary_size=self.limits.max_binary_size,
                max_settings_per_user=self.limits.admin_max_settings_per_user,
                max_total_storage_per_user=self.limits.admin_max_total_storage_per_user,
            )
            return admin_limits
        return self.limits
    
    async def initialize(self) -> bool:
        """Initialize the service and ensure database tables exist."""
        if self._initialized:
            return True
        
        try:
            if database_manager:
                await database_manager.initialize()
                
                # Create client_settings table
                await database_manager.ensure_table_exists(
                    "client_settings",
                    {
                        "id": "INTEGER PRIMARY KEY AUTOINCREMENT" if database_manager.config.db_type == "sqlite" else "SERIAL PRIMARY KEY",
                        "user_id": "TEXT NOT NULL",
                        "setting_key": "TEXT NOT NULL",
                        "setting_value": "TEXT",
                        "setting_type": "TEXT NOT NULL",
                        "is_encrypted": "BOOLEAN DEFAULT FALSE",
                        "created_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
                        "updated_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
                        "size_bytes": "INTEGER DEFAULT 0",
                        "access_count": "INTEGER DEFAULT 0",
                        "last_accessed": "TIMESTAMP",
                        "UNIQUE": "(user_id, setting_key)" if database_manager.config.db_type == "sqlite" else "",
                    }
                )
                
                # Create audit table
                if self.security_config.enable_audit_logging:
                    await database_manager.ensure_table_exists(
                        "client_settings_audit",
                        {
                            "id": "INTEGER PRIMARY KEY AUTOINCREMENT" if database_manager.config.db_type == "sqlite" else "SERIAL PRIMARY KEY",
                            "timestamp": "TIMESTAMP NOT NULL",
                            "operation": "TEXT NOT NULL",
                            "user_id": "TEXT NOT NULL",
                            "setting_key": "TEXT",
                            "success": "BOOLEAN NOT NULL",
                            "error": "TEXT",
                            "metadata": "TEXT",
                            "ip_address": "TEXT",
                            "user_agent": "TEXT",
                        }
                    )
                
                # Create indexes for performance
                async with get_session() as session:
                    try:
                        await session.execute(
                            "CREATE INDEX IF NOT EXISTS idx_client_settings_user_id ON client_settings(user_id)"
                        )
                        await session.execute(
                            "CREATE INDEX IF NOT EXISTS idx_client_settings_user_key ON client_settings(user_id, setting_key)"
                        )
                        await session.execute(
                            "CREATE INDEX IF NOT EXISTS idx_client_settings_updated_at ON client_settings(updated_at)"
                        )
                        if self.security_config.enable_audit_logging:
                            await session.execute(
                                "CREATE INDEX IF NOT EXISTS idx_client_settings_audit_user_id ON client_settings_audit(user_id)"
                            )
                            await session.execute(
                                "CREATE INDEX IF NOT EXISTS idx_client_settings_audit_timestamp ON client_settings_audit(timestamp)"
                            )
                        await session.commit()
                    except Exception as e:
                        self.logger.warning(f"Failed to create indexes: {e}")
                
                self._initialized = True
                self.logger.info("Client settings service initialized successfully")
                return True
            else:
                self.logger.warning("Database manager not available, running in mock mode")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to initialize client settings service: {e}")
            return False
    
    @security_required(SecurityLevel.AUTHENTICATED)
    @rate_limited_with_global()
    async def get_user_settings(self, 
                               user_id: str, 
                               user_permissions: Optional[Set[str]] = None,
                               security_context: Optional[SecurityContext] = None,
                               metadata: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Get all settings for a user with security and audit logging."""
        await self.initialize()
        
        if not database_manager:
            await self.audit_logger.log_operation("get_user_settings", user_id, success=False, 
                                                 error="Database not available", metadata=metadata)
            return []
        
        try:
            self.metrics.total_requests += 1
            
            async with get_session(user_permissions) as session:
                query = """
                    SELECT setting_key, setting_value, setting_type, is_encrypted, 
                           updated_at, size_bytes, access_count
                    FROM client_settings 
                    WHERE user_id = :user_id
                    ORDER BY setting_key
                """
                rows = await session.fetchall(query, {"user_id": user_id})
                
                settings = []
                for row in rows:
                    # Decrypt value if encrypted
                    setting_value = row["setting_value"]
                    if row.get("is_encrypted", False) and self.security_config.enable_encryption:
                        try:
                            setting_value = self.encryption_manager.decrypt_value(setting_value)
                        except EncryptionError as e:
                            self.logger.error(f"Failed to decrypt setting {row['setting_key']}: {e}")
                            continue
                    
                    setting = {
                        "setting_key": row["setting_key"],
                        "setting_value": self._deserialize_value(setting_value, row["setting_type"]),
                        "setting_type": row["setting_type"],
                        "updated_at": row["updated_at"],
                        "size_bytes": row["size_bytes"],
                        "access_count": row.get("access_count", 0)
                    }
                    settings.append(setting)
                
                # Update access tracking
                await self._update_access_tracking(session, user_id, None)
                
                self.metrics.successful_requests += 1
                await self.audit_logger.log_operation("get_user_settings", user_id, 
                                                     success=True, metadata=metadata)
                return settings
                
        except Exception as e:
            self.metrics.failed_requests += 1
            self.logger.error(f"Failed to get user settings for {user_id}: {e}")
            await self.audit_logger.log_operation("get_user_settings", user_id, 
                                                 success=False, error=str(e), metadata=metadata)
            raise
    
    @security_required(SecurityLevel.AUTHENTICATED)
    @rate_limited_with_global()
    async def get_setting(self, 
                         user_id: str, 
                         key: str, 
                         user_permissions: Optional[Set[str]] = None,
                         security_context: Optional[SecurityContext] = None,
                         metadata: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Get a specific setting for a user with security and decryption."""
        await self.initialize()
        
        if not database_manager:
            await self.audit_logger.log_operation("get_setting", user_id, key, success=False,
                                                 error="Database not available", metadata=metadata)
            return None
        
        try:
            self.metrics.total_requests += 1
            self.validator.validate_key(key)
            
            async with get_session(user_permissions) as session:
                query = """
                    SELECT setting_value, setting_type, is_encrypted, updated_at, 
                           size_bytes, access_count
                    FROM client_settings 
                    WHERE user_id = :user_id AND setting_key = :key
                """
                row = await session.fetchone(query, {"user_id": user_id, "key": key})
                
                if not row:
                    await self.audit_logger.log_operation("get_setting", user_id, key, 
                                                         success=True, metadata={**metadata, "found": False})
                    return None
                
                # Decrypt value if encrypted
                setting_value = row["setting_value"]
                if row.get("is_encrypted", False) and self.security_config.enable_encryption:
                    try:
                        setting_value = self.encryption_manager.decrypt_value(setting_value)
                    except EncryptionError as e:
                        self.logger.error(f"Failed to decrypt setting {key}: {e}")
                        await self.audit_logger.log_operation("get_setting", user_id, key,
                                                             success=False, error=f"Decryption failed: {e}", metadata=metadata)
                        raise
                
                # Update access tracking
                await self._update_access_tracking(session, user_id, key)
                await session.commit()
                
                result = {
                    "setting_key": key,
                    "setting_value": self._deserialize_value(setting_value, row["setting_type"]),
                    "setting_type": row["setting_type"],
                    "updated_at": row["updated_at"],
                    "size_bytes": row["size_bytes"],
                    "access_count": row.get("access_count", 0) + 1
                }
                
                self.metrics.successful_requests += 1
                await self.audit_logger.log_operation("get_setting", user_id, key,
                                                     success=True, metadata=metadata)
                return result
                
        except Exception as e:
            self.metrics.failed_requests += 1
            self.logger.error(f"Failed to get setting {key} for user {user_id}: {e}")
            await self.audit_logger.log_operation("get_setting", user_id, key,
                                                 success=False, error=str(e), metadata=metadata)
            raise
    
    @security_required(SecurityLevel.AUTHENTICATED)
    @rate_limited_with_global()
    async def set_setting(self, 
                         user_id: str, 
                         key: str, 
                         value: Any, 
                         setting_type: Union[str, SettingType] = SettingType.STRING,
                         user_permissions: Optional[Set[str]] = None,
                         security_context: Optional[SecurityContext] = None,
                         metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Set or update a setting for a user with security and encryption."""
        await self.initialize()
        
        if not database_manager:
            await self.audit_logger.log_operation("set_setting", user_id, key, success=False,
                                                 error="Database not available", metadata=metadata)
            return {"setting_key": key, "setting_value": value, "updated_at": datetime.utcnow()}
        
        try:
            self.metrics.total_requests += 1
            
            # Validate inputs
            self.validator.validate_key(key)
            
            if isinstance(setting_type, str):
                setting_type = SettingType(setting_type)
            
            validated_value = self.validator.validate_value(value, setting_type)
            
            # Get effective limits based on user privileges
            effective_limits = self._get_effective_limits(security_context)
            
            # Check storage limits with effective limits
            await self._check_storage_limits(user_id, key, validated_value, user_permissions, 
                                           effective_limits=effective_limits)
            
            async with get_session(user_permissions) as session:
                serialized_value = self._serialize_value(validated_value, setting_type)
                
                # Encrypt sensitive values
                is_encrypted = False
                if (self.security_config.enable_encryption and 
                    self.validator.is_sensitive_key(key)):
                    try:
                        serialized_value = self.encryption_manager.encrypt_value(serialized_value)
                        is_encrypted = True
                        self.metrics.encryption_operations += 1
                    except EncryptionError as e:
                        self.logger.warning(f"Failed to encrypt sensitive setting {key}: {e}")
                
                size_bytes = len(serialized_value.encode('utf-8')) if serialized_value else 0
                now = datetime.utcnow()
                
                # Check if setting exists
                existing = await session.fetchone(
                    "SELECT id FROM client_settings WHERE user_id = :user_id AND setting_key = :key",
                    {"user_id": user_id, "key": key}
                )
                
                if existing:
                    # Update existing setting
                    await session.update(
                        "client_settings",
                        {
                            "setting_value": serialized_value,
                            "setting_type": setting_type.value,
                            "is_encrypted": is_encrypted,
                            "updated_at": now,
                            "size_bytes": size_bytes
                        },
                        {"user_id": user_id, "setting_key": key}
                    )
                else:
                    # Insert new setting
                    await session.insert(
                        "client_settings",
                        {
                            "user_id": user_id,
                            "setting_key": key,
                            "setting_value": serialized_value,
                            "setting_type": setting_type.value,
                            "is_encrypted": is_encrypted,
                            "created_at": now,
                            "updated_at": now,
                            "size_bytes": size_bytes,
                            "access_count": 0,
                            "last_accessed": now
                        }
                    )
                
                await session.commit()
                
                # Update metrics
                self.metrics.successful_requests += 1
                self.metrics.storage_bytes_used += size_bytes
                
                result = {
                    "setting_key": key,
                    "setting_value": validated_value,
                    "setting_type": setting_type.value,
                    "updated_at": now,
                    "size_bytes": size_bytes,
                    "is_encrypted": is_encrypted
                }
                
                await self.audit_logger.log_operation("set_setting", user_id, key, 
                                                     success=True, metadata=metadata)
                return result
                
        except Exception as e:
            self.metrics.failed_requests += 1
            self.logger.error(f"Failed to set setting {key} for user {user_id}: {e}")
            await self.audit_logger.log_operation("set_setting", user_id, key,
                                                 success=False, error=str(e), metadata=metadata)
            raise
    
    @security_required(SecurityLevel.AUTHENTICATED)
    @rate_limited_with_global()
    async def delete_setting(self, 
                            user_id: str, 
                            key: str, 
                            user_permissions: Optional[Set[str]] = None,
                            security_context: Optional[SecurityContext] = None,
                            metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Delete a setting for a user with security and audit logging."""
        await self.initialize()
        
        if not database_manager:
            await self.audit_logger.log_operation("delete_setting", user_id, key, success=False,
                                                 error="Database not available", metadata=metadata)
            return True
        
        try:
            self.metrics.total_requests += 1
            self.validator.validate_key(key)
            
            async with get_session(user_permissions) as session:
                # Get setting info before deletion for audit
                existing = await session.fetchone(
                    "SELECT size_bytes FROM client_settings WHERE user_id = :user_id AND setting_key = :key",
                    {"user_id": user_id, "key": key}
                )
                
                if existing:
                    size_bytes = existing.get("size_bytes", 0)
                    
                    result = await session.delete(
                        "client_settings",
                        {"user_id": user_id, "setting_key": key}
                    )
                    await session.commit()
                    
                    # Update metrics
                    self.metrics.storage_bytes_used = max(0, self.metrics.storage_bytes_used - size_bytes)
                    self.metrics.settings_count = max(0, self.metrics.settings_count - 1)
                    
                    self.metrics.successful_requests += 1
                    await self.audit_logger.log_operation("delete_setting", user_id, key,
                                                         success=True, metadata={**metadata, "size_bytes": size_bytes})
                    return True
                else:
                    # Setting doesn't exist
                    await self.audit_logger.log_operation("delete_setting", user_id, key,
                                                         success=True, metadata={**metadata, "found": False})
                    return True
                
        except Exception as e:
            self.metrics.failed_requests += 1
            self.logger.error(f"Failed to delete setting {key} for user {user_id}: {e}")
            await self.audit_logger.log_operation("delete_setting", user_id, key,
                                                 success=False, error=str(e), metadata=metadata)
            raise
    
    @security_required(SecurityLevel.AUTHENTICATED)
    @rate_limited_with_global()
    async def bulk_update_settings(self, 
                                  user_id: str, 
                                  settings: Dict[str, Any],
                                  user_permissions: Optional[Set[str]] = None,
                                  security_context: Optional[SecurityContext] = None,
                                  metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Bulk update multiple settings for a user with security and encryption."""
        await self.initialize()
        
        if not database_manager:
            await self.audit_logger.log_operation("bulk_update_settings", user_id, success=False,
                                                 error="Database not available", metadata=metadata)
            return {"updated_count": len(settings)}
        
        # Limit bulk operations based on user privileges
        max_bulk_size = 1000 if self._is_admin_user(security_context) else 100
        if len(settings) > max_bulk_size:
            raise ValidationError(f"Too many settings in bulk update (max {max_bulk_size})")
        
        try:
            self.metrics.total_requests += 1
            updated_count = 0
            errors = []
            total_size_added = 0
            
            # Get effective limits
            effective_limits = self._get_effective_limits(security_context)
            
            async with get_session(user_permissions) as session:
                for key, value in settings.items():
                    try:
                        # Validate each setting
                        self.validator.validate_key(key)
                        
                        # Determine type from value
                        setting_type = self._infer_type(value)
                        validated_value = self.validator.validate_value(value, setting_type)
                        
                        # Check storage limits for this setting
                        await self._check_storage_limits(user_id, key, validated_value, user_permissions, 
                                                       session, effective_limits)
                        
                        serialized_value = self._serialize_value(validated_value, setting_type)
                        
                        # Encrypt sensitive values
                        is_encrypted = False
                        if (self.security_config.enable_encryption and 
                            self.validator.is_sensitive_key(key)):
                            try:
                                serialized_value = self.encryption_manager.encrypt_value(serialized_value)
                                is_encrypted = True
                                self.metrics.encryption_operations += 1
                            except EncryptionError as e:
                                self.logger.warning(f"Failed to encrypt sensitive setting {key}: {e}")
                        
                        size_bytes = len(serialized_value.encode('utf-8')) if serialized_value else 0
                        now = datetime.utcnow()
                        
                        # Check if setting exists
                        existing = await session.fetchone(
                            "SELECT id, size_bytes FROM client_settings WHERE user_id = :user_id AND setting_key = :key",
                            {"user_id": user_id, "key": key}
                        )
                        
                        if existing:
                            old_size = existing.get("size_bytes", 0)
                            await session.update(
                                "client_settings",
                                {
                                    "setting_value": serialized_value,
                                    "setting_type": setting_type.value,
                                    "is_encrypted": is_encrypted,
                                    "updated_at": now,
                                    "size_bytes": size_bytes
                                },
                                {"user_id": user_id, "setting_key": key}
                            )
                            total_size_added += (size_bytes - old_size)
                        else:
                            await session.insert(
                                "client_settings",
                                {
                                    "user_id": user_id,
                                    "setting_key": key,
                                    "setting_value": serialized_value,
                                    "setting_type": setting_type.value,
                                    "is_encrypted": is_encrypted,
                                    "created_at": now,
                                    "updated_at": now,
                                    "size_bytes": size_bytes,
                                    "access_count": 0,
                                    "last_accessed": now
                                }
                            )
                            total_size_added += size_bytes
                            self.metrics.settings_count += 1
                        
                        updated_count += 1
                        
                    except Exception as e:
                        errors.append({"key": key, "error": str(e)})
                        self.logger.warning(f"Failed to update setting {key}: {e}")
                
                await session.commit()
                
                # Update metrics
                self.metrics.storage_bytes_used += total_size_added
                self.metrics.successful_requests += 1
                
                result = {
                    "updated_count": updated_count,
                    "total_size_added": total_size_added
                }
                if errors:
                    result["errors"] = errors
                
                await self.audit_logger.log_operation("bulk_update_settings", user_id,
                                                     success=True, 
                                                     metadata={**metadata, "updated_count": updated_count, "errors": len(errors)})
                return result
                
        except Exception as e:
            self.metrics.failed_requests += 1
            self.logger.error(f"Failed to bulk update settings for user {user_id}: {e}")
            await self.audit_logger.log_operation("bulk_update_settings", user_id,
                                                 success=False, error=str(e), metadata=metadata)
            raise
    
    async def get_user_stats(self, 
                           user_id: str, 
                           user_permissions: Optional[Set[str]] = None,
                           security_context: Optional[SecurityContext] = None,
                           metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Get storage statistics for a user with effective limits."""
        await self.initialize()
        
        if not database_manager:
            return {"total_settings": 0, "total_storage_bytes": 0}
        
        try:
            # Get effective limits based on user privileges
            effective_limits = self._get_effective_limits(security_context)
            
            async with get_session(user_permissions) as session:
                query = """
                    SELECT 
                        COUNT(*) as total_settings,
                        COALESCE(SUM(size_bytes), 0) as total_storage_bytes,
                        COUNT(CASE WHEN setting_type = 'image' THEN 1 END) as image_count,
                        COUNT(CASE WHEN setting_type = 'binary' THEN 1 END) as binary_count,
                        COUNT(CASE WHEN is_encrypted = 1 THEN 1 END) as encrypted_count,
                        COALESCE(SUM(access_count), 0) as total_access_count,
                        MAX(last_accessed) as last_accessed
                    FROM client_settings 
                    WHERE user_id = :user_id
                """
                row = await session.fetchone(query, {"user_id": user_id})
                
                stats = {
                    "total_settings": row["total_settings"] or 0,
                    "total_storage_bytes": row["total_storage_bytes"] or 0,
                    "image_count": row["image_count"] or 0,
                    "binary_count": row["binary_count"] or 0,
                    "encrypted_count": row["encrypted_count"] or 0,
                    "total_access_count": row["total_access_count"] or 0,
                    "last_accessed": row["last_accessed"],
                    "storage_limit_bytes": effective_limits.max_total_storage_per_user,
                    "settings_limit": effective_limits.max_settings_per_user,
                    "storage_usage_percent": 0,
                    "settings_usage_percent": 0,
                    "is_admin_user": self._is_admin_user(security_context)
                }
                
                # Calculate usage percentages
                if effective_limits.max_total_storage_per_user > 0:
                    stats["storage_usage_percent"] = (stats["total_storage_bytes"] / effective_limits.max_total_storage_per_user) * 100
                
                if effective_limits.max_settings_per_user > 0:
                    stats["settings_usage_percent"] = (stats["total_settings"] / effective_limits.max_settings_per_user) * 100
                
                return stats
                
        except Exception as e:
            self.logger.error(f"Failed to get user stats for {user_id}: {e}")
            return {"total_settings": 0, "total_storage_bytes": 0}
    
    async def get_user_images(self, 
                            user_id: str, 
                            user_permissions: Optional[Set[str]] = None,
                            security_context: Optional[SecurityContext] = None,
                            metadata: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Get all image settings for a user with security and decryption."""
        await self.initialize()
        
        if not database_manager:
            return []
        
        try:
            async with get_session(user_permissions) as session:
                query = """
                    SELECT setting_key, setting_value, is_encrypted, updated_at, 
                           size_bytes, access_count
                    FROM client_settings 
                    WHERE user_id = :user_id AND setting_type = 'image'
                    ORDER BY updated_at DESC
                """
                rows = await session.fetchall(query, {"user_id": user_id})
                
                images = []
                for row in rows:
                    try:
                        # Decrypt value if encrypted
                        setting_value = row["setting_value"]
                        if row.get("is_encrypted", False) and self.security_config.enable_encryption:
                            setting_value = self.encryption_manager.decrypt_value(setting_value)
                        
                        image_data = self._deserialize_value(setting_value, "image")
                        images.append({
                            "setting_key": row["setting_key"],
                            "content_type": image_data.get("content_type", "image/jpeg"),
                            "size": row["size_bytes"],
                            "hash": image_data.get("hash"),
                            "updated_at": row["updated_at"],
                            "access_count": row.get("access_count", 0),
                            "is_encrypted": row.get("is_encrypted", False)
                        })
                    except Exception as e:
                        self.logger.error(f"Failed to process image setting {row['setting_key']}: {e}")
                        continue
                
                return images
                
        except Exception as e:
            self.logger.error(f"Failed to get user images for {user_id}: {e}")
            return []
    
    async def cleanup_expired_settings(self, 
                                     days_old: int = 365,
                                     security_context: Optional[SecurityContext] = None,
                                     metadata: Optional[Dict[str, Any]] = None) -> int:
        """Clean up old unused settings (admin operation)."""
        await self.initialize()
        
        # Require admin privileges for cleanup
        if not self._is_admin_user(security_context):
            await self.audit_logger.log_operation("cleanup_expired_settings", "system",
                                                 success=False, error="Admin privileges required", metadata=metadata)
            raise SecurityError("Admin privileges required for cleanup operation")
        
        if not database_manager:
            return 0
        
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_old)
            
            async with get_session() as session:
                # Get count before deletion for audit
                count_query = "SELECT COUNT(*) as count FROM client_settings WHERE updated_at < :cutoff"
                count_result = await session.fetchone(count_query, {"cutoff": cutoff_date})
                settings_to_delete = count_result["count"] if count_result else 0
                
                # Delete expired settings
                result = await session.execute(
                    "DELETE FROM client_settings WHERE updated_at < :cutoff",
                    {"cutoff": cutoff_date}
                )
                await session.commit()
                
                # Clean up audit logs if enabled
                if self.security_config.enable_audit_logging:
                    audit_cutoff = datetime.utcnow() - timedelta(days=self.security_config.audit_retention_days)
                    await session.execute(
                        "DELETE FROM client_settings_audit WHERE timestamp < :cutoff",
                        {"cutoff": audit_cutoff}
                    )
                    await session.commit()
                
                deleted_count = getattr(result, 'rowcount', settings_to_delete)
                
                await self.audit_logger.log_operation("cleanup_expired_settings", "system",
                                                     success=True, 
                                                     metadata={**metadata, "deleted_count": deleted_count, "days_old": days_old})
                
                self.logger.info(f"Cleaned up {deleted_count} expired settings older than {days_old} days")
                return deleted_count
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup expired settings: {e}")
            await self.audit_logger.log_operation("cleanup_expired_settings", "system",
                                                 success=False, error=str(e), metadata=metadata)
            return 0
    
    async def get_service_metrics(self, 
                                security_context: Optional[SecurityContext] = None) -> Dict[str, Any]:
        """Get service metrics (admin operation)."""
        if not self._is_admin_user(security_context):
            raise SecurityError("Admin privileges required for metrics access")
        
        await self.initialize()
        
        metrics = {
            "total_requests": self.metrics.total_requests,
            "successful_requests": self.metrics.successful_requests,
            "failed_requests": self.metrics.failed_requests,
            "rate_limited_requests": self.metrics.rate_limited_requests,
            "security_violations": self.metrics.security_violations,
            "encryption_operations": self.metrics.encryption_operations,
            "audit_events": self.metrics.audit_events,
            "storage_bytes_used": self.metrics.storage_bytes_used,
            "settings_count": self.metrics.settings_count,
            "service_initialized": self._initialized,
            "encryption_enabled": self.security_config.enable_encryption,
            "audit_logging_enabled": self.security_config.enable_audit_logging,
        }
        
        # Add database metrics if available
        if database_manager:
            try:
                async with get_session() as session:
                    # Get total settings count
                    count_query = "SELECT COUNT(*) as total FROM client_settings"
                    count_result = await session.fetchone(count_query)
                    metrics["total_settings_in_db"] = count_result["total"] if count_result else 0
                    
                    # Get total storage used
                    storage_query = "SELECT COALESCE(SUM(size_bytes), 0) as total_storage FROM client_settings"
                    storage_result = await session.fetchone(storage_query)
                    metrics["total_storage_in_db"] = storage_result["total_storage"] if storage_result else 0
                    
                    # Get user count
                    user_query = "SELECT COUNT(DISTINCT user_id) as user_count FROM client_settings"
                    user_result = await session.fetchone(user_query)
                    metrics["unique_users"] = user_result["user_count"] if user_result else 0
                    
            except Exception as e:
                self.logger.error(f"Failed to get database metrics: {e}")
        
        return metrics
    
    async def _update_access_tracking(self, session, user_id: str, setting_key: Optional[str]) -> None:
        """Update access tracking for settings."""
        try:
            now = datetime.utcnow()
            if setting_key:
                # Update specific setting
                await session.update(
                    "client_settings",
                    {
                        "access_count": "access_count + 1",
                        "last_accessed": now
                    },
                    {"user_id": user_id, "setting_key": setting_key}
                )
            else:
                # Update all settings for user (bulk access)
                await session.execute(
                    "UPDATE client_settings SET last_accessed = :now WHERE user_id = :user_id",
                    {"now": now, "user_id": user_id}
                )
        except Exception as e:
            self.logger.warning(f"Failed to update access tracking: {e}")
    
    def _serialize_value(self, value: Any, setting_type: SettingType) -> str:
        """Serialize a value for database storage."""
        if value is None:
            return ""
        
        if setting_type in (SettingType.IMAGE, SettingType.BINARY, SettingType.JSON):
            return json.dumps(value)
        else:
            return str(value)
    
    def _deserialize_value(self, serialized: str, setting_type: str) -> Any:
        """Deserialize a value from database storage."""
        if not serialized:
            return None
        
        setting_type_enum = SettingType(setting_type)
        
        if setting_type_enum == SettingType.STRING:
            return serialized
        elif setting_type_enum == SettingType.INTEGER:
            return int(serialized)
        elif setting_type_enum == SettingType.FLOAT:
            return float(serialized)
        elif setting_type_enum == SettingType.BOOLEAN:
            return serialized.lower() in ('true', '1', 'yes')
        elif setting_type_enum in (SettingType.JSON, SettingType.IMAGE, SettingType.BINARY):
            return json.loads(serialized)
        else:
            return serialized
    
    def _infer_type(self, value: Any) -> SettingType:
        """Infer the setting type from a value."""
        if isinstance(value, bool):
            return SettingType.BOOLEAN
        elif isinstance(value, int):
            return SettingType.INTEGER
        elif isinstance(value, float):
            return SettingType.FLOAT
        elif isinstance(value, (dict, list)):
            # Check if it looks like image data
            if isinstance(value, dict) and 'data' in value and 'content_type' in value:
                content_type = value.get('content_type', '')
                if content_type.startswith('image/'):
                    return SettingType.IMAGE
                else:
                    return SettingType.BINARY
            return SettingType.JSON
        else:
            return SettingType.STRING
    
    async def _check_storage_limits(self, 
                                   user_id: str, 
                                   key: str, 
                                   value: Any, 
                                   user_permissions: Optional[Set[str]] = None,
                                   session=None,
                                   effective_limits: Optional[SettingLimits] = None) -> None:
        """Check if setting the value would exceed storage limits."""
        if not database_manager:
            return
        
        # Use provided limits or default
        limits = effective_limits or self.limits
        
        # Calculate size of new value
        setting_type = self._infer_type(value)
        serialized_value = self._serialize_value(value, setting_type)
        new_size = len(serialized_value.encode('utf-8')) if serialized_value else 0
        
        # Get current stats
        if session:
            # Use existing session
            stats_query = """
                SELECT 
                    COUNT(*) as total_settings,
                    COALESCE(SUM(size_bytes), 0) as total_storage_bytes,
                    COALESCE(SUM(CASE WHEN setting_key = :key THEN size_bytes ELSE 0 END), 0) as current_key_size
                FROM client_settings 
                WHERE user_id = :user_id
            """
            row = await session.fetchone(stats_query, {"user_id": user_id, "key": key})
        else:
            async with get_session(user_permissions) as temp_session:
                stats_query = """
                    SELECT 
                        COUNT(*) as total_settings,
                        COALESCE(SUM(size_bytes), 0) as total_storage_bytes,
                        COALESCE(SUM(CASE WHEN setting_key = :key THEN size_bytes ELSE 0 END), 0) as current_key_size
                    FROM client_settings 
                    WHERE user_id = :user_id
                """
                row = await temp_session.fetchone(stats_query, {"user_id": user_id, "key": key})
        
        current_settings = row["total_settings"] or 0
        current_storage = row["total_storage_bytes"] or 0
        current_key_size = row["current_key_size"] or 0
        
        # Check settings count limit (only if this is a new setting)
        if current_key_size == 0 and current_settings >= limits.max_settings_per_user:
            raise StorageLimitError(f"Maximum number of settings exceeded ({limits.max_settings_per_user})")
        
        # Check total storage limit
        new_total_storage = current_storage - current_key_size + new_size
        if new_total_storage > limits.max_total_storage_per_user:
            raise StorageLimitError(f"Storage limit exceeded ({limits.max_total_storage_per_user} bytes)")


# Global service instance
client_settings_service = ClientSettingsService()


# Convenience functions for backward compatibility with enhanced security
async def get_user_settings(user_id: str, 
                           user_permissions: Optional[Set[str]] = None,
                           security_context: Optional[SecurityContext] = None,
                           metadata: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Get all settings for a user."""
    return await client_settings_service.get_user_settings(user_id, user_permissions, security_context, metadata)


async def get_setting(user_id: str, 
                     key: str, 
                     user_permissions: Optional[Set[str]] = None,
                     security_context: Optional[SecurityContext] = None,
                     metadata: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Get a specific setting for a user."""
    return await client_settings_service.get_setting(user_id, key, user_permissions, security_context, metadata)


async def set_setting(user_id: str, 
                     key: str, 
                     value: Any, 
                     setting_type: Union[str, SettingType] = SettingType.STRING,
                     user_permissions: Optional[Set[str]] = None,
                     security_context: Optional[SecurityContext] = None,
                     metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Set or update a setting for a user."""
    return await client_settings_service.set_setting(user_id, key, value, setting_type, 
                                                     user_permissions, security_context, metadata)


async def delete_setting(user_id: str, 
                        key: str, 
                        user_permissions: Optional[Set[str]] = None,
                        security_context: Optional[SecurityContext] = None,
                        metadata: Optional[Dict[str, Any]] = None) -> bool:
    """Delete a setting for a user."""
    return await client_settings_service.delete_setting(user_id, key, user_permissions, security_context, metadata)


async def bulk_update_settings(user_id: str, 
                              settings: Dict[str, Any],
                              user_permissions: Optional[Set[str]] = None,
                              security_context: Optional[SecurityContext] = None,
                              metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Bulk update multiple settings for a user."""
    return await client_settings_service.bulk_update_settings(user_id, settings, user_permissions, 
                                                             security_context, metadata)


async def get_user_stats(user_id: str, 
                        user_permissions: Optional[Set[str]] = None,
                        security_context: Optional[SecurityContext] = None,
                        metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Get storage statistics for a user."""
    return await client_settings_service.get_user_stats(user_id, user_permissions, security_context, metadata)


async def get_user_images(user_id: str, 
                         user_permissions: Optional[Set[str]] = None,
                         security_context: Optional[SecurityContext] = None,
                         metadata: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Get all image settings for a user."""
    return await client_settings_service.get_user_images(user_id, user_permissions, security_context, metadata)


async def cleanup_expired_settings(days_old: int = 365,
                                  security_context: Optional[SecurityContext] = None,
                                  metadata: Optional[Dict[str, Any]] = None) -> int:
    """Clean up old unused settings (admin operation)."""
    return await client_settings_service.cleanup_expired_settings(days_old, security_context, metadata)


async def get_service_metrics(security_context: Optional[SecurityContext] = None) -> Dict[str, Any]:
    """Get service metrics (admin operation)."""
    return await client_settings_service.get_service_metrics(security_context)


# Initialize service on module import
async def initialize_client_settings_service() -> bool:
    """Initialize the client settings service."""
    return await client_settings_service.initialize()


# Shutdown service
async def shutdown_client_settings_service() -> None:
    """Shutdown the client settings service."""
    if client_settings_service._initialized:
        client_settings_service.logger.info("Client settings service shutting down")
        client_settings_service._initialized = False
